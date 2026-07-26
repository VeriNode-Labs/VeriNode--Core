//! Per-tenant token-bucket rate limiting for API-facing services.
//!
//! The limiter is intentionally dependency-free and deterministic so it can be
//! exercised in consensus-adjacent tests and embedded by off-chain API
//! gateways. Each tenant receives an isolated token bucket, making noisy-neighbor
//! throttling impossible while keeping the hot path to one map lookup and a few
//! integer operations.

extern crate alloc;

use alloc::collections::BTreeMap;

/// Default sustained tenant rate in tokens per second.
pub const DEFAULT_REFILL_RATE_PER_SECOND: u64 = 100;
/// Default tenant burst capacity.
pub const DEFAULT_BURST_CAPACITY: u64 = 1_000;
/// Critical-path latency budget from issue #73, expressed in milliseconds.
pub const CRITICAL_PATH_P99_BUDGET_MS: u64 = 100;
/// Recommended availability objective for rate-limit enforcement.
pub const AVAILABILITY_TARGET_BPS: u32 = 9_999; // 99.99%

/// Tenant identifier used by API gateways and internal services.
pub type TenantId = u64;

/// Token-bucket configuration applied to newly-created tenant buckets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitConfig {
    /// Maximum number of tokens a tenant may accumulate for burst traffic.
    pub burst_capacity: u64,
    /// Number of tokens replenished per second.
    pub refill_rate_per_second: u64,
}

impl RateLimitConfig {
    /// Creates a configuration and rejects unusable buckets.
    pub const fn new(burst_capacity: u64, refill_rate_per_second: u64) -> Option<Self> {
        if burst_capacity == 0 || refill_rate_per_second == 0 {
            return None;
        }

        Some(Self {
            burst_capacity,
            refill_rate_per_second,
        })
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            burst_capacity: DEFAULT_BURST_CAPACITY,
            refill_rate_per_second: DEFAULT_REFILL_RATE_PER_SECOND,
        }
    }
}

/// Runtime view of a tenant bucket for monitoring and dashboards.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BucketSnapshot {
    pub tenant_id: TenantId,
    pub available_tokens: u64,
    pub burst_capacity: u64,
    pub refill_rate_per_second: u64,
    pub last_refill_timestamp: u64,
    pub accepted_requests: u64,
    pub rejected_requests: u64,
}

/// Aggregate counters suitable for alerting pipelines.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RateLimitMetrics {
    pub tenants_tracked: u64,
    pub accepted_requests: u64,
    pub rejected_requests: u64,
}

/// Decision returned by [`TenantRateLimiter::check`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitDecision {
    Allowed { remaining_tokens: u64 },
    Denied { retry_after_seconds: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TenantBucket {
    available_tokens: u64,
    last_refill_timestamp: u64,
    accepted_requests: u64,
    rejected_requests: u64,
}

impl TenantBucket {
    fn new(now: u64, config: RateLimitConfig) -> Self {
        Self {
            available_tokens: config.burst_capacity,
            last_refill_timestamp: now,
            accepted_requests: 0,
            rejected_requests: 0,
        }
    }

    fn refill(&mut self, now: u64, config: RateLimitConfig) {
        let elapsed = now.saturating_sub(self.last_refill_timestamp);
        if elapsed == 0 {
            return;
        }

        let refill = elapsed.saturating_mul(config.refill_rate_per_second);
        self.available_tokens = self
            .available_tokens
            .saturating_add(refill)
            .min(config.burst_capacity);
        self.last_refill_timestamp = now;
    }
}

/// In-memory per-tenant token bucket limiter.
#[derive(Clone, Debug)]
pub struct TenantRateLimiter {
    config: RateLimitConfig,
    buckets: BTreeMap<TenantId, TenantBucket>,
}

impl TenantRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: BTreeMap::new(),
        }
    }

    /// Checks and consumes `cost` tokens for `tenant_id` at timestamp `now`.
    pub fn check(&mut self, tenant_id: TenantId, now: u64, cost: u64) -> RateLimitDecision {
        if cost == 0 {
            return RateLimitDecision::Allowed {
                remaining_tokens: self.snapshot_or_default(tenant_id, now).available_tokens,
            };
        }

        let bucket = self
            .buckets
            .entry(tenant_id)
            .or_insert_with(|| TenantBucket::new(now, self.config));
        bucket.refill(now, self.config);

        if bucket.available_tokens >= cost {
            bucket.available_tokens -= cost;
            bucket.accepted_requests = bucket.accepted_requests.saturating_add(1);
            RateLimitDecision::Allowed {
                remaining_tokens: bucket.available_tokens,
            }
        } else {
            bucket.rejected_requests = bucket.rejected_requests.saturating_add(1);
            let missing = cost - bucket.available_tokens;
            let retry_after_seconds = missing.div_ceil(self.config.refill_rate_per_second);
            RateLimitDecision::Denied {
                retry_after_seconds,
            }
        }
    }

    pub fn snapshot(&self, tenant_id: TenantId) -> Option<BucketSnapshot> {
        self.buckets
            .get(&tenant_id)
            .map(|bucket| self.snapshot_from_bucket(tenant_id, *bucket))
    }

    pub fn metrics(&self) -> RateLimitMetrics {
        self.buckets.values().fold(
            RateLimitMetrics {
                tenants_tracked: self.buckets.len() as u64,
                ..RateLimitMetrics::default()
            },
            |mut metrics, bucket| {
                metrics.accepted_requests = metrics
                    .accepted_requests
                    .saturating_add(bucket.accepted_requests);
                metrics.rejected_requests = metrics
                    .rejected_requests
                    .saturating_add(bucket.rejected_requests);
                metrics
            },
        )
    }

    fn snapshot_or_default(&self, tenant_id: TenantId, now: u64) -> BucketSnapshot {
        self.snapshot(tenant_id).unwrap_or(BucketSnapshot {
            tenant_id,
            available_tokens: self.config.burst_capacity,
            burst_capacity: self.config.burst_capacity,
            refill_rate_per_second: self.config.refill_rate_per_second,
            last_refill_timestamp: now,
            accepted_requests: 0,
            rejected_requests: 0,
        })
    }

    fn snapshot_from_bucket(&self, tenant_id: TenantId, bucket: TenantBucket) -> BucketSnapshot {
        BucketSnapshot {
            tenant_id,
            available_tokens: bucket.available_tokens,
            burst_capacity: self.config.burst_capacity,
            refill_rate_per_second: self.config.refill_rate_per_second,
            last_refill_timestamp: bucket.last_refill_timestamp,
            accepted_requests: bucket.accepted_requests,
            rejected_requests: bucket.rejected_requests,
        }
    }
}

impl Default for TenantRateLimiter {
    fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }
}
