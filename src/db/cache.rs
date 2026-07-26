//! System-wide cache facade with configurable TTL and Redis-ready settings.
//!
//! The core contract crate cannot open network sockets when compiled to
//! Soroban/WASM, so this module keeps the cache backend dependency-free while
//! still modeling the configuration an off-chain service uses to front the
//! same API with Redis. Critical paths can use [`TtlCache`] in-process and
//! export [`CacheMetrics`] to monitoring; service adapters can translate
//! [`RedisCacheConfig`] into their Redis client of choice without changing call
//! sites.

extern crate alloc;

use alloc::collections::BTreeMap;

/// Default item lifetime used by [`CacheConfig::default`].
pub const DEFAULT_TTL_MS: u64 = 30_000;
/// Default namespace prefix used to avoid key collisions in shared Redis.
pub const DEFAULT_NAMESPACE: &str = "verinode";
/// Default soft latency budget for cache operations on critical paths.
pub const DEFAULT_OPERATION_BUDGET_MS: u64 = 100;

/// Cache configuration shared by in-memory and Redis-backed deployments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheConfig {
    /// Default TTL assigned when callers do not provide an override.
    pub default_ttl_ms: u64,
    /// Maximum entries retained by the in-memory fallback.
    pub max_entries: usize,
    /// Namespace prepended by service adapters before writing to Redis.
    pub namespace: &'static str,
    /// Soft P99 budget used by monitoring/alerting dashboards.
    pub operation_budget_ms: u64,
    /// Optional Redis connection information for off-chain services.
    pub redis: Option<RedisCacheConfig>,
}

impl CacheConfig {
    /// Create a config with a custom default TTL.
    pub fn with_ttl(default_ttl_ms: u64) -> Self {
        Self {
            default_ttl_ms,
            ..Self::default()
        }
    }

    /// Return the effective TTL, falling back to the configured default.
    pub fn ttl_or_default(&self, ttl_ms: Option<u64>) -> u64 {
        ttl_ms.unwrap_or(self.default_ttl_ms)
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            default_ttl_ms: DEFAULT_TTL_MS,
            max_entries: 10_000,
            namespace: DEFAULT_NAMESPACE,
            operation_budget_ms: DEFAULT_OPERATION_BUDGET_MS,
            redis: None,
        }
    }
}

/// Redis deployment settings consumed by off-chain service adapters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedisCacheConfig {
    /// Redis URL, for example `redis://cache.internal:6379/0`.
    pub url: &'static str,
    /// Connection pool size for high-availability service deployments.
    pub pool_size: u32,
    /// Socket/connect timeout in milliseconds.
    pub timeout_ms: u64,
    /// Whether adapters must require TLS-capable Redis endpoints.
    pub require_tls: bool,
}

impl RedisCacheConfig {
    /// Build a secure Redis configuration with conservative defaults.
    pub fn new(url: &'static str) -> Self {
        Self {
            url,
            pool_size: 16,
            timeout_ms: DEFAULT_OPERATION_BUDGET_MS,
            require_tls: true,
        }
    }
}

/// Cache hit/miss/eviction counters for monitoring and alerting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheMetrics {
    pub hits: u64,
    pub misses: u64,
    pub writes: u64,
    pub evictions: u64,
    pub expirations: u64,
}

impl CacheMetrics {
    /// Integer hit ratio in basis points, suitable for compact dashboards.
    pub fn hit_ratio_bps(&self) -> u32 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0;
        }
        ((self.hits * 10_000) / total) as u32
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry<V> {
    value: V,
    expires_at_ms: u64,
    written_at_ms: u64,
}

/// Deterministic in-memory TTL cache used by tests and single-process services.
#[derive(Clone, Debug)]
pub struct TtlCache<K, V> {
    entries: BTreeMap<K, Entry<V>>,
    config: CacheConfig,
    metrics: CacheMetrics,
}

impl<K, V> TtlCache<K, V>
where
    K: Ord + Clone,
    V: Clone,
{
    /// Create an empty cache using the supplied configuration.
    pub fn new(config: CacheConfig) -> Self {
        Self {
            entries: BTreeMap::new(),
            config,
            metrics: CacheMetrics::default(),
        }
    }

    /// Insert a value with an optional per-entry TTL override.
    pub fn insert(&mut self, key: K, value: V, now_ms: u64, ttl_ms: Option<u64>) {
        self.expire(now_ms);
        let effective_ttl = self.config.ttl_or_default(ttl_ms);
        self.entries.insert(
            key,
            Entry {
                value,
                expires_at_ms: now_ms.saturating_add(effective_ttl),
                written_at_ms: now_ms,
            },
        );
        self.metrics.writes = self.metrics.writes.saturating_add(1);
        self.evict_to_capacity();
    }

    /// Return a cached value if present and unexpired.
    pub fn get(&mut self, key: &K, now_ms: u64) -> Option<V> {
        let expired = self
            .entries
            .get(key)
            .map(|entry| now_ms >= entry.expires_at_ms)
            .unwrap_or(false);
        if expired {
            self.entries.remove(key);
            self.metrics.expirations = self.metrics.expirations.saturating_add(1);
        }

        match self.entries.get(key) {
            Some(entry) => {
                self.metrics.hits = self.metrics.hits.saturating_add(1);
                Some(entry.value.clone())
            }
            None => {
                self.metrics.misses = self.metrics.misses.saturating_add(1);
                None
            }
        }
    }

    /// Remove all expired entries as of `now_ms`.
    pub fn expire(&mut self, now_ms: u64) {
        let before = self.entries.len();
        self.entries.retain(|_, entry| now_ms < entry.expires_at_ms);
        self.metrics.expirations = self
            .metrics
            .expirations
            .saturating_add((before - self.entries.len()) as u64);
    }

    /// Current number of live entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when there are no live entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Snapshot cache counters for observability export.
    pub fn metrics(&self) -> CacheMetrics {
        self.metrics
    }

    fn evict_to_capacity(&mut self) {
        while self.entries.len() > self.config.max_entries {
            let oldest_key = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.written_at_ms)
                .map(|(key, _)| key.clone());
            if let Some(key) = oldest_key {
                self.entries.remove(&key);
                self.metrics.evictions = self.metrics.evictions.saturating_add(1);
            } else {
                break;
            }
        }
    }
}

impl<K, V> Default for TtlCache<K, V>
where
    K: Ord + Clone,
    V: Clone,
{
    fn default() -> Self {
        Self::new(CacheConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_value_before_ttl_and_miss_after_expiry() {
        let mut cache = TtlCache::new(CacheConfig::with_ttl(50));
        cache.insert("validator:1", 42u64, 1_000, None);

        assert_eq!(cache.get(&"validator:1", 1_049), Some(42));
        assert_eq!(cache.get(&"validator:1", 1_050), None);

        let metrics = cache.metrics();
        assert_eq!(metrics.hits, 1);
        assert_eq!(metrics.misses, 1);
        assert_eq!(metrics.expirations, 1);
    }

    #[test]
    fn per_entry_ttl_overrides_default() {
        let mut cache = TtlCache::new(CacheConfig::with_ttl(1_000));
        cache.insert("committee", [7u8; 32], 10, Some(5));

        assert_eq!(cache.get(&"committee", 14), Some([7u8; 32]));
        assert_eq!(cache.get(&"committee", 15), None);
    }

    #[test]
    fn capacity_evicts_oldest_entry() {
        let mut config = CacheConfig::default();
        config.max_entries = 2;
        let mut cache = TtlCache::new(config);

        cache.insert(1u64, "a", 10, None);
        cache.insert(2u64, "b", 11, None);
        cache.insert(3u64, "c", 12, None);

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&1, 13), None);
        assert_eq!(cache.get(&2, 13), Some("b"));
        assert_eq!(cache.metrics().evictions, 1);
    }

    #[test]
    fn metrics_report_hit_ratio_for_dashboards() {
        let mut cache = TtlCache::default();
        cache.insert("key", "value", 0, None);
        assert_eq!(cache.get(&"key", 1), Some("value"));
        assert_eq!(cache.get(&"missing", 1), None);

        assert_eq!(cache.metrics().hit_ratio_bps(), 5_000);
    }

    #[test]
    fn redis_config_defaults_to_tls_and_latency_budget() {
        let redis = RedisCacheConfig::new("rediss://cache.internal:6379/0");
        assert!(redis.require_tls);
        assert_eq!(redis.timeout_ms, DEFAULT_OPERATION_BUDGET_MS);
        assert_eq!(redis.pool_size, 16);
    }
}
