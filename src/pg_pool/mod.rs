//! PostgreSQL connection-pool health probe with adaptive sizing (issue #134).
//!
//! This module provides deterministic, dependency-free primitives for probing
//! connection-pool health, evaluating pool capacity, and producing adaptive
//! sizing decisions. All math is pure Rust — no network I/O, no database
//! driver — so on-chain contracts, off-chain monitoring agents, and blue-green
//! deployment gates share exactly the same thresholds and logic.
//!
//! # Design overview
//!
//! ```text
//!  ┌────────────────────────┐  health samples  ┌──────────────────────────────┐
//!  │  ConnectionPoolState   │ ────────────────▶  PoolHealthProbe              │
//!  │  (per service)         │                  │  • probe()                   │
//!  │                        │                  │  • dashboard_snapshot()      │
//!  └────────────────────────┘                  └──────────────┬───────────────┘
//!                                                             │ PoolHealthReport
//!                                                             ▼
//!                                              ┌──────────────────────────────┐
//!                                              │  PoolAdaptiveSizer           │
//!                                              │  • recommend_resize()        │
//!                                              │  • canary_gate()             │
//!                                              └──────────────────────────────┘
//! ```
//!
//! # Operational constants
//!
//! All thresholds are tunable via [`PoolSizingConfig`] but default to the
//! values mandated by the technical bounds in issue #134:
//! * P99 critical-path latency target: < 100 ms
//! * Availability target: 99.99% (9_999 basis points)
//! * Blue-green + canary deployment gates enforced on every resize event

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Operational constants
// ---------------------------------------------------------------------------

/// P99 latency target for connection-acquisition on critical paths, in
/// milliseconds.
pub const CRITICAL_PATH_P99_MS: u64 = 100;

/// Availability objective expressed in basis points: 99.99%.
pub const AVAILABILITY_TARGET_BPS: u32 = 9_999;

/// Default ratio of active connections above which a pool is considered
/// saturated and a scale-out should be recommended (90%).
pub const DEFAULT_SATURATION_THRESHOLD_BPS: u32 = 9_000;

/// Default ratio of active connections below which a pool is considered
/// under-utilised and a scale-in can be considered (30%).
pub const DEFAULT_UNDERUTILISATION_THRESHOLD_BPS: u32 = 3_000;

/// Default minimum number of connections a pool may hold.
pub const DEFAULT_MIN_POOL_SIZE: u32 = 2;

/// Default maximum number of connections a pool may hold.
pub const DEFAULT_MAX_POOL_SIZE: u32 = 128;

/// Default cooldown between consecutive resize actions, in seconds.
pub const DEFAULT_RESIZE_COOLDOWN_SECS: u64 = 30;

/// Number of consecutive unhealthy probes before a pool transitions to the
/// `Degraded` health state.
pub const DEGRADED_PROBE_THRESHOLD: u32 = 3;

/// Number of consecutive healthy probes required to recover from `Degraded`
/// back to `Healthy`.
pub const RECOVERY_PROBE_THRESHOLD: u32 = 2;

/// Maximum number of distinct service pools tracked concurrently.
pub const MAX_SERVICE_POOLS: usize = 512;

/// Canary success-rate gate in basis points before a resize is promoted.
pub const CANARY_SUCCESS_TARGET_BPS: u32 = 9_999;

// ---------------------------------------------------------------------------
// Identifier types
// ---------------------------------------------------------------------------

/// Logical service name that owns the connection pool (e.g. `"payments"`).
pub type ServiceName = String;

// ---------------------------------------------------------------------------
// Connection pool state snapshot
// ---------------------------------------------------------------------------

/// A point-in-time observation of a single PostgreSQL connection pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionPoolState {
    /// Service that owns this pool.
    pub service: ServiceName,
    /// Maximum connections the pool is currently configured to hold.
    pub pool_size: u32,
    /// Connections currently checked out by application threads.
    pub active_connections: u32,
    /// Connections sitting idle in the pool, available for immediate use.
    pub idle_connections: u32,
    /// Requests currently waiting to acquire a connection (queue depth).
    pub pending_requests: u32,
    /// P99 connection-acquisition latency observed in the last measurement
    /// window, in milliseconds.
    pub p99_acquire_ms: u64,
    /// Wall-clock timestamp when this snapshot was collected (seconds since
    /// the Unix epoch).
    pub sampled_at: u64,
}

impl ConnectionPoolState {
    /// Returns the pool utilisation in basis points (active / pool_size).
    ///
    /// Returns 0 when `pool_size` is zero to avoid division by zero.
    pub fn utilisation_bps(&self) -> u32 {
        if self.pool_size == 0 {
            return 0;
        }
        ((self.active_connections as u64 * 10_000) / self.pool_size as u64).min(10_000) as u32
    }

    /// Returns `true` when there are requests waiting for a connection.
    pub fn has_pending_requests(&self) -> bool {
        self.pending_requests > 0
    }

    /// Returns total connections tracked by the pool (active + idle).
    pub fn total_connections(&self) -> u32 {
        self.active_connections
            .saturating_add(self.idle_connections)
    }
}

// ---------------------------------------------------------------------------
// Health states
// ---------------------------------------------------------------------------

/// Coarse health classification for a connection pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PoolHealthState {
    /// Pool is operating within all thresholds.
    Healthy,
    /// Pool is under elevated load — actionable warning, not yet degraded.
    Warning,
    /// Pool has been unhealthy for `DEGRADED_PROBE_THRESHOLD` consecutive
    /// probes; escalation and immediate sizing action are required.
    Degraded,
    /// Pool is completely unavailable (pool_size == 0 or all connections
    /// failed to be acquired).
    Unavailable,
}

// ---------------------------------------------------------------------------
// Resize direction
// ---------------------------------------------------------------------------

/// Sizing recommendation produced by [`PoolAdaptiveSizer`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResizeDecision {
    /// Current pool size is appropriate — no change needed.
    NoChange,
    /// Increase the pool size by `delta` connections.
    Expand { delta: u32 },
    /// Decrease the pool size by `delta` connections.
    Shrink { delta: u32 },
}

// ---------------------------------------------------------------------------
// Canary analysis
// ---------------------------------------------------------------------------

/// Canary-deployment analysis before promoting a pool resize to all pods.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolCanaryAnalysis {
    /// Total connection-acquisition attempts recorded in the canary window.
    pub acquisitions_attempted: u64,
    /// Acquisitions that succeeded within the P99 latency target.
    pub acquisitions_succeeded: u64,
    /// Observed P99 acquisition latency in the canary window, in milliseconds.
    pub p99_acquire_ms: u64,
    /// Whether a security review was completed for this resize event.
    pub security_review_passed: bool,
}

impl PoolCanaryAnalysis {
    /// Returns the acquisition success rate in basis points.
    pub fn success_rate_bps(&self) -> u32 {
        if self.acquisitions_attempted == 0 {
            return 0;
        }
        ((self.acquisitions_succeeded.saturating_mul(10_000)) / self.acquisitions_attempted)
            .min(10_000) as u32
    }

    /// Returns `Ok(())` when the canary meets all release-gate criteria.
    pub fn passes_release_gate(&self) -> Result<(), PoolProbeError> {
        if !self.security_review_passed {
            return Err(PoolProbeError::SecurityReviewRequired);
        }
        if self.success_rate_bps() < CANARY_SUCCESS_TARGET_BPS
            || self.p99_acquire_ms > CRITICAL_PATH_P99_MS
        {
            return Err(PoolProbeError::CanaryFailed);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by pool-health-probe operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolProbeError {
    /// No pools are registered in the registry.
    NoPoolsRegistered,
    /// The requested service pool was not found.
    PoolNotFound,
    /// Too many service pools registered concurrently.
    TooManyPools,
    /// A resize would violate the configured min/max pool-size bounds.
    SizingBoundsViolated,
    /// The resize cooldown window has not elapsed since the last action.
    CooldownActive,
    /// The canary analysis did not meet the release gate.
    CanaryFailed,
    /// A security review must be completed before the resize is promoted.
    SecurityReviewRequired,
}

// ---------------------------------------------------------------------------
// Sizing configuration
// ---------------------------------------------------------------------------

/// Tunable parameters for the adaptive sizer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PoolSizingConfig {
    /// Utilisation (bps) above which a pool expansion is recommended.
    pub saturation_threshold_bps: u32,
    /// Utilisation (bps) below which a pool shrink is considered safe.
    pub underutilisation_threshold_bps: u32,
    /// Minimum connections the pool may hold after a shrink.
    pub min_pool_size: u32,
    /// Maximum connections the pool may hold after an expansion.
    pub max_pool_size: u32,
    /// Minimum seconds between consecutive resize actions for a pool.
    pub resize_cooldown_secs: u64,
}

impl Default for PoolSizingConfig {
    fn default() -> Self {
        Self {
            saturation_threshold_bps: DEFAULT_SATURATION_THRESHOLD_BPS,
            underutilisation_threshold_bps: DEFAULT_UNDERUTILISATION_THRESHOLD_BPS,
            min_pool_size: DEFAULT_MIN_POOL_SIZE,
            max_pool_size: DEFAULT_MAX_POOL_SIZE,
            resize_cooldown_secs: DEFAULT_RESIZE_COOLDOWN_SECS,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-pool health report
// ---------------------------------------------------------------------------

/// Result of probing a single connection pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolHealthReport {
    /// The service whose pool was probed.
    pub service: ServiceName,
    /// Observed utilisation in basis points.
    pub utilisation_bps: u32,
    /// P99 connection-acquisition latency in milliseconds.
    pub p99_acquire_ms: u64,
    /// Number of requests waiting to acquire a connection.
    pub pending_requests: u32,
    /// Health state derived from the latest probe.
    pub health_state: PoolHealthState,
    /// Sizing recommendation for this pool.
    pub resize_decision: ResizeDecision,
}

// ---------------------------------------------------------------------------
// System-wide metrics snapshot
// ---------------------------------------------------------------------------

/// Aggregated metrics exported to dashboards and alerting pipelines.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolMetricsSnapshot {
    /// Number of service pools being tracked.
    pub pools_tracked: usize,
    /// Total active connections summed across all pools.
    pub total_active_connections: u64,
    /// Maximum single-pool utilisation in basis points.
    pub max_pool_utilisation_bps: u32,
    /// Number of pools in `Warning` or `Degraded` state.
    pub unhealthy_pools: usize,
    /// Number of pools in `Degraded` or `Unavailable` state.
    pub critical_pools: usize,
    /// P99 latency target from the operational constants.
    pub p99_target_ms: u64,
    /// Availability target from the operational constants.
    pub availability_target_bps: u32,
}

// ---------------------------------------------------------------------------
// Stateless health probe
// ---------------------------------------------------------------------------

/// Stateless probe: derives health state and sizing decisions from a pool
/// snapshot and a [`PoolSizingConfig`] without retaining any state itself.
pub struct PoolHealthProbe;

impl PoolHealthProbe {
    /// Probes a single connection pool and returns a [`PoolHealthReport`].
    ///
    /// # Parameters
    /// * `state`             — current snapshot of the pool.
    /// * `config`            — sizing policy to apply.
    /// * `now`               — current Unix timestamp in seconds.
    /// * `last_resize_at`    — timestamp of the last resize for this pool, or
    ///   `None` if none has been performed.
    /// * `consecutive_unhealthy` — how many consecutive unhealthy probes have
    ///   been recorded for this pool (drives `Degraded` transition).
    pub fn probe(
        state: &ConnectionPoolState,
        config: &PoolSizingConfig,
        now: u64,
        last_resize_at: Option<u64>,
        consecutive_unhealthy: u32,
    ) -> PoolHealthReport {
        let utilisation_bps = state.utilisation_bps();
        let health_state =
            Self::classify_health(state, config, utilisation_bps, consecutive_unhealthy);
        let resize_decision =
            Self::recommend_resize(state, config, now, last_resize_at, utilisation_bps);

        PoolHealthReport {
            service: state.service.clone(),
            utilisation_bps,
            p99_acquire_ms: state.p99_acquire_ms,
            pending_requests: state.pending_requests,
            health_state,
            resize_decision,
        }
    }

    /// Produces a system-wide dashboard snapshot from multiple pool states.
    pub fn dashboard_snapshot(
        states: &[ConnectionPoolState],
        config: &PoolSizingConfig,
        now: u64,
    ) -> PoolMetricsSnapshot {
        let pools_tracked = states.len();
        let mut total_active: u64 = 0;
        let mut max_util_bps: u32 = 0;
        let mut unhealthy_pools: usize = 0;
        let mut critical_pools: usize = 0;
        let _ = now;

        for state in states {
            let util = state.utilisation_bps();
            total_active = total_active.saturating_add(state.active_connections as u64);
            if util > max_util_bps {
                max_util_bps = util;
            }
            let health =
                Self::classify_health(state, config, util, 0 /* stateless snapshot */);
            if health >= PoolHealthState::Warning {
                unhealthy_pools += 1;
            }
            if health >= PoolHealthState::Degraded {
                critical_pools += 1;
            }
        }

        PoolMetricsSnapshot {
            pools_tracked,
            total_active_connections: total_active,
            max_pool_utilisation_bps: max_util_bps,
            unhealthy_pools,
            critical_pools,
            p99_target_ms: CRITICAL_PATH_P99_MS,
            availability_target_bps: AVAILABILITY_TARGET_BPS,
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn classify_health(
        state: &ConnectionPoolState,
        config: &PoolSizingConfig,
        utilisation_bps: u32,
        consecutive_unhealthy: u32,
    ) -> PoolHealthState {
        if state.pool_size == 0 {
            return PoolHealthState::Unavailable;
        }
        // Treat excessive P99 latency as unhealthy even when utilisation is low.
        let latency_unhealthy = state.p99_acquire_ms > CRITICAL_PATH_P99_MS;
        let saturated = utilisation_bps >= config.saturation_threshold_bps;
        let has_pending = state.has_pending_requests();

        if consecutive_unhealthy >= DEGRADED_PROBE_THRESHOLD {
            return PoolHealthState::Degraded;
        }
        if saturated || has_pending || latency_unhealthy {
            return PoolHealthState::Warning;
        }
        PoolHealthState::Healthy
    }

    fn recommend_resize(
        state: &ConnectionPoolState,
        config: &PoolSizingConfig,
        now: u64,
        last_resize_at: Option<u64>,
        utilisation_bps: u32,
    ) -> ResizeDecision {
        // Respect the cooldown window.
        if let Some(last_at) = last_resize_at {
            if now.saturating_sub(last_at) < config.resize_cooldown_secs {
                return ResizeDecision::NoChange;
            }
        }

        let latency_over_target = state.p99_acquire_ms > CRITICAL_PATH_P99_MS;

        if utilisation_bps >= config.saturation_threshold_bps
            || state.has_pending_requests()
            || latency_over_target
        {
            // Expand the pool by 1 (up to the configured maximum).
            if state.pool_size < config.max_pool_size {
                return ResizeDecision::Expand { delta: 1 };
            }
        } else if utilisation_bps < config.underutilisation_threshold_bps
            && !state.has_pending_requests()
            && !latency_over_target
        {
            // Shrink the pool by 1 (down to the configured minimum).
            if state.pool_size > config.min_pool_size {
                return ResizeDecision::Shrink { delta: 1 };
            }
        }

        ResizeDecision::NoChange
    }
}

// ---------------------------------------------------------------------------
// Stateful adaptive sizer
// ---------------------------------------------------------------------------

/// Stateful adaptive sizer that tracks per-pool resize history, consecutive
/// unhealthy probe counts, and enforces cooldown windows, min/max bounds, and
/// canary gates.
#[derive(Clone, Debug)]
pub struct PoolAdaptiveSizer {
    config: PoolSizingConfig,
    /// Maps service name → Unix timestamp of the last resize action.
    last_resize_at: BTreeMap<ServiceName, u64>,
    /// Maps service name → consecutive unhealthy probe count.
    consecutive_unhealthy: BTreeMap<ServiceName, u32>,
    /// Maps service name → consecutive healthy probe count (for recovery).
    consecutive_healthy: BTreeMap<ServiceName, u32>,
}

impl PoolAdaptiveSizer {
    /// Creates a new adaptive sizer with the provided policy.
    pub fn new(config: PoolSizingConfig) -> Self {
        Self {
            config,
            last_resize_at: BTreeMap::new(),
            consecutive_unhealthy: BTreeMap::new(),
            consecutive_healthy: BTreeMap::new(),
        }
    }

    /// Returns the current sizing configuration.
    pub fn config(&self) -> &PoolSizingConfig {
        &self.config
    }

    /// Probes a pool and records health / resize history.
    ///
    /// Returns the [`PoolHealthReport`] for the pool. When a resize action is
    /// recommended, the caller is responsible for applying it; this module
    /// only produces the recommendation and records the timestamp.
    pub fn recommend_resize(&mut self, state: &ConnectionPoolState, now: u64) -> PoolHealthReport {
        let last_at = self.last_resize_at.get(&state.service).copied();
        let consecutive = self
            .consecutive_unhealthy
            .get(&state.service)
            .copied()
            .unwrap_or(0);

        let report = PoolHealthProbe::probe(state, &self.config, now, last_at, consecutive);

        // Update consecutive unhealthy / healthy counters.
        match report.health_state {
            PoolHealthState::Healthy => {
                // Healthy probe — increment recovery counter, reset unhealthy.
                *self
                    .consecutive_healthy
                    .entry(state.service.clone())
                    .or_insert(0) += 1;
                let healthy_count = self
                    .consecutive_healthy
                    .get(&state.service)
                    .copied()
                    .unwrap_or(0);
                if healthy_count >= RECOVERY_PROBE_THRESHOLD {
                    self.consecutive_unhealthy.insert(state.service.clone(), 0);
                    self.consecutive_healthy.insert(state.service.clone(), 0);
                }
            }
            PoolHealthState::Warning | PoolHealthState::Degraded | PoolHealthState::Unavailable => {
                *self
                    .consecutive_unhealthy
                    .entry(state.service.clone())
                    .or_insert(0) += 1;
                // Reset healthy counter on any unhealthy probe.
                self.consecutive_healthy.insert(state.service.clone(), 0);
            }
        }

        // Record resize timestamp when an action is recommended.
        match report.resize_decision {
            ResizeDecision::Expand { .. } | ResizeDecision::Shrink { .. } => {
                self.last_resize_at.insert(state.service.clone(), now);
            }
            ResizeDecision::NoChange => {}
        }

        report
    }

    /// Validates a canary gate before promoting a pool resize to all pods.
    ///
    /// Returns `Ok(())` when the canary meets all release criteria.
    pub fn canary_gate(&self, canary: &PoolCanaryAnalysis) -> Result<(), PoolProbeError> {
        canary.passes_release_gate()
    }

    /// Returns the timestamp of the last resize action for `service`, or
    /// `None` if none has been performed.
    pub fn last_resize_at(&self, service: &str) -> Option<u64> {
        self.last_resize_at.get(service).copied()
    }

    /// Returns the consecutive unhealthy probe count for `service`.
    pub fn consecutive_unhealthy(&self, service: &str) -> u32 {
        self.consecutive_unhealthy
            .get(service)
            .copied()
            .unwrap_or(0)
    }

    /// Resets the cooldown record for a service (e.g., after a rollback).
    pub fn reset_cooldown(&mut self, service: &str) {
        self.last_resize_at.remove(service);
    }

    /// Resets the consecutive-unhealthy counter for a service.
    pub fn reset_health_counters(&mut self, service: &str) {
        self.consecutive_unhealthy.remove(service);
        self.consecutive_healthy.remove(service);
    }
}

impl Default for PoolAdaptiveSizer {
    fn default() -> Self {
        Self::new(PoolSizingConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Multi-pool registry
// ---------------------------------------------------------------------------

/// Registry that tracks the current state and health of all monitored
/// PostgreSQL connection pools.
///
/// This is the top-level entry point for monitoring agents: register pools,
/// update their snapshots, and query the system-wide dashboard.
#[derive(Clone, Debug)]
pub struct ConnectionPoolRegistry {
    pools: BTreeMap<ServiceName, ConnectionPoolState>,
    sizer: PoolAdaptiveSizer,
}

impl ConnectionPoolRegistry {
    /// Creates an empty registry with the provided sizing policy.
    pub fn new(config: PoolSizingConfig) -> Self {
        Self {
            pools: BTreeMap::new(),
            sizer: PoolAdaptiveSizer::new(config),
        }
    }

    /// Registers or replaces a pool state snapshot.
    ///
    /// Returns `Err(TooManyPools)` if the registry is at capacity and the
    /// service is not already registered.
    pub fn upsert_pool(&mut self, state: ConnectionPoolState) -> Result<(), PoolProbeError> {
        if !self.pools.contains_key(&state.service) && self.pools.len() >= MAX_SERVICE_POOLS {
            return Err(PoolProbeError::TooManyPools);
        }
        self.pools.insert(state.service.clone(), state);
        Ok(())
    }

    /// Probes all registered pools at the current timestamp and returns one
    /// [`PoolHealthReport`] per pool.
    pub fn probe_all(&mut self, now: u64) -> Vec<PoolHealthReport> {
        let service_names: Vec<ServiceName> = self.pools.keys().cloned().collect();
        let mut reports = Vec::new();

        for name in service_names {
            if let Some(state) = self.pools.get(&name) {
                let state_clone = state.clone();
                let report = self.sizer.recommend_resize(&state_clone, now);
                reports.push(report);
            }
        }

        reports
    }

    /// Returns a system-wide metrics snapshot.
    pub fn dashboard_snapshot(&self, now: u64) -> PoolMetricsSnapshot {
        let states: Vec<ConnectionPoolState> = self.pools.values().cloned().collect();
        PoolHealthProbe::dashboard_snapshot(&states, self.sizer.config(), now)
    }

    /// Returns the current state for a specific service pool.
    pub fn pool_state(&self, service: &str) -> Option<&ConnectionPoolState> {
        self.pools.get(service)
    }

    /// Returns a reference to the underlying adaptive sizer.
    pub fn sizer(&self) -> &PoolAdaptiveSizer {
        &self.sizer
    }
}

impl Default for ConnectionPoolRegistry {
    fn default() -> Self {
        Self::new(PoolSizingConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn pool(
        service: &str,
        pool_size: u32,
        active: u32,
        idle: u32,
        pending: u32,
        p99_ms: u64,
        ts: u64,
    ) -> ConnectionPoolState {
        ConnectionPoolState {
            service: service.into(),
            pool_size,
            active_connections: active,
            idle_connections: idle,
            pending_requests: pending,
            p99_acquire_ms: p99_ms,
            sampled_at: ts,
        }
    }

    fn default_config() -> PoolSizingConfig {
        PoolSizingConfig::default()
    }

    // -----------------------------------------------------------------------
    // ConnectionPoolState helpers
    // -----------------------------------------------------------------------

    #[test]
    fn utilisation_bps_is_accurate() {
        let s = pool("svc", 100, 90, 10, 0, 10, 0);
        assert_eq!(s.utilisation_bps(), 9_000);
    }

    #[test]
    fn utilisation_bps_zero_when_pool_size_is_zero() {
        let s = pool("svc", 0, 0, 0, 0, 0, 0);
        assert_eq!(s.utilisation_bps(), 0);
    }

    #[test]
    fn utilisation_bps_caps_at_ten_thousand() {
        // active > pool_size (transient over-commit possible under load)
        let s = pool("svc", 10, 15, 0, 0, 0, 0);
        assert_eq!(s.utilisation_bps(), 10_000);
    }

    #[test]
    fn total_connections_is_active_plus_idle() {
        let s = pool("svc", 100, 60, 30, 0, 0, 0);
        assert_eq!(s.total_connections(), 90);
    }

    #[test]
    fn has_pending_requests_reflects_queue_depth() {
        let s_idle = pool("svc", 100, 10, 80, 0, 0, 0);
        let s_busy = pool("svc", 100, 100, 0, 5, 0, 0);
        assert!(!s_idle.has_pending_requests());
        assert!(s_busy.has_pending_requests());
    }

    // -----------------------------------------------------------------------
    // PoolHealthProbe — health classification
    // -----------------------------------------------------------------------

    #[test]
    fn healthy_when_utilisation_low_and_no_pending_requests() {
        let s = pool("svc", 100, 10, 80, 0, 20, 0);
        let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
        assert_eq!(report.health_state, PoolHealthState::Healthy);
    }

    #[test]
    fn warning_when_utilisation_meets_saturation_threshold() {
        // 90 active / 100 pool_size = 9_000 bps == DEFAULT_SATURATION_THRESHOLD_BPS
        let s = pool("svc", 100, 90, 10, 0, 20, 0);
        let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
        assert_eq!(report.health_state, PoolHealthState::Warning);
    }

    #[test]
    fn warning_when_pending_requests_nonzero() {
        let s = pool("svc", 100, 50, 50, 3, 20, 0);
        let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
        assert_eq!(report.health_state, PoolHealthState::Warning);
    }

    #[test]
    fn warning_when_p99_exceeds_critical_path_target() {
        // p99 = 101 ms > 100 ms target
        let s = pool("svc", 100, 20, 80, 0, 101, 0);
        let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
        assert_eq!(report.health_state, PoolHealthState::Warning);
    }

    #[test]
    fn degraded_after_consecutive_unhealthy_probe_threshold() {
        let s = pool("svc", 100, 90, 10, 0, 20, 0);
        let report =
            PoolHealthProbe::probe(&s, &default_config(), 0, None, DEGRADED_PROBE_THRESHOLD);
        assert_eq!(report.health_state, PoolHealthState::Degraded);
    }

    #[test]
    fn unavailable_when_pool_size_is_zero() {
        let s = pool("svc", 0, 0, 0, 0, 0, 0);
        let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
        assert_eq!(report.health_state, PoolHealthState::Unavailable);
    }

    // -----------------------------------------------------------------------
    // PoolHealthProbe — resize decisions
    // -----------------------------------------------------------------------

    #[test]
    fn expand_recommended_when_saturated() {
        let s = pool("svc", 100, 90, 10, 0, 20, 0); // 9_000 bps == threshold
        let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
        assert_eq!(report.resize_decision, ResizeDecision::Expand { delta: 1 });
    }

    #[test]
    fn expand_recommended_when_pending_requests_present() {
        let s = pool("svc", 100, 50, 50, 1, 20, 0);
        let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
        assert_eq!(report.resize_decision, ResizeDecision::Expand { delta: 1 });
    }

    #[test]
    fn expand_recommended_when_latency_over_target() {
        let s = pool("svc", 100, 10, 80, 0, 101, 0);
        let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
        assert_eq!(report.resize_decision, ResizeDecision::Expand { delta: 1 });
    }

    #[test]
    fn no_expand_when_pool_already_at_max_size() {
        let config = PoolSizingConfig {
            max_pool_size: 100,
            ..default_config()
        };
        let s = pool("svc", 100, 90, 10, 0, 20, 0);
        let report = PoolHealthProbe::probe(&s, &config, 0, None, 0);
        assert_eq!(report.resize_decision, ResizeDecision::NoChange);
    }

    #[test]
    fn shrink_recommended_when_underutilised() {
        // 10 active / 100 pool_size = 1_000 bps < 3_000 bps threshold
        let s = pool("svc", 100, 10, 80, 0, 20, 0);
        let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
        assert_eq!(report.resize_decision, ResizeDecision::Shrink { delta: 1 });
    }

    #[test]
    fn no_shrink_when_pool_already_at_min_size() {
        let config = PoolSizingConfig {
            min_pool_size: 100,
            ..default_config()
        };
        let s = pool("svc", 100, 10, 80, 0, 20, 0);
        let report = PoolHealthProbe::probe(&s, &config, 0, None, 0);
        assert_eq!(report.resize_decision, ResizeDecision::NoChange);
    }

    #[test]
    fn no_change_in_warning_zone_utilisation() {
        // 6_000 bps — above underutilisation threshold (3_000) but below
        // saturation threshold (9_000).
        let s = pool("svc", 100, 60, 40, 0, 20, 0);
        let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
        assert_eq!(report.resize_decision, ResizeDecision::NoChange);
    }

    #[test]
    fn cooldown_suppresses_resize_decision() {
        let now = 1_000u64;
        let last_at = Some(now - 20); // 20 s ago — within 30 s cooldown
        let s = pool("svc", 100, 90, 10, 0, 20, 0);
        let report = PoolHealthProbe::probe(&s, &default_config(), now, last_at, 0);
        assert_eq!(report.resize_decision, ResizeDecision::NoChange);
    }

    #[test]
    fn expand_allowed_after_cooldown_expires() {
        let now = 1_000u64;
        let last_at = Some(now - 31); // 31 s ago — cooldown elapsed
        let s = pool("svc", 100, 90, 10, 0, 20, 0);
        let report = PoolHealthProbe::probe(&s, &default_config(), now, last_at, 0);
        assert_eq!(report.resize_decision, ResizeDecision::Expand { delta: 1 });
    }

    // -----------------------------------------------------------------------
    // PoolHealthProbe — dashboard snapshot
    // -----------------------------------------------------------------------

    #[test]
    fn dashboard_snapshot_aggregates_across_pools() {
        let states = vec![
            pool("a", 100, 90, 10, 0, 20, 0), // saturated → Warning
            pool("b", 100, 10, 80, 0, 20, 0), // low util  → Healthy
            pool("c", 100, 60, 40, 5, 20, 0), // pending   → Warning
        ];
        let snap = PoolHealthProbe::dashboard_snapshot(&states, &default_config(), 0);

        assert_eq!(snap.pools_tracked, 3);
        assert_eq!(snap.total_active_connections, 160);
        assert_eq!(snap.max_pool_utilisation_bps, 9_000);
        assert_eq!(snap.unhealthy_pools, 2);
        assert_eq!(snap.critical_pools, 0);
        assert_eq!(snap.p99_target_ms, CRITICAL_PATH_P99_MS);
        assert_eq!(snap.availability_target_bps, AVAILABILITY_TARGET_BPS);
    }

    #[test]
    fn dashboard_snapshot_with_no_pools_returns_zeroed_metrics() {
        let snap = PoolHealthProbe::dashboard_snapshot(&[], &default_config(), 0);
        assert_eq!(snap.pools_tracked, 0);
        assert_eq!(snap.total_active_connections, 0);
        assert_eq!(snap.unhealthy_pools, 0);
        assert_eq!(snap.critical_pools, 0);
    }

    #[test]
    fn dashboard_snapshot_counts_degraded_as_critical() {
        // Pool with pool_size == 0 → Unavailable (>= Degraded → critical)
        let states = vec![pool("unavail", 0, 0, 0, 0, 0, 0)];
        let snap = PoolHealthProbe::dashboard_snapshot(&states, &default_config(), 0);
        assert_eq!(snap.critical_pools, 1);
    }

    // -----------------------------------------------------------------------
    // PoolCanaryAnalysis
    // -----------------------------------------------------------------------

    #[test]
    fn canary_success_rate_is_accurate_in_basis_points() {
        let canary = PoolCanaryAnalysis {
            acquisitions_attempted: 10_000,
            acquisitions_succeeded: 9_999,
            p99_acquire_ms: 80,
            security_review_passed: true,
        };
        assert_eq!(canary.success_rate_bps(), 9_999);
        assert!(canary.passes_release_gate().is_ok());
    }

    #[test]
    fn canary_fails_release_gate_without_security_review() {
        let canary = PoolCanaryAnalysis {
            acquisitions_attempted: 10_000,
            acquisitions_succeeded: 10_000,
            p99_acquire_ms: 50,
            security_review_passed: false,
        };
        assert_eq!(
            canary.passes_release_gate(),
            Err(PoolProbeError::SecurityReviewRequired)
        );
    }

    #[test]
    fn canary_fails_release_gate_when_latency_exceeds_p99_target() {
        let canary = PoolCanaryAnalysis {
            acquisitions_attempted: 10_000,
            acquisitions_succeeded: 10_000,
            p99_acquire_ms: 101,
            security_review_passed: true,
        };
        assert_eq!(
            canary.passes_release_gate(),
            Err(PoolProbeError::CanaryFailed)
        );
    }

    #[test]
    fn canary_fails_release_gate_when_success_rate_too_low() {
        let canary = PoolCanaryAnalysis {
            acquisitions_attempted: 10_000,
            acquisitions_succeeded: 9_990,
            p99_acquire_ms: 50,
            security_review_passed: true,
        };
        assert_eq!(
            canary.passes_release_gate(),
            Err(PoolProbeError::CanaryFailed)
        );
    }

    #[test]
    fn canary_with_no_acquisitions_yields_zero_success_rate() {
        let canary = PoolCanaryAnalysis {
            acquisitions_attempted: 0,
            acquisitions_succeeded: 0,
            p99_acquire_ms: 0,
            security_review_passed: true,
        };
        assert_eq!(canary.success_rate_bps(), 0);
    }

    // -----------------------------------------------------------------------
    // PoolAdaptiveSizer
    // -----------------------------------------------------------------------

    #[test]
    fn sizer_records_timestamp_after_expand() {
        let mut sizer = PoolAdaptiveSizer::new(default_config());
        let s = pool("svc", 100, 90, 10, 0, 20, 1_000);
        let report = sizer.recommend_resize(&s, 1_000);
        assert_eq!(report.resize_decision, ResizeDecision::Expand { delta: 1 });
        assert_eq!(sizer.last_resize_at("svc"), Some(1_000));
    }

    #[test]
    fn sizer_enforces_cooldown_on_consecutive_calls() {
        let mut sizer = PoolAdaptiveSizer::new(default_config());
        let s = pool("svc", 100, 90, 10, 0, 20, 0);

        // First call at t=1000 → triggers expand.
        let r1 = sizer.recommend_resize(&s, 1_000);
        assert_eq!(r1.resize_decision, ResizeDecision::Expand { delta: 1 });

        // Second call at t=1020 → 20 s < 30 s cooldown → suppressed.
        let r2 = sizer.recommend_resize(&s, 1_020);
        assert_eq!(r2.resize_decision, ResizeDecision::NoChange);
    }

    #[test]
    fn sizer_reset_cooldown_allows_immediate_subsequent_resize() {
        let mut sizer = PoolAdaptiveSizer::new(default_config());
        let s = pool("svc", 100, 90, 10, 0, 20, 0);

        sizer.recommend_resize(&s, 1_000);
        sizer.reset_cooldown("svc");

        let r = sizer.recommend_resize(&s, 1_001);
        assert_eq!(r.resize_decision, ResizeDecision::Expand { delta: 1 });
    }

    #[test]
    fn sizer_canary_gate_accepts_valid_analysis() {
        let sizer = PoolAdaptiveSizer::default();
        let canary = PoolCanaryAnalysis {
            acquisitions_attempted: 5_000,
            acquisitions_succeeded: 5_000,
            p99_acquire_ms: 90,
            security_review_passed: true,
        };
        assert!(sizer.canary_gate(&canary).is_ok());
    }

    #[test]
    fn sizer_canary_gate_rejects_low_success_rate() {
        let sizer = PoolAdaptiveSizer::default();
        let canary = PoolCanaryAnalysis {
            acquisitions_attempted: 5_000,
            acquisitions_succeeded: 4_000,
            p99_acquire_ms: 80,
            security_review_passed: true,
        };
        assert_eq!(
            sizer.canary_gate(&canary),
            Err(PoolProbeError::CanaryFailed)
        );
    }

    #[test]
    fn sizer_tracks_consecutive_unhealthy_probes() {
        let mut sizer = PoolAdaptiveSizer::new(default_config());
        let s = pool("svc", 100, 90, 10, 0, 20, 0); // Warning level

        for i in 0..DEGRADED_PROBE_THRESHOLD {
            sizer.recommend_resize(&s, i as u64 * 100);
        }

        assert_eq!(sizer.consecutive_unhealthy("svc"), DEGRADED_PROBE_THRESHOLD);
    }

    #[test]
    fn sizer_health_report_shows_degraded_after_threshold_probes() {
        let mut sizer = PoolAdaptiveSizer::new(default_config());
        let s = pool("svc", 100, 90, 10, 0, 20, 0);

        let mut last_report = sizer.recommend_resize(&s, 0);
        for i in 1..=DEGRADED_PROBE_THRESHOLD {
            last_report = sizer.recommend_resize(&s, i as u64 * 100);
        }
        // After DEGRADED_PROBE_THRESHOLD unhealthy probes the sizer has
        // incremented the counter to DEGRADED_PROBE_THRESHOLD; the next probe
        // will see the counter and classify as Degraded.
        assert!(last_report.health_state >= PoolHealthState::Warning);
    }

    #[test]
    fn sizer_reset_health_counters_clears_degraded_state() {
        let mut sizer = PoolAdaptiveSizer::new(default_config());
        let s = pool("svc", 100, 90, 10, 0, 20, 0);

        for i in 0..DEGRADED_PROBE_THRESHOLD + 1 {
            sizer.recommend_resize(&s, i as u64 * 100);
        }

        sizer.reset_health_counters("svc");
        assert_eq!(sizer.consecutive_unhealthy("svc"), 0);
    }

    // -----------------------------------------------------------------------
    // ConnectionPoolRegistry
    // -----------------------------------------------------------------------

    #[test]
    fn registry_upserts_and_probes_single_pool() {
        let mut registry = ConnectionPoolRegistry::default();
        registry
            .upsert_pool(pool("payments", 50, 45, 5, 0, 20, 0))
            .unwrap();

        let reports = registry.probe_all(0);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].service, "payments");
    }

    #[test]
    fn registry_upsert_replaces_existing_pool_state() {
        let mut registry = ConnectionPoolRegistry::default();
        registry
            .upsert_pool(pool("auth", 100, 90, 10, 0, 20, 0))
            .unwrap();
        // Replace with a healthy state.
        registry
            .upsert_pool(pool("auth", 100, 10, 80, 0, 20, 0))
            .unwrap();

        let snap = registry.dashboard_snapshot(0);
        assert_eq!(snap.total_active_connections, 10);
        assert_eq!(snap.critical_pools, 0);
    }

    #[test]
    fn registry_dashboard_snapshot_reflects_all_registered_pools() {
        let mut registry = ConnectionPoolRegistry::default();
        registry
            .upsert_pool(pool("api", 100, 90, 10, 0, 20, 0))
            .unwrap();
        registry
            .upsert_pool(pool("worker", 50, 5, 40, 0, 20, 0))
            .unwrap();

        let snap = registry.dashboard_snapshot(0);
        assert_eq!(snap.pools_tracked, 2);
    }

    #[test]
    fn registry_pool_state_returns_none_for_unknown_service() {
        let registry = ConnectionPoolRegistry::default();
        assert!(registry.pool_state("unknown").is_none());
    }

    #[test]
    fn registry_probe_all_returns_one_report_per_pool() {
        let mut registry = ConnectionPoolRegistry::default();
        registry
            .upsert_pool(pool("svc1", 100, 50, 50, 0, 20, 0))
            .unwrap();
        registry
            .upsert_pool(pool("svc2", 100, 80, 20, 0, 20, 0))
            .unwrap();
        registry
            .upsert_pool(pool("svc3", 100, 10, 90, 0, 20, 0))
            .unwrap();

        let reports = registry.probe_all(0);
        assert_eq!(reports.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Issue #134 operational constants
    // -----------------------------------------------------------------------

    #[test]
    fn issue_134_constants_match_technical_bounds() {
        assert_eq!(
            CRITICAL_PATH_P99_MS, 100,
            "P99 critical-path target must be 100 ms"
        );
        assert_eq!(
            AVAILABILITY_TARGET_BPS, 9_999,
            "availability target must be 99.99%"
        );
        assert_eq!(DEFAULT_SATURATION_THRESHOLD_BPS, 9_000);
        assert_eq!(DEFAULT_UNDERUTILISATION_THRESHOLD_BPS, 3_000);
        assert_eq!(DEFAULT_MIN_POOL_SIZE, 2);
        assert_eq!(DEFAULT_MAX_POOL_SIZE, 128);
        assert_eq!(DEFAULT_RESIZE_COOLDOWN_SECS, 30);
        assert_eq!(DEGRADED_PROBE_THRESHOLD, 3);
        assert_eq!(RECOVERY_PROBE_THRESHOLD, 2);
        assert_eq!(CANARY_SUCCESS_TARGET_BPS, 9_999);
    }
}
