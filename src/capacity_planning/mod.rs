//! Capacity Planning with Historical Usage Trending (issue #127).
//!
//! This module provides deterministic, dependency-free primitives for capacity
//! planning, resource usage tracking, linear and Holt-Winters trend forecasting,
//! runway estimation, automated sizing recommendations, and blue-green canary
//! validation. All algorithms are pure Rust without network I/O or external
//! system dependencies, allowing smart contracts, monitoring agents, and canary
//! deployment gates to share identical logic and verification criteria.
//!
//! # Architecture overview
//!
//! ```text
//!  ┌─────────────────────────┐  usage metrics   ┌───────────────────────────────┐
//!  │  ServiceUsageTelemetry  │ ────────────────▶│    HistoricalUsageBuffer      │
//!  │  (CPU, Mem, IOPS, P99)  │                  │    (fixed-size ring buffer)   │
//!  └─────────────────────────┘                  └───────────────┬───────────────┘
//!                                                               │
//!                                                               ▼
//!  ┌─────────────────────────┐  linear regression ┌───────────────────────────────┐
//!  │   CapacityForecaster    │◀──────────────────│    CapacityForecaster         │
//!  │   • slope & R-squared   │  Holt-Winters     │    • compute_trend()          │
//!  │   • runway estimation   │                   │    • classify_health()        │
//!  └────────────┬────────────┘                   └───────────────┬───────────────┘
//!               │                                                │
//!               ▼                                                ▼
//!  ┌─────────────────────────┐  canary analysis  ┌───────────────────────────────┐
//!  │   CapacityAction        │ ────────────────▶│    CapacityCanaryAnalysis     │
//!  │   • ScaleUp / ScaleDown │                  │    • 99.99% availability gate │
//!  │   • EmergencyThrottle   │                  │    • P99 < 100 ms gate        │
//!  │   • Rebalance           │                  │    • Security review sign-off │
//!  └─────────────────────────┘                  └───────────────┬───────────────┘
//!                                                               │
//!                                                               ▼
//!                                               ┌───────────────────────────────┐
//!                                               │   CapacityPlanningRegistry    │
//!                                               │   • multi-service tracking    │
//!                                               │   • promote_canary()          │
//!                                               │   • dashboard_snapshot()      │
//!                                               └───────────────────────────────┘
//! ```
//!
//! # Technical bounds & operational constants
//!
//! Derived strictly from issue #127:
//! * Critical-path latency target: P99 < 100 ms ([`CRITICAL_PATH_P99_MS`])
//! * Availability target: 99.99% uptime ([`AVAILABILITY_TARGET_BPS`])
//! * Mandatory security review sign-off before promoting canary deployments
//! * Cooldown enforcement: minimum 30 seconds between consecutive scaling actions

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Operational constants (mandated by issue #127)
// ---------------------------------------------------------------------------

/// P99 latency target for critical-path operations, in milliseconds.
pub const CRITICAL_PATH_P99_MS: u64 = 100;

/// Availability objective expressed in basis points: 99.99% (9_999 / 10_000).
pub const AVAILABILITY_TARGET_BPS: u32 = 9_999;

/// Canary deployment success rate required for promotion, in basis points (99.99%).
pub const CANARY_SUCCESS_TARGET_BPS: u32 = 9_999;

/// Default warning saturation threshold in basis points: 80.00%.
pub const DEFAULT_WARNING_THRESHOLD_BPS: u32 = 8_000;

/// Default critical saturation threshold in basis points: 90.00%.
pub const DEFAULT_CRITICAL_THRESHOLD_BPS: u32 = 9_000;

/// Exhaustion saturation threshold in basis points: 100.00%.
pub const DEFAULT_EXHAUSTION_THRESHOLD_BPS: u32 = 10_000;

/// Default minimum allocated capacity units (nodes / shards / worker threads).
pub const DEFAULT_MIN_ALLOCATED_UNITS: u32 = 1;

/// Default maximum allocated capacity units.
pub const DEFAULT_MAX_ALLOCATED_UNITS: u32 = 256;

/// Default cooldown window between consecutive capacity adjustments, in seconds.
pub const DEFAULT_REACTION_COOLDOWN_SECS: u64 = 30;

/// Default number of historical samples retained in the ring buffer.
pub const DEFAULT_HISTORY_BUFFER_CAPACITY: usize = 120;

/// Maximum number of services tracked concurrently by the registry.
pub const MAX_TRACKED_SERVICES: usize = 256;

/// Minimum historical samples required to execute statistical trend projection.
pub const MIN_SAMPLES_FOR_TREND: usize = 3;

/// Target capacity headroom maintained during automated scale-up (20.00%).
pub const DEFAULT_TARGET_HEADROOM_BPS: u32 = 2_000;

// ---------------------------------------------------------------------------
// Identifiers & basic types
// ---------------------------------------------------------------------------

/// Logical service name identifier (e.g. `"consensus"`, `"mempool"`, `"pg_pool"`).
pub type ServiceName = String;

// ---------------------------------------------------------------------------
// Resource metrics & telemetry
// ---------------------------------------------------------------------------

/// Snapshot of individual resource utilization dimensions for a service.
///
/// All utilization values are expressed in basis points (0..10_000).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceMetrics {
    /// CPU utilization in basis points (0..10_000).
    pub cpu_utilization_bps: u32,
    /// Memory (RAM) utilization in basis points (0..10_000).
    pub memory_utilization_bps: u32,
    /// Storage / IOPS utilization in basis points (0..10_000).
    pub iops_utilization_bps: u32,
    /// Network bandwidth utilization in basis points (0..10_000).
    pub network_utilization_bps: u32,
    /// Worker thread / connection pool saturation in basis points (0..10_000).
    pub worker_saturation_bps: u32,
}

impl ResourceMetrics {
    /// Creates a new resource metrics snapshot.
    pub fn new(
        cpu_bps: u32,
        memory_bps: u32,
        iops_bps: u32,
        network_bps: u32,
        worker_bps: u32,
    ) -> Self {
        Self {
            cpu_utilization_bps: cpu_bps.min(10_000),
            memory_utilization_bps: memory_bps.min(10_000),
            iops_utilization_bps: iops_bps.min(10_000),
            network_utilization_bps: network_bps.min(10_000),
            worker_saturation_bps: worker_bps.min(10_000),
        }
    }

    /// Computes the peak saturation across all resource dimensions.
    ///
    /// The bottleneck resource dictates the overall system saturation.
    pub fn peak_saturation_bps(&self) -> u32 {
        self.cpu_utilization_bps
            .max(self.memory_utilization_bps)
            .max(self.iops_utilization_bps)
            .max(self.network_utilization_bps)
            .max(self.worker_saturation_bps)
    }

    /// Computes the arithmetic mean utilization across all resource dimensions.
    pub fn mean_utilization_bps(&self) -> u32 {
        let sum = self.cpu_utilization_bps as u64
            + self.memory_utilization_bps as u64
            + self.iops_utilization_bps as u64
            + self.network_utilization_bps as u64
            + self.worker_saturation_bps as u64;
        (sum / 5).min(10_000) as u32
    }
}

// ---------------------------------------------------------------------------
// Usage sample
// ---------------------------------------------------------------------------

/// A point-in-time observation of a service's capacity consumption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageSample {
    /// Wall-clock timestamp of the sample (seconds since Unix epoch).
    pub timestamp_secs: u64,
    /// Detailed multi-dimensional resource metrics.
    pub metrics: ResourceMetrics,
    /// Observed P99 latency on the critical path, in milliseconds.
    pub p99_latency_ms: u64,
    /// Currently allocated capacity units (instances, pods, or shards).
    pub active_units: u32,
    /// Total request throughput in queries per second (QPS).
    pub throughput_qps: u64,
    /// Cumulative error count observed during this sample window.
    pub error_count: u64,
}

impl UsageSample {
    /// Creates a new usage sample.
    pub fn new(
        timestamp_secs: u64,
        metrics: ResourceMetrics,
        p99_latency_ms: u64,
        active_units: u32,
        throughput_qps: u64,
        error_count: u64,
    ) -> Self {
        Self {
            timestamp_secs,
            metrics,
            p99_latency_ms,
            active_units: active_units.max(1),
            throughput_qps,
            error_count,
        }
    }

    /// Returns the governing peak saturation in basis points.
    pub fn saturation_bps(&self) -> u32 {
        self.metrics.peak_saturation_bps()
    }
}

// ---------------------------------------------------------------------------
// Historical usage ring buffer
// ---------------------------------------------------------------------------

/// Fixed-capacity ring buffer storing timestamped usage samples for trending.
#[derive(Clone, Debug)]
pub struct HistoricalUsageBuffer {
    capacity: usize,
    samples: VecDeque<UsageSample>,
}

impl HistoricalUsageBuffer {
    /// Creates an empty buffer with the specified maximum sample capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(MIN_SAMPLES_FOR_TREND),
            samples: VecDeque::with_capacity(capacity.max(MIN_SAMPLES_FOR_TREND)),
        }
    }

    /// Appends a new sample to the buffer, evicting the oldest sample if at capacity.
    pub fn push(&mut self, sample: UsageSample) {
        if self.samples.len() >= self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    /// Returns a slice/reference to all stored samples in chronological order.
    pub fn samples(&self) -> &VecDeque<UsageSample> {
        &self.samples
    }

    /// Returns the most recent sample, if available.
    pub fn latest(&self) -> Option<&UsageSample> {
        self.samples.back()
    }

    /// Returns the oldest recorded sample, if available.
    pub fn oldest(&self) -> Option<&UsageSample> {
        self.samples.front()
    }

    /// Returns the number of samples stored in the buffer.
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Returns `true` if the buffer contains no samples.
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Clears all recorded samples from the buffer.
    pub fn clear(&mut self) {
        self.samples.clear();
    }
}

// ---------------------------------------------------------------------------
// Trend projection & forecasting
// ---------------------------------------------------------------------------

/// Statistical trend projection derived from historical usage samples.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TrendProjection {
    /// Linear regression growth rate of saturation in basis points per second.
    pub slope_bps_per_sec: f64,
    /// Projected saturation growth rate per hour, in basis points.
    pub hourly_growth_rate_bps: f64,
    /// Projected saturation growth rate per day (24 hours), in basis points.
    pub daily_growth_rate_bps: f64,
    /// Coefficient of determination (R²) indicating goodness of linear fit (0.0..1.0).
    pub r_squared: f64,
    /// Exponentially smoothed forecast for the next evaluation window (basis points).
    pub holt_winters_forecast_bps: u32,
    /// Estimated time remaining until reaching the warning threshold (80%), in seconds.
    pub runway_warning_secs: Option<u64>,
    /// Estimated time remaining until reaching the critical threshold (90%), in seconds.
    pub runway_critical_secs: Option<u64>,
    /// Estimated time remaining until total resource exhaustion (100%), in seconds.
    pub runway_exhaustion_secs: Option<u64>,
    /// Whether usage trending is strictly accelerating (positive slope).
    pub is_accelerating: bool,
}

// ---------------------------------------------------------------------------
// Capacity health state
// ---------------------------------------------------------------------------

/// Coarse operational health state of a service's capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum CapacityHealthState {
    /// Operating normally with ample runway and P99 latency within target (< 100 ms).
    Healthy,
    /// Elevated utilization (>= 80%) or runway under 48 hours; scaling recommended.
    Warning,
    /// Critical saturation (>= 90%) or runway under 12 hours; prompt action required.
    Critical,
    /// Resource exhaustion (100%) or critical-path P99 latency target violation.
    Exhausted,
}

// ---------------------------------------------------------------------------
// Capacity action & sizing recommendation
// ---------------------------------------------------------------------------

/// Recommended capacity action produced by the planning engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapacityAction {
    /// No scaling action required; capacity is balanced.
    NoAction,
    /// Provision additional units to relieve rising saturation.
    ScaleUp {
        /// Number of units to add.
        delta_units: u32,
        /// Target total units after scale-up.
        target_units: u32,
        /// Human-readable rationale.
        reason: String,
    },
    /// Deprovision excess units to reduce idle overhead safely.
    ScaleDown {
        /// Number of units to remove.
        delta_units: u32,
        /// Target total units after scale-down.
        target_units: u32,
        /// Human-readable rationale.
        reason: String,
    },
    /// Rebalance allocations across nodes/shards without altering net capacity.
    Rebalance {
        /// Target units configuration.
        target_units: u32,
        /// Human-readable rationale.
        reason: String,
    },
    /// Emergency shed or throttle due to imminent exhaustion or SLA violation.
    EmergencyThrottle {
        /// Percentage of traffic to shed (in basis points).
        drop_percentage_bps: u32,
        /// Human-readable rationale.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Canary analysis & blue-green validation gate
// ---------------------------------------------------------------------------

/// Canary analysis validating a capacity change before full-fleet promotion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityCanaryAnalysis {
    /// Logical service name evaluated.
    pub service: ServiceName,
    /// Candidate capacity units evaluated in canary.
    pub candidate_units: u32,
    /// Total requests routed to the canary during evaluation.
    pub requests_evaluated: u64,
    /// Requests completing successfully within SLA bounds.
    pub requests_successful: u64,
    /// Observed P99 latency on the canary instances, in milliseconds.
    pub observed_p99_ms: u64,
    /// Availability observed in canary window, in basis points (e.g. 9_999).
    pub availability_bps: u32,
    /// Mandatory security review sign-off indicator.
    pub security_review_passed: bool,
}

impl CapacityCanaryAnalysis {
    /// Creates a new canary analysis record.
    pub fn new(
        service: &str,
        candidate_units: u32,
        requests_evaluated: u64,
        requests_successful: u64,
        observed_p99_ms: u64,
        availability_bps: u32,
        security_review_passed: bool,
    ) -> Self {
        Self {
            service: service.into(),
            candidate_units,
            requests_evaluated,
            requests_successful,
            observed_p99_ms,
            availability_bps,
            security_review_passed,
        }
    }

    /// Computes the request success rate in basis points (0..10_000).
    pub fn success_rate_bps(&self) -> u32 {
        if self.requests_evaluated == 0 {
            return 0;
        }
        ((self.requests_successful.saturating_mul(10_000)) / self.requests_evaluated).min(10_000)
            as u32
    }

    /// Verifies all release-gate criteria mandated by issue #127.
    ///
    /// * Security review MUST be completed (`security_review_passed == true`).
    /// * Availability MUST meet or exceed 99.99% ([`AVAILABILITY_TARGET_BPS`]).
    /// * Critical path latency MUST NOT exceed 100 ms ([`CRITICAL_PATH_P99_MS`]).
    /// * Request success rate MUST meet or exceed 99.99% ([`CANARY_SUCCESS_TARGET_BPS`]).
    pub fn passes_release_gate(&self) -> Result<(), CapacityError> {
        if !self.security_review_passed {
            return Err(CapacityError::SecurityReviewRequired);
        }
        if self.availability_bps < AVAILABILITY_TARGET_BPS {
            return Err(CapacityError::AvailabilityTargetViolated);
        }
        if self.observed_p99_ms > CRITICAL_PATH_P99_MS {
            return Err(CapacityError::LatencyTargetViolated);
        }
        if self.success_rate_bps() < CANARY_SUCCESS_TARGET_BPS {
            return Err(CapacityError::CanaryValidationFailed);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned by capacity planning and canary validation routines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityError {
    /// Service is not registered in the capacity planning registry.
    ServiceNotFound,
    /// Service already registered.
    ServiceAlreadyExists,
    /// Registry capacity exceeded (maximum 256 services).
    TooManyServices,
    /// Fewer than `MIN_SAMPLES_FOR_TREND` samples available for analysis.
    InsufficientHistory,
    /// Cooldown window is currently active; action deferred.
    CooldownActive,
    /// Scaling action violates min/max unit boundaries.
    AllocationBoundsViolated,
    /// Security review is mandatory before canary promotion.
    SecurityReviewRequired,
    /// Canary availability fell below the 99.99% technical bound.
    AvailabilityTargetViolated,
    /// Canary P99 latency exceeded the 100 ms technical bound.
    LatencyTargetViolated,
    /// Canary request success rate fell below the 99.99% promotion threshold.
    CanaryValidationFailed,
    /// Sizing parameters or thresholds are invalid.
    InvalidConfiguration,
}

// ---------------------------------------------------------------------------
// Planning configuration
// ---------------------------------------------------------------------------

/// Tunable parameters for trend forecasting and capacity recommendations.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CapacityPlanningConfig {
    /// Saturation threshold for `Warning` state (default 8,000 bps = 80%).
    pub warning_threshold_bps: u32,
    /// Saturation threshold for `Critical` state (default 9,000 bps = 90%).
    pub critical_threshold_bps: u32,
    /// Saturation threshold for `Exhausted` state (default 10,000 bps = 100%).
    pub exhaustion_threshold_bps: u32,
    /// Minimum permissible unit allocation for a service.
    pub min_units: u32,
    /// Maximum permissible unit allocation for a service.
    pub max_units: u32,
    /// Minimum cooldown between consecutive resizing actions (seconds).
    pub cooldown_secs: u64,
    /// Maximum history buffer capacity per service.
    pub history_window_capacity: usize,
    /// Holt-Winters level smoothing factor alpha (0.0 < alpha <= 1.0).
    pub holt_winters_alpha: f64,
    /// Holt-Winters trend smoothing factor beta (0.0 < beta <= 1.0).
    pub holt_winters_beta: f64,
    /// Target headroom maintained during automated scale-up (in bps).
    pub target_headroom_bps: u32,
}

impl Default for CapacityPlanningConfig {
    fn default() -> Self {
        Self {
            warning_threshold_bps: DEFAULT_WARNING_THRESHOLD_BPS,
            critical_threshold_bps: DEFAULT_CRITICAL_THRESHOLD_BPS,
            exhaustion_threshold_bps: DEFAULT_EXHAUSTION_THRESHOLD_BPS,
            min_units: DEFAULT_MIN_ALLOCATED_UNITS,
            max_units: DEFAULT_MAX_ALLOCATED_UNITS,
            cooldown_secs: DEFAULT_REACTION_COOLDOWN_SECS,
            history_window_capacity: DEFAULT_HISTORY_BUFFER_CAPACITY,
            holt_winters_alpha: 0.3,
            holt_winters_beta: 0.1,
            target_headroom_bps: DEFAULT_TARGET_HEADROOM_BPS,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-service capacity report
// ---------------------------------------------------------------------------

/// Comprehensive health and capacity planning report for a single service.
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceCapacityReport {
    /// Service identifier.
    pub service: ServiceName,
    /// Currently allocated capacity units.
    pub current_units: u32,
    /// Most recent observed peak saturation in basis points.
    pub current_saturation_bps: u32,
    /// Most recent observed P99 critical path latency in milliseconds.
    pub current_p99_ms: u64,
    /// Derived capacity health classification.
    pub health_state: CapacityHealthState,
    /// Historical trend projection and runway calculations, if history allows.
    pub trend: Option<TrendProjection>,
    /// Recommended sizing or mitigating capacity action.
    pub recommended_action: CapacityAction,
}

// ---------------------------------------------------------------------------
// System-wide capacity dashboard snapshot
// ---------------------------------------------------------------------------

/// System-wide aggregation of capacity health across all services.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemCapacitySnapshot {
    /// Number of active services monitored.
    pub services_monitored: usize,
    /// Sum of all capacity units allocated across services.
    pub total_units_allocated: u32,
    /// Highest peak saturation observed across any service (bps).
    pub max_saturation_bps: u32,
    /// Mean saturation across all registered services (bps).
    pub avg_saturation_bps: u32,
    /// Services currently in `Healthy` state.
    pub healthy_count: usize,
    /// Services currently in `Warning` state.
    pub warning_count: usize,
    /// Services currently in `Critical` state.
    pub critical_count: usize,
    /// Services currently in `Exhausted` state.
    pub exhausted_count: usize,
    /// Service with the shortest runway to exhaustion, with seconds remaining.
    pub shortest_runway: Option<(ServiceName, u64)>,
    /// P99 latency target constant.
    pub p99_target_ms: u64,
    /// 99.99% availability target constant.
    pub availability_target_bps: u32,
}

// ---------------------------------------------------------------------------
// Capacity forecasting & sizing engine
// ---------------------------------------------------------------------------

/// Stateless forecasting engine for linear trending and Holt-Winters estimation.
pub struct CapacityForecaster;

impl CapacityForecaster {
    /// Computes statistical trend analysis from historical usage samples.
    pub fn compute_trend(
        buffer: &HistoricalUsageBuffer,
        config: &CapacityPlanningConfig,
    ) -> Result<TrendProjection, CapacityError> {
        let n = buffer.len();
        if n < MIN_SAMPLES_FOR_TREND {
            return Err(CapacityError::InsufficientHistory);
        }

        let samples = buffer.samples();
        let first_ts = buffer.oldest().map(|s| s.timestamp_secs).unwrap_or(0);
        let latest_saturation = buffer.latest().map(|s| s.saturation_bps()).unwrap_or(0);

        // Compute means for linear regression
        let mut sum_x: f64 = 0.0;
        let mut sum_y: f64 = 0.0;

        for s in samples.iter() {
            let rel_x = s.timestamp_secs.saturating_sub(first_ts) as f64;
            let y = s.saturation_bps() as f64;
            sum_x += rel_x;
            sum_y += y;
        }

        let mean_x = sum_x / (n as f64);
        let mean_y = sum_y / (n as f64);

        let mut cov_xy: f64 = 0.0;
        let mut var_x: f64 = 0.0;
        let mut var_y: f64 = 0.0;

        for s in samples.iter() {
            let rel_x = s.timestamp_secs.saturating_sub(first_ts) as f64;
            let y = s.saturation_bps() as f64;
            let dx = rel_x - mean_x;
            let dy = y - mean_y;
            cov_xy += dx * dy;
            var_x += dx * dx;
            var_y += dy * dy;
        }

        let slope = if var_x > 1e-9 { cov_xy / var_x } else { 0.0 };

        let r_squared = if var_x > 1e-9 && var_y > 1e-9 {
            ((cov_xy * cov_xy) / (var_x * var_y)).clamp(0.0, 1.0)
        } else {
            0.0
        };

        // Holt-Winters / Double Exponential Smoothing
        let alpha = config.holt_winters_alpha.clamp(0.01, 1.0);
        let beta = config.holt_winters_beta.clamp(0.01, 1.0);

        let mut level = samples[0].saturation_bps() as f64;
        let mut trend = if n > 1 {
            (samples[1].saturation_bps() as f64) - (samples[0].saturation_bps() as f64)
        } else {
            0.0
        };

        for i in 1..n {
            let actual = samples[i].saturation_bps() as f64;
            let prev_level = level;
            level = alpha * actual + (1.0 - alpha) * (prev_level + trend);
            trend = beta * (level - prev_level) + (1.0 - beta) * trend;
        }

        let hw_forecast = (level + trend).clamp(0.0, 10_000.0) as u32;

        // Runway calculation based on linear slope
        let runway_warning_secs =
            Self::calculate_runway(latest_saturation, config.warning_threshold_bps, slope);
        let runway_critical_secs =
            Self::calculate_runway(latest_saturation, config.critical_threshold_bps, slope);
        let runway_exhaustion_secs =
            Self::calculate_runway(latest_saturation, config.exhaustion_threshold_bps, slope);

        let hourly_growth_rate_bps = slope * 3600.0;
        let daily_growth_rate_bps = slope * 86400.0;
        let is_accelerating = slope > 1e-6;

        Ok(TrendProjection {
            slope_bps_per_sec: slope,
            hourly_growth_rate_bps,
            daily_growth_rate_bps,
            r_squared,
            holt_winters_forecast_bps: hw_forecast,
            runway_warning_secs,
            runway_critical_secs,
            runway_exhaustion_secs,
            is_accelerating,
        })
    }

    /// Evaluates capacity health state based on latest sample, trend, and SLA targets.
    pub fn classify_health(
        sample: &UsageSample,
        trend: Option<&TrendProjection>,
        config: &CapacityPlanningConfig,
    ) -> CapacityHealthState {
        let saturation = sample.saturation_bps();

        // Technical Bound 1: Critical path P99 latency target < 100 ms
        if sample.p99_latency_ms > CRITICAL_PATH_P99_MS {
            return CapacityHealthState::Exhausted;
        }

        if saturation >= config.exhaustion_threshold_bps {
            return CapacityHealthState::Exhausted;
        }

        if saturation >= config.critical_threshold_bps {
            return CapacityHealthState::Critical;
        }

        if let Some(t) = trend {
            // Imminent exhaustion runway check (< 12 hours = 43,200s)
            if let Some(exhaust_secs) = t.runway_exhaustion_secs {
                if exhaust_secs < 43_200 {
                    return CapacityHealthState::Critical;
                }
            }
        }

        if saturation >= config.warning_threshold_bps {
            return CapacityHealthState::Warning;
        }

        if let Some(t) = trend {
            // Warning runway check (< 48 hours = 172,800s to critical threshold)
            if let Some(crit_secs) = t.runway_critical_secs {
                if crit_secs < 172_800 {
                    return CapacityHealthState::Warning;
                }
            }
        }

        CapacityHealthState::Healthy
    }

    /// Computes automated sizing recommendation adhering to cooldown and bounds.
    pub fn recommend_action(
        state: &ServiceCapacityState,
        trend: Option<&TrendProjection>,
        config: &CapacityPlanningConfig,
        now: u64,
    ) -> CapacityAction {
        // Enforce reaction cooldown window
        if let Some(last_at) = state.last_action_at {
            if now.saturating_sub(last_at) < config.cooldown_secs {
                return CapacityAction::NoAction;
            }
        }

        let latest = match state.history.latest() {
            Some(s) => s,
            None => return CapacityAction::NoAction,
        };

        let saturation = latest.saturation_bps();
        let p99 = latest.p99_latency_ms;
        let current_units = state.current_units;

        // Emergency throttle check: SLA breached or fully saturated
        if p99 > CRITICAL_PATH_P99_MS && saturation >= config.critical_threshold_bps {
            let drop_rate = if saturation >= config.exhaustion_threshold_bps {
                5_000 // Shed 50% traffic in extreme emergency
            } else {
                2_500 // Shed 25%
            };
            return CapacityAction::EmergencyThrottle {
                drop_percentage_bps: drop_rate,
                reason: String::from(
                    "P99 latency exceeded 100ms technical bound under critical saturation",
                ),
            };
        }

        // Scale Up condition: saturation elevated or runway short
        let needs_scale_up = saturation >= config.warning_threshold_bps
            || p99 > CRITICAL_PATH_P99_MS
            || trend.is_some_and(|t| t.runway_critical_secs.is_some_and(|s| s < 86_400));

        if needs_scale_up {
            if current_units < config.max_units {
                // Calculate proportional delta units based on headroom target
                let headroom_deficit = saturation
                    .saturating_add(config.target_headroom_bps)
                    .saturating_sub(config.warning_threshold_bps);
                let delta = if headroom_deficit > 3_000 { 2 } else { 1 };
                let target = current_units.saturating_add(delta).min(config.max_units);
                let effective_delta = target.saturating_sub(current_units);
                if effective_delta > 0 {
                    return CapacityAction::ScaleUp {
                        delta_units: effective_delta,
                        target_units: target,
                        reason: String::from(
                            "Proactive scale-up to maintain 20% headroom and prevent SLA breaches",
                        ),
                    };
                }
            }
            return CapacityAction::NoAction;
        }

        // Scale Down condition: sustained low saturation (< 30%) with ample runway
        let safe_scale_down = saturation < 3_000
            && p99 < (CRITICAL_PATH_P99_MS / 2)
            && !trend.is_some_and(|t| t.is_accelerating);

        if safe_scale_down && current_units > config.min_units {
            let target = current_units.saturating_sub(1).max(config.min_units);
            if target < current_units {
                return CapacityAction::ScaleDown {
                    delta_units: 1,
                    target_units: target,
                    reason: String::from(
                        "Under-utilization detected (<30% saturation); safe capacity reclamation",
                    ),
                };
            }
        }

        CapacityAction::NoAction
    }

    /// Internal runway calculation: seconds to reach target saturation.
    fn calculate_runway(current_bps: u32, target_bps: u32, slope_bps_per_sec: f64) -> Option<u64> {
        if current_bps >= target_bps {
            return Some(0); // Already at or past threshold
        }
        if slope_bps_per_sec <= 1e-9 {
            return None; // Non-increasing trend; infinite runway
        }
        let delta = (target_bps - current_bps) as f64;
        let secs = delta / slope_bps_per_sec;
        if secs.is_finite() && secs >= 0.0 {
            Some(secs as u64)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Per-service state tracking
// ---------------------------------------------------------------------------

/// Tracks state, sample history, and scale actions for a specific service.
#[derive(Clone, Debug)]
pub struct ServiceCapacityState {
    /// Service identifier.
    pub service: ServiceName,
    /// Currently assigned capacity units.
    pub current_units: u32,
    /// Ring buffer storing past telemetry samples.
    pub history: HistoricalUsageBuffer,
    /// Timestamp of the last applied scaling action.
    pub last_action_at: Option<u64>,
    /// Last applied capacity action.
    pub last_action: Option<CapacityAction>,
}

impl ServiceCapacityState {
    /// Initializes a new service capacity state.
    pub fn new(service: &str, initial_units: u32, history_capacity: usize) -> Self {
        Self {
            service: service.into(),
            current_units: initial_units.max(1),
            history: HistoricalUsageBuffer::new(history_capacity),
            last_action_at: None,
            last_action: None,
        }
    }

    /// Records a new telemetry sample.
    pub fn record_sample(&mut self, sample: UsageSample) {
        self.history.push(sample);
    }
}

// ---------------------------------------------------------------------------
// Multi-service capacity planning registry
// ---------------------------------------------------------------------------

/// Top-level coordinator managing multi-service capacity planning.
#[derive(Clone, Debug)]
pub struct CapacityPlanningRegistry {
    services: BTreeMap<ServiceName, ServiceCapacityState>,
    config: CapacityPlanningConfig,
}

impl CapacityPlanningRegistry {
    /// Creates a new capacity registry with the given configuration.
    pub fn new(config: CapacityPlanningConfig) -> Self {
        Self {
            services: BTreeMap::new(),
            config,
        }
    }

    /// Returns the active configuration.
    pub fn config(&self) -> &CapacityPlanningConfig {
        &self.config
    }

    /// Registers a new service for capacity tracking.
    pub fn register_service(
        &mut self,
        service: &str,
        initial_units: u32,
    ) -> Result<(), CapacityError> {
        if self.services.contains_key(service) {
            return Err(CapacityError::ServiceAlreadyExists);
        }
        if self.services.len() >= MAX_TRACKED_SERVICES {
            return Err(CapacityError::TooManyServices);
        }
        if initial_units < self.config.min_units || initial_units > self.config.max_units {
            return Err(CapacityError::AllocationBoundsViolated);
        }

        let state =
            ServiceCapacityState::new(service, initial_units, self.config.history_window_capacity);
        self.services.insert(service.into(), state);
        Ok(())
    }

    /// Ingests a new usage telemetry sample for the specified service.
    pub fn record_sample(
        &mut self,
        service: &str,
        sample: UsageSample,
    ) -> Result<(), CapacityError> {
        let state = self
            .services
            .get_mut(service)
            .ok_or(CapacityError::ServiceNotFound)?;
        state.record_sample(sample);
        Ok(())
    }

    /// Evaluates current health, trend, and recommended action for a service.
    pub fn evaluate_service(
        &self,
        service: &str,
        now: u64,
    ) -> Result<ServiceCapacityReport, CapacityError> {
        let state = self
            .services
            .get(service)
            .ok_or(CapacityError::ServiceNotFound)?;

        let latest = state
            .history
            .latest()
            .ok_or(CapacityError::InsufficientHistory)?;

        let trend = CapacityForecaster::compute_trend(&state.history, &self.config).ok();
        let health_state =
            CapacityForecaster::classify_health(latest, trend.as_ref(), &self.config);
        let recommended_action =
            CapacityForecaster::recommend_action(state, trend.as_ref(), &self.config, now);

        Ok(ServiceCapacityReport {
            service: service.into(),
            current_units: state.current_units,
            current_saturation_bps: latest.saturation_bps(),
            current_p99_ms: latest.p99_latency_ms,
            health_state,
            trend,
            recommended_action,
        })
    }

    /// Evaluates all registered services.
    pub fn evaluate_all(&self, now: u64) -> Vec<ServiceCapacityReport> {
        let mut reports = Vec::with_capacity(self.services.len());
        for service in self.services.keys() {
            if let Ok(report) = self.evaluate_service(service, now) {
                reports.push(report);
            }
        }
        reports
    }

    /// Promotes a canary deployment to production after release-gate verification.
    ///
    /// Checks:
    /// * `canary.passes_release_gate()` (Security review, 99.99% availability, P99 < 100ms)
    /// * Target units within bounds (`min_units`..`max_units`)
    /// * Cooldown window respected
    pub fn promote_canary_deployment(
        &mut self,
        service: &str,
        canary: &CapacityCanaryAnalysis,
        now: u64,
    ) -> Result<u32, CapacityError> {
        // Enforce all canary release gate criteria
        canary.passes_release_gate()?;

        let config = self.config;
        let state = self
            .services
            .get_mut(service)
            .ok_or(CapacityError::ServiceNotFound)?;

        // Enforce bounds
        if canary.candidate_units < config.min_units || canary.candidate_units > config.max_units {
            return Err(CapacityError::AllocationBoundsViolated);
        }

        // Enforce cooldown
        if let Some(last_at) = state.last_action_at {
            if now.saturating_sub(last_at) < config.cooldown_secs {
                return Err(CapacityError::CooldownActive);
            }
        }

        let old_units = state.current_units;
        state.current_units = canary.candidate_units;
        state.last_action_at = Some(now);
        state.last_action = Some(CapacityAction::Rebalance {
            target_units: canary.candidate_units,
            reason: String::from("Promoted canary deployment after passing all release gates"),
        });

        Ok(old_units)
    }

    /// Resets the cooldown timer for a service (e.g., after an emergency rollback).
    pub fn reset_cooldown(&mut self, service: &str) -> Result<(), CapacityError> {
        let state = self
            .services
            .get_mut(service)
            .ok_or(CapacityError::ServiceNotFound)?;
        state.last_action_at = None;
        Ok(())
    }

    /// Produces a system-wide dashboard snapshot for alerting and operations.
    pub fn dashboard_snapshot(&self, now: u64) -> SystemCapacitySnapshot {
        let _ = now;
        let services_monitored = self.services.len();
        let mut total_units: u32 = 0;
        let mut max_sat_bps: u32 = 0;
        let mut sum_sat_bps: u64 = 0;
        let mut healthy_count: usize = 0;
        let mut warning_count: usize = 0;
        let mut critical_count: usize = 0;
        let mut exhausted_count: usize = 0;
        let mut shortest_runway: Option<(ServiceName, u64)> = None;

        for (name, state) in self.services.iter() {
            total_units = total_units.saturating_add(state.current_units);
            if let Some(latest) = state.history.latest() {
                let sat = latest.saturation_bps();
                sum_sat_bps = sum_sat_bps.saturating_add(sat as u64);
                if sat > max_sat_bps {
                    max_sat_bps = sat;
                }

                let trend = CapacityForecaster::compute_trend(&state.history, &self.config).ok();
                let health =
                    CapacityForecaster::classify_health(latest, trend.as_ref(), &self.config);

                match health {
                    CapacityHealthState::Healthy => healthy_count += 1,
                    CapacityHealthState::Warning => warning_count += 1,
                    CapacityHealthState::Critical => critical_count += 1,
                    CapacityHealthState::Exhausted => exhausted_count += 1,
                }

                if let Some(t) = trend {
                    if let Some(exhaust_secs) = t.runway_exhaustion_secs {
                        match shortest_runway {
                            None => shortest_runway = Some((name.clone(), exhaust_secs)),
                            Some((_, min_secs)) if exhaust_secs < min_secs => {
                                shortest_runway = Some((name.clone(), exhaust_secs));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        let avg_sat_bps = if services_monitored > 0 {
            (sum_sat_bps / services_monitored as u64).min(10_000) as u32
        } else {
            0
        };

        SystemCapacitySnapshot {
            services_monitored,
            total_units_allocated: total_units,
            max_saturation_bps: max_sat_bps,
            avg_saturation_bps: avg_sat_bps,
            healthy_count,
            warning_count,
            critical_count,
            exhausted_count,
            shortest_runway,
            p99_target_ms: CRITICAL_PATH_P99_MS,
            availability_target_bps: AVAILABILITY_TARGET_BPS,
        }
    }

    /// Returns a reference to a registered service's state.
    pub fn service_state(&self, service: &str) -> Option<&ServiceCapacityState> {
        self.services.get(service)
    }
}

impl Default for CapacityPlanningRegistry {
    fn default() -> Self {
        Self::new(CapacityPlanningConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sample(ts: u64, peak_bps: u32, p99_ms: u64) -> UsageSample {
        UsageSample::new(
            ts,
            ResourceMetrics::new(peak_bps, peak_bps / 2, peak_bps / 3, peak_bps / 4, peak_bps),
            p99_ms,
            4,
            1_000,
            0,
        )
    }

    #[test]
    fn test_issue_127_technical_invariants() {
        assert_eq!(CRITICAL_PATH_P99_MS, 100);
        assert_eq!(AVAILABILITY_TARGET_BPS, 9_999);
        assert_eq!(CANARY_SUCCESS_TARGET_BPS, 9_999);
        assert_eq!(DEFAULT_WARNING_THRESHOLD_BPS, 8_000);
        assert_eq!(DEFAULT_CRITICAL_THRESHOLD_BPS, 9_000);
        assert_eq!(DEFAULT_EXHAUSTION_THRESHOLD_BPS, 10_000);
        assert_eq!(DEFAULT_REACTION_COOLDOWN_SECS, 30);
    }

    #[test]
    fn test_metrics_peak_and_mean() {
        let metrics = ResourceMetrics::new(5_000, 7_000, 3_000, 2_000, 4_000);
        assert_eq!(metrics.peak_saturation_bps(), 7_000);
        assert_eq!(metrics.mean_utilization_bps(), 4_200);
    }

    #[test]
    fn test_historical_buffer_capacity_and_eviction() {
        let mut buffer = HistoricalUsageBuffer::new(3);
        buffer.push(make_sample(10, 2_000, 40));
        buffer.push(make_sample(20, 3_000, 45));
        buffer.push(make_sample(30, 4_000, 50));
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.oldest().unwrap().timestamp_secs, 10);
        assert_eq!(buffer.latest().unwrap().timestamp_secs, 30);

        buffer.push(make_sample(40, 5_000, 55));
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.oldest().unwrap().timestamp_secs, 20);
        assert_eq!(buffer.latest().unwrap().timestamp_secs, 40);
    }

    #[test]
    fn test_linear_regression_positive_trend() {
        let mut buffer = HistoricalUsageBuffer::new(10);
        // Saturation increases by 10 bps per second
        buffer.push(make_sample(0, 1_000, 20));
        buffer.push(make_sample(10, 1_100, 22));
        buffer.push(make_sample(20, 1_200, 25));
        buffer.push(make_sample(30, 1_300, 28));

        let config = CapacityPlanningConfig::default();
        let trend = CapacityForecaster::compute_trend(&buffer, &config).unwrap();

        assert!((trend.slope_bps_per_sec - 10.0).abs() < 1e-4);
        assert!(trend.is_accelerating);
        assert!((trend.r_squared - 1.0).abs() < 1e-4);
        assert!((trend.hourly_growth_rate_bps - 36_000.0).abs() < 1e-2);

        // Runway to 8000 bps from 1300 bps at 10 bps/sec: (8000 - 1300) / 10 = 670s
        assert_eq!(trend.runway_warning_secs, Some(670));
    }

    #[test]
    fn test_linear_regression_flat_trend() {
        let mut buffer = HistoricalUsageBuffer::new(10);
        buffer.push(make_sample(0, 5_000, 30));
        buffer.push(make_sample(10, 5_000, 30));
        buffer.push(make_sample(20, 5_000, 30));

        let config = CapacityPlanningConfig::default();
        let trend = CapacityForecaster::compute_trend(&buffer, &config).unwrap();

        assert!(trend.slope_bps_per_sec.abs() < 1e-6);
        assert!(!trend.is_accelerating);
        assert_eq!(trend.runway_warning_secs, None);
        assert_eq!(trend.runway_critical_secs, None);
        assert_eq!(trend.runway_exhaustion_secs, None);
    }

    #[test]
    fn test_linear_regression_declining_trend() {
        let mut buffer = HistoricalUsageBuffer::new(10);
        buffer.push(make_sample(0, 6_000, 40));
        buffer.push(make_sample(10, 5_500, 35));
        buffer.push(make_sample(20, 5_000, 30));

        let config = CapacityPlanningConfig::default();
        let trend = CapacityForecaster::compute_trend(&buffer, &config).unwrap();

        assert!(trend.slope_bps_per_sec < 0.0);
        assert!(!trend.is_accelerating);
        assert_eq!(trend.runway_warning_secs, None);
    }

    #[test]
    fn test_runway_already_exceeded() {
        let mut buffer = HistoricalUsageBuffer::new(10);
        buffer.push(make_sample(0, 8_500, 40));
        buffer.push(make_sample(10, 8_600, 45));
        buffer.push(make_sample(20, 8_700, 50));

        let config = CapacityPlanningConfig::default();
        let trend = CapacityForecaster::compute_trend(&buffer, &config).unwrap();

        // Already past 8000 warning threshold
        assert_eq!(trend.runway_warning_secs, Some(0));
        assert!(trend.runway_critical_secs.is_some());
    }

    #[test]
    fn test_health_classification_healthy() {
        let sample = make_sample(100, 5_000, 40);
        let config = CapacityPlanningConfig::default();
        assert_eq!(
            CapacityForecaster::classify_health(&sample, None, &config),
            CapacityHealthState::Healthy
        );
    }

    #[test]
    fn test_health_classification_warning_and_critical() {
        let config = CapacityPlanningConfig::default();
        let warning_sample = make_sample(100, 8_200, 50);
        assert_eq!(
            CapacityForecaster::classify_health(&warning_sample, None, &config),
            CapacityHealthState::Warning
        );

        let critical_sample = make_sample(100, 9_200, 60);
        assert_eq!(
            CapacityForecaster::classify_health(&critical_sample, None, &config),
            CapacityHealthState::Critical
        );
    }

    #[test]
    fn test_health_classification_p99_violation_triggers_exhausted() {
        // Latency exceeds 100ms bound even if saturation is moderate
        let sample = make_sample(100, 4_000, 105);
        let config = CapacityPlanningConfig::default();
        assert_eq!(
            CapacityForecaster::classify_health(&sample, None, &config),
            CapacityHealthState::Exhausted
        );
    }

    #[test]
    fn test_sizing_recommendation_scale_up_on_saturation() {
        let mut state = ServiceCapacityState::new("consensus", 4, 10);
        state.record_sample(make_sample(0, 8_200, 45));
        let config = CapacityPlanningConfig::default();

        let action = CapacityForecaster::recommend_action(&state, None, &config, 100);
        match action {
            CapacityAction::ScaleUp {
                delta_units,
                target_units,
                ..
            } => {
                assert!(delta_units >= 1);
                assert_eq!(target_units, 4 + delta_units);
            }
            _ => panic!("Expected ScaleUp action"),
        }
    }

    #[test]
    fn test_sizing_recommendation_cooldown_active() {
        let mut state = ServiceCapacityState::new("consensus", 4, 10);
        state.record_sample(make_sample(100, 8_500, 45));
        state.last_action_at = Some(90); // 10 seconds ago, cooldown is 30s
        let config = CapacityPlanningConfig::default();

        let action = CapacityForecaster::recommend_action(&state, None, &config, 100);
        assert_eq!(action, CapacityAction::NoAction);
    }

    #[test]
    fn test_sizing_recommendation_scale_down_when_underutilized() {
        let mut state = ServiceCapacityState::new("settlement", 4, 10);
        state.record_sample(make_sample(0, 1_500, 15));
        let config = CapacityPlanningConfig::default();

        let action = CapacityForecaster::recommend_action(&state, None, &config, 100);
        match action {
            CapacityAction::ScaleDown {
                delta_units,
                target_units,
                ..
            } => {
                assert_eq!(delta_units, 1);
                assert_eq!(target_units, 3);
            }
            _ => panic!("Expected ScaleDown action"),
        }
    }

    #[test]
    fn test_canary_gate_success() {
        let canary = CapacityCanaryAnalysis::new("mempool", 8, 100_000, 99_995, 75, 9_999, true);
        assert_eq!(canary.success_rate_bps(), 9_999);
        assert!(canary.passes_release_gate().is_ok());
    }

    #[test]
    fn test_canary_gate_security_review_required() {
        let canary = CapacityCanaryAnalysis::new(
            "mempool", 8, 100_000, 99_995, 75, 9_999, false, // Security review missing
        );
        assert_eq!(
            canary.passes_release_gate(),
            Err(CapacityError::SecurityReviewRequired)
        );
    }

    #[test]
    fn test_canary_gate_availability_target_violated() {
        let canary = CapacityCanaryAnalysis::new(
            "mempool", 8, 100_000, 99_995, 75, 9_990, // 99.90% < 99.99% target
            true,
        );
        assert_eq!(
            canary.passes_release_gate(),
            Err(CapacityError::AvailabilityTargetViolated)
        );
    }

    #[test]
    fn test_canary_gate_p99_latency_violated() {
        let canary = CapacityCanaryAnalysis::new(
            "mempool", 8, 100_000, 99_995, 105, // 105ms > 100ms target
            9_999, true,
        );
        assert_eq!(
            canary.passes_release_gate(),
            Err(CapacityError::LatencyTargetViolated)
        );
    }

    #[test]
    fn test_canary_gate_success_rate_violated() {
        let canary = CapacityCanaryAnalysis::new(
            "mempool", 8, 100_000, 99_800, // 99.80% < 99.99%
            80, 9_999, true,
        );
        assert_eq!(
            canary.passes_release_gate(),
            Err(CapacityError::CanaryValidationFailed)
        );
    }

    #[test]
    fn test_registry_lifecycle_and_dashboard() {
        let mut registry = CapacityPlanningRegistry::default();
        assert!(registry.register_service("consensus", 4).is_ok());
        assert!(registry.register_service("mempool", 6).is_ok());

        assert_eq!(
            registry.register_service("consensus", 4),
            Err(CapacityError::ServiceAlreadyExists)
        );

        registry
            .record_sample("consensus", make_sample(10, 4_000, 30))
            .unwrap();
        registry
            .record_sample("consensus", make_sample(20, 4_000, 30))
            .unwrap();
        registry
            .record_sample("consensus", make_sample(30, 4_000, 30))
            .unwrap();

        registry
            .record_sample("mempool", make_sample(10, 8_500, 45))
            .unwrap();

        let snapshot = registry.dashboard_snapshot(50);
        assert_eq!(snapshot.services_monitored, 2);
        assert_eq!(snapshot.total_units_allocated, 10);
        assert_eq!(snapshot.max_saturation_bps, 8_500);
        assert_eq!(snapshot.warning_count, 1);
        assert_eq!(snapshot.healthy_count, 1);
    }

    #[test]
    fn test_registry_promote_canary() {
        let mut registry = CapacityPlanningRegistry::default();
        registry.register_service("attestation", 4).unwrap();

        let canary = CapacityCanaryAnalysis::new("attestation", 8, 50_000, 49_998, 45, 9_999, true);

        let old = registry
            .promote_canary_deployment("attestation", &canary, 100)
            .unwrap();
        assert_eq!(old, 4);
        assert_eq!(
            registry.service_state("attestation").unwrap().current_units,
            8
        );
    }
}
