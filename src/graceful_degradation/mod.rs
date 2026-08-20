//! Graceful degradation with feature flags and capacity shedding (issue #132).
//!
//! This module provides deterministic, dependency-free primitives for:
//!
//! * **Feature flags** — boolean gates that enable or disable named service
//!   features system-wide, per deployment stage, or per canary cohort.
//! * **Capacity shedding** — load-shedding decisions based on a configurable
//!   capacity utilisation threshold so services shed excess load rather than
//!   failing hard under pressure.
//! * **Degradation policy** — combines feature-flag state and capacity signals
//!   into a `DegradationDecision` that tells the caller whether to serve a
//!   request in full, serve a degraded fallback, or shed the load entirely.
//! * **Monitoring** — a `DegradationMetrics` snapshot exported to dashboards
//!   and alerting pipelines.
//! * **Blue-green / canary gate** — a `CanaryGate` checks that a canary
//!   cohort meets the success-rate and latency targets before the feature
//!   flag is promoted to full rollout.
//!
//! # Design
//!
//! ```text
//! ┌─────────────────┐   flag lookup   ┌──────────────────────────┐
//! │  FeatureFlagSet │ ──────────────▶ │  DegradationPolicy       │
//! └─────────────────┘                 │  • evaluate()            │
//! ┌─────────────────┐  capacity check │  • dashboard_snapshot()  │
//! │  CapacitySensor │ ──────────────▶ └───────────┬──────────────┘
//! └─────────────────┘                             │ DegradationDecision
//!                                                 ▼
//!                                    ┌──────────────────────────┐
//!                                    │  CanaryGate              │
//!                                    │  • passes_release_gate() │
//!                                    └──────────────────────────┘
//! ```
//!
//! All logic is pure Rust using only `alloc::`-based collections so it
//! compiles to WASM (`no_std`) and can be exercised by off-chain monitoring
//! agents without any platform-specific I/O.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Operational constants
// ---------------------------------------------------------------------------

/// P99 latency target for critical-path requests, in milliseconds (issue #132).
pub const CRITICAL_PATH_P99_TARGET_MS: u64 = 100;

/// Availability target in basis points: 99.99%.
pub const AVAILABILITY_TARGET_BPS: u32 = 9_999;

/// Default capacity utilisation threshold (in basis points) above which
/// capacity shedding is activated.  1_000 bps = 10 % headroom below full
/// capacity, i.e. shedding begins when utilisation exceeds 90 %.
pub const DEFAULT_SHEDDING_THRESHOLD_BPS: u32 = 9_000;

/// Capacity utilisation that triggers hard-shed (full load rejection),
/// in basis points.  9_500 bps = 95 % utilisation.
pub const DEFAULT_HARD_SHED_THRESHOLD_BPS: u32 = 9_500;

/// Canary success-rate gate in basis points before a flag is promoted.
pub const CANARY_SUCCESS_TARGET_BPS: u32 = 9_999;

/// Maximum number of feature flags tracked in a single flag set.
pub const MAX_FEATURE_FLAGS: usize = 256;

/// Maximum number of deployment stages tracked concurrently.
pub const MAX_DEPLOYMENT_STAGES: usize = 16;

// ---------------------------------------------------------------------------
// Feature flags
// ---------------------------------------------------------------------------

/// State of a single feature flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlagState {
    /// Feature is fully enabled for all traffic.
    Enabled,
    /// Feature is disabled; callers receive the degraded fallback.
    Disabled,
    /// Feature is enabled for the canary cohort only.
    Canary,
}

/// A named feature flag entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureFlag {
    /// Stable, lower-case-kebab-case identifier.
    pub name: String,
    /// Current runtime state.
    pub state: FlagState,
    /// Whether a security review was completed before this flag was modified.
    pub security_reviewed: bool,
}

impl FeatureFlag {
    /// Creates a new flag in `Disabled` state pending security review.
    pub fn new(name: String) -> Self {
        Self {
            name,
            state: FlagState::Disabled,
            security_reviewed: false,
        }
    }

    /// Returns `true` when the flag should be served to the given `canary`
    /// status.  A `Canary`-state flag is enabled only for canary traffic;
    /// an `Enabled` flag is available to everyone; a `Disabled` flag serves
    /// nobody.
    pub fn is_active(&self, is_canary_traffic: bool) -> bool {
        match self.state {
            FlagState::Enabled => true,
            FlagState::Canary => is_canary_traffic,
            FlagState::Disabled => false,
        }
    }
}

/// Errors returned by feature-flag operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlagError {
    /// The flag registry is at capacity.
    TooManyFlags,
    /// The requested flag was not found.
    FlagNotFound,
    /// A security review must be completed before activating a flag.
    SecurityReviewRequired,
    /// The flag name is empty.
    EmptyFlagName,
}

/// Registry of all feature flags for the system.
#[derive(Clone, Debug, Default)]
pub struct FeatureFlagSet {
    flags: BTreeMap<String, FeatureFlag>,
}

impl FeatureFlagSet {
    /// Creates an empty flag set.
    pub fn new() -> Self {
        Self {
            flags: BTreeMap::new(),
        }
    }

    /// Registers a new flag or replaces an existing one.
    ///
    /// Returns `Err(TooManyFlags)` if the registry is at capacity.
    pub fn register(&mut self, flag: FeatureFlag) -> Result<(), FlagError> {
        if flag.name.is_empty() {
            return Err(FlagError::EmptyFlagName);
        }
        if !self.flags.contains_key(&flag.name) && self.flags.len() >= MAX_FEATURE_FLAGS {
            return Err(FlagError::TooManyFlags);
        }
        self.flags.insert(flag.name.clone(), flag);
        Ok(())
    }

    /// Updates the state of an existing flag.
    ///
    /// Enabling or promoting to `Canary` requires `security_reviewed = true`.
    pub fn set_state(
        &mut self,
        name: &str,
        state: FlagState,
        security_reviewed: bool,
    ) -> Result<(), FlagError> {
        let flag = self.flags.get_mut(name).ok_or(FlagError::FlagNotFound)?;
        if matches!(state, FlagState::Enabled | FlagState::Canary) && !security_reviewed {
            return Err(FlagError::SecurityReviewRequired);
        }
        flag.state = state;
        flag.security_reviewed = security_reviewed;
        Ok(())
    }

    /// Returns `true` if the named flag is active for the given traffic class.
    ///
    /// An unknown flag is treated as `Disabled`.
    pub fn is_active(&self, name: &str, is_canary_traffic: bool) -> bool {
        self.flags
            .get(name)
            .map(|f| f.is_active(is_canary_traffic))
            .unwrap_or(false)
    }

    /// Returns the current state of a flag, or `None` if it is not registered.
    pub fn state(&self, name: &str) -> Option<FlagState> {
        self.flags.get(name).map(|f| f.state)
    }

    /// Returns the total number of registered flags.
    pub fn flag_count(&self) -> usize {
        self.flags.len()
    }

    /// Returns the number of flags currently in `Enabled` state.
    pub fn enabled_count(&self) -> usize {
        self.flags
            .values()
            .filter(|f| f.state == FlagState::Enabled)
            .count()
    }

    /// Returns the number of flags currently in `Canary` state.
    pub fn canary_count(&self) -> usize {
        self.flags
            .values()
            .filter(|f| f.state == FlagState::Canary)
            .count()
    }
}

// ---------------------------------------------------------------------------
// Capacity sensor
// ---------------------------------------------------------------------------

/// A snapshot of current capacity utilisation for one service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacitySensor {
    /// Current request-processing utilisation in basis points (0–10_000).
    pub utilisation_bps: u32,
    /// Observed P99 request latency in milliseconds.
    pub p99_latency_ms: u64,
    /// Number of in-flight requests at sample time.
    pub in_flight_requests: u64,
}

impl CapacitySensor {
    /// Returns `true` when utilisation exceeds the soft-shedding threshold.
    pub fn exceeds_soft_threshold(&self, config: &DegradationConfig) -> bool {
        self.utilisation_bps >= config.shedding_threshold_bps
    }

    /// Returns `true` when utilisation exceeds the hard-shedding threshold.
    pub fn exceeds_hard_threshold(&self, config: &DegradationConfig) -> bool {
        self.utilisation_bps >= config.hard_shed_threshold_bps
    }

    /// Returns `true` when P99 latency exceeds the critical-path target.
    pub fn latency_violated(&self) -> bool {
        self.p99_latency_ms > CRITICAL_PATH_P99_TARGET_MS
    }
}

// ---------------------------------------------------------------------------
// Degradation policy configuration
// ---------------------------------------------------------------------------

/// Policy configuration for the degradation engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DegradationConfig {
    /// Utilisation (bps) at which soft shedding begins.
    pub shedding_threshold_bps: u32,
    /// Utilisation (bps) at which hard (full) shedding begins.
    pub hard_shed_threshold_bps: u32,
    /// Whether to honour feature flags at all — can be used to disable all
    /// flags system-wide in a single toggle.
    pub flags_enabled: bool,
}

impl Default for DegradationConfig {
    fn default() -> Self {
        Self {
            shedding_threshold_bps: DEFAULT_SHEDDING_THRESHOLD_BPS,
            hard_shed_threshold_bps: DEFAULT_HARD_SHED_THRESHOLD_BPS,
            flags_enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Degradation decision
// ---------------------------------------------------------------------------

/// The outcome of a single policy evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DegradationDecision {
    /// Serve the request in full with all features active.
    FullService,
    /// Serve a degraded fallback; the feature is disabled or capacity is soft-
    /// shedding.
    DegradedFallback,
    /// Reject the request immediately; capacity is hard-shedding.
    ShedLoad,
}

// ---------------------------------------------------------------------------
// Degradation policy
// ---------------------------------------------------------------------------

/// Stateless degradation policy evaluator.
///
/// Feed it a [`CapacitySensor`] snapshot and a [`FeatureFlagSet`] and it
/// produces a [`DegradationDecision`] for each request.
pub struct DegradationPolicy;

impl DegradationPolicy {
    /// Evaluates a request against the capacity sensor and flag registry.
    ///
    /// Decision rules (in priority order):
    /// 1. **Hard shed**: utilisation ≥ `hard_shed_threshold_bps` → `ShedLoad`.
    /// 2. **Flags disabled globally**: `config.flags_enabled == false` →
    ///    `DegradedFallback`.
    /// 3. **Flag inactive** for this traffic class → `DegradedFallback`.
    /// 4. **Soft shed** (latency violated or utilisation ≥ soft threshold) →
    ///    `DegradedFallback`.
    /// 5. Otherwise → `FullService`.
    pub fn evaluate(
        flag_name: &str,
        is_canary_traffic: bool,
        sensor: &CapacitySensor,
        flags: &FeatureFlagSet,
        config: &DegradationConfig,
    ) -> DegradationDecision {
        // Rule 1: hard capacity shed always wins.
        if sensor.exceeds_hard_threshold(config) {
            return DegradationDecision::ShedLoad;
        }

        // Rule 2: global flag kill-switch.
        if !config.flags_enabled {
            return DegradationDecision::DegradedFallback;
        }

        // Rule 3: feature flag state.
        if !flags.is_active(flag_name, is_canary_traffic) {
            return DegradationDecision::DegradedFallback;
        }

        // Rule 4: soft capacity pressure.
        if sensor.exceeds_soft_threshold(config) || sensor.latency_violated() {
            return DegradationDecision::DegradedFallback;
        }

        DegradationDecision::FullService
    }
}

// ---------------------------------------------------------------------------
// Metrics / dashboard snapshot
// ---------------------------------------------------------------------------

/// System-wide degradation metrics exported to dashboards and alerting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DegradationMetrics {
    /// Total flags registered.
    pub flags_total: usize,
    /// Flags in `Enabled` state.
    pub flags_enabled: usize,
    /// Flags in `Canary` state.
    pub flags_canary: usize,
    /// Flags in `Disabled` state.
    pub flags_disabled: usize,
    /// Current capacity utilisation in basis points.
    pub utilisation_bps: u32,
    /// Whether soft shedding is currently active.
    pub soft_shedding_active: bool,
    /// Whether hard shedding is currently active.
    pub hard_shedding_active: bool,
    /// Whether P99 latency has exceeded the critical-path target.
    pub latency_violated: bool,
    /// Availability target (from operational constants).
    pub availability_target_bps: u32,
    /// P99 latency target (from operational constants).
    pub p99_target_ms: u64,
}

/// Produces a system-wide metrics snapshot from a flag set and capacity sensor.
pub fn dashboard_snapshot(
    flags: &FeatureFlagSet,
    sensor: &CapacitySensor,
    config: &DegradationConfig,
) -> DegradationMetrics {
    let flags_total = flags.flag_count();
    let flags_enabled = flags.enabled_count();
    let flags_canary = flags.canary_count();
    let flags_disabled = flags_total.saturating_sub(flags_enabled + flags_canary);

    DegradationMetrics {
        flags_total,
        flags_enabled,
        flags_canary,
        flags_disabled,
        utilisation_bps: sensor.utilisation_bps,
        soft_shedding_active: sensor.exceeds_soft_threshold(config),
        hard_shedding_active: sensor.exceeds_hard_threshold(config),
        latency_violated: sensor.latency_violated(),
        availability_target_bps: AVAILABILITY_TARGET_BPS,
        p99_target_ms: CRITICAL_PATH_P99_TARGET_MS,
    }
}

// ---------------------------------------------------------------------------
// Canary gate
// ---------------------------------------------------------------------------

/// Analysis of a canary deployment before promoting a feature flag to
/// `Enabled` state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanaryGate {
    /// Total requests handled by the canary cohort.
    pub requests: u64,
    /// Requests that completed successfully.
    pub successful_requests: u64,
    /// Observed P99 latency for canary traffic in milliseconds.
    pub p99_latency_ms: u64,
    /// Whether a security review was signed off for this promotion.
    pub security_review_passed: bool,
}

/// Errors returned by canary gate evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanaryError {
    /// The canary did not meet the success-rate or latency gate.
    CanaryFailed,
    /// A security review must be completed before promotion.
    SecurityReviewRequired,
}

impl CanaryGate {
    /// Returns the canary success rate in basis points.
    pub fn success_rate_bps(&self) -> u32 {
        if self.requests == 0 {
            return 0;
        }
        ((self.successful_requests.saturating_mul(10_000)) / self.requests).min(10_000) as u32
    }

    /// Returns `Ok(())` when the canary meets all release criteria.
    ///
    /// Criteria:
    /// * Security review passed.
    /// * Success rate ≥ [`CANARY_SUCCESS_TARGET_BPS`].
    /// * P99 latency ≤ [`CRITICAL_PATH_P99_TARGET_MS`].
    pub fn passes_release_gate(&self) -> Result<(), CanaryError> {
        if !self.security_review_passed {
            return Err(CanaryError::SecurityReviewRequired);
        }
        if self.success_rate_bps() < CANARY_SUCCESS_TARGET_BPS
            || self.p99_latency_ms > CRITICAL_PATH_P99_TARGET_MS
        {
            return Err(CanaryError::CanaryFailed);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Deployment stage registry
// ---------------------------------------------------------------------------

/// Coarse deployment stage for blue-green and canary rollouts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum DeploymentStage {
    Development,
    BlueGreenShadow,
    CanaryOnePercent,
    CanaryTenPercent,
    FullRollout,
}

impl DeploymentStage {
    /// Returns the next stage in the promotion sequence.
    pub const fn next(self) -> Self {
        match self {
            Self::Development => Self::BlueGreenShadow,
            Self::BlueGreenShadow => Self::CanaryOnePercent,
            Self::CanaryOnePercent => Self::CanaryTenPercent,
            Self::CanaryTenPercent => Self::FullRollout,
            Self::FullRollout => Self::FullRollout,
        }
    }

    /// Returns `true` for stages that carry canary traffic.
    pub const fn is_canary(self) -> bool {
        matches!(self, Self::CanaryOnePercent | Self::CanaryTenPercent)
    }
}

/// Per-feature deployment stage tracking.
#[derive(Clone, Debug, Default)]
pub struct DeploymentStageRegistry {
    stages: BTreeMap<String, DeploymentStage>,
}

impl DeploymentStageRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            stages: BTreeMap::new(),
        }
    }

    /// Sets the deployment stage for a named feature.
    pub fn set_stage(&mut self, feature: String, stage: DeploymentStage) -> Result<(), FlagError> {
        if feature.is_empty() {
            return Err(FlagError::EmptyFlagName);
        }
        if !self.stages.contains_key(&feature) && self.stages.len() >= MAX_DEPLOYMENT_STAGES {
            return Err(FlagError::TooManyFlags);
        }
        self.stages.insert(feature, stage);
        Ok(())
    }

    /// Returns the current stage for a feature, or `None` if not registered.
    pub fn stage(&self, feature: &str) -> Option<DeploymentStage> {
        self.stages.get(feature).copied()
    }

    /// Advances the stage for a named feature, gated by a canary analysis.
    ///
    /// Promotion from any canary stage requires the canary to pass the release
    /// gate. Promotion from `Development` or `BlueGreenShadow` is unconditional
    /// (canary analysis not yet applicable).
    pub fn promote(
        &mut self,
        feature: &str,
        canary: Option<&CanaryGate>,
    ) -> Result<DeploymentStage, CanaryError> {
        let current = self
            .stages
            .get(feature)
            .copied()
            .unwrap_or(DeploymentStage::Development);

        if current.is_canary() {
            match canary {
                Some(gate) => gate.passes_release_gate()?,
                None => return Err(CanaryError::CanaryFailed),
            }
        }

        let next = current.next();
        self.stages.insert(feature.into(), next);
        Ok(next)
    }

    /// Returns the number of features tracked.
    pub fn feature_count(&self) -> usize {
        self.stages.len()
    }

    /// Returns a sorted snapshot of all (feature, stage) pairs.
    pub fn snapshot(&self) -> Vec<(String, DeploymentStage)> {
        self.stages.iter().map(|(k, v)| (k.clone(), *v)).collect()
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

    fn healthy_sensor() -> CapacitySensor {
        CapacitySensor {
            utilisation_bps: 5_000, // 50 %
            p99_latency_ms: 80,
            in_flight_requests: 100,
        }
    }

    fn overloaded_sensor_soft() -> CapacitySensor {
        CapacitySensor {
            utilisation_bps: 9_200, // above soft, below hard
            p99_latency_ms: 80,
            in_flight_requests: 500,
        }
    }

    fn overloaded_sensor_hard() -> CapacitySensor {
        CapacitySensor {
            utilisation_bps: 9_600, // above hard threshold
            p99_latency_ms: 80,
            in_flight_requests: 800,
        }
    }

    fn slow_sensor() -> CapacitySensor {
        CapacitySensor {
            utilisation_bps: 5_000,
            p99_latency_ms: 101, // exceeds P99 target
            in_flight_requests: 100,
        }
    }

    fn config() -> DegradationConfig {
        DegradationConfig::default()
    }

    fn enabled_flag(name: &str) -> FeatureFlag {
        FeatureFlag {
            name: name.into(),
            state: FlagState::Enabled,
            security_reviewed: true,
        }
    }

    fn flags_with(flag: FeatureFlag) -> FeatureFlagSet {
        let mut set = FeatureFlagSet::new();
        set.register(flag).unwrap();
        set
    }

    // -----------------------------------------------------------------------
    // FeatureFlag
    // -----------------------------------------------------------------------

    #[test]
    fn enabled_flag_is_active_for_all_traffic() {
        let f = enabled_flag("consensus");
        assert!(f.is_active(false));
        assert!(f.is_active(true));
    }

    #[test]
    fn disabled_flag_is_inactive_for_all_traffic() {
        let f = FeatureFlag {
            name: "consensus".into(),
            state: FlagState::Disabled,
            security_reviewed: false,
        };
        assert!(!f.is_active(false));
        assert!(!f.is_active(true));
    }

    #[test]
    fn canary_flag_is_active_only_for_canary_traffic() {
        let f = FeatureFlag {
            name: "consensus".into(),
            state: FlagState::Canary,
            security_reviewed: true,
        };
        assert!(!f.is_active(false));
        assert!(f.is_active(true));
    }

    // -----------------------------------------------------------------------
    // FeatureFlagSet
    // -----------------------------------------------------------------------

    #[test]
    fn flag_set_rejects_empty_name() {
        let mut set = FeatureFlagSet::new();
        assert_eq!(
            set.register(FeatureFlag::new(String::new())),
            Err(FlagError::EmptyFlagName)
        );
    }

    #[test]
    fn flag_set_requires_security_review_to_enable() {
        let mut set = FeatureFlagSet::new();
        set.register(FeatureFlag::new("f".into())).unwrap();
        assert_eq!(
            set.set_state("f", FlagState::Enabled, false),
            Err(FlagError::SecurityReviewRequired)
        );
    }

    #[test]
    fn flag_set_requires_security_review_for_canary() {
        let mut set = FeatureFlagSet::new();
        set.register(FeatureFlag::new("f".into())).unwrap();
        assert_eq!(
            set.set_state("f", FlagState::Canary, false),
            Err(FlagError::SecurityReviewRequired)
        );
    }

    #[test]
    fn flag_set_allows_disable_without_review() {
        let mut set = FeatureFlagSet::new();
        set.register(enabled_flag("f")).unwrap();
        assert!(set.set_state("f", FlagState::Disabled, false).is_ok());
        assert_eq!(set.state("f"), Some(FlagState::Disabled));
    }

    #[test]
    fn flag_set_counts_states_correctly() {
        let mut set = FeatureFlagSet::new();
        set.register(enabled_flag("a")).unwrap();
        set.register(FeatureFlag {
            name: "b".into(),
            state: FlagState::Canary,
            security_reviewed: true,
        })
        .unwrap();
        set.register(FeatureFlag::new("c".into())).unwrap();

        assert_eq!(set.flag_count(), 3);
        assert_eq!(set.enabled_count(), 1);
        assert_eq!(set.canary_count(), 1);
    }

    #[test]
    fn flag_set_returns_none_for_unknown_flag() {
        let set = FeatureFlagSet::new();
        assert_eq!(set.state("unknown"), None);
        assert!(!set.is_active("unknown", true));
    }

    // -----------------------------------------------------------------------
    // CapacitySensor
    // -----------------------------------------------------------------------

    #[test]
    fn sensor_soft_threshold_triggers_at_boundary() {
        let cfg = config();
        let at_boundary = CapacitySensor {
            utilisation_bps: DEFAULT_SHEDDING_THRESHOLD_BPS,
            p99_latency_ms: 50,
            in_flight_requests: 0,
        };
        assert!(at_boundary.exceeds_soft_threshold(&cfg));

        let below = CapacitySensor {
            utilisation_bps: DEFAULT_SHEDDING_THRESHOLD_BPS - 1,
            ..at_boundary
        };
        assert!(!below.exceeds_soft_threshold(&cfg));
    }

    #[test]
    fn sensor_hard_threshold_triggers_at_boundary() {
        let cfg = config();
        let at_boundary = CapacitySensor {
            utilisation_bps: DEFAULT_HARD_SHED_THRESHOLD_BPS,
            p99_latency_ms: 50,
            in_flight_requests: 0,
        };
        assert!(at_boundary.exceeds_hard_threshold(&cfg));

        let below = CapacitySensor {
            utilisation_bps: DEFAULT_HARD_SHED_THRESHOLD_BPS - 1,
            ..at_boundary
        };
        assert!(!below.exceeds_hard_threshold(&cfg));
    }

    #[test]
    fn sensor_latency_violation_at_p99_boundary() {
        let ok = CapacitySensor {
            utilisation_bps: 0,
            p99_latency_ms: CRITICAL_PATH_P99_TARGET_MS,
            in_flight_requests: 0,
        };
        // Exactly at target — no violation.
        assert!(!ok.latency_violated());

        let violated = CapacitySensor {
            p99_latency_ms: CRITICAL_PATH_P99_TARGET_MS + 1,
            ..ok
        };
        assert!(violated.latency_violated());
    }

    // -----------------------------------------------------------------------
    // DegradationPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn full_service_when_healthy_and_flag_enabled() {
        let flags = flags_with(enabled_flag("payments"));
        let decision =
            DegradationPolicy::evaluate("payments", false, &healthy_sensor(), &flags, &config());
        assert_eq!(decision, DegradationDecision::FullService);
    }

    #[test]
    fn degraded_fallback_when_flag_disabled() {
        let flags = flags_with(FeatureFlag::new("payments".into()));
        let decision =
            DegradationPolicy::evaluate("payments", false, &healthy_sensor(), &flags, &config());
        assert_eq!(decision, DegradationDecision::DegradedFallback);
    }

    #[test]
    fn degraded_fallback_when_global_flags_disabled() {
        let flags = flags_with(enabled_flag("payments"));
        let cfg = DegradationConfig {
            flags_enabled: false,
            ..config()
        };
        let decision =
            DegradationPolicy::evaluate("payments", false, &healthy_sensor(), &flags, &cfg);
        assert_eq!(decision, DegradationDecision::DegradedFallback);
    }

    #[test]
    fn degraded_fallback_under_soft_capacity_pressure() {
        let flags = flags_with(enabled_flag("payments"));
        let decision = DegradationPolicy::evaluate(
            "payments",
            false,
            &overloaded_sensor_soft(),
            &flags,
            &config(),
        );
        assert_eq!(decision, DegradationDecision::DegradedFallback);
    }

    #[test]
    fn shed_load_under_hard_capacity_pressure() {
        let flags = flags_with(enabled_flag("payments"));
        let decision = DegradationPolicy::evaluate(
            "payments",
            false,
            &overloaded_sensor_hard(),
            &flags,
            &config(),
        );
        assert_eq!(decision, DegradationDecision::ShedLoad);
    }

    #[test]
    fn hard_shed_beats_flag_disabled_and_global_kill_switch() {
        // Even with flags disabled and global kill-switch, hard-shed takes priority.
        let flags = FeatureFlagSet::new();
        let cfg = DegradationConfig {
            flags_enabled: false,
            ..config()
        };
        let decision =
            DegradationPolicy::evaluate("any", false, &overloaded_sensor_hard(), &flags, &cfg);
        assert_eq!(decision, DegradationDecision::ShedLoad);
    }

    #[test]
    fn degraded_fallback_when_latency_violated() {
        let flags = flags_with(enabled_flag("payments"));
        let decision =
            DegradationPolicy::evaluate("payments", false, &slow_sensor(), &flags, &config());
        assert_eq!(decision, DegradationDecision::DegradedFallback);
    }

    #[test]
    fn canary_flag_gives_full_service_for_canary_traffic_only() {
        let mut flags = FeatureFlagSet::new();
        flags
            .register(FeatureFlag {
                name: "fast-path".into(),
                state: FlagState::Canary,
                security_reviewed: true,
            })
            .unwrap();

        let canary_decision = DegradationPolicy::evaluate(
            "fast-path",
            true, // canary traffic
            &healthy_sensor(),
            &flags,
            &config(),
        );
        let normal_decision = DegradationPolicy::evaluate(
            "fast-path",
            false, // normal traffic
            &healthy_sensor(),
            &flags,
            &config(),
        );

        assert_eq!(canary_decision, DegradationDecision::FullService);
        assert_eq!(normal_decision, DegradationDecision::DegradedFallback);
    }

    // -----------------------------------------------------------------------
    // dashboard_snapshot
    // -----------------------------------------------------------------------

    #[test]
    fn snapshot_reflects_flag_counts_and_capacity() {
        let mut flags = FeatureFlagSet::new();
        flags.register(enabled_flag("a")).unwrap();
        flags
            .register(FeatureFlag {
                name: "b".into(),
                state: FlagState::Canary,
                security_reviewed: true,
            })
            .unwrap();
        flags.register(FeatureFlag::new("c".into())).unwrap();

        let sensor = overloaded_sensor_soft();
        let snap = dashboard_snapshot(&flags, &sensor, &config());

        assert_eq!(snap.flags_total, 3);
        assert_eq!(snap.flags_enabled, 1);
        assert_eq!(snap.flags_canary, 1);
        assert_eq!(snap.flags_disabled, 1);
        assert_eq!(snap.utilisation_bps, sensor.utilisation_bps);
        assert!(snap.soft_shedding_active);
        assert!(!snap.hard_shedding_active);
        assert!(!snap.latency_violated);
        assert_eq!(snap.p99_target_ms, CRITICAL_PATH_P99_TARGET_MS);
        assert_eq!(snap.availability_target_bps, AVAILABILITY_TARGET_BPS);
    }

    // -----------------------------------------------------------------------
    // CanaryGate
    // -----------------------------------------------------------------------

    #[test]
    fn canary_passes_release_gate_when_all_criteria_met() {
        let gate = CanaryGate {
            requests: 10_000,
            successful_requests: 9_999,
            p99_latency_ms: 100,
            security_review_passed: true,
        };
        assert_eq!(gate.success_rate_bps(), 9_999);
        assert!(gate.passes_release_gate().is_ok());
    }

    #[test]
    fn canary_fails_without_security_review() {
        let gate = CanaryGate {
            requests: 10_000,
            successful_requests: 10_000,
            p99_latency_ms: 50,
            security_review_passed: false,
        };
        assert_eq!(
            gate.passes_release_gate(),
            Err(CanaryError::SecurityReviewRequired)
        );
    }

    #[test]
    fn canary_fails_when_latency_exceeds_p99_target() {
        let gate = CanaryGate {
            requests: 10_000,
            successful_requests: 10_000,
            p99_latency_ms: 101,
            security_review_passed: true,
        };
        assert_eq!(gate.passes_release_gate(), Err(CanaryError::CanaryFailed));
    }

    #[test]
    fn canary_fails_when_success_rate_below_gate() {
        let gate = CanaryGate {
            requests: 10_000,
            successful_requests: 9_990,
            p99_latency_ms: 50,
            security_review_passed: true,
        };
        assert_eq!(gate.passes_release_gate(), Err(CanaryError::CanaryFailed));
    }

    #[test]
    fn canary_zero_requests_yields_zero_success_rate() {
        let gate = CanaryGate {
            requests: 0,
            successful_requests: 0,
            p99_latency_ms: 0,
            security_review_passed: true,
        };
        assert_eq!(gate.success_rate_bps(), 0);
    }

    // -----------------------------------------------------------------------
    // DeploymentStage
    // -----------------------------------------------------------------------

    #[test]
    fn deployment_stage_advances_through_full_sequence() {
        assert_eq!(
            DeploymentStage::Development.next(),
            DeploymentStage::BlueGreenShadow
        );
        assert_eq!(
            DeploymentStage::BlueGreenShadow.next(),
            DeploymentStage::CanaryOnePercent
        );
        assert_eq!(
            DeploymentStage::CanaryOnePercent.next(),
            DeploymentStage::CanaryTenPercent
        );
        assert_eq!(
            DeploymentStage::CanaryTenPercent.next(),
            DeploymentStage::FullRollout
        );
        assert_eq!(
            DeploymentStage::FullRollout.next(),
            DeploymentStage::FullRollout
        );
    }

    #[test]
    fn canary_stages_are_identified_correctly() {
        assert!(!DeploymentStage::Development.is_canary());
        assert!(!DeploymentStage::BlueGreenShadow.is_canary());
        assert!(DeploymentStage::CanaryOnePercent.is_canary());
        assert!(DeploymentStage::CanaryTenPercent.is_canary());
        assert!(!DeploymentStage::FullRollout.is_canary());
    }

    // -----------------------------------------------------------------------
    // DeploymentStageRegistry
    // -----------------------------------------------------------------------

    #[test]
    fn registry_promotes_through_pre_canary_stages_unconditionally() {
        let mut reg = DeploymentStageRegistry::new();
        reg.set_stage("feat".into(), DeploymentStage::Development)
            .unwrap();

        let next = reg.promote("feat", None).unwrap();
        assert_eq!(next, DeploymentStage::BlueGreenShadow);
        assert_eq!(reg.stage("feat"), Some(DeploymentStage::BlueGreenShadow));
    }

    #[test]
    fn registry_requires_passing_canary_to_promote_from_canary_stage() {
        let mut reg = DeploymentStageRegistry::new();
        reg.set_stage("feat".into(), DeploymentStage::CanaryOnePercent)
            .unwrap();

        // No canary → fails.
        assert_eq!(reg.promote("feat", None), Err(CanaryError::CanaryFailed));

        // Failing canary → fails.
        let bad = CanaryGate {
            requests: 1_000,
            successful_requests: 900,
            p99_latency_ms: 50,
            security_review_passed: true,
        };
        assert_eq!(
            reg.promote("feat", Some(&bad)),
            Err(CanaryError::CanaryFailed)
        );
    }

    #[test]
    fn registry_promotes_from_canary_stage_with_passing_gate() {
        let mut reg = DeploymentStageRegistry::new();
        reg.set_stage("feat".into(), DeploymentStage::CanaryOnePercent)
            .unwrap();

        let good = CanaryGate {
            requests: 10_000,
            successful_requests: 9_999,
            p99_latency_ms: 90,
            security_review_passed: true,
        };
        let next = reg.promote("feat", Some(&good)).unwrap();
        assert_eq!(next, DeploymentStage::CanaryTenPercent);
    }

    #[test]
    fn registry_snapshot_returns_all_features() {
        let mut reg = DeploymentStageRegistry::new();
        reg.set_stage("a".into(), DeploymentStage::FullRollout)
            .unwrap();
        reg.set_stage("b".into(), DeploymentStage::Development)
            .unwrap();

        let snap = reg.snapshot();
        assert_eq!(snap.len(), 2);
        // BTreeMap guarantees lexicographic order.
        assert_eq!(snap[0].0, "a");
        assert_eq!(snap[1].0, "b");
    }

    #[test]
    fn registry_rejects_empty_feature_name() {
        let mut reg = DeploymentStageRegistry::new();
        assert_eq!(
            reg.set_stage(String::new(), DeploymentStage::Development),
            Err(FlagError::EmptyFlagName)
        );
    }

    // -----------------------------------------------------------------------
    // Issue #132 operational constants
    // -----------------------------------------------------------------------

    #[test]
    fn issue_132_constants_match_technical_bounds() {
        assert_eq!(CRITICAL_PATH_P99_TARGET_MS, 100);
        assert_eq!(AVAILABILITY_TARGET_BPS, 9_999);
        assert_eq!(DEFAULT_SHEDDING_THRESHOLD_BPS, 9_000);
        assert_eq!(DEFAULT_HARD_SHED_THRESHOLD_BPS, 9_500);
        assert_eq!(CANARY_SUCCESS_TARGET_BPS, 9_999);
    }
}
