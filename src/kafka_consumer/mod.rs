//! Kafka consumer lag monitoring and auto-scaling consumer groups (issue #131).
//!
//! This module provides deterministic, dependency-free primitives for tracking
//! per-partition consumer lag, evaluating scaling policies, and producing
//! canary-gated scale-out / scale-in decisions. It intentionally keeps all
//! math in pure Rust — no network I/O, no broker client — so on-chain
//! contracts, off-chain monitoring agents, and blue-green deployment gates
//! share exactly the same thresholds.
//!
//! # Design overview
//!
//! ```text
//!  ┌─────────────────────┐  lag samples  ┌──────────────────────────┐
//!  │  ConsumerGroupState │ ──────────────▶  ConsumerLagMonitor      │
//!  │  (per partition)    │               │  • evaluate_lag()        │
//!  └─────────────────────┘               │  • dashboard_snapshot()  │
//!                                        └──────────┬───────────────┘
//!                                                   │ ScalingDecision
//!                                                   ▼
//!                                        ┌──────────────────────────┐
//!                                        │  ConsumerAutoScaler      │
//!                                        │  • recommend_scale()     │
//!                                        │  • canary_gate()         │
//!                                        └──────────────────────────┘
//! ```
//!
//! # Operational constants
//!
//! All thresholds are tunable via [`ScalingConfig`] but default to the values
//! mandated by the technical bounds in issue #131:
//! * P99 critical-path latency target: < 100 ms
//! * Availability target: 99.99% (9_999 basis points)
//! * Blue-green + canary deployment gates enforced on every scale event

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Operational constants
// ---------------------------------------------------------------------------

/// P99 latency target for consumer-group critical paths, in milliseconds.
pub const CRITICAL_PATH_P99_TARGET_MS: u64 = 100;

/// Availability objective in basis points: 99.99%.
pub const AVAILABILITY_TARGET_BPS: u32 = 9_999;

/// Default consumer-lag threshold (messages) above which a scale-out is
/// recommended.
pub const DEFAULT_LAG_SCALEOUT_THRESHOLD: u64 = 10_000;

/// Default consumer-lag threshold (messages) below which a scale-in is
/// considered safe.
pub const DEFAULT_LAG_SCALEIN_THRESHOLD: u64 = 500;

/// Default maximum number of consumer instances per group.
pub const DEFAULT_MAX_CONSUMERS: u32 = 32;

/// Default minimum number of consumer instances per group.
pub const DEFAULT_MIN_CONSUMERS: u32 = 1;

/// Default cooldown period between consecutive scaling actions, in seconds.
pub const DEFAULT_SCALING_COOLDOWN_SECS: u64 = 60;

/// Canary success-rate gate in basis points before a scale-out is promoted.
pub const CANARY_SUCCESS_TARGET_BPS: u32 = 9_999;

/// Maximum number of partitions tracked per consumer group.
pub const MAX_PARTITIONS_PER_GROUP: usize = 1_024;

/// Maximum number of consumer groups tracked concurrently.
pub const MAX_CONSUMER_GROUPS: usize = 256;

// ---------------------------------------------------------------------------
// Identifier types
// ---------------------------------------------------------------------------

/// Logical Kafka topic name.
pub type TopicName = String;

/// Numeric partition identifier within a topic.
pub type PartitionId = u32;

/// Logical consumer group identifier.
pub type ConsumerGroupId = String;

// ---------------------------------------------------------------------------
// Per-partition lag snapshot
// ---------------------------------------------------------------------------

/// A single partition's lag observation: latest committed offset vs. log-end
/// offset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionLag {
    /// Topic this partition belongs to.
    pub topic: TopicName,
    /// Partition index within the topic.
    pub partition_id: PartitionId,
    /// Last offset the consumer group successfully committed.
    pub committed_offset: u64,
    /// Current end offset of the partition log.
    pub log_end_offset: u64,
    /// Wall-clock timestamp when this sample was collected, in seconds since
    /// the Unix epoch.
    pub sampled_at: u64,
}

impl PartitionLag {
    /// Returns the number of unconsumed messages in this partition.
    ///
    /// Uses saturating subtraction: a committed offset ahead of the log-end
    /// offset (possible after log compaction) yields 0 rather than wrapping.
    pub fn lag(&self) -> u64 {
        self.log_end_offset.saturating_sub(self.committed_offset)
    }
}

// ---------------------------------------------------------------------------
// Consumer group state
// ---------------------------------------------------------------------------

/// Full lag state for a consumer group across all its assigned partitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerGroupState {
    /// Unique group identifier.
    pub group_id: ConsumerGroupId,
    /// Number of consumer instances currently active in the group.
    pub active_consumers: u32,
    /// Per-partition lag snapshots.
    pub partitions: Vec<PartitionLag>,
    /// Epoch timestamp of the most recent state update.
    pub last_updated: u64,
}

impl ConsumerGroupState {
    /// Creates a new group state with the provided partitions.
    pub fn new(
        group_id: ConsumerGroupId,
        active_consumers: u32,
        partitions: Vec<PartitionLag>,
        last_updated: u64,
    ) -> Self {
        Self {
            group_id,
            active_consumers,
            partitions,
            last_updated,
        }
    }

    /// Returns the total lag across all partitions.
    pub fn total_lag(&self) -> u64 {
        self.partitions.iter().map(|p| p.lag()).fold(0u64, |acc, l| acc.saturating_add(l))
    }

    /// Returns the maximum single-partition lag.
    pub fn max_partition_lag(&self) -> u64 {
        self.partitions.iter().map(|p| p.lag()).max().unwrap_or(0)
    }

    /// Returns the number of partitions with non-zero lag.
    pub fn lagging_partition_count(&self) -> usize {
        self.partitions.iter().filter(|p| p.lag() > 0).count()
    }
}

// ---------------------------------------------------------------------------
// Lag alert levels
// ---------------------------------------------------------------------------

/// Coarse severity assigned to a lag observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum LagAlertLevel {
    /// Lag is within acceptable bounds — no action required.
    Healthy,
    /// Lag is elevated — a ticket or warning should be raised.
    Warning,
    /// Lag is critical — an immediate page and scale-out are required.
    Critical,
}

// ---------------------------------------------------------------------------
// Scaling decision
// ---------------------------------------------------------------------------

/// Recommendation produced by [`ConsumerAutoScaler`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalingDecision {
    /// Current instance count is sufficient.
    NoChange,
    /// Add `delta` consumers to the group.
    ScaleOut { delta: u32 },
    /// Remove `delta` consumers from the group.
    ScaleIn { delta: u32 },
}

// ---------------------------------------------------------------------------
// Canary analysis for scale-out events
// ---------------------------------------------------------------------------

/// Analysis of a canary consumer deployment before promoting a scale-out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerCanaryAnalysis {
    /// Total messages processed by the canary consumer(s).
    pub messages_processed: u64,
    /// Messages processed without error.
    pub successful_messages: u64,
    /// Observed P99 processing latency in milliseconds.
    pub p99_latency_ms: u64,
    /// Whether a security review was completed for this scale event.
    pub security_review_passed: bool,
}

impl ConsumerCanaryAnalysis {
    /// Returns the success rate in basis points.
    pub fn success_rate_bps(&self) -> u32 {
        if self.messages_processed == 0 {
            return 0;
        }
        ((self.successful_messages.saturating_mul(10_000)) / self.messages_processed)
            .min(10_000) as u32
    }

    /// Returns `Ok(())` when the canary meets the release gate criteria.
    pub fn passes_release_gate(&self) -> Result<(), ConsumerLagError> {
        if !self.security_review_passed {
            return Err(ConsumerLagError::SecurityReviewRequired);
        }
        if self.success_rate_bps() < CANARY_SUCCESS_TARGET_BPS
            || self.p99_latency_ms > CRITICAL_PATH_P99_TARGET_MS
        {
            return Err(ConsumerLagError::CanaryFailed);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by consumer-lag monitoring operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumerLagError {
    /// No consumer groups are registered in the monitor.
    NoGroupsRegistered,
    /// The requested consumer group was not found.
    GroupNotFound,
    /// Too many partitions supplied for a single group.
    TooManyPartitions,
    /// Too many consumer groups registered concurrently.
    TooManyGroups,
    /// A scale-out or scale-in would violate the min/max bounds.
    ScalingBoundsViolated,
    /// The scaling cooldown window has not elapsed since the last action.
    CooldownActive,
    /// The canary analysis did not meet the release gate.
    CanaryFailed,
    /// A security review must be completed before the scale event is promoted.
    SecurityReviewRequired,
}

// ---------------------------------------------------------------------------
// Scaling configuration
// ---------------------------------------------------------------------------

/// Tunable parameters for the auto-scaler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScalingConfig {
    /// Total lag threshold above which a scale-out is recommended.
    pub lag_scaleout_threshold: u64,
    /// Total lag threshold below which a scale-in is considered safe.
    pub lag_scalein_threshold: u64,
    /// Minimum consumers allowed in the group.
    pub min_consumers: u32,
    /// Maximum consumers allowed in the group.
    pub max_consumers: u32,
    /// Minimum seconds between consecutive scaling actions.
    pub cooldown_secs: u64,
}

impl Default for ScalingConfig {
    fn default() -> Self {
        Self {
            lag_scaleout_threshold: DEFAULT_LAG_SCALEOUT_THRESHOLD,
            lag_scalein_threshold: DEFAULT_LAG_SCALEIN_THRESHOLD,
            min_consumers: DEFAULT_MIN_CONSUMERS,
            max_consumers: DEFAULT_MAX_CONSUMERS,
            cooldown_secs: DEFAULT_SCALING_COOLDOWN_SECS,
        }
    }
}

// ---------------------------------------------------------------------------
// Monitoring metrics / dashboard snapshot
// ---------------------------------------------------------------------------

/// System-wide snapshot exported to dashboards and alerting pipelines.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerLagMetrics {
    /// Number of consumer groups being tracked.
    pub groups_tracked: usize,
    /// Total messages lagging across all groups.
    pub total_lag: u64,
    /// Maximum single-group total lag.
    pub max_group_lag: u64,
    /// Number of groups currently in a `Warning` or `Critical` state.
    pub unhealthy_groups: usize,
    /// Number of groups at `Critical` lag level.
    pub critical_groups: usize,
    /// P99 latency target (from operational constants).
    pub p99_target_ms: u64,
    /// Availability target (from operational constants).
    pub availability_target_bps: u32,
}

// ---------------------------------------------------------------------------
// Per-group evaluation result
// ---------------------------------------------------------------------------

/// Result of evaluating a single consumer group's lag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LagEvaluation {
    /// The group that was evaluated.
    pub group_id: ConsumerGroupId,
    /// Total lag across all partitions.
    pub total_lag: u64,
    /// Maximum single-partition lag.
    pub max_partition_lag: u64,
    /// Number of partitions with non-zero lag.
    pub lagging_partitions: usize,
    /// Alert level assigned to this group.
    pub alert_level: LagAlertLevel,
    /// Scaling recommendation produced by the evaluation.
    pub scaling_decision: ScalingDecision,
}

// ---------------------------------------------------------------------------
// Consumer lag monitor
// ---------------------------------------------------------------------------

/// Stateless lag monitor: computes alert levels and scaling decisions from
/// a group snapshot and a [`ScalingConfig`].
pub struct ConsumerLagMonitor;

impl ConsumerLagMonitor {
    /// Evaluates lag for a single consumer group.
    ///
    /// # Parameters
    /// * `state`  — current observed state of the group.
    /// * `config` — scaling policy to apply.
    /// * `now`    — current Unix timestamp in seconds.
    /// * `last_scaling_at` — Unix timestamp of the last scaling action for
    ///   this group, or `None` if no action has been taken.
    pub fn evaluate_lag(
        state: &ConsumerGroupState,
        config: &ScalingConfig,
        now: u64,
        last_scaling_at: Option<u64>,
    ) -> LagEvaluation {
        let total_lag = state.total_lag();
        let max_partition_lag = state.max_partition_lag();
        let lagging_partitions = state.lagging_partition_count();

        let alert_level = Self::classify_lag(total_lag, config);
        let scaling_decision = Self::recommend_scale(state, config, now, last_scaling_at);

        LagEvaluation {
            group_id: state.group_id.clone(),
            total_lag,
            max_partition_lag,
            lagging_partitions,
            alert_level,
            scaling_decision,
        }
    }

    /// Produces a system-wide dashboard snapshot from multiple groups.
    pub fn dashboard_snapshot(
        groups: &[ConsumerGroupState],
        config: &ScalingConfig,
        now: u64,
    ) -> ConsumerLagMetrics {
        let groups_tracked = groups.len();
        let mut total_lag: u64 = 0;
        let mut max_group_lag: u64 = 0;
        let mut unhealthy_groups: usize = 0;
        let mut critical_groups: usize = 0;

        for state in groups {
            let group_lag = state.total_lag();
            total_lag = total_lag.saturating_add(group_lag);
            if group_lag > max_group_lag {
                max_group_lag = group_lag;
            }
            let level = Self::classify_lag(group_lag, config);
            if level >= LagAlertLevel::Warning {
                unhealthy_groups += 1;
            }
            if level == LagAlertLevel::Critical {
                critical_groups += 1;
            }
            let _ = now; // used by callers for cooldown logic; snapshot is stateless
        }

        ConsumerLagMetrics {
            groups_tracked,
            total_lag,
            max_group_lag,
            unhealthy_groups,
            critical_groups,
            p99_target_ms: CRITICAL_PATH_P99_TARGET_MS,
            availability_target_bps: AVAILABILITY_TARGET_BPS,
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn classify_lag(total_lag: u64, config: &ScalingConfig) -> LagAlertLevel {
        if total_lag >= config.lag_scaleout_threshold {
            LagAlertLevel::Critical
        } else if total_lag > config.lag_scalein_threshold {
            LagAlertLevel::Warning
        } else {
            LagAlertLevel::Healthy
        }
    }

    fn recommend_scale(
        state: &ConsumerGroupState,
        config: &ScalingConfig,
        now: u64,
        last_scaling_at: Option<u64>,
    ) -> ScalingDecision {
        // Respect cooldown window.
        if let Some(last_at) = last_scaling_at {
            if now.saturating_sub(last_at) < config.cooldown_secs {
                return ScalingDecision::NoChange;
            }
        }

        let total_lag = state.total_lag();

        if total_lag >= config.lag_scaleout_threshold {
            // Scale out by 1 (or up to max).
            if state.active_consumers < config.max_consumers {
                return ScalingDecision::ScaleOut { delta: 1 };
            }
        } else if total_lag <= config.lag_scalein_threshold && total_lag < config.lag_scaleout_threshold {
            // Scale in by 1 (or down to min).
            if state.active_consumers > config.min_consumers {
                return ScalingDecision::ScaleIn { delta: 1 };
            }
        }

        ScalingDecision::NoChange
    }
}

// ---------------------------------------------------------------------------
// Auto-scaler state machine
// ---------------------------------------------------------------------------

/// Stateful auto-scaler that tracks per-group scaling history and enforces
/// cooldown windows, min/max bounds, and canary gates.
#[derive(Clone, Debug)]
pub struct ConsumerAutoScaler {
    config: ScalingConfig,
    /// Maps group_id → Unix timestamp of the last scaling action.
    last_scaling_at: BTreeMap<ConsumerGroupId, u64>,
}

impl ConsumerAutoScaler {
    /// Creates a new auto-scaler with the provided policy.
    pub fn new(config: ScalingConfig) -> Self {
        Self {
            config,
            last_scaling_at: BTreeMap::new(),
        }
    }

    /// Returns the current scaling configuration.
    pub fn config(&self) -> &ScalingConfig {
        &self.config
    }

    /// Evaluates a group's lag and applies a scaling decision, recording the
    /// timestamp when an action was taken.
    ///
    /// Returns the [`LagEvaluation`] for the group. If a scale event is
    /// triggered, the caller is responsible for actually adjusting the group
    /// (this module only produces the recommendation).
    pub fn recommend_scale(
        &mut self,
        state: &ConsumerGroupState,
        now: u64,
    ) -> Result<LagEvaluation, ConsumerLagError> {
        let last_at = self.last_scaling_at.get(&state.group_id).copied();
        let evaluation = ConsumerLagMonitor::evaluate_lag(state, &self.config, now, last_at);

        match evaluation.scaling_decision {
            ScalingDecision::ScaleOut { .. } | ScalingDecision::ScaleIn { .. } => {
                self.last_scaling_at.insert(state.group_id.clone(), now);
            }
            ScalingDecision::NoChange => {}
        }

        Ok(evaluation)
    }

    /// Validates a canary gate before promoting a scale-out to the full group.
    ///
    /// Returns `Ok(())` when the canary meets all release criteria.
    pub fn canary_gate(
        &self,
        canary: &ConsumerCanaryAnalysis,
    ) -> Result<(), ConsumerLagError> {
        canary.passes_release_gate()
    }

    /// Returns the timestamp of the last scaling action for `group_id`, or
    /// `None` if no action has been taken.
    pub fn last_scaling_at(&self, group_id: &str) -> Option<u64> {
        self.last_scaling_at.get(group_id).copied()
    }

    /// Resets the cooldown record for a group (e.g., after a rollback).
    pub fn reset_cooldown(&mut self, group_id: &str) {
        self.last_scaling_at.remove(group_id);
    }
}

impl Default for ConsumerAutoScaler {
    fn default() -> Self {
        Self::new(ScalingConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Multi-group registry
// ---------------------------------------------------------------------------

/// Registry that tracks the current state of all monitored consumer groups.
///
/// This is the top-level entry point for monitoring agents: register groups,
/// update their lag snapshots, and query the system-wide dashboard.
#[derive(Clone, Debug)]
pub struct ConsumerGroupRegistry {
    groups: BTreeMap<ConsumerGroupId, ConsumerGroupState>,
    scaler: ConsumerAutoScaler,
}

impl ConsumerGroupRegistry {
    /// Creates an empty registry with the provided scaling policy.
    pub fn new(config: ScalingConfig) -> Self {
        Self {
            groups: BTreeMap::new(),
            scaler: ConsumerAutoScaler::new(config),
        }
    }

    /// Registers or replaces a consumer group state.
    ///
    /// Returns `Err(TooManyGroups)` if the registry is at capacity.
    pub fn upsert_group(
        &mut self,
        state: ConsumerGroupState,
    ) -> Result<(), ConsumerLagError> {
        if !self.groups.contains_key(&state.group_id)
            && self.groups.len() >= MAX_CONSUMER_GROUPS
        {
            return Err(ConsumerLagError::TooManyGroups);
        }
        if state.partitions.len() > MAX_PARTITIONS_PER_GROUP {
            return Err(ConsumerLagError::TooManyPartitions);
        }
        self.groups.insert(state.group_id.clone(), state);
        Ok(())
    }

    /// Evaluates all registered groups at the current timestamp and returns
    /// one [`LagEvaluation`] per group.
    pub fn evaluate_all(
        &mut self,
        now: u64,
    ) -> Vec<LagEvaluation> {
        let group_ids: Vec<ConsumerGroupId> = self.groups.keys().cloned().collect();
        let mut evaluations = Vec::new();

        for id in group_ids {
            if let Some(state) = self.groups.get(&id) {
                // Clone state to avoid borrow conflict with &mut self.scaler.
                let state_clone = state.clone();
                if let Ok(eval) = self.scaler.recommend_scale(&state_clone, now) {
                    evaluations.push(eval);
                }
            }
        }

        evaluations
    }

    /// Returns a system-wide metrics snapshot.
    pub fn dashboard_snapshot(&self, now: u64) -> ConsumerLagMetrics {
        let groups: Vec<ConsumerGroupState> = self.groups.values().cloned().collect();
        ConsumerLagMonitor::dashboard_snapshot(&groups, self.scaler.config(), now)
    }

    /// Returns the current state for a specific group.
    pub fn group_state(&self, group_id: &str) -> Option<&ConsumerGroupState> {
        self.groups.get(group_id)
    }

    /// Returns a reference to the underlying auto-scaler.
    pub fn scaler(&self) -> &ConsumerAutoScaler {
        &self.scaler
    }
}

impl Default for ConsumerGroupRegistry {
    fn default() -> Self {
        Self::new(ScalingConfig::default())
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

    fn partition(topic: &str, pid: u32, committed: u64, end: u64, ts: u64) -> PartitionLag {
        PartitionLag {
            topic: topic.into(),
            partition_id: pid,
            committed_offset: committed,
            log_end_offset: end,
            sampled_at: ts,
        }
    }

    fn group(id: &str, consumers: u32, partitions: Vec<PartitionLag>, ts: u64) -> ConsumerGroupState {
        ConsumerGroupState::new(id.into(), consumers, partitions, ts)
    }

    fn default_config() -> ScalingConfig {
        ScalingConfig::default()
    }

    // -----------------------------------------------------------------------
    // PartitionLag
    // -----------------------------------------------------------------------

    #[test]
    fn partition_lag_is_saturating() {
        let p = partition("events", 0, 100, 200, 0);
        assert_eq!(p.lag(), 100);

        // Committed ahead of log-end (post-compaction): must not underflow.
        let p_ahead = partition("events", 0, 500, 200, 0);
        assert_eq!(p_ahead.lag(), 0);
    }

    // -----------------------------------------------------------------------
    // ConsumerGroupState
    // -----------------------------------------------------------------------

    #[test]
    fn group_state_aggregates_partition_lags_correctly() {
        let g = group(
            "payments",
            2,
            vec![
                partition("events", 0, 900, 1_000, 0),  // lag 100
                partition("events", 1, 800, 1_000, 0),  // lag 200
                partition("events", 2, 1_000, 1_000, 0), // lag 0
            ],
            0,
        );
        assert_eq!(g.total_lag(), 300);
        assert_eq!(g.max_partition_lag(), 200);
        assert_eq!(g.lagging_partition_count(), 2);
    }

    #[test]
    fn group_state_with_no_partitions_returns_zero_lag() {
        let g = group("empty-group", 1, vec![], 0);
        assert_eq!(g.total_lag(), 0);
        assert_eq!(g.max_partition_lag(), 0);
        assert_eq!(g.lagging_partition_count(), 0);
    }

    // -----------------------------------------------------------------------
    // ConsumerLagMonitor — alert levels
    // -----------------------------------------------------------------------

    #[test]
    fn healthy_when_lag_below_scalein_threshold() {
        let g = group("g1", 2, vec![partition("t", 0, 999_600, 1_000_000, 0)], 0); // lag = 400
        let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), 100, None);
        assert_eq!(eval.alert_level, LagAlertLevel::Healthy);
    }

    #[test]
    fn warning_when_lag_between_thresholds() {
        // lag = 5_000, between DEFAULT_LAG_SCALEIN_THRESHOLD (500) and
        // DEFAULT_LAG_SCALEOUT_THRESHOLD (10_000)
        let g = group("g2", 2, vec![partition("t", 0, 995_000, 1_000_000, 0)], 0);
        let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), 100, None);
        assert_eq!(eval.alert_level, LagAlertLevel::Warning);
    }

    #[test]
    fn critical_when_lag_meets_or_exceeds_scaleout_threshold() {
        // lag = 10_000 — exactly at the threshold → Critical
        let g = group("g3", 2, vec![partition("t", 0, 990_000, 1_000_000, 0)], 0);
        let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), 100, None);
        assert_eq!(eval.alert_level, LagAlertLevel::Critical);
    }

    // -----------------------------------------------------------------------
    // ConsumerLagMonitor — scaling decisions
    // -----------------------------------------------------------------------

    #[test]
    fn scale_out_recommended_at_critical_lag() {
        // lag = 15_000
        let g = group("g4", 2, vec![partition("t", 0, 985_000, 1_000_000, 0)], 0);
        let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), 100, None);
        assert_eq!(eval.scaling_decision, ScalingDecision::ScaleOut { delta: 1 });
    }

    #[test]
    fn scale_in_recommended_when_lag_is_at_or_below_scalein_threshold() {
        // lag = 100 — well below DEFAULT_LAG_SCALEIN_THRESHOLD
        let g = group("g5", 4, vec![partition("t", 0, 999_900, 1_000_000, 0)], 0);
        let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), 100, None);
        assert_eq!(eval.scaling_decision, ScalingDecision::ScaleIn { delta: 1 });
    }

    #[test]
    fn no_change_when_at_max_consumers_and_lag_is_critical() {
        let config = ScalingConfig {
            max_consumers: 2,
            ..default_config()
        };
        // lag = 15_000, but already at max
        let g = group("g6", 2, vec![partition("t", 0, 985_000, 1_000_000, 0)], 0);
        let eval = ConsumerLagMonitor::evaluate_lag(&g, &config, 100, None);
        assert_eq!(eval.scaling_decision, ScalingDecision::NoChange);
    }

    #[test]
    fn no_change_when_at_min_consumers_and_lag_is_low() {
        let config = ScalingConfig {
            min_consumers: 1,
            ..default_config()
        };
        // lag = 100 — below scale-in threshold, but already at min
        let g = group("g7", 1, vec![partition("t", 0, 999_900, 1_000_000, 0)], 0);
        let eval = ConsumerLagMonitor::evaluate_lag(&g, &config, 100, None);
        assert_eq!(eval.scaling_decision, ScalingDecision::NoChange);
    }

    #[test]
    fn cooldown_suppresses_scaling_decision() {
        // lag is critical but the last scale was 30s ago — within the 60s cooldown
        let g = group("g8", 2, vec![partition("t", 0, 985_000, 1_000_000, 0)], 0);
        let now = 1_000;
        let last_scaling_at = Some(now - 30); // 30 s ago, cooldown = 60 s
        let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), now, last_scaling_at);
        assert_eq!(eval.scaling_decision, ScalingDecision::NoChange);
    }

    #[test]
    fn scale_out_allowed_after_cooldown_expires() {
        let g = group("g9", 2, vec![partition("t", 0, 985_000, 1_000_000, 0)], 0);
        let now = 1_000;
        let last_scaling_at = Some(now - 61); // 61 s ago, cooldown = 60 s → elapsed
        let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), now, last_scaling_at);
        assert_eq!(eval.scaling_decision, ScalingDecision::ScaleOut { delta: 1 });
    }

    // -----------------------------------------------------------------------
    // ConsumerLagMonitor — dashboard snapshot
    // -----------------------------------------------------------------------

    #[test]
    fn dashboard_snapshot_aggregates_multiple_groups() {
        let groups = vec![
            group("ga", 2, vec![partition("t", 0, 985_000, 1_000_000, 0)], 0), // lag 15_000 → Critical
            group("gb", 2, vec![partition("t", 0, 999_900, 1_000_000, 0)], 0), // lag 100    → Healthy
            group("gc", 3, vec![partition("t", 0, 995_000, 1_000_000, 0)], 0), // lag 5_000  → Warning
        ];
        let snap = ConsumerLagMonitor::dashboard_snapshot(&groups, &default_config(), 0);

        assert_eq!(snap.groups_tracked, 3);
        assert_eq!(snap.total_lag, 20_100);
        assert_eq!(snap.max_group_lag, 15_000);
        assert_eq!(snap.unhealthy_groups, 2); // Warning + Critical
        assert_eq!(snap.critical_groups, 1);
        assert_eq!(snap.p99_target_ms, CRITICAL_PATH_P99_TARGET_MS);
        assert_eq!(snap.availability_target_bps, AVAILABILITY_TARGET_BPS);
    }

    // -----------------------------------------------------------------------
    // ConsumerCanaryAnalysis
    // -----------------------------------------------------------------------

    #[test]
    fn canary_passes_when_success_rate_and_latency_meet_gate() {
        let canary = ConsumerCanaryAnalysis {
            messages_processed: 10_000,
            successful_messages: 9_999,
            p99_latency_ms: 100,
            security_review_passed: true,
        };
        assert_eq!(canary.success_rate_bps(), 9_999);
        assert!(canary.passes_release_gate().is_ok());
    }

    #[test]
    fn canary_fails_without_security_review() {
        let canary = ConsumerCanaryAnalysis {
            messages_processed: 10_000,
            successful_messages: 10_000,
            p99_latency_ms: 50,
            security_review_passed: false,
        };
        assert_eq!(
            canary.passes_release_gate(),
            Err(ConsumerLagError::SecurityReviewRequired)
        );
    }

    #[test]
    fn canary_fails_when_latency_exceeds_p99_target() {
        let canary = ConsumerCanaryAnalysis {
            messages_processed: 10_000,
            successful_messages: 10_000,
            p99_latency_ms: 101,
            security_review_passed: true,
        };
        assert_eq!(
            canary.passes_release_gate(),
            Err(ConsumerLagError::CanaryFailed)
        );
    }

    #[test]
    fn canary_fails_when_success_rate_below_gate() {
        let canary = ConsumerCanaryAnalysis {
            messages_processed: 10_000,
            successful_messages: 9_998,
            p99_latency_ms: 50,
            security_review_passed: true,
        };
        assert_eq!(
            canary.passes_release_gate(),
            Err(ConsumerLagError::CanaryFailed)
        );
    }

    #[test]
    fn zero_messages_processed_yields_zero_success_rate() {
        let canary = ConsumerCanaryAnalysis {
            messages_processed: 0,
            successful_messages: 0,
            p99_latency_ms: 0,
            security_review_passed: true,
        };
        assert_eq!(canary.success_rate_bps(), 0);
    }

    // -----------------------------------------------------------------------
    // ConsumerAutoScaler
    // -----------------------------------------------------------------------

    #[test]
    fn auto_scaler_records_scaling_timestamp() {
        let mut scaler = ConsumerAutoScaler::new(default_config());
        let g = group("pay", 2, vec![partition("t", 0, 985_000, 1_000_000, 0)], 0);

        let eval = scaler.recommend_scale(&g, 1_000).unwrap();
        assert_eq!(eval.scaling_decision, ScalingDecision::ScaleOut { delta: 1 });
        assert_eq!(scaler.last_scaling_at("pay"), Some(1_000));
    }

    #[test]
    fn auto_scaler_enforces_cooldown_on_successive_calls() {
        let mut scaler = ConsumerAutoScaler::new(default_config());
        let g = group("pay", 2, vec![partition("t", 0, 985_000, 1_000_000, 0)], 0);

        // First call at t=1000 — should trigger scale-out.
        let e1 = scaler.recommend_scale(&g, 1_000).unwrap();
        assert_eq!(e1.scaling_decision, ScalingDecision::ScaleOut { delta: 1 });

        // Second call at t=1030 — within cooldown, should be suppressed.
        let e2 = scaler.recommend_scale(&g, 1_030).unwrap();
        assert_eq!(e2.scaling_decision, ScalingDecision::NoChange);
    }

    #[test]
    fn auto_scaler_reset_cooldown_allows_immediate_rescaling() {
        let mut scaler = ConsumerAutoScaler::new(default_config());
        let g = group("pay", 2, vec![partition("t", 0, 985_000, 1_000_000, 0)], 0);

        scaler.recommend_scale(&g, 1_000).unwrap();
        scaler.reset_cooldown("pay");
        let eval = scaler.recommend_scale(&g, 1_001).unwrap();
        assert_eq!(eval.scaling_decision, ScalingDecision::ScaleOut { delta: 1 });
    }

    #[test]
    fn canary_gate_passes_valid_analysis() {
        let scaler = ConsumerAutoScaler::default();
        let canary = ConsumerCanaryAnalysis {
            messages_processed: 5_000,
            successful_messages: 5_000,
            p99_latency_ms: 80,
            security_review_passed: true,
        };
        assert!(scaler.canary_gate(&canary).is_ok());
    }

    #[test]
    fn canary_gate_rejects_failed_analysis() {
        let scaler = ConsumerAutoScaler::default();
        let canary = ConsumerCanaryAnalysis {
            messages_processed: 5_000,
            successful_messages: 4_000,
            p99_latency_ms: 80,
            security_review_passed: true,
        };
        assert_eq!(
            scaler.canary_gate(&canary),
            Err(ConsumerLagError::CanaryFailed)
        );
    }

    // -----------------------------------------------------------------------
    // ConsumerGroupRegistry
    // -----------------------------------------------------------------------

    #[test]
    fn registry_rejects_group_exceeding_partition_limit() {
        let mut registry = ConsumerGroupRegistry::default();
        let partitions: Vec<PartitionLag> =
            (0..MAX_PARTITIONS_PER_GROUP + 1)
                .map(|i| partition("t", i as u32, 0, 100, 0))
                .collect();
        let state = group("oversized", 1, partitions, 0);
        assert_eq!(
            registry.upsert_group(state),
            Err(ConsumerLagError::TooManyPartitions)
        );
    }

    #[test]
    fn registry_evaluates_all_groups_and_returns_evaluations() {
        let mut registry = ConsumerGroupRegistry::default();

        registry
            .upsert_group(group("g1", 2, vec![partition("t", 0, 985_000, 1_000_000, 0)], 0))
            .unwrap();
        registry
            .upsert_group(group("g2", 1, vec![partition("t", 0, 999_900, 1_000_000, 0)], 0))
            .unwrap();

        let evals = registry.evaluate_all(1_000);
        assert_eq!(evals.len(), 2);
    }

    #[test]
    fn registry_dashboard_snapshot_reflects_all_groups() {
        let mut registry = ConsumerGroupRegistry::default();
        registry
            .upsert_group(group("g1", 2, vec![partition("t", 0, 985_000, 1_000_000, 0)], 0))
            .unwrap();

        let snap = registry.dashboard_snapshot(0);
        assert_eq!(snap.groups_tracked, 1);
        assert_eq!(snap.total_lag, 15_000);
        assert_eq!(snap.critical_groups, 1);
    }

    #[test]
    fn registry_upsert_replaces_existing_group() {
        let mut registry = ConsumerGroupRegistry::default();
        registry
            .upsert_group(group("g1", 2, vec![partition("t", 0, 985_000, 1_000_000, 0)], 0))
            .unwrap();
        // Replace with a healthy state.
        registry
            .upsert_group(group("g1", 2, vec![partition("t", 0, 999_900, 1_000_000, 0)], 0))
            .unwrap();

        let snap = registry.dashboard_snapshot(0);
        assert_eq!(snap.total_lag, 100);
    }

    #[test]
    fn issue_131_operational_constants_are_documented() {
        assert_eq!(CRITICAL_PATH_P99_TARGET_MS, 100);
        assert_eq!(AVAILABILITY_TARGET_BPS, 9_999);
        assert_eq!(DEFAULT_LAG_SCALEOUT_THRESHOLD, 10_000);
        assert_eq!(DEFAULT_LAG_SCALEIN_THRESHOLD, 500);
        assert_eq!(DEFAULT_MIN_CONSUMERS, 1);
        assert_eq!(DEFAULT_MAX_CONSUMERS, 32);
        assert_eq!(DEFAULT_SCALING_COOLDOWN_SECS, 60);
        assert_eq!(CANARY_SUCCESS_TARGET_BPS, 9_999);
    }
}
