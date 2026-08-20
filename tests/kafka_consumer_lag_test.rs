//! Integration tests for Kafka consumer lag monitoring and auto-scaling
//! consumer groups (issue #131).

use sorosusu_contracts::kafka_consumer::{
    ConsumerAutoScaler, ConsumerCanaryAnalysis, ConsumerGroupRegistry, ConsumerGroupState,
    ConsumerLagError, ConsumerLagMonitor, LagAlertLevel, PartitionLag, ScalingConfig,
    ScalingDecision, AVAILABILITY_TARGET_BPS, CANARY_SUCCESS_TARGET_BPS,
    CRITICAL_PATH_P99_TARGET_MS, DEFAULT_LAG_SCALEIN_THRESHOLD, DEFAULT_LAG_SCALEOUT_THRESHOLD,
    DEFAULT_MAX_CONSUMERS, DEFAULT_MIN_CONSUMERS, DEFAULT_SCALING_COOLDOWN_SECS,
    MAX_PARTITIONS_PER_GROUP,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn partition(topic: &str, pid: u32, committed: u64, end: u64) -> PartitionLag {
    PartitionLag {
        topic: topic.into(),
        partition_id: pid,
        committed_offset: committed,
        log_end_offset: end,
        sampled_at: 0,
    }
}

fn group(id: &str, consumers: u32, partitions: Vec<PartitionLag>) -> ConsumerGroupState {
    ConsumerGroupState::new(id.into(), consumers, partitions, 0)
}

fn default_config() -> ScalingConfig {
    ScalingConfig::default()
}

// ---------------------------------------------------------------------------
// Partition lag
// ---------------------------------------------------------------------------

#[test]
fn partition_lag_returns_unconsumed_messages() {
    let p = partition("orders", 0, 5_000, 6_000);
    assert_eq!(p.lag(), 1_000);
}

#[test]
fn partition_lag_saturates_at_zero_when_committed_exceeds_end() {
    // After log compaction the committed offset may be > log-end offset.
    let p = partition("orders", 0, 6_000, 5_000);
    assert_eq!(p.lag(), 0, "must not underflow to u64::MAX");
}

// ---------------------------------------------------------------------------
// ConsumerGroupState aggregates
// ---------------------------------------------------------------------------

#[test]
fn group_state_computes_total_lag_as_sum_of_partitions() {
    let g = group(
        "payments",
        3,
        vec![
            partition("t", 0, 900, 1_000), // 100
            partition("t", 1, 700, 1_000), // 300
            partition("t", 2, 500, 1_000), // 500
        ],
    );
    assert_eq!(g.total_lag(), 900);
    assert_eq!(g.max_partition_lag(), 500);
    assert_eq!(g.lagging_partition_count(), 3);
}

#[test]
fn group_state_with_fully_caught_up_partitions_reports_zero_lag() {
    let g = group(
        "fully-caught-up",
        2,
        vec![
            partition("t", 0, 1_000, 1_000),
            partition("t", 1, 2_000, 2_000),
        ],
    );
    assert_eq!(g.total_lag(), 0);
    assert_eq!(g.lagging_partition_count(), 0);
}

// ---------------------------------------------------------------------------
// ConsumerLagMonitor — alert level classification
// ---------------------------------------------------------------------------

#[test]
fn monitor_classifies_healthy_when_lag_below_scalein_threshold() {
    // Lag of 200 is below DEFAULT_LAG_SCALEIN_THRESHOLD (500).
    let g = group("g", 2, vec![partition("t", 0, 999_800, 1_000_000)]);
    let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), 0, None);
    assert_eq!(eval.alert_level, LagAlertLevel::Healthy);
    assert_eq!(eval.total_lag, 200);
}

#[test]
fn monitor_classifies_warning_between_thresholds() {
    // Lag = 5_000, between scale-in (500) and scale-out (10_000).
    let g = group("g", 2, vec![partition("t", 0, 995_000, 1_000_000)]);
    let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), 0, None);
    assert_eq!(eval.alert_level, LagAlertLevel::Warning);
}

#[test]
fn monitor_classifies_critical_at_scaleout_threshold() {
    // Lag = 10_000 — exactly at DEFAULT_LAG_SCALEOUT_THRESHOLD.
    let g = group("g", 2, vec![partition("t", 0, 990_000, 1_000_000)]);
    let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), 0, None);
    assert_eq!(eval.alert_level, LagAlertLevel::Critical);
}

#[test]
fn monitor_classifies_critical_above_scaleout_threshold() {
    let g = group("g", 2, vec![partition("t", 0, 980_000, 1_000_000)]);
    let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), 0, None);
    assert_eq!(eval.alert_level, LagAlertLevel::Critical);
}

// ---------------------------------------------------------------------------
// ConsumerLagMonitor — scaling decisions
// ---------------------------------------------------------------------------

#[test]
fn monitor_recommends_scale_out_when_lag_critical() {
    let g = group("g", 4, vec![partition("t", 0, 980_000, 1_000_000)]);
    let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), 0, None);
    assert_eq!(
        eval.scaling_decision,
        ScalingDecision::ScaleOut { delta: 1 }
    );
}

#[test]
fn monitor_recommends_scale_in_when_lag_below_scalein_threshold() {
    let g = group("g", 4, vec![partition("t", 0, 999_900, 1_000_000)]); // lag=100
    let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), 0, None);
    assert_eq!(eval.scaling_decision, ScalingDecision::ScaleIn { delta: 1 });
}

#[test]
fn monitor_no_change_when_lag_is_in_warning_zone() {
    // Lag = 5_000 is Warning but doesn't trigger scale-out or scale-in.
    let g = group("g", 4, vec![partition("t", 0, 995_000, 1_000_000)]);
    let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), 0, None);
    assert_eq!(eval.scaling_decision, ScalingDecision::NoChange);
}

#[test]
fn monitor_no_change_at_max_consumers_despite_critical_lag() {
    let config = ScalingConfig {
        max_consumers: 4,
        ..default_config()
    };
    let g = group("g", 4, vec![partition("t", 0, 980_000, 1_000_000)]);
    let eval = ConsumerLagMonitor::evaluate_lag(&g, &config, 0, None);
    assert_eq!(eval.scaling_decision, ScalingDecision::NoChange);
}

#[test]
fn monitor_no_change_at_min_consumers_despite_low_lag() {
    let config = ScalingConfig {
        min_consumers: 2,
        ..default_config()
    };
    let g = group("g", 2, vec![partition("t", 0, 999_900, 1_000_000)]); // lag=100
    let eval = ConsumerLagMonitor::evaluate_lag(&g, &config, 0, None);
    assert_eq!(eval.scaling_decision, ScalingDecision::NoChange);
}

#[test]
fn monitor_suppresses_scaling_within_cooldown_window() {
    let g = group("g", 2, vec![partition("t", 0, 980_000, 1_000_000)]);
    let now = 2_000u64;
    let last_at = Some(now - 30); // 30 s ago, cooldown = 60 s
    let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), now, last_at);
    assert_eq!(eval.scaling_decision, ScalingDecision::NoChange);
}

#[test]
fn monitor_allows_scaling_after_cooldown_expires() {
    let g = group("g", 2, vec![partition("t", 0, 980_000, 1_000_000)]);
    let now = 2_000u64;
    let last_at = Some(now - 61); // 61 s ago — cooldown elapsed
    let eval = ConsumerLagMonitor::evaluate_lag(&g, &default_config(), now, last_at);
    assert_eq!(
        eval.scaling_decision,
        ScalingDecision::ScaleOut { delta: 1 }
    );
}

// ---------------------------------------------------------------------------
// ConsumerLagMonitor — dashboard snapshot
// ---------------------------------------------------------------------------

#[test]
fn dashboard_snapshot_counts_groups_and_aggregates_lag() {
    let groups = vec![
        group("a", 2, vec![partition("t", 0, 980_000, 1_000_000)]), // lag 20_000 → Critical
        group("b", 1, vec![partition("t", 0, 999_900, 1_000_000)]), // lag 100    → Healthy
        group("c", 3, vec![partition("t", 0, 995_000, 1_000_000)]), // lag 5_000  → Warning
    ];
    let snap = ConsumerLagMonitor::dashboard_snapshot(&groups, &default_config(), 0);

    assert_eq!(snap.groups_tracked, 3);
    assert_eq!(snap.total_lag, 25_100);
    assert_eq!(snap.max_group_lag, 20_000);
    assert_eq!(snap.unhealthy_groups, 2); // Warning + Critical
    assert_eq!(snap.critical_groups, 1);
    assert_eq!(snap.p99_target_ms, CRITICAL_PATH_P99_TARGET_MS);
    assert_eq!(snap.availability_target_bps, AVAILABILITY_TARGET_BPS);
}

#[test]
fn dashboard_snapshot_empty_groups_returns_zeroed_metrics() {
    let snap = ConsumerLagMonitor::dashboard_snapshot(&[], &default_config(), 0);
    assert_eq!(snap.groups_tracked, 0);
    assert_eq!(snap.total_lag, 0);
    assert_eq!(snap.max_group_lag, 0);
    assert_eq!(snap.unhealthy_groups, 0);
    assert_eq!(snap.critical_groups, 0);
}

// ---------------------------------------------------------------------------
// ConsumerCanaryAnalysis
// ---------------------------------------------------------------------------

#[test]
fn canary_success_rate_is_accurate_in_basis_points() {
    let canary = ConsumerCanaryAnalysis {
        messages_processed: 10_000,
        successful_messages: 9_999,
        p99_latency_ms: 80,
        security_review_passed: true,
    };
    assert_eq!(canary.success_rate_bps(), 9_999);
    assert!(canary.passes_release_gate().is_ok());
}

#[test]
fn canary_fails_release_gate_without_security_review() {
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
fn canary_fails_release_gate_when_latency_exceeds_p99_target() {
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
fn canary_fails_release_gate_when_success_rate_too_low() {
    let canary = ConsumerCanaryAnalysis {
        messages_processed: 10_000,
        successful_messages: 9_990,
        p99_latency_ms: 50,
        security_review_passed: true,
    };
    assert_eq!(
        canary.passes_release_gate(),
        Err(ConsumerLagError::CanaryFailed)
    );
}

#[test]
fn canary_with_no_messages_processed_yields_zero_success_rate() {
    let canary = ConsumerCanaryAnalysis {
        messages_processed: 0,
        successful_messages: 0,
        p99_latency_ms: 0,
        security_review_passed: true,
    };
    assert_eq!(canary.success_rate_bps(), 0);
}

// ---------------------------------------------------------------------------
// ConsumerAutoScaler
// ---------------------------------------------------------------------------

#[test]
fn auto_scaler_records_timestamp_after_scale_out() {
    let mut scaler = ConsumerAutoScaler::new(default_config());
    let g = group("pay", 2, vec![partition("t", 0, 980_000, 1_000_000)]);

    let eval = scaler.recommend_scale(&g, 1_000).unwrap();
    assert_eq!(
        eval.scaling_decision,
        ScalingDecision::ScaleOut { delta: 1 }
    );
    assert_eq!(scaler.last_scaling_at("pay"), Some(1_000));
}

#[test]
fn auto_scaler_enforces_cooldown_on_consecutive_calls() {
    let mut scaler = ConsumerAutoScaler::new(default_config());
    let g = group("pay", 2, vec![partition("t", 0, 980_000, 1_000_000)]);

    // t=1000 → triggers scale-out.
    let e1 = scaler.recommend_scale(&g, 1_000).unwrap();
    assert_eq!(e1.scaling_decision, ScalingDecision::ScaleOut { delta: 1 });

    // t=1040 → 40 s < 60 s cooldown → suppressed.
    let e2 = scaler.recommend_scale(&g, 1_040).unwrap();
    assert_eq!(e2.scaling_decision, ScalingDecision::NoChange);
}

#[test]
fn auto_scaler_no_change_when_at_max_consumers() {
    let config = ScalingConfig {
        max_consumers: 2,
        ..default_config()
    };
    let mut scaler = ConsumerAutoScaler::new(config);
    let g = group("pay", 2, vec![partition("t", 0, 980_000, 1_000_000)]);

    let eval = scaler.recommend_scale(&g, 0).unwrap();
    assert_eq!(eval.scaling_decision, ScalingDecision::NoChange);
}

#[test]
fn auto_scaler_reset_cooldown_allows_immediate_subsequent_scale() {
    let mut scaler = ConsumerAutoScaler::new(default_config());
    let g = group("pay", 2, vec![partition("t", 0, 980_000, 1_000_000)]);

    scaler.recommend_scale(&g, 1_000).unwrap();
    scaler.reset_cooldown("pay");

    let eval = scaler.recommend_scale(&g, 1_001).unwrap();
    assert_eq!(
        eval.scaling_decision,
        ScalingDecision::ScaleOut { delta: 1 }
    );
}

#[test]
fn auto_scaler_canary_gate_accepts_valid_analysis() {
    let scaler = ConsumerAutoScaler::default();
    let canary = ConsumerCanaryAnalysis {
        messages_processed: 5_000,
        successful_messages: 5_000,
        p99_latency_ms: 90,
        security_review_passed: true,
    };
    assert!(scaler.canary_gate(&canary).is_ok());
}

#[test]
fn auto_scaler_canary_gate_rejects_low_success_rate() {
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

// ---------------------------------------------------------------------------
// ConsumerGroupRegistry
// ---------------------------------------------------------------------------

#[test]
fn registry_rejects_group_exceeding_partition_limit() {
    let mut registry = ConsumerGroupRegistry::default();
    let partitions: Vec<PartitionLag> = (0..MAX_PARTITIONS_PER_GROUP + 1)
        .map(|i| partition("t", i as u32, 0, 100))
        .collect();
    let state = ConsumerGroupState::new("oversized".into(), 1, partitions, 0);
    assert_eq!(
        registry.upsert_group(state),
        Err(ConsumerLagError::TooManyPartitions)
    );
}

#[test]
fn registry_evaluates_all_groups_and_returns_one_evaluation_per_group() {
    let mut registry = ConsumerGroupRegistry::default();
    registry
        .upsert_group(group("g1", 2, vec![partition("t", 0, 980_000, 1_000_000)]))
        .unwrap();
    registry
        .upsert_group(group("g2", 1, vec![partition("t", 0, 999_900, 1_000_000)]))
        .unwrap();

    let evals = registry.evaluate_all(1_000);
    assert_eq!(evals.len(), 2);
}

#[test]
fn registry_dashboard_snapshot_reflects_registered_groups() {
    let mut registry = ConsumerGroupRegistry::default();
    registry
        .upsert_group(group("g1", 2, vec![partition("t", 0, 980_000, 1_000_000)]))
        .unwrap();

    let snap = registry.dashboard_snapshot(0);
    assert_eq!(snap.groups_tracked, 1);
    assert_eq!(snap.total_lag, 20_000);
    assert_eq!(snap.critical_groups, 1);
}

#[test]
fn registry_upsert_replaces_existing_group_state() {
    let mut registry = ConsumerGroupRegistry::default();
    registry
        .upsert_group(group("g1", 2, vec![partition("t", 0, 980_000, 1_000_000)]))
        .unwrap();
    // Replace with a healthy state.
    registry
        .upsert_group(group("g1", 2, vec![partition("t", 0, 999_900, 1_000_000)]))
        .unwrap();

    let snap = registry.dashboard_snapshot(0);
    assert_eq!(snap.total_lag, 100);
    assert_eq!(snap.critical_groups, 0);
}

#[test]
fn registry_group_state_returns_none_for_unknown_group() {
    let registry = ConsumerGroupRegistry::default();
    assert!(registry.group_state("nonexistent").is_none());
}

// ---------------------------------------------------------------------------
// Issue #131 operational constants
// ---------------------------------------------------------------------------

#[test]
fn issue_131_constants_match_technical_bounds() {
    assert_eq!(
        CRITICAL_PATH_P99_TARGET_MS, 100,
        "P99 critical-path target must be < 100 ms"
    );
    assert_eq!(
        AVAILABILITY_TARGET_BPS, 9_999,
        "availability target must be 99.99%"
    );
    assert_eq!(DEFAULT_LAG_SCALEOUT_THRESHOLD, 10_000);
    assert_eq!(DEFAULT_LAG_SCALEIN_THRESHOLD, 500);
    assert_eq!(DEFAULT_MIN_CONSUMERS, 1);
    assert_eq!(DEFAULT_MAX_CONSUMERS, 32);
    assert_eq!(DEFAULT_SCALING_COOLDOWN_SECS, 60);
    assert_eq!(CANARY_SUCCESS_TARGET_BPS, 9_999);
}
