//! Integration tests for the PostgreSQL connection-pool health probe with
//! adaptive sizing (issue #134).
//!
//! These tests verify:
//! * Technical invariants: P99 target, availability target, and all default
//!   thresholds match the bounds stated in the issue.
//! * Health-state transitions: Healthy → Warning → Degraded → Unavailable.
//! * Adaptive sizing: expansion on saturation, shrink on under-utilisation,
//!   no-change in the warning zone, and cooldown enforcement.
//! * Canary gate: success-rate gate, P99 latency gate, security-review gate.
//! * Registry: upsert, probe-all, dashboard aggregation, and capacity limits.

use sorosusu_contracts::pg_pool::{
    ConnectionPoolRegistry, ConnectionPoolState, PoolAdaptiveSizer, PoolCanaryAnalysis,
    PoolHealthProbe, PoolHealthState, PoolProbeError, PoolSizingConfig, ResizeDecision,
    AVAILABILITY_TARGET_BPS, CANARY_SUCCESS_TARGET_BPS, CRITICAL_PATH_P99_MS,
    DEFAULT_MAX_POOL_SIZE, DEFAULT_MIN_POOL_SIZE, DEFAULT_RESIZE_COOLDOWN_SECS,
    DEFAULT_SATURATION_THRESHOLD_BPS, DEFAULT_UNDERUTILISATION_THRESHOLD_BPS,
    DEGRADED_PROBE_THRESHOLD, MAX_SERVICE_POOLS, RECOVERY_PROBE_THRESHOLD,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pool_state(
    service: &str,
    pool_size: u32,
    active: u32,
    idle: u32,
    pending: u32,
    p99_ms: u64,
) -> ConnectionPoolState {
    ConnectionPoolState {
        service: service.into(),
        pool_size,
        active_connections: active,
        idle_connections: idle,
        pending_requests: pending,
        p99_acquire_ms: p99_ms,
        sampled_at: 0,
    }
}

fn default_config() -> PoolSizingConfig {
    PoolSizingConfig::default()
}

// ---------------------------------------------------------------------------
// Issue #134 technical invariants
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ConnectionPoolState helpers
// ---------------------------------------------------------------------------

#[test]
fn utilisation_bps_computes_correctly() {
    let s = pool_state("svc", 100, 90, 10, 0, 10);
    assert_eq!(s.utilisation_bps(), 9_000);
}

#[test]
fn utilisation_bps_zero_for_empty_pool() {
    let s = pool_state("svc", 0, 0, 0, 0, 0);
    assert_eq!(s.utilisation_bps(), 0);
}

#[test]
fn utilisation_bps_caps_at_ten_thousand_when_over_committed() {
    let s = pool_state("svc", 10, 20, 0, 0, 0);
    assert_eq!(s.utilisation_bps(), 10_000);
}

#[test]
fn has_pending_requests_true_when_queue_depth_nonzero() {
    let s = pool_state("svc", 100, 100, 0, 1, 0);
    assert!(s.has_pending_requests());
}

#[test]
fn has_pending_requests_false_when_queue_is_empty() {
    let s = pool_state("svc", 100, 50, 50, 0, 0);
    assert!(!s.has_pending_requests());
}

#[test]
fn total_connections_is_active_plus_idle() {
    let s = pool_state("svc", 100, 60, 35, 0, 0);
    assert_eq!(s.total_connections(), 95);
}

// ---------------------------------------------------------------------------
// PoolHealthProbe — health state classification
// ---------------------------------------------------------------------------

#[test]
fn probe_healthy_under_normal_load() {
    // 50% utilisation, no pending, P99 well within target.
    let s = pool_state("auth", 100, 50, 50, 0, 40);
    let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
    assert_eq!(report.health_state, PoolHealthState::Healthy);
}

#[test]
fn probe_warning_at_saturation_threshold() {
    // 9_000 bps == DEFAULT_SATURATION_THRESHOLD_BPS
    let s = pool_state("auth", 100, 90, 10, 0, 40);
    let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
    assert_eq!(report.health_state, PoolHealthState::Warning);
}

#[test]
fn probe_warning_above_saturation_threshold() {
    let s = pool_state("auth", 100, 95, 5, 0, 40);
    let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
    assert_eq!(report.health_state, PoolHealthState::Warning);
}

#[test]
fn probe_warning_when_requests_are_queued() {
    let s = pool_state("auth", 100, 40, 60, 2, 40);
    let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
    assert_eq!(report.health_state, PoolHealthState::Warning);
}

#[test]
fn probe_warning_when_p99_latency_exceeds_100ms() {
    let s = pool_state("auth", 100, 20, 80, 0, 101);
    let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
    assert_eq!(report.health_state, PoolHealthState::Warning);
}

#[test]
fn probe_healthy_when_p99_exactly_at_target() {
    let s = pool_state("auth", 100, 20, 80, 0, 100);
    let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
    assert_eq!(report.health_state, PoolHealthState::Healthy);
}

#[test]
fn probe_degraded_after_threshold_consecutive_unhealthy_probes() {
    let s = pool_state("auth", 100, 90, 10, 0, 40);
    let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, DEGRADED_PROBE_THRESHOLD);
    assert_eq!(report.health_state, PoolHealthState::Degraded);
}

#[test]
fn probe_unavailable_when_pool_has_no_connections_configured() {
    let s = pool_state("auth", 0, 0, 0, 0, 0);
    let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
    assert_eq!(report.health_state, PoolHealthState::Unavailable);
}

// ---------------------------------------------------------------------------
// PoolHealthProbe — resize decisions
// ---------------------------------------------------------------------------

#[test]
fn probe_recommends_expand_when_saturated() {
    let s = pool_state("svc", 100, 90, 10, 0, 40);
    let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
    assert_eq!(report.resize_decision, ResizeDecision::Expand { delta: 1 });
}

#[test]
fn probe_recommends_expand_when_latency_over_target() {
    let s = pool_state("svc", 100, 20, 80, 0, 150);
    let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
    assert_eq!(report.resize_decision, ResizeDecision::Expand { delta: 1 });
}

#[test]
fn probe_recommends_expand_when_pending_requests_queued() {
    let s = pool_state("svc", 100, 50, 50, 3, 40);
    let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
    assert_eq!(report.resize_decision, ResizeDecision::Expand { delta: 1 });
}

#[test]
fn probe_no_expand_when_already_at_configured_max() {
    let config = PoolSizingConfig {
        max_pool_size: 100,
        ..default_config()
    };
    let s = pool_state("svc", 100, 90, 10, 0, 40);
    let report = PoolHealthProbe::probe(&s, &config, 0, None, 0);
    assert_eq!(report.resize_decision, ResizeDecision::NoChange);
}

#[test]
fn probe_recommends_shrink_when_underutilised() {
    // 10% utilisation < 30% under-utilisation threshold
    let s = pool_state("svc", 100, 10, 80, 0, 40);
    let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
    assert_eq!(report.resize_decision, ResizeDecision::Shrink { delta: 1 });
}

#[test]
fn probe_no_shrink_when_already_at_configured_min() {
    let config = PoolSizingConfig {
        min_pool_size: 100,
        ..default_config()
    };
    let s = pool_state("svc", 100, 10, 80, 0, 40);
    let report = PoolHealthProbe::probe(&s, &config, 0, None, 0);
    assert_eq!(report.resize_decision, ResizeDecision::NoChange);
}

#[test]
fn probe_no_change_in_healthy_mid_range_utilisation() {
    // 60% utilisation — above under-utilisation (30%) but below saturation (90%)
    let s = pool_state("svc", 100, 60, 40, 0, 40);
    let report = PoolHealthProbe::probe(&s, &default_config(), 0, None, 0);
    assert_eq!(report.resize_decision, ResizeDecision::NoChange);
}

#[test]
fn probe_cooldown_suppresses_resize_within_window() {
    let now = 500u64;
    let last_at = Some(now - 20); // 20 s ago < 30 s cooldown
    let s = pool_state("svc", 100, 90, 10, 0, 40);
    let report = PoolHealthProbe::probe(&s, &default_config(), now, last_at, 0);
    assert_eq!(report.resize_decision, ResizeDecision::NoChange);
}

#[test]
fn probe_allows_resize_after_cooldown_expires() {
    let now = 500u64;
    let last_at = Some(now - 31); // 31 s ago — cooldown elapsed
    let s = pool_state("svc", 100, 90, 10, 0, 40);
    let report = PoolHealthProbe::probe(&s, &default_config(), now, last_at, 0);
    assert_eq!(report.resize_decision, ResizeDecision::Expand { delta: 1 });
}

// ---------------------------------------------------------------------------
// PoolHealthProbe — dashboard snapshot
// ---------------------------------------------------------------------------

#[test]
fn dashboard_snapshot_counts_pools_and_aggregates_metrics() {
    let states = vec![
        pool_state("a", 100, 90, 10, 0, 40), // saturated → Warning
        pool_state("b", 100, 10, 80, 0, 40), // low util  → Healthy (shrink candidate)
        pool_state("c", 100, 60, 40, 2, 40), // pending   → Warning
    ];
    let snap = PoolHealthProbe::dashboard_snapshot(&states, &default_config(), 0);

    assert_eq!(snap.pools_tracked, 3);
    assert_eq!(snap.total_active_connections, 160);
    assert_eq!(snap.max_pool_utilisation_bps, 9_000);
    assert_eq!(snap.unhealthy_pools, 2); // a and c
    assert_eq!(snap.critical_pools, 0);
    assert_eq!(snap.p99_target_ms, CRITICAL_PATH_P99_MS);
    assert_eq!(snap.availability_target_bps, AVAILABILITY_TARGET_BPS);
}

#[test]
fn dashboard_snapshot_empty_returns_zeroed_metrics() {
    let snap = PoolHealthProbe::dashboard_snapshot(&[], &default_config(), 0);
    assert_eq!(snap.pools_tracked, 0);
    assert_eq!(snap.total_active_connections, 0);
    assert_eq!(snap.unhealthy_pools, 0);
    assert_eq!(snap.critical_pools, 0);
}

#[test]
fn dashboard_snapshot_counts_unavailable_pool_as_critical() {
    let states = vec![pool_state("gone", 0, 0, 0, 0, 0)];
    let snap = PoolHealthProbe::dashboard_snapshot(&states, &default_config(), 0);
    assert_eq!(snap.critical_pools, 1);
    assert_eq!(snap.unhealthy_pools, 1);
}

// ---------------------------------------------------------------------------
// PoolCanaryAnalysis
// ---------------------------------------------------------------------------

#[test]
fn canary_computes_success_rate_in_basis_points() {
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
fn canary_yields_zero_rate_when_no_acquisitions() {
    let canary = PoolCanaryAnalysis {
        acquisitions_attempted: 0,
        acquisitions_succeeded: 0,
        p99_acquire_ms: 0,
        security_review_passed: true,
    };
    assert_eq!(canary.success_rate_bps(), 0);
}

#[test]
fn canary_gate_fails_without_security_review() {
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
fn canary_gate_fails_when_p99_exceeds_target() {
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
fn canary_gate_fails_when_success_rate_below_threshold() {
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
fn canary_gate_passes_at_boundary_conditions() {
    // Exactly 9_999 / 10_000 acquisitions succeeded and P99 == 100 ms.
    let canary = PoolCanaryAnalysis {
        acquisitions_attempted: 10_000,
        acquisitions_succeeded: 9_999,
        p99_acquire_ms: 100,
        security_review_passed: true,
    };
    assert!(canary.passes_release_gate().is_ok());
}

// ---------------------------------------------------------------------------
// PoolAdaptiveSizer
// ---------------------------------------------------------------------------

#[test]
fn sizer_records_resize_timestamp_after_expand() {
    let mut sizer = PoolAdaptiveSizer::new(default_config());
    let s = pool_state("pay", 100, 90, 10, 0, 40);
    let report = sizer.recommend_resize(&s, 2_000);

    assert_eq!(report.resize_decision, ResizeDecision::Expand { delta: 1 });
    assert_eq!(sizer.last_resize_at("pay"), Some(2_000));
}

#[test]
fn sizer_enforces_cooldown_between_consecutive_resizes() {
    let mut sizer = PoolAdaptiveSizer::new(default_config());
    let s = pool_state("pay", 100, 90, 10, 0, 40);

    let r1 = sizer.recommend_resize(&s, 1_000);
    assert_eq!(r1.resize_decision, ResizeDecision::Expand { delta: 1 });

    // 29 s later — cooldown not yet elapsed.
    let r2 = sizer.recommend_resize(&s, 1_029);
    assert_eq!(r2.resize_decision, ResizeDecision::NoChange);
}

#[test]
fn sizer_allows_resize_after_cooldown_expires() {
    let mut sizer = PoolAdaptiveSizer::new(default_config());
    let s = pool_state("pay", 100, 90, 10, 0, 40);

    sizer.recommend_resize(&s, 1_000);
    let r = sizer.recommend_resize(&s, 1_031); // 31 s later
    assert_eq!(r.resize_decision, ResizeDecision::Expand { delta: 1 });
}

#[test]
fn sizer_reset_cooldown_enables_immediate_resize() {
    let mut sizer = PoolAdaptiveSizer::new(default_config());
    let s = pool_state("pay", 100, 90, 10, 0, 40);

    sizer.recommend_resize(&s, 1_000);
    sizer.reset_cooldown("pay");

    let r = sizer.recommend_resize(&s, 1_001);
    assert_eq!(r.resize_decision, ResizeDecision::Expand { delta: 1 });
}

#[test]
fn sizer_accumulates_consecutive_unhealthy_count() {
    let mut sizer = PoolAdaptiveSizer::new(default_config());
    // Saturated pool → Warning every probe.
    let s = pool_state("svc", 100, 90, 10, 0, 40);

    for i in 0..DEGRADED_PROBE_THRESHOLD {
        sizer.recommend_resize(&s, i as u64 * 100);
    }
    assert_eq!(sizer.consecutive_unhealthy("svc"), DEGRADED_PROBE_THRESHOLD);
}

#[test]
fn sizer_reset_health_counters_clears_unhealthy_state() {
    let mut sizer = PoolAdaptiveSizer::new(default_config());
    let s = pool_state("svc", 100, 90, 10, 0, 40);

    for i in 0..DEGRADED_PROBE_THRESHOLD + 1 {
        sizer.recommend_resize(&s, i as u64 * 100);
    }
    sizer.reset_health_counters("svc");
    assert_eq!(sizer.consecutive_unhealthy("svc"), 0);
}

#[test]
fn sizer_canary_gate_accepts_passing_analysis() {
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

// ---------------------------------------------------------------------------
// ConnectionPoolRegistry
// ---------------------------------------------------------------------------

#[test]
fn registry_upserts_pool_and_probes_it() {
    let mut registry = ConnectionPoolRegistry::default();
    registry
        .upsert_pool(pool_state("payments", 50, 45, 5, 0, 40))
        .unwrap();

    let reports = registry.probe_all(0);
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].service, "payments");
}

#[test]
fn registry_upsert_replaces_existing_pool() {
    let mut registry = ConnectionPoolRegistry::default();
    registry
        .upsert_pool(pool_state("api", 100, 90, 10, 0, 40))
        .unwrap();
    // Replace with a healthy, low-utilisation snapshot.
    registry
        .upsert_pool(pool_state("api", 100, 5, 90, 0, 40))
        .unwrap();

    let snap = registry.dashboard_snapshot(0);
    assert_eq!(snap.total_active_connections, 5);
    assert_eq!(snap.critical_pools, 0);
}

#[test]
fn registry_dashboard_aggregates_all_pools() {
    let mut registry = ConnectionPoolRegistry::default();
    registry
        .upsert_pool(pool_state("svc1", 100, 90, 10, 0, 40))
        .unwrap();
    registry
        .upsert_pool(pool_state("svc2", 50, 5, 40, 0, 40))
        .unwrap();

    let snap = registry.dashboard_snapshot(0);
    assert_eq!(snap.pools_tracked, 2);
    assert_eq!(snap.total_active_connections, 95);
}

#[test]
fn registry_pool_state_returns_none_for_unregistered_service() {
    let registry = ConnectionPoolRegistry::default();
    assert!(registry.pool_state("ghost").is_none());
}

#[test]
fn registry_probe_all_returns_one_report_per_registered_pool() {
    let mut registry = ConnectionPoolRegistry::default();
    for i in 0..5u32 {
        registry
            .upsert_pool(pool_state(&alloc::format!("svc{i}"), 100, 50, 50, 0, 40))
            .unwrap();
    }
    let reports = registry.probe_all(0);
    assert_eq!(reports.len(), 5);
}

#[test]
fn registry_rejects_new_pool_when_at_capacity() {
    let mut registry = ConnectionPoolRegistry::new(default_config());
    // Fill the registry to capacity.
    for i in 0..MAX_SERVICE_POOLS {
        registry
            .upsert_pool(pool_state(&alloc::format!("svc{i}"), 10, 5, 5, 0, 40))
            .unwrap();
    }
    // One more new service must be rejected.
    let result = registry.upsert_pool(pool_state("overflow", 10, 5, 5, 0, 40));
    assert_eq!(result, Err(PoolProbeError::TooManyPools));
}

// Module-level use for alloc::format in the test above.
extern crate alloc;
