//! Integration tests for Capacity Planning with Historical Usage Trending (issue #127).
//!
//! Verifies:
//! * Issue #127 technical bounds: P99 < 100 ms, 99.99% availability, security review.
//! * Telemetry & ring buffer behavior under high throughput.
//! * Linear regression slope, R-squared, and Holt-Winters forecasting.
//! * Capacity runway estimation (warning, critical, exhaustion).
//! * Health state transitions: Healthy → Warning → Critical → Exhausted.
//! * Automated sizing recommendations, headroom targets, and reaction cooldown.
//! * Blue-green deployment canary release gates and rejection modes.
//! * Multi-service registry coordination and system-wide dashboard aggregation.

use sorosusu_contracts::capacity_planning::{
    CapacityAction, CapacityCanaryAnalysis, CapacityError, CapacityForecaster, CapacityHealthState,
    CapacityPlanningConfig, CapacityPlanningRegistry, HistoricalUsageBuffer, ResourceMetrics,
    ServiceCapacityState, UsageSample, AVAILABILITY_TARGET_BPS, CANARY_SUCCESS_TARGET_BPS,
    CRITICAL_PATH_P99_MS, DEFAULT_CRITICAL_THRESHOLD_BPS, DEFAULT_EXHAUSTION_THRESHOLD_BPS,
    DEFAULT_MAX_ALLOCATED_UNITS, DEFAULT_MIN_ALLOCATED_UNITS, DEFAULT_REACTION_COOLDOWN_SECS,
    DEFAULT_TARGET_HEADROOM_BPS, DEFAULT_WARNING_THRESHOLD_BPS, MAX_TRACKED_SERVICES,
    MIN_SAMPLES_FOR_TREND,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample(
    ts: u64,
    cpu: u32,
    mem: u32,
    iops: u32,
    net: u32,
    worker: u32,
    p99_ms: u64,
    units: u32,
) -> UsageSample {
    UsageSample::new(
        ts,
        ResourceMetrics::new(cpu, mem, iops, net, worker),
        p99_ms,
        units,
        5_000,
        0,
    )
}

fn uniform_sample(ts: u64, sat_bps: u32, p99_ms: u64, units: u32) -> UsageSample {
    sample(
        ts, sat_bps, sat_bps, sat_bps, sat_bps, sat_bps, p99_ms, units,
    )
}

// ---------------------------------------------------------------------------
// 1. Issue #127 technical bounds & invariants
// ---------------------------------------------------------------------------

#[test]
fn test_technical_bounds_match_issue_specification() {
    assert_eq!(
        CRITICAL_PATH_P99_MS, 100,
        "Critical-path P99 latency target must be < 100ms"
    );
    assert_eq!(
        AVAILABILITY_TARGET_BPS, 9_999,
        "Availability target must be 99.99% (9_999 bps)"
    );
    assert_eq!(
        CANARY_SUCCESS_TARGET_BPS, 9_999,
        "Canary promotion requires 99.99% success rate"
    );
    assert_eq!(
        DEFAULT_WARNING_THRESHOLD_BPS, 8_000,
        "Warning threshold must be 80.00%"
    );
    assert_eq!(
        DEFAULT_CRITICAL_THRESHOLD_BPS, 9_000,
        "Critical threshold must be 90.00%"
    );
    assert_eq!(
        DEFAULT_EXHAUSTION_THRESHOLD_BPS, 10_000,
        "Exhaustion threshold must be 100.00%"
    );
    assert_eq!(
        DEFAULT_REACTION_COOLDOWN_SECS, 30,
        "Minimum scaling cooldown must be 30 seconds"
    );
    assert_eq!(
        DEFAULT_MIN_ALLOCATED_UNITS, 1,
        "Minimum units allocated is 1"
    );
    assert_eq!(
        DEFAULT_MAX_ALLOCATED_UNITS, 256,
        "Maximum units allocated is 256"
    );
    assert_eq!(
        DEFAULT_TARGET_HEADROOM_BPS, 2_000,
        "Default capacity headroom target is 20.00%"
    );
    assert_eq!(
        MAX_TRACKED_SERVICES, 256,
        "Registry tracks up to 256 services"
    );
}

// ---------------------------------------------------------------------------
// 2. Resource metrics bottleneck detection
// ---------------------------------------------------------------------------

#[test]
fn test_resource_metrics_peak_identifies_cpu_bottleneck() {
    let metrics = ResourceMetrics::new(8_500, 4_000, 3_000, 2_000, 5_000);
    assert_eq!(metrics.peak_saturation_bps(), 8_500);
}

#[test]
fn test_resource_metrics_peak_identifies_memory_bottleneck() {
    let metrics = ResourceMetrics::new(3_000, 9_200, 4_000, 1_000, 2_000);
    assert_eq!(metrics.peak_saturation_bps(), 9_200);
}

#[test]
fn test_resource_metrics_peak_identifies_iops_bottleneck() {
    let metrics = ResourceMetrics::new(2_000, 3_000, 7_800, 1_000, 4_000);
    assert_eq!(metrics.peak_saturation_bps(), 7_800);
}

#[test]
fn test_resource_metrics_peak_identifies_network_bottleneck() {
    let metrics = ResourceMetrics::new(1_000, 2_000, 3_000, 8_900, 4_000);
    assert_eq!(metrics.peak_saturation_bps(), 8_900);
}

#[test]
fn test_resource_metrics_peak_identifies_worker_saturation_bottleneck() {
    let metrics = ResourceMetrics::new(2_000, 2_000, 3_000, 1_000, 9_500);
    assert_eq!(metrics.peak_saturation_bps(), 9_500);
}

#[test]
fn test_resource_metrics_caps_at_10000_bps() {
    let metrics = ResourceMetrics::new(12_000, 15_000, 11_000, 10_500, 20_000);
    assert_eq!(metrics.peak_saturation_bps(), 10_000);
    assert_eq!(metrics.mean_utilization_bps(), 10_000);
}

// ---------------------------------------------------------------------------
// 3. Historical ring buffer operations
// ---------------------------------------------------------------------------

#[test]
fn test_ring_buffer_fifo_eviction_under_continuous_push() {
    let mut buffer = HistoricalUsageBuffer::new(4);
    for i in 1..=10 {
        buffer.push(uniform_sample(i * 10, (i * 1_000) as u32, 20, 2));
    }
    assert_eq!(buffer.len(), 4);
    assert_eq!(buffer.oldest().unwrap().timestamp_secs, 70);
    assert_eq!(buffer.latest().unwrap().timestamp_secs, 100);
}

#[test]
fn test_ring_buffer_clear() {
    let mut buffer = HistoricalUsageBuffer::new(5);
    buffer.push(uniform_sample(10, 2_000, 20, 2));
    buffer.push(uniform_sample(20, 3_000, 25, 2));
    assert_eq!(buffer.len(), 2);
    buffer.clear();
    assert_eq!(buffer.len(), 0);
    assert!(buffer.is_empty());
    assert!(buffer.latest().is_none());
}

// ---------------------------------------------------------------------------
// 4. Statistical trending & linear regression
// ---------------------------------------------------------------------------

#[test]
fn test_trend_insufficient_samples_error() {
    let mut buffer = HistoricalUsageBuffer::new(10);
    let config = CapacityPlanningConfig::default();
    assert_eq!(
        CapacityForecaster::compute_trend(&buffer, &config),
        Err(CapacityError::InsufficientHistory)
    );

    buffer.push(uniform_sample(10, 2_000, 20, 2));
    buffer.push(uniform_sample(20, 3_000, 20, 2));
    assert_eq!(
        CapacityForecaster::compute_trend(&buffer, &config),
        Err(CapacityError::InsufficientHistory),
        "Must require at least MIN_SAMPLES_FOR_TREND ({}) samples",
        MIN_SAMPLES_FOR_TREND
    );
}

#[test]
fn test_linear_regression_slope_and_r_squared_perfect_fit() {
    let mut buffer = HistoricalUsageBuffer::new(10);
    // Linear progression: +50 bps every 10 seconds => slope = 5.0 bps/sec
    for i in 0..5 {
        buffer.push(uniform_sample(i * 10, 1_000 + (i as u32 * 50), 30, 2));
    }

    let config = CapacityPlanningConfig::default();
    let trend = CapacityForecaster::compute_trend(&buffer, &config).unwrap();

    assert!((trend.slope_bps_per_sec - 5.0).abs() < 1e-5);
    assert!((trend.r_squared - 1.0).abs() < 1e-4);
    assert!(trend.is_accelerating);
    assert!((trend.hourly_growth_rate_bps - 18_000.0).abs() < 1e-2);
    assert!((trend.daily_growth_rate_bps - 432_000.0).abs() < 1e-1);
}

#[test]
fn test_holt_winters_exponential_smoothing_projection() {
    let mut buffer = HistoricalUsageBuffer::new(20);
    // Increasing usage with noise
    let values = [2_000, 2_200, 2_500, 2_900, 3_400, 4_000];
    for (i, &val) in values.iter().enumerate() {
        buffer.push(uniform_sample(i as u64 * 30, val, 25, 2));
    }

    let config = CapacityPlanningConfig::default();
    let trend = CapacityForecaster::compute_trend(&buffer, &config).unwrap();

    // Holt-Winters forecasted utilization should reflect recent upward trend
    assert!(trend.holt_winters_forecast_bps > 3_500);
    assert!(trend.holt_winters_forecast_bps <= 10_000);
}

// ---------------------------------------------------------------------------
// 5. Capacity runway calculations
// ---------------------------------------------------------------------------

#[test]
fn test_runway_calculation_exact_seconds() {
    let mut buffer = HistoricalUsageBuffer::new(10);
    // Current at t=0 is 5,000. Slope = 10 bps/sec
    buffer.push(uniform_sample(0, 5_000, 30, 2));
    buffer.push(uniform_sample(10, 5_100, 30, 2));
    buffer.push(uniform_sample(20, 5_200, 30, 2));

    let config = CapacityPlanningConfig::default();
    let trend = CapacityForecaster::compute_trend(&buffer, &config).unwrap();

    // Latest sample is 5_200 bps at t=20.
    // Warning (8_000): (8_000 - 5_200) / 10 = 280s
    // Critical (9_000): (9_000 - 5_200) / 10 = 380s
    // Exhaustion (10_000): (10_000 - 5_200) / 10 = 480s
    assert_eq!(trend.runway_warning_secs, Some(280));
    assert_eq!(trend.runway_critical_secs, Some(380));
    assert_eq!(trend.runway_exhaustion_secs, Some(480));
}

#[test]
fn test_runway_infinite_when_slope_is_negative_or_zero() {
    let mut buffer = HistoricalUsageBuffer::new(10);
    buffer.push(uniform_sample(0, 4_000, 20, 2));
    buffer.push(uniform_sample(10, 3_800, 20, 2));
    buffer.push(uniform_sample(20, 3_600, 20, 2));

    let config = CapacityPlanningConfig::default();
    let trend = CapacityForecaster::compute_trend(&buffer, &config).unwrap();

    assert!(!trend.is_accelerating);
    assert_eq!(trend.runway_warning_secs, None);
    assert_eq!(trend.runway_critical_secs, None);
    assert_eq!(trend.runway_exhaustion_secs, None);
}

// ---------------------------------------------------------------------------
// 6. Capacity health state classification
// ---------------------------------------------------------------------------

#[test]
fn test_health_classification_transitions() {
    let config = CapacityPlanningConfig::default();

    // Healthy: < 80% and P99 < 100ms
    let healthy_sample = uniform_sample(10, 7_500, 50, 4);
    assert_eq!(
        CapacityForecaster::classify_health(&healthy_sample, None, &config),
        CapacityHealthState::Healthy
    );

    // Warning: >= 80%
    let warning_sample = uniform_sample(20, 8_000, 60, 4);
    assert_eq!(
        CapacityForecaster::classify_health(&warning_sample, None, &config),
        CapacityHealthState::Warning
    );

    // Critical: >= 90%
    let critical_sample = uniform_sample(30, 9_000, 70, 4);
    assert_eq!(
        CapacityForecaster::classify_health(&critical_sample, None, &config),
        CapacityHealthState::Critical
    );

    // Exhausted: 100%
    let exhausted_sample = uniform_sample(40, 10_000, 90, 4);
    assert_eq!(
        CapacityForecaster::classify_health(&exhausted_sample, None, &config),
        CapacityHealthState::Exhausted
    );
}

#[test]
fn test_health_classification_p99_latency_sla_breach_forces_exhaustion() {
    let config = CapacityPlanningConfig::default();

    // Low saturation (30%) but P99 is 101ms (> 100ms bound)
    let latency_breach_sample = uniform_sample(10, 3_000, 101, 4);
    assert_eq!(
        CapacityForecaster::classify_health(&latency_breach_sample, None, &config),
        CapacityHealthState::Exhausted,
        "Any P99 latency above 100ms must trigger Exhausted state"
    );
}

// ---------------------------------------------------------------------------
// 7. Automated sizing recommendations & cooldown
// ---------------------------------------------------------------------------

#[test]
fn test_recommend_scale_up_with_proportional_delta() {
    let mut state = ServiceCapacityState::new("mempool", 4, 10);
    // Severe saturation at 9,500 bps
    state.record_sample(uniform_sample(100, 9_500, 50, 4));
    let config = CapacityPlanningConfig::default();

    let action = CapacityForecaster::recommend_action(&state, None, &config, 100);
    match action {
        CapacityAction::ScaleUp {
            delta_units,
            target_units,
            ..
        } => {
            assert_eq!(
                delta_units, 2,
                "Headroom deficit > 3000 should recommend +2 units"
            );
            assert_eq!(target_units, 6);
        }
        other => panic!("Expected ScaleUp action, got {:?}", other),
    }
}

#[test]
fn test_recommend_action_respects_max_units_ceiling() {
    let mut state = ServiceCapacityState::new("storage", 256, 10);
    state.record_sample(uniform_sample(100, 9_500, 50, 256));
    let config = CapacityPlanningConfig::default();

    let action = CapacityForecaster::recommend_action(&state, None, &config, 100);
    assert_eq!(
        action,
        CapacityAction::NoAction,
        "Cannot scale up beyond max_units (256)"
    );
}

#[test]
fn test_recommend_action_respects_min_units_floor() {
    let mut state = ServiceCapacityState::new("backup", 1, 10);
    state.record_sample(uniform_sample(100, 1_000, 10, 1));
    let config = CapacityPlanningConfig::default();

    let action = CapacityForecaster::recommend_action(&state, None, &config, 100);
    assert_eq!(
        action,
        CapacityAction::NoAction,
        "Cannot scale down below min_units (1)"
    );
}

#[test]
fn test_recommend_action_enforces_cooldown_window() {
    let mut state = ServiceCapacityState::new("consensus", 4, 10);
    state.record_sample(uniform_sample(100, 8_500, 40, 4));
    state.last_action_at = Some(80); // 20s ago, cooldown is 30s
    let config = CapacityPlanningConfig::default();

    let action = CapacityForecaster::recommend_action(&state, None, &config, 100);
    assert_eq!(
        action,
        CapacityAction::NoAction,
        "Action must be deferred while cooldown is active"
    );

    // After cooldown elapses (111 - 80 = 31s > 30s)
    let post_cooldown_action = CapacityForecaster::recommend_action(&state, None, &config, 111);
    match post_cooldown_action {
        CapacityAction::ScaleUp { .. } => {}
        other => panic!("Expected ScaleUp after cooldown elapsed, got {:?}", other),
    }
}

#[test]
fn test_emergency_throttle_under_p99_and_saturation_breach() {
    let mut state = ServiceCapacityState::new("attestation", 8, 10);
    // 9,200 bps saturation and 120ms P99 latency
    state.record_sample(uniform_sample(100, 9_200, 120, 8));
    let config = CapacityPlanningConfig::default();

    let action = CapacityForecaster::recommend_action(&state, None, &config, 100);
    match action {
        CapacityAction::EmergencyThrottle {
            drop_percentage_bps,
            ..
        } => {
            assert_eq!(drop_percentage_bps, 2_500); // 25% shed
        }
        other => panic!("Expected EmergencyThrottle, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 8. Blue-green deployment canary validation gates
// ---------------------------------------------------------------------------

#[test]
fn test_canary_gate_all_criteria_met() {
    let canary = CapacityCanaryAnalysis::new("network", 12, 200_000, 199_998, 65, 9_999, true);
    assert_eq!(canary.success_rate_bps(), 9_999);
    assert!(canary.passes_release_gate().is_ok());
}

#[test]
fn test_canary_gate_fails_on_missing_security_review() {
    let canary = CapacityCanaryAnalysis::new(
        "network", 12, 200_000, 199_998, 65, 9_999, false, // Missing security review sign-off
    );
    assert_eq!(
        canary.passes_release_gate(),
        Err(CapacityError::SecurityReviewRequired)
    );
}

#[test]
fn test_canary_gate_fails_on_sub_9999_availability() {
    let canary = CapacityCanaryAnalysis::new(
        "network", 12, 200_000, 199_998, 65, 9_995, // 99.95% < 99.99% target
        true,
    );
    assert_eq!(
        canary.passes_release_gate(),
        Err(CapacityError::AvailabilityTargetViolated)
    );
}

#[test]
fn test_canary_gate_fails_on_p99_latency_target_breach() {
    let canary = CapacityCanaryAnalysis::new(
        "network", 12, 200_000, 199_998, 101, // 101ms > 100ms target
        9_999, true,
    );
    assert_eq!(
        canary.passes_release_gate(),
        Err(CapacityError::LatencyTargetViolated)
    );
}

#[test]
fn test_canary_gate_fails_on_success_rate_breach() {
    let canary = CapacityCanaryAnalysis::new(
        "network", 12, 200_000, 199_000, // 99.50% < 99.99% target
        70, 9_999, true,
    );
    assert_eq!(
        canary.passes_release_gate(),
        Err(CapacityError::CanaryValidationFailed)
    );
}

// ---------------------------------------------------------------------------
// 9. Multi-service registry & dashboard snapshot
// ---------------------------------------------------------------------------

#[test]
fn test_registry_multi_service_isolation_and_evaluation() {
    let mut registry = CapacityPlanningRegistry::default();
    registry.register_service("consensus", 6).unwrap();
    registry.register_service("mempool", 4).unwrap();
    registry.register_service("pg_pool", 8).unwrap();

    // Ingest data
    registry
        .record_sample("consensus", uniform_sample(10, 4_000, 30, 6))
        .unwrap();
    registry
        .record_sample("consensus", uniform_sample(20, 4_000, 30, 6))
        .unwrap();
    registry
        .record_sample("consensus", uniform_sample(30, 4_000, 30, 6))
        .unwrap();

    registry
        .record_sample("mempool", uniform_sample(30, 8_500, 50, 4))
        .unwrap();
    registry
        .record_sample("pg_pool", uniform_sample(30, 2_000, 15, 8))
        .unwrap();

    let reports = registry.evaluate_all(50);
    assert_eq!(reports.len(), 3);

    let consensus_report = registry.evaluate_service("consensus", 50).unwrap();
    assert_eq!(consensus_report.health_state, CapacityHealthState::Healthy);
    assert!(consensus_report.trend.is_some());

    let mempool_report = registry.evaluate_service("mempool", 50).unwrap();
    assert_eq!(mempool_report.health_state, CapacityHealthState::Warning);

    let snapshot = registry.dashboard_snapshot(50);
    assert_eq!(snapshot.services_monitored, 3);
    assert_eq!(snapshot.total_units_allocated, 18);
    assert_eq!(snapshot.max_saturation_bps, 8_500);
    assert_eq!(snapshot.healthy_count, 2); // consensus & pg_pool
    assert_eq!(snapshot.warning_count, 1); // mempool
    assert_eq!(snapshot.critical_count, 0);
    assert_eq!(snapshot.exhausted_count, 0);
}

#[test]
fn test_registry_canary_promotion_lifecycle() {
    let mut registry = CapacityPlanningRegistry::default();
    registry.register_service("state", 4).unwrap();

    let canary = CapacityCanaryAnalysis::new("state", 8, 100_000, 99_999, 50, 9_999, true);

    // Promote canary at t=100
    let old_units = registry
        .promote_canary_deployment("state", &canary, 100)
        .unwrap();
    assert_eq!(old_units, 4);
    assert_eq!(registry.service_state("state").unwrap().current_units, 8);

    // Attempt second promotion immediately -> CooldownActive
    let second_canary = CapacityCanaryAnalysis::new("state", 12, 100_000, 99_999, 50, 9_999, true);
    assert_eq!(
        registry.promote_canary_deployment("state", &second_canary, 110),
        Err(CapacityError::CooldownActive)
    );

    // Reset cooldown (e.g. emergency intervention)
    assert!(registry.reset_cooldown("state").is_ok());
    assert!(registry
        .promote_canary_deployment("state", &second_canary, 115)
        .is_ok());
    assert_eq!(registry.service_state("state").unwrap().current_units, 12);
}

#[test]
fn test_registry_service_bounds_and_capacity_limits() {
    let mut registry = CapacityPlanningRegistry::default();

    // Allocation out of bounds (min is 1, max is 256)
    assert_eq!(
        registry.register_service("invalid_zero", 0),
        Err(CapacityError::AllocationBoundsViolated)
    );
    assert_eq!(
        registry.register_service("invalid_huge", 500),
        Err(CapacityError::AllocationBoundsViolated)
    );
}
