//! Integration tests for graceful degradation with feature flags and capacity
//! shedding (issue #132).

use sorosusu_contracts::graceful_degradation::{
    dashboard_snapshot, CanaryError, CanaryGate, CapacitySensor, DegradationConfig,
    DegradationDecision, DegradationPolicy, DeploymentStage, DeploymentStageRegistry, FeatureFlag,
    FeatureFlagSet, FlagError, FlagState, AVAILABILITY_TARGET_BPS, CANARY_SUCCESS_TARGET_BPS,
    CRITICAL_PATH_P99_TARGET_MS, DEFAULT_HARD_SHED_THRESHOLD_BPS, DEFAULT_SHEDDING_THRESHOLD_BPS,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn healthy_sensor() -> CapacitySensor {
    CapacitySensor {
        utilisation_bps: 5_000,
        p99_latency_ms: 80,
        in_flight_requests: 100,
    }
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

fn default_config() -> DegradationConfig {
    DegradationConfig::default()
}

fn passing_canary() -> CanaryGate {
    CanaryGate {
        requests: 10_000,
        successful_requests: 9_999,
        p99_latency_ms: 90,
        security_review_passed: true,
    }
}

// ---------------------------------------------------------------------------
// Feature flags
// ---------------------------------------------------------------------------

#[test]
fn enabled_flag_active_for_all_traffic_classes() {
    let f = enabled_flag("settlement");
    assert!(f.is_active(false));
    assert!(f.is_active(true));
}

#[test]
fn disabled_flag_inactive_for_all_traffic_classes() {
    let f = FeatureFlag::new("settlement".into());
    assert!(!f.is_active(false));
    assert!(!f.is_active(true));
}

#[test]
fn canary_flag_active_only_for_canary_traffic() {
    let f = FeatureFlag {
        name: "settlement".into(),
        state: FlagState::Canary,
        security_reviewed: true,
    };
    assert!(!f.is_active(false));
    assert!(f.is_active(true));
}

#[test]
fn flag_set_rejects_empty_name() {
    let mut set = FeatureFlagSet::new();
    assert_eq!(
        set.register(FeatureFlag::new(String::new())),
        Err(FlagError::EmptyFlagName)
    );
}

#[test]
fn flag_set_blocks_enable_without_security_review() {
    let mut set = FeatureFlagSet::new();
    set.register(FeatureFlag::new("f".into())).unwrap();
    assert_eq!(
        set.set_state("f", FlagState::Enabled, false),
        Err(FlagError::SecurityReviewRequired)
    );
}

#[test]
fn flag_set_blocks_canary_without_security_review() {
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
    assert!(!set.is_active("f", false));
}

#[test]
fn flag_set_unknown_flag_treated_as_disabled() {
    let set = FeatureFlagSet::new();
    assert!(!set.is_active("nonexistent", true));
    assert_eq!(set.state("nonexistent"), None);
}

#[test]
fn flag_set_counts_states_across_all_flags() {
    let mut set = FeatureFlagSet::new();
    set.register(enabled_flag("a")).unwrap();
    set.register(FeatureFlag {
        name: "b".into(),
        state: FlagState::Canary,
        security_reviewed: true,
    })
    .unwrap();
    set.register(FeatureFlag::new("c".into())).unwrap();
    set.register(FeatureFlag::new("d".into())).unwrap();

    assert_eq!(set.flag_count(), 4);
    assert_eq!(set.enabled_count(), 1);
    assert_eq!(set.canary_count(), 1);
}

// ---------------------------------------------------------------------------
// CapacitySensor thresholds
// ---------------------------------------------------------------------------

#[test]
fn soft_threshold_triggers_at_exact_boundary() {
    let cfg = default_config();
    let at = CapacitySensor {
        utilisation_bps: DEFAULT_SHEDDING_THRESHOLD_BPS,
        p99_latency_ms: 50,
        in_flight_requests: 0,
    };
    assert!(at.exceeds_soft_threshold(&cfg));
    assert!(!CapacitySensor {
        utilisation_bps: DEFAULT_SHEDDING_THRESHOLD_BPS - 1,
        ..at
    }
    .exceeds_soft_threshold(&cfg));
}

#[test]
fn hard_threshold_triggers_at_exact_boundary() {
    let cfg = default_config();
    let at = CapacitySensor {
        utilisation_bps: DEFAULT_HARD_SHED_THRESHOLD_BPS,
        p99_latency_ms: 50,
        in_flight_requests: 0,
    };
    assert!(at.exceeds_hard_threshold(&cfg));
    assert!(!CapacitySensor {
        utilisation_bps: DEFAULT_HARD_SHED_THRESHOLD_BPS - 1,
        ..at
    }
    .exceeds_hard_threshold(&cfg));
}

#[test]
fn latency_violation_triggers_above_p99_target() {
    let ok = CapacitySensor {
        utilisation_bps: 0,
        p99_latency_ms: CRITICAL_PATH_P99_TARGET_MS,
        in_flight_requests: 0,
    };
    assert!(!ok.latency_violated());
    assert!(CapacitySensor {
        p99_latency_ms: CRITICAL_PATH_P99_TARGET_MS + 1,
        ..ok
    }
    .latency_violated());
}

// ---------------------------------------------------------------------------
// DegradationPolicy decisions
// ---------------------------------------------------------------------------

#[test]
fn full_service_when_healthy_and_flag_enabled() {
    let flags = flags_with(enabled_flag("consensus"));
    assert_eq!(
        DegradationPolicy::evaluate(
            "consensus",
            false,
            &healthy_sensor(),
            &flags,
            &default_config()
        ),
        DegradationDecision::FullService
    );
}

#[test]
fn degraded_fallback_when_flag_is_disabled() {
    let flags = flags_with(FeatureFlag::new("consensus".into()));
    assert_eq!(
        DegradationPolicy::evaluate(
            "consensus",
            false,
            &healthy_sensor(),
            &flags,
            &default_config()
        ),
        DegradationDecision::DegradedFallback
    );
}

#[test]
fn degraded_fallback_when_global_flags_disabled() {
    let flags = flags_with(enabled_flag("consensus"));
    let cfg = DegradationConfig {
        flags_enabled: false,
        ..default_config()
    };
    assert_eq!(
        DegradationPolicy::evaluate("consensus", false, &healthy_sensor(), &flags, &cfg),
        DegradationDecision::DegradedFallback
    );
}

#[test]
fn degraded_fallback_under_soft_capacity_pressure() {
    let flags = flags_with(enabled_flag("consensus"));
    let sensor = CapacitySensor {
        utilisation_bps: DEFAULT_SHEDDING_THRESHOLD_BPS + 100,
        p99_latency_ms: 50,
        in_flight_requests: 400,
    };
    assert_eq!(
        DegradationPolicy::evaluate("consensus", false, &sensor, &flags, &default_config()),
        DegradationDecision::DegradedFallback
    );
}

#[test]
fn shed_load_under_hard_capacity_pressure() {
    let flags = flags_with(enabled_flag("consensus"));
    let sensor = CapacitySensor {
        utilisation_bps: DEFAULT_HARD_SHED_THRESHOLD_BPS + 100,
        p99_latency_ms: 50,
        in_flight_requests: 900,
    };
    assert_eq!(
        DegradationPolicy::evaluate("consensus", false, &sensor, &flags, &default_config()),
        DegradationDecision::ShedLoad
    );
}

#[test]
fn hard_shed_takes_priority_over_all_other_rules() {
    let flags = FeatureFlagSet::new(); // no flags registered
    let sensor = CapacitySensor {
        utilisation_bps: DEFAULT_HARD_SHED_THRESHOLD_BPS + 200,
        p99_latency_ms: 50,
        in_flight_requests: 0,
    };
    let cfg = DegradationConfig {
        flags_enabled: false,
        ..default_config()
    };
    assert_eq!(
        DegradationPolicy::evaluate("any", false, &sensor, &flags, &cfg),
        DegradationDecision::ShedLoad
    );
}

#[test]
fn degraded_fallback_when_latency_violated_despite_healthy_utilisation() {
    let flags = flags_with(enabled_flag("consensus"));
    let sensor = CapacitySensor {
        utilisation_bps: 3_000,
        p99_latency_ms: CRITICAL_PATH_P99_TARGET_MS + 1,
        in_flight_requests: 50,
    };
    assert_eq!(
        DegradationPolicy::evaluate("consensus", false, &sensor, &flags, &default_config()),
        DegradationDecision::DegradedFallback
    );
}

#[test]
fn canary_flag_gives_full_service_to_canary_traffic_only() {
    let mut flags = FeatureFlagSet::new();
    flags
        .register(FeatureFlag {
            name: "fast-path".into(),
            state: FlagState::Canary,
            security_reviewed: true,
        })
        .unwrap();

    assert_eq!(
        DegradationPolicy::evaluate(
            "fast-path",
            true,
            &healthy_sensor(),
            &flags,
            &default_config()
        ),
        DegradationDecision::FullService
    );
    assert_eq!(
        DegradationPolicy::evaluate(
            "fast-path",
            false,
            &healthy_sensor(),
            &flags,
            &default_config()
        ),
        DegradationDecision::DegradedFallback
    );
}

// ---------------------------------------------------------------------------
// Dashboard snapshot
// ---------------------------------------------------------------------------

#[test]
fn dashboard_snapshot_reflects_all_flags_and_sensor_state() {
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

    let sensor = CapacitySensor {
        utilisation_bps: DEFAULT_SHEDDING_THRESHOLD_BPS + 50,
        p99_latency_ms: 80,
        in_flight_requests: 200,
    };
    let snap = dashboard_snapshot(&flags, &sensor, &default_config());

    assert_eq!(snap.flags_total, 3);
    assert_eq!(snap.flags_enabled, 1);
    assert_eq!(snap.flags_canary, 1);
    assert_eq!(snap.flags_disabled, 1);
    assert!(snap.soft_shedding_active);
    assert!(!snap.hard_shedding_active);
    assert!(!snap.latency_violated);
    assert_eq!(snap.p99_target_ms, CRITICAL_PATH_P99_TARGET_MS);
    assert_eq!(snap.availability_target_bps, AVAILABILITY_TARGET_BPS);
}

#[test]
fn dashboard_snapshot_empty_flags_zeroed_metrics() {
    let flags = FeatureFlagSet::new();
    let sensor = CapacitySensor {
        utilisation_bps: 0,
        p99_latency_ms: 0,
        in_flight_requests: 0,
    };
    let snap = dashboard_snapshot(&flags, &sensor, &default_config());
    assert_eq!(snap.flags_total, 0);
    assert_eq!(snap.flags_enabled, 0);
    assert_eq!(snap.flags_canary, 0);
    assert_eq!(snap.flags_disabled, 0);
    assert!(!snap.soft_shedding_active);
    assert!(!snap.hard_shedding_active);
}

// ---------------------------------------------------------------------------
// CanaryGate
// ---------------------------------------------------------------------------

#[test]
fn canary_passes_when_all_criteria_met() {
    assert!(passing_canary().passes_release_gate().is_ok());
    assert_eq!(passing_canary().success_rate_bps(), 9_999);
}

#[test]
fn canary_fails_without_security_review() {
    let gate = CanaryGate {
        security_review_passed: false,
        ..passing_canary()
    };
    assert_eq!(
        gate.passes_release_gate(),
        Err(CanaryError::SecurityReviewRequired)
    );
}

#[test]
fn canary_fails_when_latency_exceeds_target() {
    let gate = CanaryGate {
        p99_latency_ms: CRITICAL_PATH_P99_TARGET_MS + 1,
        ..passing_canary()
    };
    assert_eq!(gate.passes_release_gate(), Err(CanaryError::CanaryFailed));
}

#[test]
fn canary_fails_when_success_rate_below_target() {
    let gate = CanaryGate {
        requests: 10_000,
        successful_requests: 9_990,
        ..passing_canary()
    };
    assert_eq!(gate.passes_release_gate(), Err(CanaryError::CanaryFailed));
}

#[test]
fn canary_zero_requests_yields_zero_rate() {
    let gate = CanaryGate {
        requests: 0,
        successful_requests: 0,
        p99_latency_ms: 0,
        security_review_passed: true,
    };
    assert_eq!(gate.success_rate_bps(), 0);
}

// ---------------------------------------------------------------------------
// DeploymentStage
// ---------------------------------------------------------------------------

#[test]
fn deployment_stage_sequence_is_correct() {
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
fn only_canary_stages_return_is_canary_true() {
    assert!(!DeploymentStage::Development.is_canary());
    assert!(!DeploymentStage::BlueGreenShadow.is_canary());
    assert!(DeploymentStage::CanaryOnePercent.is_canary());
    assert!(DeploymentStage::CanaryTenPercent.is_canary());
    assert!(!DeploymentStage::FullRollout.is_canary());
}

// ---------------------------------------------------------------------------
// DeploymentStageRegistry
// ---------------------------------------------------------------------------

#[test]
fn registry_promotes_pre_canary_stages_without_gate() {
    let mut reg = DeploymentStageRegistry::new();
    reg.set_stage("feat".into(), DeploymentStage::Development)
        .unwrap();
    assert_eq!(
        reg.promote("feat", None).unwrap(),
        DeploymentStage::BlueGreenShadow
    );
}

#[test]
fn registry_rejects_canary_promotion_without_gate() {
    let mut reg = DeploymentStageRegistry::new();
    reg.set_stage("feat".into(), DeploymentStage::CanaryOnePercent)
        .unwrap();
    assert_eq!(reg.promote("feat", None), Err(CanaryError::CanaryFailed));
}

#[test]
fn registry_promotes_canary_stage_with_passing_gate() {
    let mut reg = DeploymentStageRegistry::new();
    reg.set_stage("feat".into(), DeploymentStage::CanaryOnePercent)
        .unwrap();
    assert_eq!(
        reg.promote("feat", Some(&passing_canary())).unwrap(),
        DeploymentStage::CanaryTenPercent
    );
}

#[test]
fn registry_rejects_canary_promotion_with_failing_gate() {
    let mut reg = DeploymentStageRegistry::new();
    reg.set_stage("feat".into(), DeploymentStage::CanaryTenPercent)
        .unwrap();
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
fn registry_snapshot_is_sorted_by_feature_name() {
    let mut reg = DeploymentStageRegistry::new();
    reg.set_stage("z-feature".into(), DeploymentStage::Development)
        .unwrap();
    reg.set_stage("a-feature".into(), DeploymentStage::FullRollout)
        .unwrap();

    let snap = reg.snapshot();
    assert_eq!(snap.len(), 2);
    assert_eq!(snap[0].0, "a-feature");
    assert_eq!(snap[1].0, "z-feature");
}

#[test]
fn registry_stage_returns_none_for_unknown_feature() {
    let reg = DeploymentStageRegistry::new();
    assert_eq!(reg.stage("unknown"), None);
}

#[test]
fn registry_rejects_empty_feature_name() {
    let mut reg = DeploymentStageRegistry::new();
    assert_eq!(
        reg.set_stage(String::new(), DeploymentStage::Development),
        Err(FlagError::EmptyFlagName)
    );
}

// ---------------------------------------------------------------------------
// Issue #132 operational constants
// ---------------------------------------------------------------------------

#[test]
fn issue_132_constants_match_technical_bounds() {
    assert_eq!(CRITICAL_PATH_P99_TARGET_MS, 100);
    assert_eq!(AVAILABILITY_TARGET_BPS, 9_999);
    assert_eq!(DEFAULT_SHEDDING_THRESHOLD_BPS, 9_000);
    assert_eq!(DEFAULT_HARD_SHED_THRESHOLD_BPS, 9_500);
    assert_eq!(CANARY_SUCCESS_TARGET_BPS, 9_999);
}
