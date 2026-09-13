//! Integration tests for Automated Performance Regression Detection in CI Pipeline (issue #133).
//!
//! These tests verify:
//! * Technical invariants mandated by issue #133 (P99 < 100ms, 99.99% availability, 5% max regression).
//! * Multi-service critical-path evaluation (consensus, attestation, mempool, state, cross-chain).
//! * Statistical regression detection across latency, throughput, and heap allocations.
//! * Hard P99 SLA violation handling (immediate CI failure & blocker severity).
//! * Blue-Green and Canary deployment gates (Promote, Hold, Rollback).
//! * System-wide dashboard snapshot generation and PagerDuty alert signals.

use sorosusu_contracts::perf_regression::{
    AlertSignal, BaselineProfile, CanaryPerformanceGate, CriticalPath, GateDecision, MetricKind,
    PerfRegressionReport, PerformanceDashboardSnapshot, PerformanceSample, RegressionDetector,
    RegressionSeverity, AVAILABILITY_TARGET_BPS, BLOCKER_REGRESSION_BPS,
    CRITICAL_PATH_P99_TARGET_MS, DEFAULT_MAX_REGRESSION_BPS, MIN_SAMPLE_COUNT,
};

// ---------------------------------------------------------------------------
// Issue #133 Technical Invariants
// ---------------------------------------------------------------------------

#[test]
fn test_issue_133_technical_bounds() {
    assert_eq!(
        CRITICAL_PATH_P99_TARGET_MS, 100,
        "Issue #133 mandates critical path P99 latency target < 100 ms"
    );
    assert_eq!(
        AVAILABILITY_TARGET_BPS, 9_999,
        "Issue #133 mandates availability target of 99.99% (9_999 bps)"
    );
    assert_eq!(
        DEFAULT_MAX_REGRESSION_BPS, 500,
        "Default allowable regression tolerance is 5.00% (500 bps)"
    );
    assert_eq!(
        BLOCKER_REGRESSION_BPS, 1_500,
        "Blocker regression threshold is 15.00% (1,500 bps)"
    );
    assert_eq!(
        MIN_SAMPLE_COUNT, 50,
        "Minimum sample count for statistically sound evaluation is 50"
    );
}

// ---------------------------------------------------------------------------
// Multi-Service Critical Path Regression Detection
// ---------------------------------------------------------------------------

#[test]
fn test_critical_paths_baseline_registration_and_drift() {
    let mut detector = RegressionDetector::new();

    // Register all core critical paths
    detector.register_baseline(BaselineProfile::new(
        "consensus",
        CriticalPath::BlockProposal,
        MetricKind::LatencyP99,
        40, // 40ms baseline
    ));
    detector.register_baseline(BaselineProfile::new(
        "attestation",
        CriticalPath::AttestationAggregation,
        MetricKind::LatencyP99,
        30, // 30ms baseline
    ));
    detector.register_baseline(BaselineProfile::new(
        "mempool",
        CriticalPath::MempoolIngestion,
        MetricKind::LatencyP99,
        15, // 15ms baseline
    ));
    detector.register_baseline(BaselineProfile::new(
        "state",
        CriticalPath::StateEpochTransition,
        MetricKind::LatencyP99,
        60, // 60ms baseline
    ));
    detector.register_baseline(BaselineProfile::new(
        "cross_chain",
        CriticalPath::CrossChainVerification,
        MetricKind::LatencyP99,
        45, // 45ms baseline
    ));

    assert_eq!(detector.baseline_count(), 5);

    // Test a candidate commit with healthy latency on all paths
    let healthy_samples = vec![
        PerformanceSample {
            service: "consensus".into(),
            path: CriticalPath::BlockProposal,
            metric: MetricKind::LatencyP99,
            value: 41, // +2.5% (< 5% tolerance)
            sample_count: 100,
            timestamp_secs: 100,
        },
        PerformanceSample {
            service: "attestation".into(),
            path: CriticalPath::AttestationAggregation,
            metric: MetricKind::LatencyP99,
            value: 31, // +3.3% (< 5% tolerance)
            sample_count: 100,
            timestamp_secs: 100,
        },
        PerformanceSample {
            service: "mempool".into(),
            path: CriticalPath::MempoolIngestion,
            metric: MetricKind::LatencyP99,
            value: 15, // 0% drift
            sample_count: 100,
            timestamp_secs: 100,
        },
        PerformanceSample {
            service: "state".into(),
            path: CriticalPath::StateEpochTransition,
            metric: MetricKind::LatencyP99,
            value: 58, // Improvement (-3.3%)
            sample_count: 100,
            timestamp_secs: 100,
        },
        PerformanceSample {
            service: "cross_chain".into(),
            path: CriticalPath::CrossChainVerification,
            metric: MetricKind::LatencyP99,
            value: 46, // +2.2% (< 5% tolerance)
            sample_count: 100,
            timestamp_secs: 100,
        },
    ];

    let report = detector.evaluate_suite(&healthy_samples);
    assert!(
        report.ci_passed,
        "CI must pass when all paths are within tolerance"
    );
    assert_eq!(report.blockers_found, 0);
    assert_eq!(report.regressions_found, 0);
    assert_eq!(report.max_critical_p99_ms, 58);
}

#[test]
fn test_hard_sla_breach_over_100ms_blocks_ci() {
    let mut detector = RegressionDetector::new();
    detector.register_baseline(BaselineProfile::new(
        "consensus",
        CriticalPath::BlockProposal,
        MetricKind::LatencyP99,
        85, // 85ms baseline
    ));

    // Observed 105ms violates the hard 100ms SLA!
    let samples = vec![PerformanceSample {
        service: "consensus".into(),
        path: CriticalPath::BlockProposal,
        metric: MetricKind::LatencyP99,
        value: 105,
        sample_count: 150,
        timestamp_secs: 200,
    }];

    let report = detector.evaluate_suite(&samples);
    assert!(!report.ci_passed, "CI must fail when P99 exceeds 100ms");
    assert_eq!(report.blockers_found, 1);
    assert_eq!(report.max_critical_p99_ms, 105);

    let verdict = &report.verdicts[0];
    assert_eq!(verdict.severity, RegressionSeverity::Blocker);
    assert!(verdict.details.contains("CRITICAL SLA BREACH"));
}

#[test]
fn test_blocker_regression_below_hard_ceiling() {
    let mut detector = RegressionDetector::new();
    detector.register_baseline(BaselineProfile::new(
        "attestation",
        CriticalPath::AttestationAggregation,
        MetricKind::LatencyP99,
        40,
    ));

    // 40ms -> 50ms is +25.00% (+2,500 bps), exceeding 1,500 bps blocker threshold
    // even though 50ms is below the 100ms hard ceiling.
    let samples = vec![PerformanceSample {
        service: "attestation".into(),
        path: CriticalPath::AttestationAggregation,
        metric: MetricKind::LatencyP99,
        value: 50,
        sample_count: 100,
        timestamp_secs: 300,
    }];

    let report = detector.evaluate_suite(&samples);
    assert!(
        !report.ci_passed,
        "CI must fail when regression exceeds blocker bps"
    );
    assert_eq!(report.blockers_found, 1);
    assert_eq!(report.verdicts[0].severity, RegressionSeverity::Blocker);
}

// ---------------------------------------------------------------------------
// Throughput and Resource Regressions
// ---------------------------------------------------------------------------

#[test]
fn test_throughput_and_allocation_regressions() {
    let mut detector = RegressionDetector::new();

    // Throughput baseline: 5,000 ops/sec
    detector.register_baseline(BaselineProfile::new(
        "mempool",
        CriticalPath::MempoolIngestion,
        MetricKind::ThroughputOps,
        5_000,
    ));

    // Memory baseline: 1,000,000 bytes
    detector.register_baseline(BaselineProfile::new(
        "mempool",
        CriticalPath::MempoolIngestion,
        MetricKind::AllocatedBytes,
        1_000_000,
    ));

    // 1. Throughput regression: drop to 4,000 ops/sec (-20%)
    let tp_sample = PerformanceSample {
        service: "mempool".into(),
        path: CriticalPath::MempoolIngestion,
        metric: MetricKind::ThroughputOps,
        value: 4_000,
        sample_count: 200,
        timestamp_secs: 400,
    };
    let tp_verdict = detector.evaluate_sample(&tp_sample);
    assert_eq!(tp_verdict.severity, RegressionSeverity::Blocker);
    assert!(tp_verdict.is_regression);

    // 2. Memory regression: increase to 1,080,000 bytes (+8% -> Warning)
    let mem_sample = PerformanceSample {
        service: "mempool".into(),
        path: CriticalPath::MempoolIngestion,
        metric: MetricKind::AllocatedBytes,
        value: 1_080_000,
        sample_count: 200,
        timestamp_secs: 400,
    };
    let mem_verdict = detector.evaluate_sample(&mem_sample);
    assert_eq!(mem_verdict.severity, RegressionSeverity::Warning);
    assert!(mem_verdict.is_regression);
}

// ---------------------------------------------------------------------------
// Blue-Green and Canary Deployment Gates
// ---------------------------------------------------------------------------

#[test]
fn test_canary_gate_promotion_success() {
    let gate = CanaryPerformanceGate::new();

    let report = PerfRegressionReport {
        total_evaluated: 5,
        regressions_found: 0,
        blockers_found: 0,
        max_critical_p99_ms: 65,
        verdicts: Vec::new(),
        ci_passed: true,
    };

    let decision = gate.evaluate_gate(&report, AVAILABILITY_TARGET_BPS, true);
    assert_eq!(
        decision,
        GateDecision::Promote,
        "Canary must promote when all gates are green"
    );
}

#[test]
fn test_canary_gate_security_review_failure_triggers_rollback() {
    let gate = CanaryPerformanceGate::new();

    let report = PerfRegressionReport {
        total_evaluated: 5,
        regressions_found: 0,
        blockers_found: 0,
        max_critical_p99_ms: 65,
        verdicts: Vec::new(),
        ci_passed: true,
    };

    // security_reviewed = false MUST reject and trigger rollback
    let decision = gate.evaluate_gate(&report, AVAILABILITY_TARGET_BPS, false);
    match decision {
        GateDecision::RollbackBlueGreen(reason) => {
            assert!(reason.contains("SECURITY GATE REJECTION"));
        }
        other => panic!("Expected RollbackBlueGreen, got {:?}", other),
    }
}

#[test]
fn test_canary_gate_availability_breach_triggers_rollback() {
    let gate = CanaryPerformanceGate::new();

    let report = PerfRegressionReport {
        total_evaluated: 5,
        regressions_found: 0,
        blockers_found: 0,
        max_critical_p99_ms: 65,
        verdicts: Vec::new(),
        ci_passed: true,
    };

    // 99.95% availability (9_995 bps) is below 99.99% target (9_999 bps)
    let decision = gate.evaluate_gate(&report, 9_995, true);
    match decision {
        GateDecision::RollbackBlueGreen(reason) => {
            assert!(reason.contains("AVAILABILITY SLA VIOLATION"));
        }
        other => panic!("Expected RollbackBlueGreen, got {:?}", other),
    }
}

#[test]
fn test_canary_gate_warning_triggers_hold() {
    let gate = CanaryPerformanceGate::new();

    let report = PerfRegressionReport {
        total_evaluated: 5,
        regressions_found: 2,
        blockers_found: 0,
        max_critical_p99_ms: 75,
        verdicts: Vec::new(),
        ci_passed: true,
    };

    let decision = gate.evaluate_gate(&report, AVAILABILITY_TARGET_BPS, true);
    match decision {
        GateDecision::HoldCanary(reason) => {
            assert!(reason.contains("CANARY HOLD"));
        }
        other => panic!("Expected HoldCanary, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Dashboard and Alert Signals
// ---------------------------------------------------------------------------

#[test]
fn test_dashboard_snapshot_healthy() {
    let report = PerfRegressionReport {
        total_evaluated: 8,
        regressions_found: 0,
        blockers_found: 0,
        max_critical_p99_ms: 55,
        verdicts: Vec::new(),
        ci_passed: true,
    };

    let snapshot = PerformanceDashboardSnapshot::from_report(&report, AVAILABILITY_TARGET_BPS);
    assert_eq!(snapshot.overall_status, "HEALTHY");
    assert_eq!(snapshot.alert_signal, AlertSignal::Healthy);
    assert_eq!(snapshot.active_blockers, 0);
    assert_eq!(snapshot.active_warnings, 0);
    assert_eq!(snapshot.peak_critical_p99_ms, 55);
}

#[test]
fn test_dashboard_snapshot_paging_on_blocker() {
    let report = PerfRegressionReport {
        total_evaluated: 8,
        regressions_found: 1,
        blockers_found: 1,
        max_critical_p99_ms: 110,
        verdicts: Vec::new(),
        ci_passed: false,
    };

    let snapshot = PerformanceDashboardSnapshot::from_report(&report, AVAILABILITY_TARGET_BPS);
    assert_eq!(snapshot.overall_status, "CRITICAL_OUTAGE");
    match snapshot.alert_signal {
        AlertSignal::PagingPagerDuty(msg) => {
            assert!(msg.contains("paging alert"));
        }
        other => panic!("Expected PagingPagerDuty, got {:?}", other),
    }
    assert_eq!(snapshot.active_blockers, 1);
}
