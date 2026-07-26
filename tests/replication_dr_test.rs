use sorosusu_contracts::replication::{
    CanaryAnalysis, DeploymentColor, DisasterRecoveryTestReport, RegionHealth, RegionStatus,
    ReplicationError, ReplicationTopology, AVAILABILITY_TARGET_BPS, CRITICAL_PATH_P99_TARGET_MS,
};

fn region(id: &str, priority: u8, health: RegionHealth, lag: u64, p99: u64) -> RegionStatus {
    RegionStatus::new(id.into(), priority, health, lag, p99, DeploymentColor::Blue)
}

#[test]
fn failover_plan_selects_lowest_priority_healthy_replica() {
    let topology = ReplicationTopology::new(
        "us-east-1".into(),
        vec![
            region("us-east-1", 0, RegionHealth::Healthy, 10, 80),
            region("eu-west-1", 2, RegionHealth::Healthy, 15, 85),
            region("us-west-2", 1, RegionHealth::Healthy, 20, 90),
        ],
    )
    .unwrap();

    let plan = topology.failover_plan().unwrap();

    assert_eq!(plan.from_region_id, "us-east-1");
    assert_eq!(plan.to_region_id, "us-west-2");
    assert_eq!(plan.dns_ttl_seconds, 30);
    assert!(plan.freeze_writes);
    assert!(plan.verify_read_after_write);
}

#[test]
fn stale_or_slow_regions_block_dr_posture() {
    let topology = ReplicationTopology::new(
        "us-east-1".into(),
        vec![
            region("us-east-1", 0, RegionHealth::Healthy, 10, 80),
            region("eu-west-1", 1, RegionHealth::Healthy, 101, 80),
            region("us-west-2", 2, RegionHealth::Healthy, 10, 101),
        ],
    )
    .unwrap();

    assert_eq!(
        topology.failover_plan(),
        Err(ReplicationError::InsufficientHealthyRegions)
    );

    let metrics = topology.dashboard_snapshot();
    assert_eq!(metrics.configured_regions, 3);
    assert_eq!(metrics.healthy_regions, 1);
    assert_eq!(metrics.max_replication_lag_ms, 101);
    assert_eq!(metrics.max_critical_path_p99_ms, 101);
    assert_eq!(metrics.availability_target_bps, AVAILABILITY_TARGET_BPS);
    assert_eq!(metrics.p99_target_ms, CRITICAL_PATH_P99_TARGET_MS);
    assert!(!metrics.dr_ready);
}

#[test]
fn canary_requires_security_review_success_rate_and_latency() {
    let secure_fast = CanaryAnalysis {
        requests: 10_000,
        successful_requests: 9_999,
        p99_latency_ms: 100,
        security_review_passed: true,
    };
    assert_eq!(secure_fast.success_rate_bps(), 9_999);
    assert!(secure_fast.passes_release_gate().is_ok());

    let no_security_review = CanaryAnalysis {
        security_review_passed: false,
        ..secure_fast.clone()
    };
    assert_eq!(
        no_security_review.passes_release_gate(),
        Err(ReplicationError::SecurityReviewRequired)
    );

    let slow = CanaryAnalysis {
        p99_latency_ms: 101,
        ..secure_fast
    };
    assert_eq!(
        slow.passes_release_gate(),
        Err(ReplicationError::CanaryFailed)
    );
}

#[test]
fn disaster_recovery_report_combines_failover_canary_rto_and_rpo() {
    let topology = ReplicationTopology::new(
        "us-east-1".into(),
        vec![
            region("us-east-1", 0, RegionHealth::Healthy, 5, 75),
            region("eu-west-1", 1, RegionHealth::Healthy, 7, 85),
        ],
    )
    .unwrap();

    let report = DisasterRecoveryTestReport {
        failover_plan: topology.failover_plan().unwrap(),
        canary: CanaryAnalysis {
            requests: 100_000,
            successful_requests: 100_000,
            p99_latency_ms: 90,
            security_review_passed: true,
        },
        recovery_time_seconds: 120,
        recovery_point_lag_ms: 7,
    };

    assert!(report.passed());
}
