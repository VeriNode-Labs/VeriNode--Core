use sorosusu_contracts::config_audit::{
    ConfigAuditor, ConfigBaseline, ConfigEntry, ConfigSeverity, DeploymentStage, DriftKind,
    RuntimeSnapshot, MAX_DRIFT_RECORDS,
};

fn entry(service: &str, key: &str, value: &str, severity: ConfigSeverity) -> ConfigEntry {
    ConfigEntry::new(service, key, value.as_bytes(), severity)
}

#[test]
fn matching_snapshot_is_rollout_safe_and_digest_is_stable() {
    let entries = vec![
        entry("api", "RATE_LIMIT", "100", ConfigSeverity::Critical),
        entry("worker", "QUEUE_DEPTH", "250", ConfigSeverity::Warning),
    ];
    let baseline = ConfigBaseline::new(7, DeploymentStage::Canary, 42, entries.clone());
    let reordered = ConfigBaseline::new(
        7,
        DeploymentStage::Canary,
        42,
        vec![entries[1].clone(), entries[0].clone()],
    );
    let snapshot = RuntimeSnapshot::new(45, entries);

    let report = ConfigAuditor::audit(&baseline, &snapshot);

    assert_eq!(baseline.digest, reordered.digest);
    assert_eq!(report.drift_count, 0);
    assert!(report.is_rollout_safe());
    assert!(!report.should_alert());
}

#[test]
fn detects_value_missing_unexpected_and_severity_drift() {
    let baseline = ConfigBaseline::new(
        8,
        DeploymentStage::Blue,
        100,
        vec![
            entry("api", "AUTH_REQUIRED", "true", ConfigSeverity::Critical),
            entry("api", "TIMEOUT_MS", "50", ConfigSeverity::Warning),
            entry("worker", "BATCH_SIZE", "64", ConfigSeverity::Informational),
        ],
    );
    let snapshot = RuntimeSnapshot::new(
        101,
        vec![
            entry("api", "AUTH_REQUIRED", "false", ConfigSeverity::Critical),
            entry("api", "TIMEOUT_MS", "50", ConfigSeverity::Critical),
            entry("search", "EXPERIMENT", "on", ConfigSeverity::Warning),
        ],
    );

    let report = ConfigAuditor::audit(&baseline, &snapshot);

    assert_eq!(report.drift_count, 4);
    assert_eq!(report.critical_drift_count, 2);
    assert!(!report.is_rollout_safe());
    assert!(report.should_alert());
    assert_eq!(report.records[0].kind, DriftKind::ValueChanged);
    assert_eq!(report.records[1].kind, DriftKind::SeverityChanged);
    assert_eq!(report.records[2].kind, DriftKind::Unexpected);
    assert_eq!(report.records[3].kind, DriftKind::Missing);
}

#[test]
fn caps_records_without_losing_drift_counters() {
    let mut expected = Vec::new();
    let observed = Vec::new();
    for i in 0..(MAX_DRIFT_RECORDS + 5) {
        expected.push(entry(
            "api",
            &format!("KEY_{i:03}"),
            "true",
            ConfigSeverity::Warning,
        ));
    }
    let baseline = ConfigBaseline::new(1, DeploymentStage::Production, 1, expected);
    let snapshot = RuntimeSnapshot::new(2, observed);

    let report = ConfigAuditor::audit(&baseline, &snapshot);

    assert_eq!(report.drift_count, (MAX_DRIFT_RECORDS + 5) as u32);
    assert_eq!(report.records.len(), MAX_DRIFT_RECORDS);
}
