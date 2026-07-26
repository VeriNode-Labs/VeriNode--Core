use sorosusu_contracts::config::{
    ConfigError, ConfigManager, DeploymentConfig, MonitoringConfig, ServiceConfig, SystemConfig,
};

fn valid_config(version: u64) -> SystemConfig {
    SystemConfig {
        version,
        availability_target_bps: 9_999,
        critical_path_p99_ms: 100,
        security_review_required: true,
        services: vec![
            ServiceConfig {
                name: "mempool".to_string(),
                enabled: true,
                critical_path_timeout_ms: 50,
                max_inflight_requests: 128,
                hot_reload: true,
            },
            ServiceConfig {
                name: "attestation".to_string(),
                enabled: true,
                critical_path_timeout_ms: 80,
                max_inflight_requests: 256,
                hot_reload: true,
            },
        ],
        monitoring: MonitoringConfig::default(),
        deployment: DeploymentConfig::default(),
    }
}

#[test]
fn accepts_valid_config_and_records_hot_reload_event() {
    let mut manager = ConfigManager::new(valid_config(1)).expect("valid initial config");
    let mut next = valid_config(2);
    next.deployment.canary_percent = 10;
    next.services[0].max_inflight_requests = 512;

    let event = manager.reload(next).expect("hot reload succeeds");

    assert_eq!(event.previous_version, 1);
    assert_eq!(event.current_version, 2);
    assert_eq!(event.changed_services, vec!["mempool".to_string()]);
    assert_eq!(event.canary_percent, 10);
    assert_eq!(manager.history(), &[event]);
    assert_eq!(manager.active().version, 2);
}

#[test]
fn rejects_schema_violations_before_activation() {
    let mut invalid = valid_config(1);
    invalid.critical_path_p99_ms = 101;
    assert_eq!(
        ConfigManager::new(invalid),
        Err(ConfigError::CriticalPathTargetTooHigh)
    );

    let mut invalid = valid_config(1);
    invalid.monitoring.alerting_enabled = false;
    assert_eq!(
        ConfigManager::new(invalid),
        Err(ConfigError::MonitoringDisabled)
    );

    let mut invalid = valid_config(1);
    invalid.security_review_required = false;
    assert_eq!(
        ConfigManager::new(invalid),
        Err(ConfigError::SecurityReviewMissing)
    );
}

#[test]
fn rejects_non_monotonic_versions_and_non_reloadable_service_changes() {
    let mut manager = ConfigManager::new(valid_config(7)).expect("valid initial config");
    assert_eq!(
        manager.reload(valid_config(7)),
        Err(ConfigError::NonMonotonicVersion)
    );

    let mut blocked = valid_config(8);
    blocked.services[1].hot_reload = false;
    blocked.services[1].critical_path_timeout_ms = 70;
    assert_eq!(
        manager.reload(blocked),
        Err(ConfigError::HotReloadDisabled("attestation".to_string()))
    );
    assert_eq!(manager.active().version, 7);
}

#[test]
fn rejects_duplicate_services_and_invalid_canary_settings() {
    let mut duplicate = valid_config(1);
    duplicate.services[1].name = "mempool".to_string();
    assert_eq!(
        ConfigManager::new(duplicate),
        Err(ConfigError::DuplicateServiceName)
    );

    let mut invalid_canary = valid_config(1);
    invalid_canary.deployment.canary_percent = 101;
    assert_eq!(
        ConfigManager::new(invalid_canary),
        Err(ConfigError::InvalidCanaryPercent)
    );
}
