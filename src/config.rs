//! Configuration management with schema validation and deterministic hot reload.
//!
//! The module is intentionally runtime-agnostic: node processes can wire
//! `ConfigManager::reload` to a file watcher, governance event stream, or
//! blue-green/canary deployment controller while tests and contracts can drive
//! reloads deterministically. Validation is pure and bounded by the number of
//! fields in `SystemConfig`, keeping critical-path checks small and predictable.

use alloc::string::String;
use alloc::vec::Vec;

pub const MAX_SERVICE_NAME_LEN: usize = 64;
pub const MAX_SERVICES: usize = 64;
pub const MAX_CONFIG_VERSION_JUMP: u64 = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceConfig {
    pub name: String,
    pub enabled: bool,
    pub critical_path_timeout_ms: u64,
    pub max_inflight_requests: u32,
    pub hot_reload: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonitoringConfig {
    pub metrics_enabled: bool,
    pub alerting_enabled: bool,
    pub dashboard_refresh_seconds: u64,
    pub p99_latency_alert_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentConfig {
    pub blue_green_enabled: bool,
    pub canary_percent: u8,
    pub canary_error_budget_bps: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemConfig {
    pub version: u64,
    pub availability_target_bps: u32,
    pub critical_path_p99_ms: u64,
    pub security_review_required: bool,
    pub services: Vec<ServiceConfig>,
    pub monitoring: MonitoringConfig,
    pub deployment: DeploymentConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigError {
    EmptyServiceName,
    ServiceNameTooLong,
    DuplicateServiceName,
    TooManyServices,
    InvalidAvailabilityTarget,
    CriticalPathTargetTooHigh,
    ServiceTimeoutExceedsTarget,
    ZeroInflightLimit,
    MonitoringDisabled,
    InvalidDashboardRefresh,
    InvalidCanaryPercent,
    InvalidCanaryErrorBudget,
    SecurityReviewMissing,
    NonMonotonicVersion,
    VersionJumpTooLarge,
    HotReloadDisabled(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigChangeEvent {
    pub previous_version: u64,
    pub current_version: u64,
    pub changed_services: Vec<String>,
    pub canary_percent: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigManager {
    active: SystemConfig,
    history: Vec<ConfigChangeEvent>,
}

impl ConfigManager {
    pub fn new(config: SystemConfig) -> Result<Self, ConfigError> {
        validate_config(&config)?;
        Ok(Self {
            active: config,
            history: Vec::new(),
        })
    }

    pub fn active(&self) -> &SystemConfig {
        &self.active
    }

    pub fn history(&self) -> &[ConfigChangeEvent] {
        &self.history
    }

    pub fn reload(&mut self, candidate: SystemConfig) -> Result<ConfigChangeEvent, ConfigError> {
        validate_reload(&self.active, &candidate)?;
        let event = ConfigChangeEvent {
            previous_version: self.active.version,
            current_version: candidate.version,
            changed_services: changed_services(&self.active.services, &candidate.services),
            canary_percent: candidate.deployment.canary_percent,
        };
        self.active = candidate;
        self.history.push(event.clone());
        Ok(event)
    }
}

pub fn validate_reload(
    current: &SystemConfig,
    candidate: &SystemConfig,
) -> Result<(), ConfigError> {
    validate_config(candidate)?;
    if candidate.version <= current.version {
        return Err(ConfigError::NonMonotonicVersion);
    }
    if candidate.version - current.version > MAX_CONFIG_VERSION_JUMP {
        return Err(ConfigError::VersionJumpTooLarge);
    }
    for service in &candidate.services {
        if service_changed(&current.services, service) && !service.hot_reload {
            return Err(ConfigError::HotReloadDisabled(service.name.clone()));
        }
    }
    Ok(())
}

pub fn validate_config(config: &SystemConfig) -> Result<(), ConfigError> {
    if config.services.len() > MAX_SERVICES {
        return Err(ConfigError::TooManyServices);
    }
    if !(9_999..=10_000).contains(&config.availability_target_bps) {
        return Err(ConfigError::InvalidAvailabilityTarget);
    }
    if config.critical_path_p99_ms == 0 || config.critical_path_p99_ms > 100 {
        return Err(ConfigError::CriticalPathTargetTooHigh);
    }
    if !config.security_review_required {
        return Err(ConfigError::SecurityReviewMissing);
    }
    if !config.monitoring.metrics_enabled || !config.monitoring.alerting_enabled {
        return Err(ConfigError::MonitoringDisabled);
    }
    if config.monitoring.dashboard_refresh_seconds == 0
        || config.monitoring.dashboard_refresh_seconds > 300
    {
        return Err(ConfigError::InvalidDashboardRefresh);
    }
    if config.monitoring.p99_latency_alert_ms > config.critical_path_p99_ms {
        return Err(ConfigError::CriticalPathTargetTooHigh);
    }
    if config.deployment.canary_percent > 100 {
        return Err(ConfigError::InvalidCanaryPercent);
    }
    if config.deployment.canary_error_budget_bps > 10_000 {
        return Err(ConfigError::InvalidCanaryErrorBudget);
    }

    let mut seen: Vec<&str> = Vec::new();
    for service in &config.services {
        if service.name.is_empty() {
            return Err(ConfigError::EmptyServiceName);
        }
        if service.name.len() > MAX_SERVICE_NAME_LEN {
            return Err(ConfigError::ServiceNameTooLong);
        }
        if seen.iter().any(|name| *name == service.name.as_str()) {
            return Err(ConfigError::DuplicateServiceName);
        }
        seen.push(service.name.as_str());
        if service.critical_path_timeout_ms > config.critical_path_p99_ms {
            return Err(ConfigError::ServiceTimeoutExceedsTarget);
        }
        if service.max_inflight_requests == 0 {
            return Err(ConfigError::ZeroInflightLimit);
        }
    }
    Ok(())
}

fn service_changed(current: &[ServiceConfig], candidate: &ServiceConfig) -> bool {
    current
        .iter()
        .find(|service| service.name == candidate.name)
        .map_or(true, |service| service != candidate)
}

fn changed_services(current: &[ServiceConfig], candidate: &[ServiceConfig]) -> Vec<String> {
    candidate
        .iter()
        .filter(|service| service_changed(current, service))
        .map(|service| service.name.clone())
        .collect()
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            metrics_enabled: true,
            alerting_enabled: true,
            dashboard_refresh_seconds: 30,
            p99_latency_alert_ms: 100,
        }
    }
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            blue_green_enabled: true,
            canary_percent: 5,
            canary_error_budget_bps: 100,
        }
    }
}
