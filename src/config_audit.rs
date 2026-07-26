//! Runtime configuration auditing and drift detection.
//!
//! The auditor keeps an append-only stream of expected configuration baselines
//! and observed runtime snapshots. Critical-path checks are deterministic
//! `O(n)` scans over pre-sorted key/value arrays, avoiding maps, heap-heavy
//! hashing, or network calls so callers can run them synchronously before a
//! service accepts traffic during blue-green or canary rollout gates.

use alloc::string::String;
use alloc::vec::Vec;

use crate::crypto::sha256::sha256;

/// Maximum number of per-key drift records returned by a single audit.
pub const MAX_DRIFT_RECORDS: usize = 64;

/// Runtime configuration deployment stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentStage {
    Development,
    Canary,
    Blue,
    Green,
    Production,
}

/// Severity assigned to a configuration key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ConfigSeverity {
    Informational,
    Warning,
    Critical,
}

/// A single expected or observed runtime configuration value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigEntry {
    pub service: String,
    pub key: String,
    pub value_hash: [u8; 32],
    pub severity: ConfigSeverity,
}

impl ConfigEntry {
    pub fn new(
        service: impl Into<String>,
        key: impl Into<String>,
        value: &[u8],
        severity: ConfigSeverity,
    ) -> Self {
        Self {
            service: service.into(),
            key: key.into(),
            value_hash: sha256(value),
            severity,
        }
    }

    fn identity_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.service
            .cmp(&other.service)
            .then_with(|| self.key.cmp(&other.key))
    }
}

/// Signed-off baseline for a rollout stage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigBaseline {
    pub version: u64,
    pub stage: DeploymentStage,
    pub generated_at_epoch: u64,
    pub entries: Vec<ConfigEntry>,
    pub digest: [u8; 32],
}

impl ConfigBaseline {
    pub fn new(
        version: u64,
        stage: DeploymentStage,
        generated_at_epoch: u64,
        mut entries: Vec<ConfigEntry>,
    ) -> Self {
        entries.sort_by(|a, b| a.identity_cmp(b));
        let digest = digest_entries(version, stage, generated_at_epoch, &entries);
        Self {
            version,
            stage,
            generated_at_epoch,
            entries,
            digest,
        }
    }
}

/// Observed runtime snapshot collected from a service fleet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSnapshot {
    pub observed_at_epoch: u64,
    pub entries: Vec<ConfigEntry>,
}

impl RuntimeSnapshot {
    pub fn new(observed_at_epoch: u64, mut entries: Vec<ConfigEntry>) -> Self {
        entries.sort_by(|a, b| a.identity_cmp(b));
        Self {
            observed_at_epoch,
            entries,
        }
    }
}

/// Drift classification for a single configuration identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriftKind {
    Missing,
    Unexpected,
    ValueChanged,
    SeverityChanged,
}

/// Auditable drift finding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriftRecord {
    pub service: String,
    pub key: String,
    pub kind: DriftKind,
    pub severity: ConfigSeverity,
}

/// Aggregate audit decision suitable for alert routing and rollout gates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditReport {
    pub baseline_version: u64,
    pub stage: DeploymentStage,
    pub observed_at_epoch: u64,
    pub baseline_digest: [u8; 32],
    pub drift_count: u32,
    pub critical_drift_count: u32,
    pub records: Vec<DriftRecord>,
}

impl AuditReport {
    pub fn is_rollout_safe(&self) -> bool {
        self.critical_drift_count == 0
    }

    pub fn should_alert(&self) -> bool {
        self.drift_count > 0
    }
}

/// Compares an approved baseline with a runtime snapshot.
pub struct ConfigAuditor;

impl ConfigAuditor {
    pub fn audit(baseline: &ConfigBaseline, snapshot: &RuntimeSnapshot) -> AuditReport {
        let mut i = 0;
        let mut j = 0;
        let mut records = Vec::new();
        let mut drift_count = 0u32;
        let mut critical_drift_count = 0u32;

        while i < baseline.entries.len() || j < snapshot.entries.len() {
            let record = match (baseline.entries.get(i), snapshot.entries.get(j)) {
                (Some(expected), Some(actual)) => match expected.identity_cmp(actual) {
                    core::cmp::Ordering::Less => {
                        i += 1;
                        Some(record_from(expected, DriftKind::Missing, expected.severity))
                    }
                    core::cmp::Ordering::Greater => {
                        j += 1;
                        Some(record_from(actual, DriftKind::Unexpected, actual.severity))
                    }
                    core::cmp::Ordering::Equal => {
                        i += 1;
                        j += 1;
                        if expected.value_hash != actual.value_hash {
                            Some(record_from(
                                expected,
                                DriftKind::ValueChanged,
                                expected.severity.max(actual.severity),
                            ))
                        } else if expected.severity != actual.severity {
                            Some(record_from(
                                expected,
                                DriftKind::SeverityChanged,
                                expected.severity.max(actual.severity),
                            ))
                        } else {
                            None
                        }
                    }
                },
                (Some(expected), None) => {
                    i += 1;
                    Some(record_from(expected, DriftKind::Missing, expected.severity))
                }
                (None, Some(actual)) => {
                    j += 1;
                    Some(record_from(actual, DriftKind::Unexpected, actual.severity))
                }
                (None, None) => None,
            };

            if let Some(record) = record {
                drift_count += 1;
                if record.severity == ConfigSeverity::Critical {
                    critical_drift_count += 1;
                }
                if records.len() < MAX_DRIFT_RECORDS {
                    records.push(record);
                }
            }
        }

        AuditReport {
            baseline_version: baseline.version,
            stage: baseline.stage,
            observed_at_epoch: snapshot.observed_at_epoch,
            baseline_digest: baseline.digest,
            drift_count,
            critical_drift_count,
            records,
        }
    }
}

fn record_from(entry: &ConfigEntry, kind: DriftKind, severity: ConfigSeverity) -> DriftRecord {
    DriftRecord {
        service: entry.service.clone(),
        key: entry.key.clone(),
        kind,
        severity,
    }
}

fn digest_entries(
    version: u64,
    stage: DeploymentStage,
    generated_at_epoch: u64,
    entries: &[ConfigEntry],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"verinode-config-baseline-v1");
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.push(stage as u8);
    bytes.extend_from_slice(&generated_at_epoch.to_be_bytes());
    for entry in entries {
        bytes.extend_from_slice(entry.service.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(entry.key.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&entry.value_hash);
        bytes.push(entry.severity as u8);
    }
    sha256(&bytes)
}
