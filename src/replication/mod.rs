//! Multi-region replication and disaster-recovery primitives (issue #91).
//!
//! The runtime intentionally stays dependency-free and deterministic: node
//! operators can feed health probes, replication-lag samples, and canary
//! results into these plain Rust types from any monitoring stack.  The module
//! then produces stable decisions for failover eligibility, blue-green deploy
//! gates, DR-test reports, and dashboard/alert snapshots.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// P99 latency target for critical paths, in milliseconds.
pub const CRITICAL_PATH_P99_TARGET_MS: u64 = 100;
/// Maximum tolerated replication lag before a region is considered stale.
pub const MAX_REPLICATION_LAG_MS: u64 = 100;
/// Availability objective in basis points: 99.99%.
pub const AVAILABILITY_TARGET_BPS: u32 = 9_999;
/// Minimum number of healthy regions needed before failover is safe.
pub const MIN_HEALTHY_REGIONS_FOR_DR: usize = 2;
/// Canary success-rate gate, in basis points.
pub const CANARY_SUCCESS_TARGET_BPS: u32 = 9_999;

/// Region deployment color used by blue-green rollouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeploymentColor {
    Blue,
    Green,
}

/// Coarse region health used by failover and alerting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionHealth {
    Healthy,
    Degraded,
    Unavailable,
}

/// Configuration and live status for one replication region.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionStatus {
    pub id: String,
    pub priority: u8,
    pub health: RegionHealth,
    pub replication_lag_ms: u64,
    pub critical_path_p99_ms: u64,
    pub deployment_color: DeploymentColor,
}

impl RegionStatus {
    pub fn new(
        id: String,
        priority: u8,
        health: RegionHealth,
        replication_lag_ms: u64,
        critical_path_p99_ms: u64,
        deployment_color: DeploymentColor,
    ) -> Self {
        Self {
            id,
            priority,
            health,
            replication_lag_ms,
            critical_path_p99_ms,
            deployment_color,
        }
    }

    pub fn is_dr_ready(&self) -> bool {
        self.health == RegionHealth::Healthy
            && self.replication_lag_ms <= MAX_REPLICATION_LAG_MS
            && self.critical_path_p99_ms <= CRITICAL_PATH_P99_TARGET_MS
    }
}

/// Errors returned by replication-planning operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplicationError {
    EmptyTopology,
    NoPrimaryRegion,
    NoFailoverCandidate,
    InsufficientHealthyRegions,
    CanaryFailed,
    SecurityReviewRequired,
}

/// Deterministic system-wide topology snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicationTopology {
    primary_region_id: String,
    regions: Vec<RegionStatus>,
}

impl ReplicationTopology {
    pub fn new(
        primary_region_id: String,
        regions: Vec<RegionStatus>,
    ) -> Result<Self, ReplicationError> {
        if regions.is_empty() {
            return Err(ReplicationError::EmptyTopology);
        }
        if !regions.iter().any(|r| r.id == primary_region_id) {
            return Err(ReplicationError::NoPrimaryRegion);
        }
        Ok(Self {
            primary_region_id,
            regions,
        })
    }

    pub fn primary_region_id(&self) -> &str {
        &self.primary_region_id
    }
    pub fn regions(&self) -> &[RegionStatus] {
        &self.regions
    }

    pub fn healthy_region_count(&self) -> usize {
        self.regions.iter().filter(|r| r.is_dr_ready()).count()
    }

    pub fn failover_candidate(&self) -> Option<&RegionStatus> {
        self.regions
            .iter()
            .filter(|r| r.id != self.primary_region_id && r.is_dr_ready())
            .min_by_key(|r| r.priority)
    }

    pub fn validate_dr_posture(&self) -> Result<(), ReplicationError> {
        if self.healthy_region_count() < MIN_HEALTHY_REGIONS_FOR_DR {
            return Err(ReplicationError::InsufficientHealthyRegions);
        }
        self.failover_candidate()
            .map(|_| ())
            .ok_or(ReplicationError::NoFailoverCandidate)
    }

    pub fn failover_plan(&self) -> Result<FailoverPlan, ReplicationError> {
        self.validate_dr_posture()?;
        let candidate = self
            .failover_candidate()
            .ok_or(ReplicationError::NoFailoverCandidate)?;
        Ok(FailoverPlan {
            from_region_id: self.primary_region_id.clone(),
            to_region_id: candidate.id.clone(),
            dns_ttl_seconds: 30,
            freeze_writes: true,
            verify_read_after_write: true,
        })
    }

    pub fn dashboard_snapshot(&self) -> ReplicationMetrics {
        let max_replication_lag_ms = self
            .regions
            .iter()
            .map(|r| r.replication_lag_ms)
            .max()
            .unwrap_or(0);
        let max_critical_path_p99_ms = self
            .regions
            .iter()
            .map(|r| r.critical_path_p99_ms)
            .max()
            .unwrap_or(0);
        ReplicationMetrics {
            configured_regions: self.regions.len(),
            healthy_regions: self.healthy_region_count(),
            max_replication_lag_ms,
            max_critical_path_p99_ms,
            availability_target_bps: AVAILABILITY_TARGET_BPS,
            p99_target_ms: CRITICAL_PATH_P99_TARGET_MS,
            dr_ready: self.validate_dr_posture().is_ok(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailoverPlan {
    pub from_region_id: String,
    pub to_region_id: String,
    pub dns_ttl_seconds: u64,
    pub freeze_writes: bool,
    pub verify_read_after_write: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanaryAnalysis {
    pub requests: u64,
    pub successful_requests: u64,
    pub p99_latency_ms: u64,
    pub security_review_passed: bool,
}

impl CanaryAnalysis {
    pub fn success_rate_bps(&self) -> u32 {
        if self.requests == 0 {
            return 0;
        }
        ((self.successful_requests.saturating_mul(10_000)) / self.requests).min(10_000) as u32
    }

    pub fn passes_release_gate(&self) -> Result<(), ReplicationError> {
        if !self.security_review_passed {
            return Err(ReplicationError::SecurityReviewRequired);
        }
        if self.success_rate_bps() < CANARY_SUCCESS_TARGET_BPS
            || self.p99_latency_ms > CRITICAL_PATH_P99_TARGET_MS
        {
            return Err(ReplicationError::CanaryFailed);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisasterRecoveryTestReport {
    pub failover_plan: FailoverPlan,
    pub canary: CanaryAnalysis,
    pub recovery_time_seconds: u64,
    pub recovery_point_lag_ms: u64,
}

impl DisasterRecoveryTestReport {
    pub fn passed(&self) -> bool {
        self.canary.passes_release_gate().is_ok()
            && self.recovery_time_seconds <= 300
            && self.recovery_point_lag_ms <= MAX_REPLICATION_LAG_MS
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicationMetrics {
    pub configured_regions: usize,
    pub healthy_regions: usize,
    pub max_replication_lag_ms: u64,
    pub max_critical_path_p99_ms: u64,
    pub availability_target_bps: u32,
    pub p99_target_ms: u64,
    pub dr_ready: bool,
}
