//! Staging chaos engineering blueprint primitives.
//!
//! This module keeps the production-facing chaos policy in code so staging
//! automation, runbooks, and tests use the same safety thresholds. It does not
//! inject faults from contracts; it defines the canonical catalog and gates that
//! off-chain staging orchestration must satisfy before and during an experiment.

/// P99 latency ceiling for critical paths, in milliseconds.
pub const CRITICAL_PATH_P99_MS: u64 = 100;

/// Availability objective for staging chaos runs, in basis points (99.99%).
pub const AVAILABILITY_TARGET_BPS: u32 = 9_999;

/// Maximum canary error-budget burn permitted before rollback.
pub const MAX_ERROR_BUDGET_BURN_BPS: u32 = 1;

/// Minimum number of healthy zones required before running a zonal experiment.
pub const MIN_HEALTHY_ZONES: u8 = 2;

/// Minimum security-review approvals required before enabling a new fault.
pub const REQUIRED_SECURITY_APPROVALS: u8 = 2;

/// Maximum default experiment duration in seconds.
pub const MAX_EXPERIMENT_DURATION_SECS: u64 = 900;

/// System-wide staging service surfaces covered by chaos experiments.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ServiceSurface {
    Consensus,
    Mempool,
    Attestation,
    Slashing,
    Settlement,
    Network,
    Observability,
}

/// Supported fault classes for staging chaos experiments.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FaultKind {
    Latency,
    PacketLoss,
    PodKill,
    DependencyBlackhole,
    ClockSkew,
    ResourcePressure,
}

/// Rollout phase for blue-green and canary guarded experiments.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum RolloutPhase {
    DesignReview,
    SecurityReview,
    BlueGreenShadow,
    CanaryOnePercent,
    CanaryTenPercent,
    FullStaging,
}

/// A single chaos experiment template.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ChaosExperiment {
    pub id: &'static str,
    pub surface: ServiceSurface,
    pub fault: FaultKind,
    pub blast_radius_percent: u8,
    pub duration_secs: u64,
    pub rollback_metric: &'static str,
}

impl ChaosExperiment {
    /// Returns true when the experiment stays within staging safety bounds.
    pub const fn is_within_safety_bounds(&self) -> bool {
        self.blast_radius_percent > 0
            && self.blast_radius_percent <= 10
            && self.duration_secs > 0
            && self.duration_secs <= MAX_EXPERIMENT_DURATION_SECS
    }
}

/// Runtime health signals used to gate experiments and canary promotion.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ChaosHealthSnapshot {
    pub critical_path_p99_ms: u64,
    pub availability_bps: u32,
    pub error_budget_burn_bps: u32,
    pub healthy_zones: u8,
    pub security_approvals: u8,
}

impl ChaosHealthSnapshot {
    /// True when staging is healthy enough to start or continue chaos testing.
    pub const fn passes_safety_gate(&self) -> bool {
        self.critical_path_p99_ms < CRITICAL_PATH_P99_MS
            && self.availability_bps >= AVAILABILITY_TARGET_BPS
            && self.error_budget_burn_bps <= MAX_ERROR_BUDGET_BURN_BPS
            && self.healthy_zones >= MIN_HEALTHY_ZONES
            && self.security_approvals >= REQUIRED_SECURITY_APPROVALS
    }
}

/// Canonical staging experiment catalog.
pub const STAGING_CHAOS_EXPERIMENTS: [ChaosExperiment; 7] = [
    ChaosExperiment {
        id: "consensus-latency-p99",
        surface: ServiceSurface::Consensus,
        fault: FaultKind::Latency,
        blast_radius_percent: 5,
        duration_secs: 300,
        rollback_metric: "consensus_critical_path_p99_ms",
    },
    ChaosExperiment {
        id: "mempool-packet-loss",
        surface: ServiceSurface::Mempool,
        fault: FaultKind::PacketLoss,
        blast_radius_percent: 5,
        duration_secs: 300,
        rollback_metric: "mempool_tx_propagation_errors_total",
    },
    ChaosExperiment {
        id: "attestation-pod-kill",
        surface: ServiceSurface::Attestation,
        fault: FaultKind::PodKill,
        blast_radius_percent: 10,
        duration_secs: 180,
        rollback_metric: "attestation_inclusion_delay_slots",
    },
    ChaosExperiment {
        id: "slashing-dependency-blackhole",
        surface: ServiceSurface::Slashing,
        fault: FaultKind::DependencyBlackhole,
        blast_radius_percent: 5,
        duration_secs: 300,
        rollback_metric: "slashing_false_positive_total",
    },
    ChaosExperiment {
        id: "settlement-resource-pressure",
        surface: ServiceSurface::Settlement,
        fault: FaultKind::ResourcePressure,
        blast_radius_percent: 5,
        duration_secs: 600,
        rollback_metric: "settlement_finalization_lag_seconds",
    },
    ChaosExperiment {
        id: "network-clock-skew",
        surface: ServiceSurface::Network,
        fault: FaultKind::ClockSkew,
        blast_radius_percent: 5,
        duration_secs: 180,
        rollback_metric: "network_peer_disconnects_total",
    },
    ChaosExperiment {
        id: "observability-blackhole",
        surface: ServiceSurface::Observability,
        fault: FaultKind::DependencyBlackhole,
        blast_radius_percent: 5,
        duration_secs: 120,
        rollback_metric: "trace_ingestion_gap_seconds",
    },
];

/// Returns the next rollout phase after the supplied canary phase succeeds.
pub const fn next_rollout_phase(phase: RolloutPhase) -> RolloutPhase {
    match phase {
        RolloutPhase::DesignReview => RolloutPhase::SecurityReview,
        RolloutPhase::SecurityReview => RolloutPhase::BlueGreenShadow,
        RolloutPhase::BlueGreenShadow => RolloutPhase::CanaryOnePercent,
        RolloutPhase::CanaryOnePercent => RolloutPhase::CanaryTenPercent,
        RolloutPhase::CanaryTenPercent => RolloutPhase::FullStaging,
        RolloutPhase::FullStaging => RolloutPhase::FullStaging,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_covers_every_service_surface_with_safe_blast_radius() {
        let surfaces = [
            ServiceSurface::Consensus,
            ServiceSurface::Mempool,
            ServiceSurface::Attestation,
            ServiceSurface::Slashing,
            ServiceSurface::Settlement,
            ServiceSurface::Network,
            ServiceSurface::Observability,
        ];

        for surface in surfaces {
            assert!(
                STAGING_CHAOS_EXPERIMENTS
                    .iter()
                    .any(|experiment| experiment.surface == surface),
                "missing chaos experiment for {surface:?}"
            );
        }

        assert!(STAGING_CHAOS_EXPERIMENTS
            .iter()
            .all(ChaosExperiment::is_within_safety_bounds));
    }

    #[test]
    fn safety_gate_enforces_latency_availability_security_and_canary_burn() {
        let healthy = ChaosHealthSnapshot {
            critical_path_p99_ms: 99,
            availability_bps: AVAILABILITY_TARGET_BPS,
            error_budget_burn_bps: MAX_ERROR_BUDGET_BURN_BPS,
            healthy_zones: MIN_HEALTHY_ZONES,
            security_approvals: REQUIRED_SECURITY_APPROVALS,
        };
        assert!(healthy.passes_safety_gate());

        assert!(!ChaosHealthSnapshot {
            critical_path_p99_ms: 100,
            ..healthy
        }
        .passes_safety_gate());
        assert!(!ChaosHealthSnapshot {
            availability_bps: 9_998,
            ..healthy
        }
        .passes_safety_gate());
        assert!(!ChaosHealthSnapshot {
            error_budget_burn_bps: 2,
            ..healthy
        }
        .passes_safety_gate());
        assert!(!ChaosHealthSnapshot {
            healthy_zones: 1,
            ..healthy
        }
        .passes_safety_gate());
        assert!(!ChaosHealthSnapshot {
            security_approvals: 1,
            ..healthy
        }
        .passes_safety_gate());
    }

    #[test]
    fn rollout_phase_advances_through_blue_green_and_canary() {
        assert_eq!(
            next_rollout_phase(RolloutPhase::DesignReview),
            RolloutPhase::SecurityReview
        );
        assert_eq!(
            next_rollout_phase(RolloutPhase::SecurityReview),
            RolloutPhase::BlueGreenShadow
        );
        assert_eq!(
            next_rollout_phase(RolloutPhase::BlueGreenShadow),
            RolloutPhase::CanaryOnePercent
        );
        assert_eq!(
            next_rollout_phase(RolloutPhase::CanaryOnePercent),
            RolloutPhase::CanaryTenPercent
        );
        assert_eq!(
            next_rollout_phase(RolloutPhase::CanaryTenPercent),
            RolloutPhase::FullStaging
        );
        assert_eq!(
            next_rollout_phase(RolloutPhase::FullStaging),
            RolloutPhase::FullStaging
        );
    }
}
