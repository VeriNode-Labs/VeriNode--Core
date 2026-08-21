//! Connection-pool capacity planning for shard nodes (issue #139).
//!
//! The `pool` module exposes the [`capacity`] sub-module, which implements the
//! two-tier capacity planning model: a per-node [`capacity::LocalEstimator`]
//! running a non-linear model (GC-pause + NUMA corrections) and a
//! [`capacity::GlobalCoordinator`] that aggregates node snapshots using a
//! linear model with a divergence-correction factor.

pub mod capacity;

pub use capacity::{
    CapacityEvent, GlobalCoordinator, LocalEstimator, LocalEstimatorSnapshot, ResourceMeasurements,
    DIVERGENCE_CONSECUTIVE_CYCLES, DIVERGENCE_TOLERANCE, GLOBAL_COORDINATOR_SYNC_INTERVAL_S,
    LOCAL_ESTIMATOR_INTERVAL_S, MAX_OVERCOMMIT_RATIO,
};
