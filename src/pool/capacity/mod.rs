//! Capacity planning for shard-pool nodes (issue #139).
//!
//! Each shard node runs a [`LocalEstimator`] that samples CPU, memory, and
//! bandwidth utilization every [`LOCAL_ESTIMATOR_INTERVAL_S`] second and
//! applies the non-linear model (GC-pause and NUMA corrections). The
//! [`GlobalCoordinator`] aggregates per-node snapshots every
//! [`GLOBAL_COORDINATOR_SYNC_INTERVAL_S`] seconds, applies a divergence
//! correction factor, and switches to the conservative estimate when the two
//! models have differed by more than [`DIVERGENCE_TOLERANCE`] for
//! [`DIVERGENCE_CONSECUTIVE_CYCLES`] consecutive cycles.
//!
//! ## Module layout
//!
//! * [`model_linear`] — simple weighted-average model used by the coordinator.
//! * [`model_nonlinear`] — GC-pause and NUMA-aware model used locally.
//! * [`local_estimator`] — per-node estimator that sends both raw measurements
//!   and both model estimates to the coordinator.
//! * [`global_coordinator`] — aggregation, correction, and divergence alerting.

pub mod global_coordinator;
pub mod local_estimator;
pub mod model_linear;
pub mod model_nonlinear;

pub use global_coordinator::{
    CapacityEvent, GlobalCoordinator, DIVERGENCE_CONSECUTIVE_CYCLES, DIVERGENCE_TOLERANCE,
    GLOBAL_COORDINATOR_SYNC_INTERVAL_S,
};
pub use local_estimator::{
    LocalEstimator, LocalEstimatorSnapshot, LOCAL_ESTIMATOR_INTERVAL_S, MAX_OVERCOMMIT_RATIO,
};
pub use model_linear::{estimate_linear, LinearCapacityEstimate, ResourceMeasurements};
pub use model_nonlinear::{
    estimate_nonlinear, NonLinearCapacityEstimate, NonLinearInputs, GC_PENALTY_WINDOW_S,
    MAX_NUMA_PENALTY, NUMA_PENALTY_PER_NODE,
};
