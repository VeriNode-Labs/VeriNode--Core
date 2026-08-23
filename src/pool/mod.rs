//! Connection-pool capacity planning and shard memory management (issues #139, #141).
//!
//! The `pool` module exposes two sub-systems:
//!
//! * [`capacity`] — two-tier capacity planning model: a per-node
//!   [`capacity::LocalEstimator`] running a non-linear model (GC-pause + NUMA
//!   corrections) and a [`capacity::GlobalCoordinator`] that aggregates node
//!   snapshots using a linear model with a divergence-correction factor.
//!
//! * [`shard_allocator`] / [`shard_defragmenter`] / [`tenant_registry`] — shard
//!   slot lifecycle management backed by the buddy-system allocator in
//!   [`crate::mem`]. Handles high-frequency tenant churn with background
//!   defragmentation and slot remapping (issue #141).

pub mod capacity;
pub mod shard_allocator;
pub mod shard_defragmenter;
pub mod tenant_registry;

pub use capacity::{
    CapacityEvent, GlobalCoordinator, LocalEstimator, LocalEstimatorSnapshot, ResourceMeasurements,
    DIVERGENCE_CONSECUTIVE_CYCLES, DIVERGENCE_TOLERANCE, GLOBAL_COORDINATOR_SYNC_INTERVAL_S,
    LOCAL_ESTIMATOR_INTERVAL_S, MAX_OVERCOMMIT_RATIO,
};

pub use shard_allocator::{
    bulk_allocate, bulk_free, PoolFragmentationGauge, ShardAllocResult, ShardAllocator,
    FRAGMENTATION_ALARM_RATIO, SHARD_SIZE_BYTES,
};

pub use shard_defragmenter::{DefragEvent, ShardDefragmenter, COALESCING_WINDOW_MS};

pub use tenant_registry::TenantRegistry;
