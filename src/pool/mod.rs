//! Connection-pool capacity planning and shard memory management.
//!
//! ## Capacity planning (issue #139)
//!
//! The [`capacity`] sub-module implements the two-tier capacity planning model:
//! a per-node [`capacity::LocalEstimator`] running a non-linear model
//! (GC-pause + NUMA corrections) and a [`capacity::GlobalCoordinator`] that
//! aggregates node snapshots using a linear model with a divergence-correction
//! factor.
//!
//! ## Shard memory defragmentation (issue #141)
//!
//! Under high-frequency tenant churn the previous free-list approach suffered
//! pathological external fragmentation.  Three new sub-modules address this:
//!
//! * [`shard_allocator`] — buddy-tree backed shard allocator with a per-pool
//!   `fragmentation_ratio` gauge.
//! * [`shard_defragmenter`] — background mark-sweep compaction triggered when
//!   the fragmentation ratio exceeds 30 %, emitting
//!   [`DefragEvent::ShardDefragStarted`] / [`DefragEvent::ShardDefragComplete`]
//!   events to coordinate with tenant migration.
//! * [`tenant_registry`] — tenant lifecycle manager that wires the allocator
//!   and defragmenter together.

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
    ShardFreeResult, ShardRelocateResult, ShardSlot, CHURN_THRESHOLD_PER_SEC,
    FRAGMENTATION_ALARM_RATIO, MAX_TENANTS, SHARD_SIZE_BYTES,
};

pub use shard_defragmenter::{DefragEvent, ShardDefragmenter, COALESCING_WINDOW_MS};

pub use tenant_registry::{TenantId, TenantRecord, TenantRegistry, TenantRegistryError};
