//! Memory management primitives for the shard connection-pool (issue #141).
//!
//! The `mem` module exposes the [`buddy_allocator`] sub-module, which implements
//! a buddy-system allocator that tracks contiguous free regions and coalesces
//! adjacent free blocks to eliminate the pathological external fragmentation
//! seen under high-frequency tenant churn.

pub mod buddy_allocator;

pub use buddy_allocator::{
    BuddyAllocResult, BuddyAllocator, BuddyFreeResult, MAX_ORDER, MAX_TENANTS, SHARD_SIZE_BYTES,
};
