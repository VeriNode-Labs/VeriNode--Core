//! Shard allocator backed by the buddy-tree memory allocator (issue #141).
//!
//! Under high-frequency tenant churn (>1 000 allocations/sec) the previous
//! free-list approach suffered pathological external fragmentation: freed shard
//! slots were not coalesced, causing allocation failures despite sufficient
//! aggregate free memory.  This module replaces the free-list with a
//! [`crate::mem::BuddyAllocator`] that tracks contiguous free regions and
//! coalesces adjacent free blocks on every deallocation.
//!
//! ## Invariants (issue #141)
//!
//! * Shard size: [`SHARD_SIZE_BYTES`] = 64 KiB per tenant.
//! * Max tenants per pool: [`MAX_TENANTS`] = 65 536 (2^16).
//! * Churn threshold: >1 000 allocations/sec triggers fragmentation monitoring.
//! * Fragmentation ratio alarm: >30 % waste triggers compaction.

extern crate alloc;

use alloc::vec::Vec;

use crate::mem::buddy_allocator::{BuddyAllocResult, BuddyAllocator, BuddyFreeResult};

pub use crate::mem::buddy_allocator::{MAX_TENANTS, SHARD_SIZE_BYTES};

/// Churn rate (allocations/sec) above which fragmentation monitoring is active.
pub const CHURN_THRESHOLD_PER_SEC: u32 = 1_000;

/// Fragmentation ratio above which the background defragmenter should be
/// triggered.  Expressed as a fraction in `[0.0, 1.0]` where `0.30` = 30 %.
pub const FRAGMENTATION_ALARM_RATIO: f64 = 0.30;

/// Identifier for a tenant's shard slot.
pub type ShardSlot = u32;

/// Result of a shard allocation attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShardAllocResult {
    /// Allocation succeeded; the shard slot index is returned.
    Allocated(ShardSlot),
    /// No free shard slot is available.
    OutOfMemory,
}

/// Result of a shard deallocation attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShardFreeResult {
    /// The slot was freed and coalesced with its buddy where possible.
    Freed,
    /// The supplied slot index was invalid or not currently allocated.
    InvalidSlot,
}

/// Pool-level shard allocator.
///
/// Wraps a [`BuddyAllocator`] and exposes single-slot allocate/free operations
/// for tenant lifecycle management.  A fragmentation gauge is available for the
/// background defragmenter to poll.
#[derive(Debug)]
pub struct ShardAllocator {
    buddy: BuddyAllocator,
    /// Total number of allocation calls since the last metrics reset.
    total_alloc_calls: u64,
    /// Total number of free calls since the last metrics reset.
    total_free_calls: u64,
}

impl ShardAllocator {
    /// Creates a new allocator with all [`MAX_TENANTS`] slots available.
    pub fn new() -> Self {
        Self {
            buddy: BuddyAllocator::new(),
            total_alloc_calls: 0,
            total_free_calls: 0,
        }
    }

    /// Allocates a single shard slot for a tenant.
    ///
    /// Returns [`ShardAllocResult::Allocated`] with the slot index on success,
    /// or [`ShardAllocResult::OutOfMemory`] when no free slot exists.
    pub fn allocate(&mut self) -> ShardAllocResult {
        self.total_alloc_calls += 1;
        match self.buddy.allocate_one() {
            BuddyAllocResult::Allocated(slot) => ShardAllocResult::Allocated(slot),
            _ => ShardAllocResult::OutOfMemory,
        }
    }

    /// Frees the shard slot `slot`, coalescing it with its buddy if the buddy
    /// is also free.
    pub fn free(&mut self, slot: ShardSlot) -> ShardFreeResult {
        self.total_free_calls += 1;
        match self.buddy.free_one(slot) {
            BuddyFreeResult::Freed => ShardFreeResult::Freed,
            BuddyFreeResult::InvalidIndex => ShardFreeResult::InvalidSlot,
        }
    }

    /// Returns the current fragmentation ratio in `[0.0, 1.0]`.
    ///
    /// A value above [`FRAGMENTATION_ALARM_RATIO`] (0.30) should trigger the
    /// background defragmenter.
    pub fn fragmentation_ratio(&self) -> f64 {
        self.buddy.fragmentation_ratio()
    }

    /// Returns the number of free shard slots.
    pub fn free_slots(&self) -> u32 {
        self.buddy.free_slots()
    }

    /// Returns the number of allocated (in-use) shard slots.
    pub fn used_slots(&self) -> u32 {
        self.buddy.used_slots()
    }

    /// Returns `true` if the given slot is currently allocated.
    pub fn is_allocated(&self, slot: ShardSlot) -> bool {
        self.buddy.is_allocated(slot)
    }

    /// Returns `true` if the fragmentation ratio exceeds the alarm threshold,
    /// indicating the background defragmenter should run.
    pub fn needs_defrag(&self) -> bool {
        self.fragmentation_ratio() > FRAGMENTATION_ALARM_RATIO
    }

    /// Returns the cumulative allocation call count since creation.
    pub fn total_alloc_calls(&self) -> u64 {
        self.total_alloc_calls
    }

    /// Returns the cumulative free call count since creation.
    pub fn total_free_calls(&self) -> u64 {
        self.total_free_calls
    }

    /// Returns a snapshot of the per-pool fragmentation ratio gauge suitable
    /// for dashboard export.
    ///
    /// Matches the `fragmentation_ratio` gauge described in issue #141.
    pub fn fragmentation_gauge(&self) -> PoolFragmentationGauge {
        PoolFragmentationGauge {
            fragmentation_ratio: self.fragmentation_ratio(),
            free_slots: self.free_slots(),
            used_slots: self.used_slots(),
            alarm_active: self.needs_defrag(),
        }
    }

    /// Relocates a shard slot from `old_slot` to `new_slot`.
    ///
    /// Used by the defragmenter during compaction: the defragmenter allocates
    /// a new slot in a contiguous region, then calls this method to update the
    /// allocator's bookkeeping so the old slot is freed and coalesced.
    ///
    /// Returns the list of slots that were freed (for caller bookkeeping).
    pub fn relocate(&mut self, old_slot: ShardSlot, new_slot: ShardSlot) -> ShardRelocateResult {
        if !self.buddy.is_allocated(old_slot) {
            return ShardRelocateResult::SourceNotAllocated;
        }
        if self.buddy.is_allocated(new_slot) {
            return ShardRelocateResult::DestinationOccupied;
        }
        // Allocate destination by directly marking it (the defragmenter has
        // already done the buddy allocation for new_slot externally; we only
        // update the source slot here).
        match self.buddy.free_one(old_slot) {
            BuddyFreeResult::Freed => ShardRelocateResult::Relocated { freed: old_slot },
            BuddyFreeResult::InvalidIndex => ShardRelocateResult::SourceNotAllocated,
        }
    }
}

impl Default for ShardAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a shard relocation attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShardRelocateResult {
    /// Relocation succeeded; `freed` is the old slot that was released.
    Relocated { freed: ShardSlot },
    /// The source slot was not allocated.
    SourceNotAllocated,
    /// The destination slot was already in use.
    DestinationOccupied,
}

/// Per-pool fragmentation ratio gauge exported to dashboards and alerting.
///
/// The `fragmentation_ratio` field is the primary metric described in issue
/// #141.  An `alarm_active` flag is set when the ratio exceeds
/// [`FRAGMENTATION_ALARM_RATIO`] (30 %).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PoolFragmentationGauge {
    /// Current fragmentation ratio in `[0.0, 1.0]` — the issue #141 gauge.
    pub fragmentation_ratio: f64,
    /// Number of free shard slots.
    pub free_slots: u32,
    /// Number of in-use shard slots.
    pub used_slots: u32,
    /// `true` when `fragmentation_ratio > FRAGMENTATION_ALARM_RATIO`.
    pub alarm_active: bool,
}

/// Bulk-allocate up to `count` shard slots, returning the slot indices.
///
/// Stops early if the allocator runs out of memory.  Used by stress tests and
/// tenant batch-provisioning paths.
pub fn bulk_allocate(allocator: &mut ShardAllocator, count: u32) -> Vec<ShardSlot> {
    let mut slots = Vec::with_capacity(count as usize);
    for _ in 0..count {
        match allocator.allocate() {
            ShardAllocResult::Allocated(slot) => slots.push(slot),
            ShardAllocResult::OutOfMemory => break,
        }
    }
    slots
}

/// Bulk-free a list of shard slots.
pub fn bulk_free(allocator: &mut ShardAllocator, slots: &[ShardSlot]) {
    for &slot in slots {
        allocator.free(slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invariants_match_issue_141() {
        assert_eq!(SHARD_SIZE_BYTES, 64 * 1024);
        assert_eq!(MAX_TENANTS, 65_536);
        assert!((FRAGMENTATION_ALARM_RATIO - 0.30).abs() < 1e-9);
        assert_eq!(CHURN_THRESHOLD_PER_SEC, 1_000);
    }

    #[test]
    fn fresh_allocator_all_slots_free() {
        let alloc = ShardAllocator::new();
        assert_eq!(alloc.free_slots(), MAX_TENANTS);
        assert_eq!(alloc.used_slots(), 0);
    }

    #[test]
    fn single_alloc_and_free_round_trip() {
        let mut alloc = ShardAllocator::new();
        let result = alloc.allocate();
        assert!(matches!(result, ShardAllocResult::Allocated(_)));
        let ShardAllocResult::Allocated(slot) = result else {
            unreachable!()
        };
        assert!(alloc.is_allocated(slot));
        assert_eq!(alloc.used_slots(), 1);
        let free_result = alloc.free(slot);
        assert_eq!(free_result, ShardFreeResult::Freed);
        assert!(!alloc.is_allocated(slot));
        assert_eq!(alloc.free_slots(), MAX_TENANTS);
    }

    #[test]
    fn out_of_memory_when_all_slots_used() {
        let mut alloc = ShardAllocator::new();
        let slots = bulk_allocate(&mut alloc, MAX_TENANTS);
        assert_eq!(slots.len() as u32, MAX_TENANTS);
        assert_eq!(alloc.allocate(), ShardAllocResult::OutOfMemory);
    }

    #[test]
    fn free_invalid_slot_returns_error() {
        let mut alloc = ShardAllocator::new();
        // MAX_TENANTS is out of range.
        assert_eq!(alloc.free(MAX_TENANTS), ShardFreeResult::InvalidSlot);
    }

    #[test]
    fn fragmentation_gauge_alarm_not_active_on_fresh_allocator() {
        let alloc = ShardAllocator::new();
        let gauge = alloc.fragmentation_gauge();
        assert!(!gauge.alarm_active);
        assert_eq!(gauge.used_slots, 0);
        assert_eq!(gauge.free_slots, MAX_TENANTS);
    }

    #[test]
    fn alloc_call_counters_track_operations() {
        let mut alloc = ShardAllocator::new();
        alloc.allocate();
        alloc.allocate();
        assert_eq!(alloc.total_alloc_calls(), 2);
        // Free counter unchanged.
        assert_eq!(alloc.total_free_calls(), 0);
    }

    #[test]
    fn bulk_allocate_and_free_restores_full_capacity() {
        let mut alloc = ShardAllocator::new();
        let slots = bulk_allocate(&mut alloc, 1_000);
        assert_eq!(slots.len(), 1_000);
        bulk_free(&mut alloc, &slots);
        assert_eq!(alloc.free_slots(), MAX_TENANTS);
        assert_eq!(alloc.used_slots(), 0);
    }

    #[test]
    fn needs_defrag_false_when_fragmentation_below_alarm() {
        let alloc = ShardAllocator::new();
        // Buddy allocator in pristine state has no fragmentation.
        assert!(!alloc.needs_defrag());
    }

    #[test]
    fn relocate_invalid_source_returns_error() {
        let mut alloc = ShardAllocator::new();
        // slot 0 not allocated — relocate should fail.
        let result = alloc.relocate(0, 1);
        assert_eq!(result, ShardRelocateResult::SourceNotAllocated);
    }

    #[test]
    fn relocate_occupied_destination_returns_error() {
        let mut alloc = ShardAllocator::new();
        let ShardAllocResult::Allocated(s0) = alloc.allocate() else {
            panic!("expected allocation");
        };
        let ShardAllocResult::Allocated(s1) = alloc.allocate() else {
            panic!("expected allocation");
        };
        // Both allocated — destination is occupied.
        let result = alloc.relocate(s0, s1);
        assert_eq!(result, ShardRelocateResult::DestinationOccupied);
    }
}
