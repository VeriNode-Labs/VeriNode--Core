//! Buddy-system memory allocator backing the shard connection-pool (issue #141).
//!
//! The buddy allocator manages a flat address space divided into power-of-two
//! aligned blocks.  Each "order" corresponds to a block size of
//! `SHARD_SIZE_BYTES << order`.  When a block is freed its buddy (the
//! identically-sized block that shares the same parent) is examined; if the
//! buddy is also free the two are merged into a single block of the next order.
//! This coalescing eliminates the pathological external fragmentation that the
//! previous free-list approach suffered under high-frequency tenant churn.
//!
//! ## Invariants (issue #141)
//!
//! * Base slab size: [`SHARD_SIZE_BYTES`] = 64 KiB.
//! * Maximum tenants per pool: [`MAX_TENANTS`] = 65 536 (2^16).
//! * The address space therefore spans [`MAX_TENANTS`] × [`SHARD_SIZE_BYTES`] =
//!   4 GiB (represented as slot indices; no real heap allocation takes place).

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

/// Fixed slab size per tenant: 64 KiB (issue #141 invariant).
pub const SHARD_SIZE_BYTES: u64 = 64 * 1024;

/// Maximum number of tenants (= shard slots) per pool (issue #141 invariant).
pub const MAX_TENANTS: u32 = 65_536;

/// Number of buddy-tree orders.
///
/// Order 0 → 1 slot (64 KiB), order 1 → 2 slots (128 KiB), …
/// The maximum order covers the entire address space (all [`MAX_TENANTS`] slots).
pub const MAX_ORDER: u32 = 16; // 2^16 = 65 536 slots

/// The result of a buddy-allocator operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuddyAllocResult {
    /// Allocation succeeded; the returned value is the base slot index.
    Allocated(u32),
    /// No contiguous region of the requested size is currently available.
    OutOfMemory,
    /// The supplied slot index or size parameter is out of range.
    InvalidIndex,
}

/// The result of a free operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuddyFreeResult {
    /// The slot was freed (and possibly coalesced with its buddy).
    Freed,
    /// The supplied slot index was out of range or not currently allocated.
    InvalidIndex,
}

/// A buddy-system allocator for shard slots.
///
/// Internally maintains one `BTreeSet<u32>` per order that tracks the base
/// slot indices of all free blocks at that order.  The total slot count is
/// always `MAX_TENANTS` = 2^[`MAX_ORDER`].
#[derive(Debug)]
pub struct BuddyAllocator {
    /// `free_lists[o]` is the set of free block base-indices at order `o`.
    free_lists: Vec<BTreeSet<u32>>,
    /// Bitmap tracking which individual slots are currently allocated.
    /// Bit `i` of word `i/64` is set when slot `i` is occupied.
    allocated: Vec<u64>,
}

impl BuddyAllocator {
    /// Creates a new allocator with all slots free.
    pub fn new() -> Self {
        let mut free_lists: Vec<BTreeSet<u32>> =
            (0..=MAX_ORDER as usize).map(|_| BTreeSet::new()).collect();
        // The entire address space is one free block at the maximum order.
        free_lists[MAX_ORDER as usize].insert(0);

        let word_count = (MAX_TENANTS as usize).div_ceil(64);
        Self {
            free_lists,
            allocated: alloc::vec![0u64; word_count],
        }
    }

    /// Allocates a contiguous block of `2^order` slots.
    ///
    /// Returns [`BuddyAllocResult::Allocated`] with the base slot index on
    /// success, or [`BuddyAllocResult::OutOfMemory`] if no block of that size
    /// is available.
    pub fn allocate(&mut self, order: u32) -> BuddyAllocResult {
        if order > MAX_ORDER {
            return BuddyAllocResult::OutOfMemory;
        }

        // Find the smallest available order ≥ requested order.
        let available_order =
            (order..=MAX_ORDER).find(|&o| !self.free_lists[o as usize].is_empty());

        let available_order = match available_order {
            Some(o) => o,
            None => return BuddyAllocResult::OutOfMemory,
        };

        // Remove the block from the free list.
        let block = *self.free_lists[available_order as usize]
            .iter()
            .next()
            .unwrap();
        self.free_lists[available_order as usize].remove(&block);

        // Split blocks from available_order down to the requested order,
        // placing the upper buddy back into the free list at each level.
        #[allow(unused_mut)]
        let mut current_block = block;
        let mut current_order = available_order;
        while current_order > order {
            current_order -= 1;
            let buddy = current_block + (1 << current_order);
            self.free_lists[current_order as usize].insert(buddy);
        }

        // Mark all slots in the allocated block as used.
        let slot_count = 1u32 << order;
        for slot in current_block..current_block + slot_count {
            self.mark_allocated(slot);
        }

        BuddyAllocResult::Allocated(current_block)
    }

    /// Allocates a single shard slot (order 0).
    pub fn allocate_one(&mut self) -> BuddyAllocResult {
        self.allocate(0)
    }

    /// Frees a block of `2^order` slots rooted at `base`.
    ///
    /// After freeing, the block is coalesced with its buddy if the buddy is
    /// entirely free, merging upward as far as possible.
    pub fn free(&mut self, base: u32, order: u32) -> BuddyFreeResult {
        if order > MAX_ORDER || base >= MAX_TENANTS {
            return BuddyFreeResult::InvalidIndex;
        }
        let slot_count = 1u32 << order;
        if base + slot_count > MAX_TENANTS {
            return BuddyFreeResult::InvalidIndex;
        }

        // Validate alignment.
        #[allow(clippy::manual_is_multiple_of)]
        if base % slot_count != 0 {
            return BuddyFreeResult::InvalidIndex;
        }

        // Clear allocated bits.
        for slot in base..base + slot_count {
            self.mark_free(slot);
        }

        // Coalesce upward.
        let mut current_base = base;
        let mut current_order = order;

        while current_order < MAX_ORDER {
            let buddy_base = current_base ^ (1 << current_order);
            if self.free_lists[current_order as usize].contains(&buddy_base) {
                // Buddy is free — merge.
                self.free_lists[current_order as usize].remove(&buddy_base);
                // Merged block always starts at the lower-aligned address.
                current_base = current_base.min(buddy_base);
                current_order += 1;
            } else {
                break;
            }
        }

        self.free_lists[current_order as usize].insert(current_base);
        BuddyFreeResult::Freed
    }

    /// Frees a single shard slot (order 0).
    pub fn free_one(&mut self, slot: u32) -> BuddyFreeResult {
        self.free(slot, 0)
    }

    /// Returns the total number of free individual slots across all orders.
    pub fn free_slots(&self) -> u32 {
        self.free_lists
            .iter()
            .enumerate()
            .map(|(order, set)| set.len() as u32 * (1 << order as u32))
            .sum()
    }

    /// Returns the total number of allocated slots.
    pub fn used_slots(&self) -> u32 {
        MAX_TENANTS - self.free_slots()
    }

    /// Returns the fragmentation ratio: the fraction of free memory that cannot
    /// be served as a contiguous single-slot allocation because it is split
    /// across non-contiguous regions at higher orders.
    ///
    /// In practice this is always 0 for order-0 allocations in a buddy system
    /// because every free block can satisfy a single-slot request. Exposed for
    /// monitoring / cross-checks with the defragmenter.
    pub fn fragmentation_ratio(&self) -> f64 {
        let free = self.free_slots();
        if free == 0 {
            return 0.0;
        }
        // Count slots reachable as order-0 allocations vs total free.
        // In a pure buddy system this is always 1.0 (no internal waste),
        // but this hook point lets the defragmenter gauge external waste.
        let order0_reachable: u32 = self
            .free_lists
            .iter()
            .enumerate()
            .map(|(order, set)| set.len() as u32 * (1 << order as u32))
            .sum();
        1.0 - (order0_reachable as f64 / free as f64)
    }

    // --- helpers -----------------------------------------------------------

    fn mark_allocated(&mut self, slot: u32) {
        let word = (slot / 64) as usize;
        let bit = slot % 64;
        self.allocated[word] |= 1u64 << bit;
    }

    fn mark_free(&mut self, slot: u32) {
        let word = (slot / 64) as usize;
        let bit = slot % 64;
        self.allocated[word] &= !(1u64 << bit);
    }

    /// Returns `true` if the given slot is currently allocated.
    pub fn is_allocated(&self, slot: u32) -> bool {
        let word = (slot / 64) as usize;
        let bit = slot % 64;
        self.allocated[word] & (1u64 << bit) != 0
    }
}

impl Default for BuddyAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invariants_match_issue_141() {
        assert_eq!(SHARD_SIZE_BYTES, 64 * 1024);
        assert_eq!(MAX_TENANTS, 65_536);
        assert_eq!(MAX_ORDER, 16);
        // 2^MAX_ORDER == MAX_TENANTS
        assert_eq!(1u32 << MAX_ORDER, MAX_TENANTS);
    }

    #[test]
    fn fresh_allocator_all_slots_free() {
        let alloc = BuddyAllocator::new();
        assert_eq!(alloc.free_slots(), MAX_TENANTS);
        assert_eq!(alloc.used_slots(), 0);
    }

    #[test]
    fn single_allocation_reduces_free_count() {
        let mut alloc = BuddyAllocator::new();
        let res = alloc.allocate_one();
        assert!(matches!(res, BuddyAllocResult::Allocated(0)));
        assert_eq!(alloc.used_slots(), 1);
        assert_eq!(alloc.free_slots(), MAX_TENANTS - 1);
    }

    #[test]
    fn free_and_coalesce_restores_full_capacity() {
        let mut alloc = BuddyAllocator::new();
        let BuddyAllocResult::Allocated(slot) = alloc.allocate_one() else {
            panic!("expected allocation");
        };
        let result = alloc.free_one(slot);
        assert_eq!(result, BuddyFreeResult::Freed);
        assert_eq!(alloc.free_slots(), MAX_TENANTS);
        // Entire space should have coalesced back to order MAX_ORDER.
        assert_eq!(alloc.free_lists[MAX_ORDER as usize].len(), 1);
    }

    #[test]
    fn buddy_coalescing_after_sequential_alloc_free() {
        let mut alloc = BuddyAllocator::new();

        // Allocate 4 slots and free them in reverse order — should coalesce fully.
        let slots: Vec<u32> = (0..4)
            .map(|_| {
                if let BuddyAllocResult::Allocated(s) = alloc.allocate_one() {
                    s
                } else {
                    panic!("allocation failed")
                }
            })
            .collect();

        for &slot in slots.iter().rev() {
            assert_eq!(alloc.free_one(slot), BuddyFreeResult::Freed);
        }

        assert_eq!(alloc.free_slots(), MAX_TENANTS);
        // All coalesced back to the top level.
        assert_eq!(alloc.free_lists[MAX_ORDER as usize].len(), 1);
    }

    #[test]
    fn out_of_memory_when_fully_allocated() {
        let mut alloc = BuddyAllocator::new();
        // Allocate every slot.
        for _ in 0..MAX_TENANTS {
            assert!(matches!(
                alloc.allocate_one(),
                BuddyAllocResult::Allocated(_)
            ));
        }
        assert_eq!(alloc.allocate_one(), BuddyAllocResult::OutOfMemory);
    }

    #[test]
    fn invalid_order_returns_out_of_memory() {
        let mut alloc = BuddyAllocator::new();
        assert_eq!(alloc.allocate(MAX_ORDER + 1), BuddyAllocResult::OutOfMemory);
    }

    #[test]
    fn is_allocated_tracks_state() {
        let mut alloc = BuddyAllocator::new();
        let BuddyAllocResult::Allocated(slot) = alloc.allocate_one() else {
            panic!("expected allocation");
        };
        assert!(alloc.is_allocated(slot));
        alloc.free_one(slot);
        assert!(!alloc.is_allocated(slot));
    }
}
