//! Committee root cache with reorg support.
//!
//! This module provides a cache for committee roots that handles mid-epoch
//! reorganizations. During a reorg window, both the old and new committee
//! roots are retained to allow attestation verification for validators
//! that may be using either root.

extern crate alloc;
use crate::crypto::merkle::Hash256;
use crate::validator::committee_assignment::{CommitteeView, SLOTS_PER_EPOCH};
use alloc::collections::BTreeMap;

/// A cache entry that may contain one or two committee roots.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CacheEntry {
    /// Primary committee root
    primary_root: Hash256,
    /// Optional secondary root during reorg window
    secondary_root: Option<Hash256>,
    /// Slot at which this entry becomes fully stable (no secondary root)
    stable_at_slot: u64,
}

impl CacheEntry {
    /// Create a stable cache entry with a single root.
    fn stable(root: Hash256, slot: u64) -> Self {
        Self {
            primary_root: root,
            secondary_root: None,
            stable_at_slot: slot,
        }
    }

    /// Create an ambiguous cache entry during reorg.
    fn ambiguous(old_root: Hash256, new_root: Hash256, reorg_end_slot: u64) -> Self {
        Self {
            primary_root: new_root,
            secondary_root: Some(old_root),
            stable_at_slot: reorg_end_slot,
        }
    }

    /// Convert to a committee view based on current slot.
    fn to_committee_view(&self, current_slot: u64) -> CommitteeView {
        if current_slot < self.stable_at_slot {
            if let Some(old_root) = self.secondary_root {
                return CommitteeView::ambiguous(old_root, self.primary_root);
            }
        }
        CommitteeView::stable(self.primary_root)
    }

    /// Check if this entry is fully stable at the given slot.
    fn is_stable(&self, slot: u64) -> bool {
        slot >= self.stable_at_slot
    }
}

/// Committee root cache with automatic cleanup.
#[derive(Clone, Debug)]
pub struct CommitteeCache {
    /// Map from epoch to cache entry
    cache: BTreeMap<u64, CacheEntry>,
    /// Maximum number of epochs to retain in cache
    max_epochs: usize,
}

impl CommitteeCache {
    /// Create a new committee cache.
    pub fn new() -> Self {
        Self::with_capacity(256) // Default: ~256 epochs (about 27 hours)
    }

    /// Create a new committee cache with specified capacity.
    pub fn with_capacity(max_epochs: usize) -> Self {
        Self {
            cache: BTreeMap::new(),
            max_epochs,
        }
    }

    /// Store a stable committee root for an epoch.
    pub fn store_stable(&mut self, epoch: u64, root: Hash256) {
        let slot = epoch * SLOTS_PER_EPOCH;
        self.cache.insert(epoch, CacheEntry::stable(root, slot));
        self.evict_old_entries(epoch);
    }

    /// Store an ambiguous committee root during a reorg.
    pub fn store_ambiguous(
        &mut self,
        epoch: u64,
        old_root: Hash256,
        new_root: Hash256,
        reorg_end_slot: u64,
    ) {
        self.cache.insert(
            epoch,
            CacheEntry::ambiguous(old_root, new_root, reorg_end_slot),
        );
        self.evict_old_entries(epoch);
    }

    /// Get the committee view for an epoch at a specific slot.
    pub fn get_committee_view(&self, epoch: u64, current_slot: u64) -> Option<CommitteeView> {
        self.cache
            .get(&epoch)
            .map(|entry| entry.to_committee_view(current_slot))
    }

    /// Finalize a reorg by removing the secondary root for an epoch.
    pub fn finalize_reorg(&mut self, epoch: u64, current_slot: u64) {
        if let Some(entry) = self.cache.get_mut(&epoch) {
            if entry.is_stable(current_slot) {
                // Convert to stable entry
                let primary = entry.primary_root;
                *entry = CacheEntry::stable(primary, current_slot);
            }
        }
    }

    /// Evict old cache entries to maintain the size limit.
    fn evict_old_entries(&mut self, _current_epoch: u64) {
        while self.cache.len() > self.max_epochs {
            // Remove the oldest entry (smallest epoch)
            if let Some(&oldest_epoch) = self.cache.keys().next() {
                self.cache.remove(&oldest_epoch);
            } else {
                break;
            }
        }
    }

    /// Clear all cache entries.
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Get the number of cached epochs.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl Default for CommitteeCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_retrieve_stable() {
        let mut cache = CommitteeCache::new();
        let root = [42u8; 32];
        let epoch = 100;

        cache.store_stable(epoch, root);

        let view = cache.get_committee_view(epoch, epoch * SLOTS_PER_EPOCH);
        assert_eq!(view, Some(CommitteeView::stable(root)));
    }

    #[test]
    fn test_store_and_retrieve_ambiguous() {
        let mut cache = CommitteeCache::new();
        let old_root = [1u8; 32];
        let new_root = [2u8; 32];
        let epoch = 100;
        let trigger_slot = epoch * SLOTS_PER_EPOCH + 5;
        let reorg_end_slot = trigger_slot + 4;

        cache.store_ambiguous(epoch, old_root, new_root, reorg_end_slot);

        // During reorg window: ambiguous view
        let view = cache.get_committee_view(epoch, trigger_slot + 1);
        match view {
            Some(CommitteeView::Ambiguous {
                old_root: o,
                new_root: n,
            }) => {
                assert_eq!(o, old_root);
                assert_eq!(n, new_root);
            }
            _ => panic!("Expected ambiguous view during reorg window"),
        }

        // After reorg window: stable view with new root
        let view = cache.get_committee_view(epoch, reorg_end_slot);
        assert_eq!(view, Some(CommitteeView::stable(new_root)));
    }

    #[test]
    fn test_finalize_reorg() {
        let mut cache = CommitteeCache::new();
        let old_root = [1u8; 32];
        let new_root = [2u8; 32];
        let epoch = 100;
        let trigger_slot = epoch * SLOTS_PER_EPOCH + 5;
        let reorg_end_slot = trigger_slot + 4;

        cache.store_ambiguous(epoch, old_root, new_root, reorg_end_slot);

        // Finalize reorg
        cache.finalize_reorg(epoch, reorg_end_slot);

        // Should now be stable
        let view = cache.get_committee_view(epoch, trigger_slot + 1);
        assert_eq!(view, Some(CommitteeView::stable(new_root)));
    }

    #[test]
    fn test_eviction() {
        let mut cache = CommitteeCache::with_capacity(3);
        let root1 = [1u8; 32];
        let root2 = [2u8; 32];
        let root3 = [3u8; 32];
        let root4 = [4u8; 32];

        cache.store_stable(100, root1);
        cache.store_stable(101, root2);
        cache.store_stable(102, root3);
        assert_eq!(cache.len(), 3);

        // Adding 4th entry should evict oldest
        cache.store_stable(103, root4);
        assert_eq!(cache.len(), 3);

        // Epoch 100 should be evicted
        assert!(cache
            .get_committee_view(100, 100 * SLOTS_PER_EPOCH)
            .is_none());
        // Epoch 101-103 should still be present
        assert!(cache
            .get_committee_view(101, 101 * SLOTS_PER_EPOCH)
            .is_some());
    }

    #[test]
    fn test_clear() {
        let mut cache = CommitteeCache::new();
        cache.store_stable(100, [1u8; 32]);
        cache.store_stable(101, [2u8; 32]);
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }
}
