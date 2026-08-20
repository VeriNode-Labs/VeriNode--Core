//! Committee assignment and root computation with reorg support.
//!
//! When a validator set reorganization occurs mid-epoch (e.g., due to an
//! irregular exit or late-inclusion activation), the committee composition
//! changes. This module tracks pending reorgs and provides committee views
//! that support attestation verification across the reorg boundary.

extern crate alloc;
use crate::crypto::merkle::Hash256;
use crate::crypto::sha256::sha256;
use crate::validator::exit_queue::ValidatorIndex;
use alloc::vec::Vec;

/// Constants from Ethereum beacon chain specification
pub const SLOTS_PER_EPOCH: u64 = 32;
pub const SHARD_COMMITTEE_PERIOD: u64 = 256; // epochs

/// A window during which a validator set reorg is active.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingReorg {
    /// Slot at which the reorg was triggered
    pub trigger_slot: u64,
    /// Slot at which the reorg window ends (typically trigger_slot + 4)
    pub end_slot: u64,
}

impl PendingReorg {
    /// Create a new pending reorg starting at `trigger_slot`.
    /// The reorg window extends for 4 slots to allow cross-boundary attestations.
    pub fn new(trigger_slot: u64) -> Self {
        Self {
            trigger_slot,
            end_slot: trigger_slot + 4,
        }
    }

    /// Check if the given slot falls within the reorg window.
    pub fn is_active(&self, slot: u64) -> bool {
        slot >= self.trigger_slot && slot < self.end_slot
    }
}

/// A committee view that may contain one or two roots depending on reorg status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitteeView {
    /// Normal operation: single committee root
    Stable(Hash256),
    /// During reorg window: both old and new roots are valid
    Ambiguous {
        old_root: Hash256,
        new_root: Hash256,
    },
}

impl CommitteeView {
    /// Create a stable committee view with a single root.
    pub fn stable(root: Hash256) -> Self {
        Self::Stable(root)
    }

    /// Create an ambiguous committee view with both old and new roots.
    pub fn ambiguous(old_root: Hash256, new_root: Hash256) -> Self {
        Self::Ambiguous { old_root, new_root }
    }

    /// Check if a given root matches this committee view.
    /// For stable views, only the single root matches.
    /// For ambiguous views, either root matches.
    pub fn matches(&self, candidate: &Hash256) -> bool {
        match self {
            Self::Stable(root) => root == candidate,
            Self::Ambiguous { old_root, new_root } => {
                old_root == candidate || new_root == candidate
            }
        }
    }
}

/// Committee assignment tracker with reorg support.
#[derive(Clone, Debug)]
pub struct CommitteeAssignment {
    /// Current validator indices in the committee
    validator_indices: Vec<ValidatorIndex>,
    /// Optional pending reorg state
    pending_reorg: Option<PendingReorg>,
    /// Pre-reorg validator indices (only valid during reorg)
    old_validator_indices: Option<Vec<ValidatorIndex>>,
}

impl CommitteeAssignment {
    /// Create a new committee assignment with the given validator indices.
    pub fn new(validator_indices: Vec<ValidatorIndex>) -> Self {
        Self {
            validator_indices,
            pending_reorg: None,
            old_validator_indices: None,
        }
    }

    /// Trigger a validator set reorganization at the given slot.
    /// This captures the current validator set as "old" and prepares
    /// for a new set to be provided.
    pub fn trigger_reorg(&mut self, slot: u64) {
        self.old_validator_indices = Some(self.validator_indices.clone());
        self.pending_reorg = Some(PendingReorg::new(slot));
    }

    /// Update the validator set during or after a reorg.
    pub fn update_validator_set(&mut self, new_indices: Vec<ValidatorIndex>) {
        self.validator_indices = new_indices;
    }

    /// Finalize the reorg, discarding the old validator set.
    /// This should be called after the reorg window closes.
    pub fn finalize_reorg(&mut self, current_slot: u64) {
        if let Some(reorg) = self.pending_reorg {
            if current_slot >= reorg.end_slot {
                self.old_validator_indices = None;
                self.pending_reorg = None;
            }
        }
    }

    /// Get the current committee view for the given slot.
    pub fn get_committee_view(&self, _slot: u64) -> CommitteeView {
        // Check if we're in a reorg window
        if let Some(_reorg) = self.pending_reorg {
            if self.old_validator_indices.is_some() {
                // During reorg window or until finalized: return ambiguous view
                let old_root =
                    self.compute_committee_root(self.old_validator_indices.as_ref().unwrap());
                let new_root = self.compute_committee_root(&self.validator_indices);
                return CommitteeView::ambiguous(old_root, new_root);
            }
        }

        // Normal operation: return stable view
        let root = self.compute_committee_root(&self.validator_indices);
        CommitteeView::stable(root)
    }

    /// Compute the committee root from a list of validator indices.
    /// The root is a SHA-256 hash over the sorted validator indices.
    fn compute_committee_root(&self, indices: &[ValidatorIndex]) -> Hash256 {
        let mut sorted = indices.to_vec();
        sorted.sort_unstable();

        // Serialize indices as little-endian u64 values
        let mut data = Vec::with_capacity(sorted.len() * 8);
        for &index in &sorted {
            data.extend_from_slice(&index.to_le_bytes());
        }

        sha256(&data)
    }

    /// Get the current validator indices.
    pub fn validator_indices(&self) -> &[ValidatorIndex] {
        &self.validator_indices
    }

    /// Get the pending reorg state, if any.
    pub fn pending_reorg(&self) -> Option<PendingReorg> {
        self.pending_reorg
    }
}

/// Compute a beacon committee for a given slot and epoch.
/// This is a simplified version that returns validator indices for a committee.
/// In production, this would implement the full shuffle algorithm.
pub fn get_beacon_committee(
    validator_indices: &[ValidatorIndex],
    slot: u64,
    _committee_index: u64,
) -> Vec<ValidatorIndex> {
    // Simplified: return a subset based on slot
    // In production, this would use the RANDAO-based shuffle
    let start = (slot as usize % validator_indices.len()).min(validator_indices.len());
    let end = (start + 8).min(validator_indices.len());
    validator_indices[start..end].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pending_reorg_window() {
        let reorg = PendingReorg::new(100);
        assert_eq!(reorg.trigger_slot, 100);
        assert_eq!(reorg.end_slot, 104);

        assert!(!reorg.is_active(99));
        assert!(reorg.is_active(100));
        assert!(reorg.is_active(103));
        assert!(!reorg.is_active(104));
    }

    #[test]
    fn test_committee_view_matches() {
        let root1 = [1u8; 32];
        let root2 = [2u8; 32];
        let root3 = [3u8; 32];

        let stable = CommitteeView::stable(root1);
        assert!(stable.matches(&root1));
        assert!(!stable.matches(&root2));

        let ambiguous = CommitteeView::ambiguous(root1, root2);
        assert!(ambiguous.matches(&root1));
        assert!(ambiguous.matches(&root2));
        assert!(!ambiguous.matches(&root3));
    }

    #[test]
    fn test_committee_assignment_stable() {
        let indices = vec![10, 20, 30, 40];
        let assignment = CommitteeAssignment::new(indices.clone());

        let view = assignment.get_committee_view(100);
        match view {
            CommitteeView::Stable(_) => {
                // Expected
            }
            _ => panic!("Expected stable view"),
        }
    }

    #[test]
    fn test_committee_assignment_reorg() {
        let indices = vec![10, 20, 30, 40];
        let mut assignment = CommitteeAssignment::new(indices.clone());

        // Trigger reorg at slot 100
        assignment.trigger_reorg(100);

        // Update to new validator set
        let new_indices = vec![10, 20, 30, 50]; // validator 40 exited, 50 joined
        assignment.update_validator_set(new_indices);

        // During reorg window, view should be ambiguous
        let view = assignment.get_committee_view(101);
        match view {
            CommitteeView::Ambiguous { old_root, new_root } => {
                assert_ne!(old_root, new_root);
            }
            _ => panic!("Expected ambiguous view during reorg window"),
        }

        // After reorg window, should finalize to stable
        assignment.finalize_reorg(104);
        let view = assignment.get_committee_view(105);
        match view {
            CommitteeView::Stable(_) => {
                // Expected
            }
            _ => panic!("Expected stable view after reorg window"),
        }
    }

    #[test]
    fn test_committee_root_computation() {
        let indices1 = vec![30, 10, 20]; // Unsorted
        let indices2 = vec![10, 20, 30]; // Sorted (same set)
        let indices3 = vec![10, 20, 40]; // Different set

        let assignment1 = CommitteeAssignment::new(indices1);
        let assignment2 = CommitteeAssignment::new(indices2);
        let assignment3 = CommitteeAssignment::new(indices3);

        let root1 = assignment1.compute_committee_root(&assignment1.validator_indices);
        let root2 = assignment2.compute_committee_root(&assignment2.validator_indices);
        let root3 = assignment3.compute_committee_root(&assignment3.validator_indices);

        // Same validator set should produce same root regardless of input order
        assert_eq!(root1, root2);
        // Different validator set should produce different root
        assert_ne!(root1, root3);
    }
}
