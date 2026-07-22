//! Integration tests for mid-epoch validator set reorganization and
//! cross-boundary attestation verification.
//!
//! These tests verify that when a validator set is dynamically reorganized
//! mid-epoch (triggered by an irregular exit or late-inclusion activation),
//! attestations can still be verified using either the pre-reorg or post-reorg
//! committee root during the reorg window.

use sorosusu_contracts::attestation::verifier::{
    AttestationData, SecretKey, Signature,
    sign_attestation, verify_attestation_with_committee_view,
};
use sorosusu_contracts::attestation::bitfield::AttestationBitfield;
use sorosusu_contracts::crypto::domain::Domain;
use sorosusu_contracts::validator::committee_assignment::{
    CommitteeAssignment, CommitteeView, SLOTS_PER_EPOCH,
};
use sorosusu_contracts::validator::validator_set::ValidatorSet;
use sorosusu_contracts::validator::exit_queue::ValidatorIndex;
use sorosusu_contracts::db::committee_cache::CommitteeCache;

/// Helper to create a test attestation data
fn create_test_attestation(slot: u64, index: u64) -> AttestationData {
    AttestationData {
        slot,
        index,
        beacon_block_root: [0u8; 32],
        source_epoch: slot / SLOTS_PER_EPOCH - 1,
        source_root: [1u8; 32],
        target_epoch: slot / SLOTS_PER_EPOCH,
        target_root: [2u8; 32],
    }
}

/// Helper to create test keys
fn create_test_keys(count: usize) -> Vec<SecretKey> {
    (0..count)
        .map(|i| {
            let mut key = [0u8; 32];
            key[0] = i as u8;
            key
        })
        .collect()
}

/// Helper to create signatures for a committee
fn create_signatures(
    keys: &[SecretKey],
    domain: &Domain,
    data: &AttestationData,
    attesters: &[bool],
) -> Vec<Signature> {
    keys.iter()
        .zip(attesters.iter())
        .map(|(key, &attesting)| {
            if attesting {
                sign_attestation(key, domain, data)
            } else {
                [0u8; 32] // Dummy signature for non-attesters
            }
        })
        .collect()
}

#[test]
fn test_stable_committee_verification() {
    // Setup: stable validator set with no reorg
    let validator_indices: Vec<ValidatorIndex> = vec![10, 20, 30, 40, 50, 60, 70, 80];
    let assignment = CommitteeAssignment::new(validator_indices.clone());
    
    let slot = 3200; // Epoch 100, slot 0
    let committee_view = assignment.get_committee_view(slot);
    
    // Verify it's a stable view
    match committee_view {
        CommitteeView::Stable(_) => {}
        _ => panic!("Expected stable committee view"),
    }
    
    // Create attestation
    let domain = [0u8; 8];
    let data = create_test_attestation(slot, 0);
    let keys = create_test_keys(validator_indices.len());
    
    // All validators attest
    let attesters = vec![true; validator_indices.len()];
    let signatures = create_signatures(&keys, &domain, &data, &attesters);
    
    // Create bitfield
    let mut bitfield = AttestationBitfield::with_committee_size(validator_indices.len()).unwrap();
    for i in 0..validator_indices.len() {
        bitfield.set(i, true).unwrap();
    }
    
    // Get committee root from view
    let committee_root = match committee_view {
        CommitteeView::Stable(root) => root,
        _ => panic!("Expected stable view"),
    };
    
    // Verify attestation
    let result = verify_attestation_with_committee_view(
        &bitfield,
        &keys,
        &domain,
        &data,
        &signatures,
        &committee_view,
        &committee_root,
    );
    
    assert!(result, "Attestation verification should succeed with stable committee");
}

#[test]
fn test_mid_epoch_exit_creates_ambiguous_view() {
    // Setup: validator set with mid-epoch exit
    let initial_indices: Vec<ValidatorIndex> = vec![10, 20, 30, 40, 50, 60, 70, 80];
    let mut assignment = CommitteeAssignment::new(initial_indices.clone());
    
    let epoch = 100;
    let epoch_start_slot = epoch * SLOTS_PER_EPOCH;
    let exit_slot = epoch_start_slot + 3; // Exit happens at slot 3 of epoch
    
    // Trigger reorg due to irregular exit
    assignment.trigger_reorg(exit_slot);
    
    // Validator 40 exits, update the set
    let new_indices: Vec<ValidatorIndex> = vec![10, 20, 30, 50, 60, 70, 80]; // 40 removed
    assignment.update_validator_set(new_indices);
    
    // During reorg window (slots 3-6), view should be ambiguous
    let view_during_reorg = assignment.get_committee_view(exit_slot + 1);
    
    match view_during_reorg {
        CommitteeView::Ambiguous { old_root, new_root } => {
            assert_ne!(old_root, new_root, "Old and new roots should differ");
        }
        _ => panic!("Expected ambiguous view during reorg window"),
    }
    
    // After reorg window, finalize
    assignment.finalize_reorg(exit_slot + 4);
    let view_after_reorg = assignment.get_committee_view(exit_slot + 4);
    
    match view_after_reorg {
        CommitteeView::Stable(_) => {}
        _ => panic!("Expected stable view after reorg window"),
    }
}

#[test]
fn test_cross_boundary_attestation_verification() {
    // This test simulates the core issue: attestations from validators
    // using the pre-reorg committee root should still verify during the
    // reorg window.
    
    let initial_indices: Vec<ValidatorIndex> = vec![10, 20, 30, 40];
    let mut assignment = CommitteeAssignment::new(initial_indices.clone());
    
    let epoch = 100;
    let epoch_start_slot = epoch * SLOTS_PER_EPOCH;
    let reorg_slot = epoch_start_slot + 2;
    
    // Get old committee root before reorg
    let old_view = assignment.get_committee_view(reorg_slot);
    let old_root = match old_view {
        CommitteeView::Stable(root) => root,
        _ => panic!("Expected stable view before reorg"),
    };
    
    // Validator creates attestation using old committee assignment
    let domain = [0u8; 8];
    let data = create_test_attestation(reorg_slot, 0);
    let keys = create_test_keys(4);
    let attesters = vec![true, true, true, true];
    let signatures = create_signatures(&keys, &domain, &data, &attesters);
    
    let mut bitfield = AttestationBitfield::with_committee_size(4).unwrap();
    for i in 0..4 {
        bitfield.set(i, true).unwrap();
    }
    
    // Trigger reorg (validator 40 exits, 50 joins)
    assignment.trigger_reorg(reorg_slot);
    let new_indices: Vec<ValidatorIndex> = vec![10, 20, 30, 50];
    assignment.update_validator_set(new_indices);
    
    // Get ambiguous view during reorg window
    let ambiguous_view = assignment.get_committee_view(reorg_slot + 1);
    
    // Attestation created with old root should verify during reorg window
    let result = verify_attestation_with_committee_view(
        &bitfield,
        &keys,
        &domain,
        &data,
        &signatures,
        &ambiguous_view,
        &old_root, // Using old committee root
    );
    
    assert!(
        result,
        "Attestation with old committee root should verify during reorg window"
    );
}

#[test]
fn test_late_inclusion_activation() {
    // Test scenario: new validator activates late in an epoch
    let initial_indices: Vec<ValidatorIndex> = vec![10, 20, 30];
    let mut assignment = CommitteeAssignment::new(initial_indices.clone());
    
    let epoch = 100;
    let activation_slot = epoch * SLOTS_PER_EPOCH + 10;
    
    // Trigger reorg due to late activation
    assignment.trigger_reorg(activation_slot);
    
    // New validator 40 activates
    let new_indices: Vec<ValidatorIndex> = vec![10, 20, 30, 40];
    assignment.update_validator_set(new_indices);
    
    // Verify ambiguous view during reorg window
    let view = assignment.get_committee_view(activation_slot + 2);
    
    match view {
        CommitteeView::Ambiguous { old_root, new_root } => {
            assert_ne!(old_root, new_root);
        }
        _ => panic!("Expected ambiguous view after late activation"),
    }
}

#[test]
fn test_committee_cache_reorg_handling() {
    let mut cache = CommitteeCache::new();
    
    let epoch = 100;
    let reorg_slot = epoch * SLOTS_PER_EPOCH + 3;
    let reorg_end_slot = reorg_slot + 4;
    
    let old_root = [1u8; 32];
    let new_root = [2u8; 32];
    
    // Store ambiguous entry during reorg
    cache.store_ambiguous(epoch, old_root, new_root, reorg_end_slot);
    
    // During reorg window: should get ambiguous view
    let view_during = cache.get_committee_view(epoch, reorg_slot + 1).unwrap();
    match view_during {
        CommitteeView::Ambiguous { old_root: o, new_root: n } => {
            assert_eq!(o, old_root);
            assert_eq!(n, new_root);
        }
        _ => panic!("Expected ambiguous view during reorg"),
    }
    
    // After reorg window: should get stable view with new root
    let view_after = cache.get_committee_view(epoch, reorg_end_slot).unwrap();
    match view_after {
        CommitteeView::Stable(root) => {
            assert_eq!(root, new_root);
        }
        _ => panic!("Expected stable view after reorg window"),
    }
}

#[test]
fn test_attestation_verification_fails_with_wrong_root() {
    // Ensure that attestations with completely wrong roots still fail
    let indices: Vec<ValidatorIndex> = vec![10, 20, 30, 40];
    let mut assignment = CommitteeAssignment::new(indices.clone());
    
    let slot = 100;
    assignment.trigger_reorg(slot);
    assignment.update_validator_set(vec![10, 20, 30, 50]);
    
    let view = assignment.get_committee_view(slot + 1);
    
    // Create attestation with valid signatures
    let domain = [0u8; 8];
    let data = create_test_attestation(slot, 0);
    let keys = create_test_keys(4);
    let attesters = vec![true; 4];
    let signatures = create_signatures(&keys, &domain, &data, &attesters);
    
    let mut bitfield = AttestationBitfield::with_committee_size(4).unwrap();
    for i in 0..4 {
        bitfield.set(i, true).unwrap();
    }
    
    // Use a completely wrong committee root
    let wrong_root = [99u8; 32];
    
    let result = verify_attestation_with_committee_view(
        &bitfield,
        &keys,
        &domain,
        &data,
        &signatures,
        &view,
        &wrong_root,
    );
    
    assert!(
        !result,
        "Attestation with wrong committee root should fail verification"
    );
}

#[test]
fn test_multiple_reorgs_in_epoch() {
    // Edge case: multiple reorganizations in the same epoch
    let mut assignment = CommitteeAssignment::new(vec![10, 20, 30, 40]);
    
    let epoch = 100;
    let slot1 = epoch * SLOTS_PER_EPOCH + 2;
    
    // First reorg
    assignment.trigger_reorg(slot1);
    assignment.update_validator_set(vec![10, 20, 30, 50]);
    
    let view1 = assignment.get_committee_view(slot1 + 1);
    assert!(matches!(view1, CommitteeView::Ambiguous { .. }));
    
    // Finalize first reorg
    assignment.finalize_reorg(slot1 + 4);
    
    // Second reorg in same epoch
    let slot2 = epoch * SLOTS_PER_EPOCH + 10;
    assignment.trigger_reorg(slot2);
    assignment.update_validator_set(vec![10, 20, 30, 60]);
    
    let view2 = assignment.get_committee_view(slot2 + 1);
    assert!(matches!(view2, CommitteeView::Ambiguous { .. }));
}

#[test]
fn test_reorg_window_boundaries() {
    // Test precise reorg window boundary conditions
    let mut assignment = CommitteeAssignment::new(vec![10, 20, 30, 40]);
    
    let trigger_slot = 1000;
    assignment.trigger_reorg(trigger_slot);
    assignment.update_validator_set(vec![10, 20, 30, 50]);
    
    // Slot before trigger: should fail (no old indices captured yet in this impl)
    // But after trigger, during window: ambiguous
    assert!(matches!(
        assignment.get_committee_view(trigger_slot),
        CommitteeView::Ambiguous { .. }
    ));
    assert!(matches!(
        assignment.get_committee_view(trigger_slot + 3),
        CommitteeView::Ambiguous { .. }
    ));
    
    // After window closes but before finalize: still ambiguous
    assert!(matches!(
        assignment.get_committee_view(trigger_slot + 4),
        CommitteeView::Ambiguous { .. }
    ));
    
    // After finalize: stable
    assignment.finalize_reorg(trigger_slot + 4);
    assert!(matches!(
        assignment.get_committee_view(trigger_slot + 5),
        CommitteeView::Stable(_)
    ));
}

#[test]
fn test_validator_set_integration() {
    // Integration test with ValidatorSet
    let mut validator_set = ValidatorSet::new();
    
    // Add validators
    for i in [10, 20, 30, 40] {
        validator_set.add_validator(i);
    }
    
    let slot = 1000;
    
    // Trigger reorg in validator set
    validator_set.reorg_validator_set(slot);
    assert_eq!(validator_set.last_reorg_slot(), Some(slot));
    
    // Get active validators for committee assignment
    let active = validator_set.active_validators();
    assert_eq!(active.len(), 4);
    
    let assignment = CommitteeAssignment::new(active);
    let view = assignment.get_committee_view(slot);
    
    // Should be stable (reorg flag in validator_set doesn't auto-trigger in assignment)
    assert!(matches!(view, CommitteeView::Stable(_)));
}

#[test]
fn test_epoch_boundary_reorg() {
    // Test reorg that happens right at epoch boundary
    let mut assignment = CommitteeAssignment::new(vec![10, 20, 30, 40]);
    
    let epoch = 100;
    let epoch_boundary_slot = epoch * SLOTS_PER_EPOCH;
    
    assignment.trigger_reorg(epoch_boundary_slot);
    assignment.update_validator_set(vec![10, 20, 30, 50]);
    
    let view = assignment.get_committee_view(epoch_boundary_slot);
    assert!(matches!(view, CommitteeView::Ambiguous { .. }));
}

#[test]
fn test_attestation_partial_committee() {
    // Test with only some validators attesting
    let indices: Vec<ValidatorIndex> = vec![10, 20, 30, 40, 50, 60];
    let mut assignment = CommitteeAssignment::new(indices.clone());
    
    let slot = 500;
    assignment.trigger_reorg(slot);
    assignment.update_validator_set(vec![10, 20, 30, 40, 50, 70]);
    
    let view = assignment.get_committee_view(slot + 1);
    let root = match &view {
        CommitteeView::Ambiguous { new_root, .. } => *new_root,
        _ => panic!("Expected ambiguous view"),
    };
    
    // Only 4 out of 6 validators attest
    let domain = [0u8; 8];
    let data = create_test_attestation(slot, 0);
    let keys = create_test_keys(6);
    let attesters = vec![true, true, false, true, true, false];
    let signatures = create_signatures(&keys, &domain, &data, &attesters);
    
    let mut bitfield = AttestationBitfield::with_committee_size(6).unwrap();
    for (i, &attesting) in attesters.iter().enumerate() {
        bitfield.set(i, attesting).unwrap();
    }
    
    let result = verify_attestation_with_committee_view(
        &bitfield,
        &keys,
        &domain,
        &data,
        &signatures,
        &view,
        &root,
    );
    
    assert!(result, "Partial attestation should verify correctly");
}
