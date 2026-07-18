use soroban_sdk::Env; // bring in crate for test context if needed

use sorosusu_contracts::slashing::evidence_verifier::*;

#[test]
fn surround_vote_at_window_boundary_is_valid_and_one_past_is_expired() {
    // earliest infraction at slot 1000 (from source_epoch)
    let source_epoch = 1000 / SLOTS_PER_EPOCH;
    let target_epoch = source_epoch + 1; // a surround that spans into next epoch
    let ev = SlashingEvidence::new(None, Some(source_epoch), Some(target_epoch));

    let earliest_start = evidence_infraction_slot_range(&ev).0;
    let boundary_slot = earliest_start + MAX_SLASHING_WINDOW; // inclusive boundary

    // At boundary: still valid
    let expired_at_boundary = verify_evidence_expiry(&ev, boundary_slot);
    assert_eq!(expired_at_boundary, false, "evidence at boundary should be valid");

    // One slot past boundary: expired
    let expired_one_past = verify_evidence_expiry(&ev, boundary_slot + 1);
    assert_eq!(expired_one_past, true, "evidence one past boundary should be expired");
}

use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_evidence_window_symmetry(slot in 0u64..1_000_000u64, src_epoch in 0u64..1000u64, tgt_epoch in 0u64..1000u64, current_slot in 0u64..2_000_000u64) {
        // Build evidence with random fields
        let ev = SlashingEvidence::new(Some(slot), Some(src_epoch), Some(tgt_epoch));
        let (start, _end) = evidence_infraction_slot_range(&ev);
        let valid_until = start.saturating_add(MAX_SLASHING_WINDOW);

        // Manual determination: not expired if current_slot <= valid_until
        let manual_not_expired = current_slot <= valid_until;
        let func_not_expired = !verify_evidence_expiry(&ev, current_slot);

        prop_assert_eq!(manual_not_expired, func_not_expired);
    }
}
