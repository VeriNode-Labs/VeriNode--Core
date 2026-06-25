//! Concurrent reputation-update race tests (#3).

use proptest::prelude::*;
use sorosusu_contracts::reputation::score::{
    ReputationLedger, ReputationSource, REPUTATION_MAX,
};

const NODE: u32 = 1;

/// Blueprint step 5: a successful attestation and a slashing event for the same
/// node both apply, regardless of order — final score is `750 + 10 - 500 = 260`,
/// never the lost-update `760` or the dropped-reward `250`.
#[test]
fn concurrent_attestation_and_slash_apply_both() {
    // Order A: reward then slash.
    let mut a = ReputationLedger::new();
    a.set_initial_score(NODE, 750);
    a.update_reputation(NODE, ReputationSource::AttestationReward);
    a.update_reputation(NODE, ReputationSource::Slashing);

    // Order B: slash then reward.
    let mut b = ReputationLedger::new();
    b.set_initial_score(NODE, 750);
    b.update_reputation(NODE, ReputationSource::Slashing);
    b.update_reputation(NODE, ReputationSource::AttestationReward);

    assert_eq!(a.score(NODE), 260);
    assert_eq!(b.score(NODE), 260);
    assert_ne!(a.score(NODE), 760); // reward did not clobber the slash
    assert_ne!(a.score(NODE), 250); // slash did not drop the reward
}

/// The slashing invariant: a slash always reduces the score by exactly 500.
#[test]
fn slash_always_reduces_by_500() {
    let mut ledger = ReputationLedger::new();
    ledger.set_initial_score(NODE, 750);
    let prior = ledger.score(NODE);

    ledger.update_reputation(NODE, ReputationSource::Slashing);

    assert_eq!(ledger.score(NODE), prior - 500);
    assert_eq!(ledger.slash_count(NODE), 1);
}

/// A duplicate slash carrying an already-consumed sequence number is skipped;
/// the genuine next slash still applies.
#[test]
fn duplicate_slash_is_skipped() {
    let mut ledger = ReputationLedger::new();
    ledger.set_initial_score(NODE, 750);

    assert!(ledger.try_slash(NODE, 1));
    assert_eq!(ledger.slash_count(NODE), 1);
    assert_eq!(ledger.score(NODE), 250);

    // Replay of the same slash (expected count 1 again) is rejected.
    assert!(!ledger.try_slash(NODE, 1));
    assert_eq!(ledger.slash_count(NODE), 1);
    assert_eq!(ledger.score(NODE), 250);

    // The real next slash applies.
    assert!(ledger.try_slash(NODE, 2));
    assert_eq!(ledger.score(NODE), -250);
    assert_eq!(ledger.slash_count(NODE), 2);
}

/// The summed score is clamped to the reputation range.
#[test]
fn score_is_clamped_to_range() {
    let mut ledger = ReputationLedger::new();
    ledger.set_initial_score(NODE, 900);
    for _ in 0..50 {
        ledger.update_reputation(NODE, ReputationSource::AttestationReward); // +500 total
    }
    assert_eq!(ledger.score(NODE), REPUTATION_MAX); // 1400 clamped to 1000
}

fn source_of(byte: u8) -> ReputationSource {
    match byte % 3 {
        0 => ReputationSource::AttestationReward,
        1 => ReputationSource::AttestationFailure,
        _ => ReputationSource::Slashing,
    }
}

proptest! {
    /// The append-only log is order-independent: applying the same multiset of
    /// adjustments in any order yields the same score (the race that dropped
    /// updates cannot occur).
    #[test]
    fn prop_score_is_order_independent(
        seq in prop::collection::vec(any::<u8>(), 0..40),
        initial in -1000_i64..=1000,
    ) {
        let mut forward = ReputationLedger::new();
        forward.set_initial_score(NODE, initial);
        for &b in &seq {
            forward.update_reputation(NODE, source_of(b));
        }

        let mut reversed = ReputationLedger::new();
        reversed.set_initial_score(NODE, initial);
        for &b in seq.iter().rev() {
            reversed.update_reputation(NODE, source_of(b));
        }

        prop_assert_eq!(forward.score(NODE), reversed.score(NODE));
        prop_assert_eq!(forward.slash_count(NODE), reversed.slash_count(NODE));
    }
}
