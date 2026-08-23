//! Integration test: Validator Stake Slashing Condition Verification with Fraud Proofs (#135).
//!
//! Scenario:
//! 1. Validator 1 equivocates (two conflicting blocks at the same height).
//! 2. A challenger submits equivocation evidence with a bond.
//! 3. We fast-forward 7 days (past the challenge period).
//! 4. The challenge expires → slashing is executed.
//! 5. We verify:
//!    - 100 % of the validator's stake is slashed.
//!    - 50 % is burned, 50 % is distributed to active validators.
//!    - The validator cannot be slashed again (idempotency).
//!
//! Additional tests cover unavailability and invalid-proposal slashing, as
//! well as the counter-evidence winning path.

use sorosusu_contracts::consensus::slashing::{
    challenge::{ChallengeManager, ChallengeStatus, CounterEvidenceOutcome, CHALLENGE_PERIOD_SECS},
    detector::{OffenseType, SlashingConditionDetector, UNAVAILABILITY_THRESHOLD},
    evidence::EvidenceStore,
    executor::{ExecutorError, SlashingExecutor, StakeRegistry},
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn pk(id: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[31] = id;
    k
}

fn hash(id: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[31] = id;
    h
}

/// 32 ETH expressed in Gwei.
const STAKE_32_ETH: u64 = 32_000_000_000;

/// Build a valid equivocation evidence payload.
fn equivocation_evidence(height: u64, hash_a_id: u8, hash_b_id: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(72);
    buf.extend_from_slice(&height.to_le_bytes());
    buf.extend_from_slice(&hash(hash_a_id));
    buf.extend_from_slice(&hash(hash_b_id));
    buf
}

/// Build a valid unavailability evidence payload.
#[allow(dead_code)]
fn unavailability_evidence(missed: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(&missed.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes()); // window_start
    buf
}

// ─── Core integration test ────────────────────────────────────────────────────

/// Full pipeline: equivocation detected → evidence submitted → challenge window
/// expires (fast-forwarded 7 days) → slashing executed → funds split 50/50.
#[test]
fn equivocation_slashed_after_challenge_period_expires() {
    let validator = pk(1);
    let challenger = pk(99);
    let active_validators = [pk(2), pk(3), pk(4)];
    const SUBMISSION_TIME: u64 = 1_000_000;

    // ── Step 1: Equivocation is detected ────────────────────────────────────
    let mut detector = SlashingConditionDetector::new();
    detector.observe_proposal(validator, 42, hash(10), true);
    let violation = detector
        .observe_proposal(validator, 42, hash(11), true)
        .expect("equivocation must be detected");
    assert_eq!(violation.offense_type, OffenseType::Equivocation);

    // ── Step 2: Challenger submits evidence with bond ────────────────────────
    let mut ev_store = EvidenceStore::new();
    let sub_id = ev_store
        .submit(
            challenger,
            validator,
            OffenseType::Equivocation,
            violation.evidence.clone(),
            /* bond = */ 1_000,
        )
        .expect("valid equivocation evidence must be accepted");

    let submission = ev_store.get(sub_id).unwrap();
    assert_eq!(submission.validator_id, validator);
    assert_eq!(submission.offense_type, OffenseType::Equivocation);

    // ── Step 3: Challenge window is opened ───────────────────────────────────
    let mut challenge_mgr = ChallengeManager::new();
    challenge_mgr.open(
        sub_id,
        validator,
        OffenseType::Equivocation,
        challenger,
        submission.bond,
        SUBMISSION_TIME,
    );
    assert_eq!(
        challenge_mgr.get(sub_id).unwrap().status,
        ChallengeStatus::Open
    );

    // ── Step 4: Fast-forward 7 days — challenge window expires ───────────────
    let after_deadline = SUBMISSION_TIME + CHALLENGE_PERIOD_SECS + 1;
    let expired_ids = challenge_mgr.expire_elapsed(after_deadline);
    assert_eq!(expired_ids, alloc::vec![sub_id]);
    assert_eq!(
        challenge_mgr.get(sub_id).unwrap().status,
        ChallengeStatus::Expired
    );

    // ── Step 5: Execute slashing ─────────────────────────────────────────────
    let mut registry = StakeRegistry::new();
    registry.register(validator, STAKE_32_ETH);
    let mut executor = SlashingExecutor::new(registry);

    let result = executor
        .execute(validator, OffenseType::Equivocation, 0, &active_validators)
        .expect("slashing must succeed");

    // ── Step 6: Verify slashing amounts ──────────────────────────────────────
    // Equivocation → 100 % of stake
    assert_eq!(result.total_slashed, STAKE_32_ETH);
    // 50 % burned
    assert_eq!(result.burned, STAKE_32_ETH / 2);
    // 50 % distributed
    assert_eq!(result.distributed, STAKE_32_ETH / 2);
    // Validator has zero stake remaining
    assert_eq!(result.remaining_stake, 0);
    // Each active validator receives an equal share
    let expected_per_validator = (STAKE_32_ETH / 2) / 3;
    assert_eq!(result.reward_per_active_validator, expected_per_validator);

    // ── Step 7: Idempotency — cannot slash the same validator twice ──────────
    let err = executor
        .execute(validator, OffenseType::Equivocation, 0, &active_validators)
        .unwrap_err();
    assert_eq!(err, ExecutorError::AlreadySlashed);
}

// ─── Unavailability slashing ─────────────────────────────────────────────────

/// 101 missed attestations → 0.1 % × 101 = 10.1 %, capped at 10 %.
#[test]
fn unavailability_slashing_capped_at_ten_percent() {
    let validator = pk(2);
    let challenger = pk(98);

    // Detect unavailability.
    let mut detector = SlashingConditionDetector::new();
    // Record UNAVAILABILITY_THRESHOLD + 1 misses.
    for i in 0..=UNAVAILABILITY_THRESHOLD {
        detector.record_missed_attestation(validator, i);
    }
    let violation = detector
        .violations()
        .iter()
        .find(|v| v.offense_type == OffenseType::Unavailability)
        .expect("unavailability must be detected");

    // Submit evidence.
    let mut ev_store = EvidenceStore::new();
    let sub_id = ev_store
        .submit(
            challenger,
            validator,
            OffenseType::Unavailability,
            violation.evidence.clone(),
            500,
        )
        .expect("valid unavailability evidence must be accepted");
    assert_eq!(
        ev_store.get(sub_id).unwrap().offense_type,
        OffenseType::Unavailability
    );

    // Challenge window expires.
    let mut challenge_mgr = ChallengeManager::new();
    challenge_mgr.open(
        sub_id,
        validator,
        OffenseType::Unavailability,
        challenger,
        500,
        0,
    );
    let expired = challenge_mgr.expire_elapsed(CHALLENGE_PERIOD_SECS + 1);
    assert_eq!(expired.len(), 1);

    // Execute slashing.
    let mut registry = StakeRegistry::new();
    registry.register(validator, STAKE_32_ETH);
    let mut executor = SlashingExecutor::new(registry);
    let result = executor
        .execute(
            validator,
            OffenseType::Unavailability,
            UNAVAILABILITY_THRESHOLD + 1,
            &[],
        )
        .expect("slashing must succeed");

    // 100 missed × 0.1 % = 10 % cap applied.
    let expected = STAKE_32_ETH / 10;
    assert_eq!(result.total_slashed, expected);
    assert_eq!(result.burned, expected / 2);
}

// ─── Invalid-proposal slashing ───────────────────────────────────────────────

/// Invalid proposal → 2 % of stake slashed.
#[test]
fn invalid_proposal_slashed_two_percent() {
    let validator = pk(3);

    let mut detector = SlashingConditionDetector::new();
    let violation = detector
        .observe_proposal(validator, 10, hash(5), /* invalid = */ false)
        .expect("invalid proposal must be detected immediately");
    assert_eq!(violation.offense_type, OffenseType::InvalidProposal);

    let mut ev_store = EvidenceStore::new();
    let sub_id = ev_store
        .submit(
            pk(97),
            validator,
            OffenseType::InvalidProposal,
            violation.evidence.clone(),
            200,
        )
        .expect("valid invalid-proposal evidence must be accepted");

    let mut challenge_mgr = ChallengeManager::new();
    challenge_mgr.open(
        sub_id,
        validator,
        OffenseType::InvalidProposal,
        pk(97),
        200,
        0,
    );
    challenge_mgr.expire_elapsed(CHALLENGE_PERIOD_SECS + 1);

    let mut registry = StakeRegistry::new();
    registry.register(validator, STAKE_32_ETH);
    let mut executor = SlashingExecutor::new(registry);
    let result = executor
        .execute(validator, OffenseType::InvalidProposal, 0, &[])
        .expect("slashing must succeed");

    let expected = (STAKE_32_ETH as u128 * 2 / 100) as u64;
    assert_eq!(result.total_slashed, expected);
    assert_eq!(result.burned, expected / 2);
    assert_eq!(result.remaining_stake, STAKE_32_ETH - expected);
}

// ─── Defender wins — challenger's bond is slashed ────────────────────────────

/// Accused validator submits valid counter-evidence before the deadline →
/// challenge resolved in defender's favour, challenger's bond is forfeited.
#[test]
fn counter_evidence_wins_challenger_bond_slashed() {
    let validator = pk(4);
    let challenger = pk(96);
    const NOW: u64 = 500_000;
    const BOND: u64 = 750;

    // Submit equivocation evidence.
    let ev = equivocation_evidence(99, 1, 2);
    let mut ev_store = EvidenceStore::new();
    let sub_id = ev_store
        .submit(challenger, validator, OffenseType::Equivocation, ev, BOND)
        .unwrap();

    // Open challenge.
    let mut challenge_mgr = ChallengeManager::new();
    challenge_mgr.open(
        sub_id,
        validator,
        OffenseType::Equivocation,
        challenger,
        BOND,
        NOW,
    );

    // Accused submits valid counter-evidence before deadline.
    // Counter-evidence layout for equivocation: [height:8][block_hash:32] = 40 bytes.
    let mut counter_ev = Vec::with_capacity(40);
    counter_ev.extend_from_slice(&99u64.to_le_bytes()); // same height
    counter_ev.extend_from_slice(&hash(1)); // valid block hash

    let outcome = challenge_mgr
        .submit_counter_evidence(sub_id, counter_ev, NOW + 3600)
        .expect("counter-evidence submission must succeed");

    // Defender wins and challenger's bond is to be slashed.
    assert_eq!(
        outcome,
        CounterEvidenceOutcome::DefenderWins {
            bond_to_slash: BOND
        }
    );
    assert_eq!(
        challenge_mgr.get(sub_id).unwrap().status,
        ChallengeStatus::DefenderWon
    );
}

// ─── Detector edge cases ─────────────────────────────────────────────────────

/// Different proposers at the same height do NOT equivocate each other.
#[test]
fn different_validators_same_height_no_equivocation() {
    let mut detector = SlashingConditionDetector::new();
    detector.observe_proposal(pk(1), 5, hash(1), true);
    let result = detector.observe_proposal(pk(2), 5, hash(2), true);
    assert!(result.is_none());
}

/// Duplicate proposals (same height, same hash, same validator) are silently
/// deduplicated and do not trigger equivocation.
#[test]
fn duplicate_proposal_not_flagged_as_equivocation() {
    let mut detector = SlashingConditionDetector::new();
    detector.observe_proposal(pk(1), 3, hash(7), true);
    let result = detector.observe_proposal(pk(1), 3, hash(7), true);
    assert!(result.is_none());
}

/// Attestation window resets after 24 h, resetting the miss counter.
#[test]
fn attestation_window_resets_after_24h() {
    use sorosusu_contracts::consensus::slashing::detector::ATTESTATION_WINDOW_SECS;

    let mut detector = SlashingConditionDetector::new();
    let v = pk(5);

    for i in 0..UNAVAILABILITY_THRESHOLD {
        detector.record_missed_attestation(v, i);
    }
    assert_eq!(detector.missed_count(&v), UNAVAILABILITY_THRESHOLD);

    // Advance time past the 24-hour window.
    detector.record_missed_attestation(v, ATTESTATION_WINDOW_SECS + 1);
    assert_eq!(detector.missed_count(&v), 1);
}

// Needed for alloc::vec! macro.
extern crate alloc;
