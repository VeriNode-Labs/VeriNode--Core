//! Chaos / integration test: Byzantine primary equivocation attack recovery (issue #137).
//!
//! A Byzantine primary sends two equivocating proposals (two different blocks
//! at the same height). This test verifies that:
//!
//! * The equivocation is detected and an [`EquivocationProof`] is produced.
//! * The consensus engine immediately advances the view (no timeout wait).
//! * After 5 deadlocked views without a commit, synchronous fallback consensus
//!   fires and selects the locked value with the highest view-number lock.
//! * Recovery occurs within 6 views from the start of the attack.

use sorosusu_contracts::consensus::{
    engine::ConsensusEngine,
    proposal::equivocation_detector::Proposal,
    recovery::fallback_sync::{LockedValue, DEADLOCK_VIEW_THRESHOLD},
    view_change::types::{AggregateSignature, BlockHash, PublicKey},
};

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn pk(id: u8) -> PublicKey {
    let mut k = [0u8; 32];
    k[31] = id;
    k
}

fn hash(id: u8) -> BlockHash {
    let mut h = [0u8; 32];
    h[31] = id;
    h
}

fn sig(id: u8) -> AggregateSignature {
    let mut s = [1u8; 96];
    s[95] = id;
    s
}

fn validators() -> Vec<PublicKey> {
    vec![pk(1), pk(2), pk(3), pk(4)]
}

fn proposal(height: u64, proposer_id: u8, block_id: u8) -> Proposal {
    Proposal::new(height, pk(proposer_id), hash(block_id), sig(block_id))
}

fn locked(block_id: u8, lock_view: u64) -> LockedValue {
    LockedValue::new(hash(block_id), lock_view)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

/// Core chaos scenario: Byzantine primary sends two equivocating proposals at
/// height 1 from the same proposer.
///
/// * Equivocation proof is generated.
/// * View advances immediately to view 1 (without waiting for timeout).
/// * Recovery happens within 6 views (well within the ≤6 bound).
#[test]
fn byzantine_equivocation_triggers_immediate_view_advance() {
    let mut engine = ConsensusEngine::new(0, validators());

    // ── Step 1: Byzantine primary sends first proposal ──
    let first = proposal(1, 1, 100);
    let result = engine.on_proposal(first).unwrap();
    assert!(
        result.is_none(),
        "first proposal should not trigger equivocation"
    );
    assert_eq!(
        engine.current_view(),
        0,
        "view must stay at 0 after first proposal"
    );

    // ── Step 2: Byzantine primary sends second, conflicting proposal ──
    let equivocating = proposal(1, 1, 200); // same height + proposer, different block
    let proof = engine.on_proposal(equivocating).unwrap();

    assert!(proof.is_some(), "equivocation proof must be produced");

    let proof = proof.unwrap();
    assert_eq!(proof.height, 1);
    assert_eq!(proof.proposer, pk(1));
    assert_ne!(
        proof.proposal_a.block_hash, proof.proposal_b.block_hash,
        "proof must contain conflicting block hashes"
    );

    // ── Step 3: View must advance IMMEDIATELY (not waiting for timeout) ──
    assert_eq!(
        engine.current_view(),
        1,
        "equivocation must advance view immediately to 1"
    );

    // ── Step 4: Verify recovery is within 6 views from attack start ──
    // At this point we are at view 1, with 0 deadlocked views (no timeout fired yet).
    // The total number of views from initial (0) to current (1) is 1.
    assert!(
        engine.current_view() <= 6,
        "must recover within 6 views; currently at view {}",
        engine.current_view()
    );
}

/// Full deadlock-then-fallback scenario:
///
/// 1. Byzantine equivocation detected → view immediately advances.
/// 2. 5 subsequent view timeouts (no commits) → fallback consensus fires.
/// 3. Fallback selects highest-lock-view value and commits it.
/// 4. Total recovery happens within 6 views from the attack.
#[test]
fn full_deadlock_recovery_within_six_views() {
    let mut engine = ConsensusEngine::new(0, validators());

    // ── Step 1: Byzantine equivocation at height 1 → immediate view advance ──
    engine.on_proposal(proposal(1, 1, 10)).unwrap();
    let proof = engine.on_proposal(proposal(1, 1, 20)).unwrap();
    assert!(proof.is_some(), "equivocation must be detected");
    // View is now 1 (advanced immediately).
    assert_eq!(engine.current_view(), 1);

    // ── Step 2: Simulate DEADLOCK_VIEW_THRESHOLD - 1 = 4 timeouts ──
    // (Replicas are locked on divergent values and cannot reach quorum.)
    // Locks collected from honest replicas:
    //   - 2 replicas locked on block_hash=10 at view 0
    //   - 2 replicas locked on block_hash=20 at view 0
    let locks = vec![locked(10, 0), locked(10, 0), locked(20, 0), locked(20, 0)];

    // 4 timeouts: deadlock counter reaches 4 (threshold=5, no fallback yet)
    for i in 0..(DEADLOCK_VIEW_THRESHOLD - 1) {
        let result = engine.on_view_timeout(4_000, &[]).unwrap();
        assert!(
            result.is_none(),
            "fallback must not fire at timeout {i} (count={})",
            engine.deadlocked_views()
        );
    }
    assert_eq!(engine.deadlocked_views(), DEADLOCK_VIEW_THRESHOLD - 1);

    // ── Step 3: 5th timeout — fallback fires ──
    let result = engine.on_view_timeout(4_000, &locks).unwrap();
    let committed = result.expect("fallback must produce a committed block hash");

    // The fallback selects the locked value with the highest lock_view.
    // Both candidate locks are at view 0 (equal), so block_hash breaks the tie.
    // hash(20) > hash(10) lexicographically → hash(20) wins.
    assert_eq!(
        committed,
        hash(20),
        "highest-view lock (tie → highest hash) must be selected"
    );

    // ── Step 4: Deadlock counter is reset after fallback commit ──
    assert_eq!(engine.deadlocked_views(), 0, "deadlock counter must reset");

    // ── Step 5: Total views elapsed ≤ 6 ──
    // Started at view 0, equivocation → view 1, then 5 more timeouts → view 6.
    assert!(
        engine.current_view() <= 6,
        "recovery must complete within 6 views; at view {}",
        engine.current_view()
    );
}

/// Verify that after fallback recovery the engine resumes normal operation:
/// a subsequent commit keeps the deadlock counter at 0.
#[test]
fn engine_resumes_normal_operation_after_fallback() {
    let mut engine = ConsensusEngine::new(0, validators());

    // Reach deadlock and recover via fallback.
    for _ in 0..DEADLOCK_VIEW_THRESHOLD {
        engine.on_view_timeout(4_000, &[locked(7, 1)]).ok();
    }
    assert_eq!(engine.deadlocked_views(), 0);

    // Normal operation: a new proposal arrives and is committed.
    let result = engine.on_proposal(proposal(99, 1, 42)).unwrap();
    assert!(result.is_none(), "no equivocation in normal operation");

    engine.on_commit(hash(42));
    assert_eq!(
        engine.deadlocked_views(),
        0,
        "commit keeps deadlock counter at 0"
    );
}

/// Verify equivocation detection works for multiple different heights / proposers.
#[test]
fn equivocation_detected_independently_per_height_and_proposer() {
    let mut engine = ConsensusEngine::new(0, validators());

    // Two proposers, each equivocating at different heights.
    engine.on_proposal(proposal(10, 1, 1)).unwrap();
    let proof_1 = engine.on_proposal(proposal(10, 1, 2)).unwrap();
    assert!(
        proof_1.is_some(),
        "proposer 1 at height 10 should equivocate"
    );

    // Engine view advanced to 1 now.
    let view_after_first = engine.current_view();

    engine.on_proposal(proposal(11, 2, 3)).unwrap();
    let proof_2 = engine.on_proposal(proposal(11, 2, 4)).unwrap();
    assert!(
        proof_2.is_some(),
        "proposer 2 at height 11 should equivocate"
    );

    assert!(
        engine.current_view() > view_after_first,
        "second equivocation must further advance the view"
    );
}

/// Verify that identical (duplicate) proposals do NOT produce equivocation proofs.
#[test]
fn duplicate_proposal_does_not_trigger_equivocation() {
    let mut engine = ConsensusEngine::new(0, validators());

    let p = proposal(5, 3, 77);
    engine.on_proposal(p.clone()).unwrap();
    let result = engine.on_proposal(p).unwrap(); // exact duplicate

    assert!(
        result.is_none(),
        "duplicate proposal must not trigger equivocation"
    );
    assert_eq!(
        engine.current_view(),
        0,
        "view must not advance on duplicate"
    );
}

/// Fallback selects the locked value with the highest lock_view number across replicas.
#[test]
fn fallback_selects_highest_lock_view_across_replicas() {
    let mut engine = ConsensusEngine::new(0, validators());

    // Trigger deadlock.
    for _ in 0..DEADLOCK_VIEW_THRESHOLD {
        let _ = engine.on_view_timeout(4_000, &[locked(99, 1)]);
    }

    // After threshold, run again with a richer lock set on a fresh engine.
    let mut engine2 = ConsensusEngine::new(0, validators());
    for _ in 0..(DEADLOCK_VIEW_THRESHOLD - 1) {
        engine2.on_view_timeout(4_000, &[]).ok();
    }

    let locks = vec![
        locked(1, 2), // lock_view=2
        locked(2, 5), // lock_view=5  ← winner
        locked(3, 3), // lock_view=3
        locked(4, 4), // lock_view=4
    ];

    let result = engine2.on_view_timeout(4_000, &locks).unwrap();
    assert_eq!(
        result,
        Some(hash(2)),
        "highest lock_view=5 (block_hash=hash(2)) must win"
    );
}
