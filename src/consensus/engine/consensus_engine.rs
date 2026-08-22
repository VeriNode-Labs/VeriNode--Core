//! Main consensus loop integrating equivocation detection, leader election,
//! and synchronous fallback recovery (issue #137).
//!
//! # Deadlock Prevention
//!
//! Byzantine equivocation attacks can deadlock the normal timeout-based
//! leader election: honest replicas lock on conflicting proposals and cannot
//! reach a 2f+1 quorum to advance.
//!
//! This engine prevents and recovers from that deadlock through two layers:
//!
//! 1. **Equivocation fast-path** (`on_proposal`): when two conflicting proposals
//!    arrive at the same height from the same proposer, an [`EquivocationProof`]
//!    is generated and the leader election immediately advances the view —
//!    without waiting for the timeout — via [`TimeoutLeader::on_equivocation`].
//!
//! 2. **Synchronous fallback** (`on_view_timeout`): if 5 consecutive views pass
//!    without a committed block, [`FallbackSyncEngine::run_fallback`] is
//!    triggered. Replicas exchange their locked values and agree synchronously
//!    on the highest-view lock as the fallback proposal.
//!
//! # View Lifecycle
//!
//! ```text
//! Proposal arrives
//!   ├─ No equivocation → normal flow (wait for commit or timeout)
//!   └─ Equivocation detected → broadcast proof → immediate view advance
//!
//! View timeout fires (no commit)
//!   ├─ deadlocked_views < 5 → normal timeout view advance
//!   └─ deadlocked_views >= 5 → trigger synchronous fallback consensus
//! ```

extern crate alloc;

use alloc::vec::Vec;

use crate::consensus::leader_election::timeout_leader::TimeoutLeader;
use crate::consensus::proposal::equivocation_detector::{EquivocationDetector, EquivocationProof};
use crate::consensus::recovery::fallback_sync::{
    FallbackSyncEngine, FallbackSyncError, LockedValue,
};
use crate::consensus::view_change::types::{BlockHash, PublicKey};

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

/// Observability events emitted by the consensus engine for monitoring.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsensusEngineEvent {
    /// A new valid proposal was accepted in the current view.
    ProposalAccepted {
        /// Current consensus view.
        view: u64,
        /// The proposal's block hash.
        block_hash: BlockHash,
    },
    /// A Byzantine equivocation was detected; view was immediately advanced.
    EquivocationDetected {
        /// The equivocation proof.
        proof: Box<EquivocationProof>,
        /// View advanced to.
        new_view: u64,
    },
    /// A block was committed in `view`, resetting the deadlock counter.
    BlockCommitted {
        /// The committed block's hash.
        block_hash: BlockHash,
        /// The view in which the block was committed.
        view: u64,
    },
    /// A view timeout occurred without a committed block.
    ViewTimeout {
        /// The view that timed out.
        timed_out_view: u64,
        /// Number of consecutive deadlocked views after this timeout.
        deadlocked_views: u64,
    },
    /// Synchronous fallback consensus was triggered.
    FallbackTriggered {
        /// View at which fallback was triggered.
        view: u64,
        /// Deadlocked view count that triggered it.
        deadlocked_views: u64,
    },
    /// Fallback consensus completed and a block was committed.
    FallbackCommitted {
        /// The fallback-committed block hash.
        block_hash: BlockHash,
        /// View in which fallback committed.
        view: u64,
    },
}

/// Errors returned by consensus engine operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusEngineError {
    /// Fallback consensus failed (no locked values available from any replica).
    FallbackFailed(FallbackSyncError),
}

// ──────────────────────────────────────────────────────────────────────────────
// ConsensusEngine
// ──────────────────────────────────────────────────────────────────────────────

/// Main consensus engine.
///
/// Coordinates [`EquivocationDetector`], [`TimeoutLeader`], and
/// [`FallbackSyncEngine`] to implement the full consensus loop with Byzantine
/// deadlock prevention and recovery.
#[derive(Clone, Debug)]
pub struct ConsensusEngine {
    /// Equivocation detector tracking proposals per `(height, proposer)`.
    equivocation_detector: EquivocationDetector,
    /// Timeout-based leader election component.
    timeout_leader: TimeoutLeader,
    /// Synchronous fallback recovery engine.
    fallback_engine: FallbackSyncEngine,
    /// Accumulated observability events.
    events: Vec<ConsensusEngineEvent>,
}

impl ConsensusEngine {
    /// Create a new consensus engine at `initial_view` with the given ordered
    /// validator set.
    ///
    /// Panics if `validators` is empty.
    pub fn new(initial_view: u64, validators: Vec<PublicKey>) -> Self {
        Self {
            equivocation_detector: EquivocationDetector::new(),
            timeout_leader: TimeoutLeader::new(initial_view, validators),
            fallback_engine: FallbackSyncEngine::new(initial_view),
            events: Vec::new(),
        }
    }

    /// Current active consensus view.
    pub fn current_view(&self) -> u64 {
        self.timeout_leader.current_view()
    }

    /// Number of consecutive views without a committed block.
    pub fn deadlocked_views(&self) -> u64 {
        self.fallback_engine.deadlocked_views()
    }

    /// Whether the engine is in a deadlocked state (≥ [`DEADLOCK_VIEW_THRESHOLD`]).
    pub fn is_deadlocked(&self) -> bool {
        self.fallback_engine.is_deadlocked()
    }

    /// Current leader's public key.
    pub fn current_leader(&self) -> PublicKey {
        self.timeout_leader.current_leader()
    }

    /// Process an incoming proposal.
    ///
    /// # Returns
    ///
    /// * `Ok(None)` — first valid proposal at this height; recorded normally.
    /// * `Ok(Some(proof))` — equivocation detected; view was immediately
    ///   advanced and the proof should be broadcast to all peers.
    /// * `Err(_)` — proposal carries an invalid (all-zero) signature.
    pub fn on_proposal(
        &mut self,
        proposal: crate::consensus::proposal::equivocation_detector::Proposal,
    ) -> Result<Option<EquivocationProof>, crate::consensus::proposal::EquivocationError> {
        let block_hash = proposal.block_hash;
        let result = self.equivocation_detector.observe(proposal)?;

        if let Some(ref proof) = result {
            // Byzantine equivocation: immediately advance the view.
            self.timeout_leader.on_equivocation(proof);
            let new_view = self.timeout_leader.current_view();
            self.events
                .push(ConsensusEngineEvent::EquivocationDetected {
                    proof: Box::new(proof.clone()),
                    new_view,
                });
        } else {
            self.events.push(ConsensusEngineEvent::ProposalAccepted {
                view: self.timeout_leader.current_view(),
                block_hash,
            });
        }

        Ok(result)
    }

    /// Notify the engine that a block was committed at the current view.
    ///
    /// Resets the deadlock counter.
    pub fn on_commit(&mut self, block_hash: BlockHash) {
        let view = self.timeout_leader.current_view();
        self.fallback_engine.on_commit();
        self.events
            .push(ConsensusEngineEvent::BlockCommitted { block_hash, view });
    }

    /// Handle a view timeout (no block committed before the timeout expired).
    ///
    /// Advances the view via the normal timeout path and increments the deadlock
    /// counter. If the counter reaches [`DEADLOCK_VIEW_THRESHOLD`] (5), this
    /// method automatically triggers synchronous fallback consensus using the
    /// provided `locked_values`.
    ///
    /// # Arguments
    ///
    /// * `elapsed_ms` — the actual elapsed timeout duration in milliseconds.
    /// * `locked_values` — locked values from all replicas, used if fallback
    ///   is triggered. Pass an empty slice if no replica has a lock.
    ///
    /// # Returns
    ///
    /// * `Ok(None)` — normal timeout advance; no fallback.
    /// * `Ok(Some(block_hash))` — fallback consensus completed; `block_hash`
    ///   is the committed fallback proposal.
    /// * `Err(ConsensusEngineError::FallbackFailed)` — fallback triggered but
    ///   failed (e.g., no locked values among all replicas).
    pub fn on_view_timeout(
        &mut self,
        elapsed_ms: u64,
        locked_values: &[LockedValue],
    ) -> Result<Option<BlockHash>, ConsensusEngineError> {
        // Normal timeout view advance.
        self.timeout_leader.on_timeout(elapsed_ms);
        self.fallback_engine.on_view_timeout();

        let timed_out_view = self.timeout_leader.current_view().saturating_sub(1);
        let deadlocked = self.fallback_engine.deadlocked_views();

        self.events.push(ConsensusEngineEvent::ViewTimeout {
            timed_out_view,
            deadlocked_views: deadlocked,
        });

        // Check deadlock threshold.
        if self.fallback_engine.is_deadlocked() {
            let view = self.timeout_leader.current_view();
            self.events.push(ConsensusEngineEvent::FallbackTriggered {
                view,
                deadlocked_views: deadlocked,
            });

            match self.fallback_engine.run_fallback(locked_values) {
                Ok(block_hash) => {
                    self.events
                        .push(ConsensusEngineEvent::FallbackCommitted { block_hash, view });
                    return Ok(Some(block_hash));
                }
                Err(e) => {
                    return Err(ConsensusEngineError::FallbackFailed(e));
                }
            }
        }

        Ok(None)
    }

    /// Drain and return all accumulated observability events.
    pub fn drain_events(&mut self) -> Vec<ConsensusEngineEvent> {
        core::mem::take(&mut self.events)
    }

    /// Slice of all accumulated events without draining.
    pub fn events(&self) -> &[ConsensusEngineEvent] {
        &self.events
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::proposal::equivocation_detector::Proposal;
    use crate::consensus::recovery::fallback_sync::DEADLOCK_VIEW_THRESHOLD;
    use crate::consensus::view_change::types::AggregateSignature;

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
        alloc::vec![pk(1), pk(2), pk(3), pk(4)]
    }

    fn proposal(height: u64, proposer_id: u8, block_id: u8) -> Proposal {
        Proposal::new(height, pk(proposer_id), hash(block_id), sig(block_id))
    }

    fn locked(block_id: u8, lock_view: u64) -> LockedValue {
        LockedValue::new(hash(block_id), lock_view)
    }

    // ─── normal flow ──────────────────────────────────────────────────────────

    #[test]
    fn first_proposal_accepted_no_equivocation() {
        let mut engine = ConsensusEngine::new(0, validators());
        let result = engine.on_proposal(proposal(1, 1, 10)).unwrap();
        assert!(result.is_none());
        assert_eq!(engine.current_view(), 0);
    }

    #[test]
    fn commit_resets_deadlock_counter() {
        let mut engine = ConsensusEngine::new(0, validators());
        engine.on_view_timeout(4_000, &[]).ok();
        engine.on_view_timeout(8_000, &[]).ok();
        assert_eq!(engine.deadlocked_views(), 2);

        engine.on_commit(hash(99));
        assert_eq!(engine.deadlocked_views(), 0);
    }

    // ─── equivocation fast-path ───────────────────────────────────────────────

    #[test]
    fn equivocation_immediately_advances_view() {
        let mut engine = ConsensusEngine::new(0, validators());
        assert_eq!(engine.current_view(), 0);

        engine.on_proposal(proposal(5, 1, 1)).unwrap(); // first proposal
        let proof = engine.on_proposal(proposal(5, 1, 2)).unwrap(); // conflicting → equivocation

        assert!(proof.is_some(), "expected equivocation proof");
        assert_eq!(
            engine.current_view(),
            1,
            "view must advance immediately on equivocation"
        );

        let events = engine.events();
        assert!(events.iter().any(|e| matches!(
            e,
            ConsensusEngineEvent::EquivocationDetected { new_view: 1, .. }
        )));
    }

    #[test]
    fn equivocation_does_not_wait_for_timeout() {
        // Verify that after equivocation the view advances even before any timeout fires.
        let mut engine = ConsensusEngine::new(3, validators());
        engine.on_proposal(proposal(10, 2, 100)).unwrap();
        engine.on_proposal(proposal(10, 2, 101)).unwrap(); // equivocation

        // View should be 4 now (advanced from 3), with no timeout calls.
        assert_eq!(engine.current_view(), 4);
    }

    // ─── fallback recovery ────────────────────────────────────────────────────

    #[test]
    fn five_consecutive_timeouts_trigger_fallback() {
        let mut engine = ConsensusEngine::new(0, validators());
        let locks = alloc::vec![locked(55, 3)];

        for i in 0..(DEADLOCK_VIEW_THRESHOLD - 1) {
            let result = engine.on_view_timeout(4_000, &[]).unwrap();
            assert!(result.is_none(), "fallback should not fire at timeout {i}");
        }

        // 5th timeout triggers fallback.
        let result = engine.on_view_timeout(4_000, &locks).unwrap();
        assert_eq!(result, Some(hash(55)));
        assert_eq!(
            engine.deadlocked_views(),
            0,
            "deadlock counter must reset after fallback commit"
        );
    }

    #[test]
    fn fallback_errors_with_no_locked_values() {
        let mut engine = ConsensusEngine::new(0, validators());
        for _ in 0..DEADLOCK_VIEW_THRESHOLD {
            let _ = engine.on_view_timeout(4_000, &[]);
        }
        // After threshold, an additional timeout with no locks must fail.
        // Manually pump enough timeouts to reach threshold on a fresh engine.
        let mut engine2 = ConsensusEngine::new(0, validators());
        for _ in 0..(DEADLOCK_VIEW_THRESHOLD - 1) {
            engine2.on_view_timeout(4_000, &[]).ok();
        }
        let err = engine2.on_view_timeout(4_000, &[]).unwrap_err();
        assert!(matches!(
            err,
            ConsensusEngineError::FallbackFailed(FallbackSyncError::NoLockedValues)
        ));
    }

    // ─── observability events ─────────────────────────────────────────────────

    #[test]
    fn view_timeout_events_are_emitted() {
        let mut engine = ConsensusEngine::new(0, validators());
        engine.on_view_timeout(4_100, &[]).ok();

        let events = engine.drain_events();
        assert!(events.iter().any(|e| matches!(
            e,
            ConsensusEngineEvent::ViewTimeout {
                timed_out_view: 0,
                ..
            }
        )));
    }

    #[test]
    fn block_committed_event_is_emitted() {
        let mut engine = ConsensusEngine::new(0, validators());
        engine.on_commit(hash(7));

        let events = engine.drain_events();
        assert!(events.iter().any(|e| matches!(
            e,
            ConsensusEngineEvent::BlockCommitted {
                block_hash,
                view: 0,
            } if *block_hash == hash(7)
        )));
    }
}
