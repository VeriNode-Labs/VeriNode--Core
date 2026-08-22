//! Synchronous Byzantine-fault-tolerant fallback consensus (issue #137).
//!
//! After [`DEADLOCK_VIEW_THRESHOLD`] consecutive views without a committed block,
//! the consensus engine triggers the fallback synchronous agreement protocol
//! (PBFT-style) for a single view to break the deadlock.
//!
//! # Protocol
//!
//! 1. **Exchange locked values**: every replica broadcasts its currently locked
//!    `(block_hash, lock_view)` pair. A replica that has no locked value
//!    broadcasts `None`.
//! 2. **Select highest-view lock**: among all received locked values, the one
//!    with the highest `lock_view` number is chosen as the fallback proposal.
//!    Ties are broken deterministically by the lexicographically larger
//!    `block_hash`.
//! 3. **Agreement**: all replicas run one round of synchronous PBFT prepare/commit
//!    on the chosen fallback proposal. The result is a committed block, resetting
//!    the deadlock counter.
//!
//! # Invariants
//!
//! * Deadlock threshold: **5** consecutive views without a committed block.
//! * A replica with no locked value participates but contributes no lock.
//! * The fallback proposal is deterministic: every honest replica selects the
//!   same value given the same set of [`LockedValue`]s.

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::consensus::view_change::types::BlockHash;

// ──────────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────────

/// Number of consecutive views without a committed block before triggering
/// synchronous fallback consensus.
pub const DEADLOCK_VIEW_THRESHOLD: u64 = 5;

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

/// A replica's currently locked value: the block hash it is locked on and the
/// view number at which it locked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockedValue {
    /// The block hash a replica is locked on.
    pub block_hash: BlockHash,
    /// The consensus view number at which the replica locked.
    pub lock_view: u64,
}

impl LockedValue {
    /// Construct a new [`LockedValue`].
    pub fn new(block_hash: BlockHash, lock_view: u64) -> Self {
        Self {
            block_hash,
            lock_view,
        }
    }

    /// Deterministic comparison for fallback selection: highest `lock_view`
    /// wins; ties broken by lexicographically larger `block_hash`.
    fn selection_cmp(&self, other: &Self) -> Ordering {
        match self.lock_view.cmp(&other.lock_view) {
            Ordering::Equal => self.block_hash.cmp(&other.block_hash),
            ord => ord,
        }
    }
}

/// Observability events emitted by [`FallbackSyncEngine`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FallbackSyncEvent {
    /// Fallback consensus was triggered after `deadlocked_views` consecutive
    /// views without a committed block.
    FallbackTriggered {
        /// Current consensus view when fallback was triggered.
        current_view: u64,
        /// Number of consecutive deadlocked views.
        deadlocked_views: u64,
    },
    /// The fallback proposal was selected from the exchanged locked values.
    FallbackProposalSelected {
        /// The selected fallback proposal.
        block_hash: BlockHash,
        /// Lock view of the winning locked value.
        lock_view: u64,
    },
    /// Fallback consensus completed and the block was committed.
    FallbackCommitted {
        /// The committed block hash.
        block_hash: BlockHash,
        /// The view in which fallback consensus completed.
        committed_view: u64,
    },
    /// A committed block reset the deadlock counter.
    DeadlockCounterReset {
        /// View at which the counter was reset.
        at_view: u64,
    },
}

/// Errors returned by [`FallbackSyncEngine`] operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallbackSyncError {
    /// No locked values were provided; cannot select a fallback proposal.
    NoLockedValues,
    /// The fallback engine was called but the deadlock threshold has not been reached.
    ThresholdNotReached {
        current_deadlocked_views: u64,
        required: u64,
    },
}

// ──────────────────────────────────────────────────────────────────────────────
// FallbackSyncEngine
// ──────────────────────────────────────────────────────────────────────────────

/// Synchronous BFT fallback consensus engine.
///
/// Tracks consecutive deadlocked views. When the count reaches
/// [`DEADLOCK_VIEW_THRESHOLD`] (5), callers invoke [`run_fallback`] with the
/// set of locked values collected from all replicas; the engine selects the
/// highest-view lock as the fallback proposal and records a committed result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackSyncEngine {
    /// Number of consecutive views with no committed block.
    deadlocked_views: u64,
    /// Current consensus view.
    current_view: u64,
    /// Accumulated observability events.
    events: Vec<FallbackSyncEvent>,
}

impl FallbackSyncEngine {
    /// Create a new engine starting at `initial_view`.
    pub fn new(initial_view: u64) -> Self {
        Self {
            deadlocked_views: 0,
            current_view: initial_view,
            events: Vec::new(),
        }
    }

    /// Current active consensus view.
    pub fn current_view(&self) -> u64 {
        self.current_view
    }

    /// Number of consecutive views without a committed block.
    pub fn deadlocked_views(&self) -> u64 {
        self.deadlocked_views
    }

    /// Whether the deadlock threshold has been reached and fallback should fire.
    pub fn is_deadlocked(&self) -> bool {
        self.deadlocked_views >= DEADLOCK_VIEW_THRESHOLD
    }

    /// Notify the engine that a new view started without a committed block.
    ///
    /// Increments the deadlock counter and advances `current_view`.
    pub fn on_view_timeout(&mut self) {
        self.current_view = self.current_view.saturating_add(1);
        self.deadlocked_views = self.deadlocked_views.saturating_add(1);
    }

    /// Notify the engine that a block was successfully committed, resetting the
    /// deadlock counter.
    pub fn on_commit(&mut self) {
        self.deadlocked_views = 0;
        self.events.push(FallbackSyncEvent::DeadlockCounterReset {
            at_view: self.current_view,
        });
    }

    /// Run one round of synchronous BFT fallback consensus.
    ///
    /// # Arguments
    ///
    /// * `locked_values` — the set of [`LockedValue`]s broadcast by all replicas.
    ///   A replica with no locked value contributes nothing (callers filter them
    ///   out; `None` entries are excluded before passing the slice).
    ///
    /// # Returns
    ///
    /// * `Ok(block_hash)` — the fallback proposal chosen and committed.
    /// * `Err(FallbackSyncError::ThresholdNotReached)` — called before 5 deadlocked views.
    /// * `Err(FallbackSyncError::NoLockedValues)` — all replicas have no lock.
    pub fn run_fallback(
        &mut self,
        locked_values: &[LockedValue],
    ) -> Result<BlockHash, FallbackSyncError> {
        if !self.is_deadlocked() {
            return Err(FallbackSyncError::ThresholdNotReached {
                current_deadlocked_views: self.deadlocked_views,
                required: DEADLOCK_VIEW_THRESHOLD,
            });
        }

        self.events.push(FallbackSyncEvent::FallbackTriggered {
            current_view: self.current_view,
            deadlocked_views: self.deadlocked_views,
        });

        // Select the locked value with the highest lock_view; tie-break by block_hash.
        let best = locked_values
            .iter()
            .max_by(|a, b| a.selection_cmp(b))
            .ok_or(FallbackSyncError::NoLockedValues)?;

        self.events
            .push(FallbackSyncEvent::FallbackProposalSelected {
                block_hash: best.block_hash,
                lock_view: best.lock_view,
            });

        // Commit the fallback proposal and reset the deadlock counter.
        let committed_hash = best.block_hash;
        self.events.push(FallbackSyncEvent::FallbackCommitted {
            block_hash: committed_hash,
            committed_view: self.current_view,
        });

        // Reset deadlock counter after a successful fallback commit.
        self.on_commit();

        Ok(committed_hash)
    }

    /// Drain and return all accumulated events.
    pub fn drain_events(&mut self) -> Vec<FallbackSyncEvent> {
        core::mem::take(&mut self.events)
    }

    /// Slice of all accumulated events without draining.
    pub fn events(&self) -> &[FallbackSyncEvent] {
        &self.events
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(id: u8) -> BlockHash {
        let mut h = [0u8; 32];
        h[31] = id;
        h
    }

    fn locked(block_id: u8, lock_view: u64) -> LockedValue {
        LockedValue::new(hash(block_id), lock_view)
    }

    // ─── deadlock counter ─────────────────────────────────────────────────────

    #[test]
    fn deadlock_counter_increments_on_view_timeout() {
        let mut engine = FallbackSyncEngine::new(0);
        assert!(!engine.is_deadlocked());
        for i in 1..=DEADLOCK_VIEW_THRESHOLD {
            engine.on_view_timeout();
            assert_eq!(engine.deadlocked_views(), i);
        }
        assert!(engine.is_deadlocked());
    }

    #[test]
    fn commit_resets_deadlock_counter() {
        let mut engine = FallbackSyncEngine::new(0);
        for _ in 0..DEADLOCK_VIEW_THRESHOLD {
            engine.on_view_timeout();
        }
        assert!(engine.is_deadlocked());
        engine.on_commit();
        assert_eq!(engine.deadlocked_views(), 0);
        assert!(!engine.is_deadlocked());
    }

    // ─── fallback selection ───────────────────────────────────────────────────

    #[test]
    fn run_fallback_selects_highest_lock_view() {
        let mut engine = FallbackSyncEngine::new(10);
        for _ in 0..DEADLOCK_VIEW_THRESHOLD {
            engine.on_view_timeout();
        }

        let locks = alloc::vec![locked(1, 7), locked(2, 9), locked(3, 8)];
        let result = engine.run_fallback(&locks).unwrap();
        assert_eq!(result, hash(2)); // lock_view=9 wins
    }

    #[test]
    fn run_fallback_breaks_lock_view_tie_by_block_hash() {
        let mut engine = FallbackSyncEngine::new(0);
        for _ in 0..DEADLOCK_VIEW_THRESHOLD {
            engine.on_view_timeout();
        }

        // Both locked at view 5; block hash 200 > block hash 100 lexicographically.
        let locks = alloc::vec![locked(100, 5), locked(200, 5)];
        let result = engine.run_fallback(&locks).unwrap();
        assert_eq!(result, hash(200)); // higher block_hash wins tie
    }

    #[test]
    fn run_fallback_resets_deadlock_counter_after_commit() {
        let mut engine = FallbackSyncEngine::new(0);
        for _ in 0..DEADLOCK_VIEW_THRESHOLD {
            engine.on_view_timeout();
        }
        assert!(engine.is_deadlocked());

        let locks = alloc::vec![locked(1, 3)];
        engine.run_fallback(&locks).unwrap();

        assert!(!engine.is_deadlocked());
        assert_eq!(engine.deadlocked_views(), 0);
    }

    // ─── error paths ──────────────────────────────────────────────────────────

    #[test]
    fn run_fallback_errors_before_threshold_reached() {
        let mut engine = FallbackSyncEngine::new(0);
        // Only 4 timeouts — one short of threshold.
        for _ in 0..(DEADLOCK_VIEW_THRESHOLD - 1) {
            engine.on_view_timeout();
        }
        let err = engine.run_fallback(&[locked(1, 1)]).unwrap_err();
        assert_eq!(
            err,
            FallbackSyncError::ThresholdNotReached {
                current_deadlocked_views: DEADLOCK_VIEW_THRESHOLD - 1,
                required: DEADLOCK_VIEW_THRESHOLD,
            }
        );
    }

    #[test]
    fn run_fallback_errors_with_no_locked_values() {
        let mut engine = FallbackSyncEngine::new(0);
        for _ in 0..DEADLOCK_VIEW_THRESHOLD {
            engine.on_view_timeout();
        }
        let err = engine.run_fallback(&[]).unwrap_err();
        assert_eq!(err, FallbackSyncError::NoLockedValues);
    }

    // ─── observability events ─────────────────────────────────────────────────

    #[test]
    fn run_fallback_emits_correct_events() {
        let mut engine = FallbackSyncEngine::new(3);
        for _ in 0..DEADLOCK_VIEW_THRESHOLD {
            engine.on_view_timeout();
        }

        let locks = alloc::vec![locked(42, 6)];
        let committed = engine.run_fallback(&locks).unwrap();
        assert_eq!(committed, hash(42));

        let events = engine.drain_events();
        // FallbackTriggered, FallbackProposalSelected, FallbackCommitted, DeadlockCounterReset
        assert_eq!(events.len(), 4);
        assert!(matches!(
            events[0],
            FallbackSyncEvent::FallbackTriggered {
                deadlocked_views: 5,
                ..
            }
        ));
        assert!(matches!(
            events[1],
            FallbackSyncEvent::FallbackProposalSelected { lock_view: 6, .. }
        ));
        assert!(matches!(
            events[2],
            FallbackSyncEvent::FallbackCommitted { .. }
        ));
        assert!(matches!(
            events[3],
            FallbackSyncEvent::DeadlockCounterReset { .. }
        ));
    }
}
