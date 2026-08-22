//! Timeout-based leader rotation with Byzantine equivocation fast-path (issue #137).
//!
//! # Timeout Progression
//!
//! * Base timeout: **4 s** (view 0).
//! * Each subsequent view **doubles** the previous timeout.
//! * Maximum timeout cap: **120 s**.
//!
//! Formula for view `v`: `min(BASE_TIMEOUT_MS * 2^v, MAX_TIMEOUT_MS)`.
//!
//! # Equivocation Fast-Path
//!
//! When an [`EquivocationProof`] is received via [`TimeoutLeader::on_equivocation`],
//! the current view is **immediately** advanced to the next view and the timeout
//! timer is reset. Honest replicas therefore do not need to wait for the
//! full timeout before rotating the leader, breaking the equivocation-induced
//! deadlock.

extern crate alloc;

use alloc::vec::Vec;

use crate::consensus::proposal::equivocation_detector::EquivocationProof;
use crate::consensus::view_change::types::PublicKey;

// ──────────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────────

/// Base view timeout in milliseconds (4 s).
pub const BASE_TIMEOUT_MS: u64 = 4_000;

/// Maximum view timeout in milliseconds (120 s).
pub const MAX_TIMEOUT_MS: u64 = 120_000;

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

/// Events emitted by [`TimeoutLeader`] for observability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaderElectionEvent {
    /// Normal timeout-triggered view advance.
    TimeoutViewAdvanced {
        /// View that timed out.
        old_view: u64,
        /// New active view.
        new_view: u64,
        /// Timeout duration that elapsed, in milliseconds.
        elapsed_ms: u64,
    },
    /// Equivocation-triggered immediate view advance (no timeout wait).
    EquivocationViewAdvanced {
        /// View that was immediately advanced.
        old_view: u64,
        /// New active view.
        new_view: u64,
        /// Height at which equivocation was detected.
        equivocation_height: u64,
        /// The equivocating proposer.
        equivocating_proposer: PublicKey,
    },
    /// View timeout was reset after an equivocation fast-path advance.
    TimeoutReset {
        /// The view whose timeout was reset.
        view: u64,
        /// New timeout value in milliseconds.
        new_timeout_ms: u64,
    },
}

/// Errors returned by [`TimeoutLeader`] operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeoutLeaderError {
    /// Attempted to advance to a view that is not strictly greater than the current view.
    ViewNotMonotonic {
        current_view: u64,
        attempted_view: u64,
    },
}

// ──────────────────────────────────────────────────────────────────────────────
// TimeoutLeader
// ──────────────────────────────────────────────────────────────────────────────

/// Timeout-based leader rotator.
///
/// Tracks the current view, computes the exponential backoff timeout for each
/// view, and reacts to [`EquivocationProof`]s by immediately advancing the view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeoutLeader {
    /// Active consensus view.
    current_view: u64,
    /// Validator committee ordered by index. Leader for view `v` is
    /// `validators[v % validators.len()]`.
    validators: Vec<PublicKey>,
    /// Emitted observability events.
    events: Vec<LeaderElectionEvent>,
}

impl TimeoutLeader {
    /// Create a new [`TimeoutLeader`] starting at `initial_view` with the
    /// given ordered validator set.
    ///
    /// Panics if `validators` is empty.
    pub fn new(initial_view: u64, validators: Vec<PublicKey>) -> Self {
        assert!(!validators.is_empty(), "validator set must not be empty");
        Self {
            current_view: initial_view,
            validators,
            events: Vec::new(),
        }
    }

    /// Current active consensus view.
    pub fn current_view(&self) -> u64 {
        self.current_view
    }

    /// Public key of the current leader.
    pub fn current_leader(&self) -> PublicKey {
        let idx = (self.current_view as usize) % self.validators.len();
        self.validators[idx]
    }

    /// Compute the timeout for the given `view` using exponential doubling
    /// capped at [`MAX_TIMEOUT_MS`].
    ///
    /// `timeout(v) = min(BASE_TIMEOUT_MS * 2^v, MAX_TIMEOUT_MS)`
    pub fn timeout_for_view(view: u64) -> u64 {
        // Use saturating_mul + saturating_shl to avoid overflow on large views.
        let shift = view.min(63); // 2^63 already overflows u64, cap the shift
        let raw = BASE_TIMEOUT_MS.saturating_mul(1u64.saturating_shl(shift as u32));
        raw.min(MAX_TIMEOUT_MS)
    }

    /// Current view's timeout in milliseconds.
    pub fn current_timeout_ms(&self) -> u64 {
        Self::timeout_for_view(self.current_view)
    }

    /// Advance the view after a normal timeout expiry.
    ///
    /// Records a [`LeaderElectionEvent::TimeoutViewAdvanced`] event.
    pub fn on_timeout(&mut self, elapsed_ms: u64) {
        let old_view = self.current_view;
        self.current_view = self.current_view.saturating_add(1);
        self.events.push(LeaderElectionEvent::TimeoutViewAdvanced {
            old_view,
            new_view: self.current_view,
            elapsed_ms,
        });
    }

    /// React to a received [`EquivocationProof`] by **immediately** advancing
    /// the view without waiting for the timeout.
    ///
    /// This breaks the Byzantine-equivocation-induced deadlock: honest replicas
    /// that locked on divergent proposals advance to the next view as soon as
    /// the proof is broadcast, resetting their timeout.
    ///
    /// Emits both an [`LeaderElectionEvent::EquivocationViewAdvanced`] and a
    /// [`LeaderElectionEvent::TimeoutReset`] event.
    pub fn on_equivocation(&mut self, proof: &EquivocationProof) {
        let old_view = self.current_view;
        self.current_view = self.current_view.saturating_add(1);
        let new_timeout_ms = Self::timeout_for_view(self.current_view);

        self.events
            .push(LeaderElectionEvent::EquivocationViewAdvanced {
                old_view,
                new_view: self.current_view,
                equivocation_height: proof.height,
                equivocating_proposer: proof.proposer,
            });

        self.events.push(LeaderElectionEvent::TimeoutReset {
            view: self.current_view,
            new_timeout_ms,
        });
    }

    /// Drain and return all accumulated events.
    pub fn drain_events(&mut self) -> Vec<LeaderElectionEvent> {
        core::mem::take(&mut self.events)
    }

    /// Slice of all accumulated events without draining.
    pub fn events(&self) -> &[LeaderElectionEvent] {
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
    use crate::consensus::view_change::types::{AggregateSignature, BlockHash};

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

    fn make_proof(height: u64, proposer_id: u8) -> EquivocationProof {
        EquivocationProof {
            height,
            proposer: pk(proposer_id),
            proposal_a: Proposal::new(height, pk(proposer_id), hash(1), sig(1)),
            proposal_b: Proposal::new(height, pk(proposer_id), hash(2), sig(2)),
        }
    }

    fn validators() -> Vec<PublicKey> {
        alloc::vec![pk(1), pk(2), pk(3), pk(4)]
    }

    // ─── timeout progression ──────────────────────────────────────────────────

    #[test]
    fn timeout_doubles_each_view_and_caps_at_max() {
        assert_eq!(TimeoutLeader::timeout_for_view(0), 4_000);
        assert_eq!(TimeoutLeader::timeout_for_view(1), 8_000);
        assert_eq!(TimeoutLeader::timeout_for_view(2), 16_000);
        assert_eq!(TimeoutLeader::timeout_for_view(3), 32_000);
        assert_eq!(TimeoutLeader::timeout_for_view(4), 64_000);
        assert_eq!(TimeoutLeader::timeout_for_view(5), 120_000); // cap
        assert_eq!(TimeoutLeader::timeout_for_view(100), 120_000); // still capped
    }

    #[test]
    fn on_timeout_advances_view_and_emits_event() {
        let mut leader = TimeoutLeader::new(0, validators());
        assert_eq!(leader.current_view(), 0);

        leader.on_timeout(4_100);

        assert_eq!(leader.current_view(), 1);
        let events = leader.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            LeaderElectionEvent::TimeoutViewAdvanced {
                old_view: 0,
                new_view: 1,
                elapsed_ms: 4_100,
            }
        ));
    }

    // ─── equivocation fast-path ───────────────────────────────────────────────

    #[test]
    fn on_equivocation_immediately_advances_view() {
        let mut leader = TimeoutLeader::new(2, validators());
        let proof = make_proof(10, 5);

        leader.on_equivocation(&proof);

        assert_eq!(leader.current_view(), 3); // advanced without waiting for timeout
        let events = leader.events();
        assert_eq!(events.len(), 2);

        assert!(matches!(
            events[0],
            LeaderElectionEvent::EquivocationViewAdvanced {
                old_view: 2,
                new_view: 3,
                equivocation_height: 10,
                ..
            }
        ));
        assert!(matches!(
            events[1],
            LeaderElectionEvent::TimeoutReset {
                view: 3,
                new_timeout_ms: 32_000, // 4s * 2^3
            }
        ));
    }

    #[test]
    fn equivocation_fast_path_resets_timeout() {
        let mut leader = TimeoutLeader::new(0, validators());
        let proof = make_proof(1, 1);
        leader.on_equivocation(&proof);

        // new view is 1, timeout for view 1 = 8000ms
        assert_eq!(leader.current_timeout_ms(), 8_000);
    }

    #[test]
    fn leader_rotates_round_robin_by_view() {
        let vset = validators();
        let mut leader = TimeoutLeader::new(0, vset.clone());
        assert_eq!(leader.current_leader(), vset[0]);

        leader.on_timeout(4_000);
        assert_eq!(leader.current_leader(), vset[1]);

        leader.on_timeout(8_000);
        assert_eq!(leader.current_leader(), vset[2]);
    }
}
