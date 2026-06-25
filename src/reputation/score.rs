//! Race-free node reputation scoring via an append-only event log (#3).
//!
//! ## The bug
//!
//! Reputation was a single `Map<NodeId, i64>` scalar, and `update_reputation()`
//! did a read-compute-write: read the current score, add the adjustment
//! (`+10` reward, `-50` failure, `-500` slash), write it back. When a
//! successful attestation and a slashing event for the same node were processed
//! together, both read the same prior score and the last writer won — so a
//! `+10` write could clobber a concurrent `-500` slash, losing the slash
//! entirely (final `760` instead of `260`).
//!
//! ## The fix
//!
//! Store reputation as a **per-event log** (blueprint step 3): every adjustment
//! is *appended* as a [`ReputationEvent`] rather than folded into a shared
//! scalar, and the score is the (clamped) sum of all adjustments. Appends do
//! not read-modify-write a shared value, so two concurrent updates each record
//! their event and the score reflects both — independent of write order.
//!
//! A monotonic [`slash_count`](ReputationLedger::slash_count) plus
//! [`try_slash`](ReputationLedger::try_slash) (blueprint step 4) additionally
//! makes slashing idempotent: a duplicate slash carrying an already-consumed
//! sequence number is skipped rather than double-applied.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Node identifier.
pub type NodeId = u32;

/// Inclusive reputation bounds.
pub const REPUTATION_MIN: i64 = -1000;
pub const REPUTATION_MAX: i64 = 1000;

/// Adjustment for a successful attestation.
pub const ATTESTATION_REWARD: i64 = 10;
/// Adjustment for a failed attestation.
pub const ATTESTATION_FAILURE_PENALTY: i64 = -50;
/// Adjustment for a slashing event.
pub const SLASHING_PENALTY: i64 = -500;

/// The origin of a reputation adjustment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReputationSource {
    /// A baseline / starting score (carries an explicit amount).
    Initial,
    /// A successful attestation (`+10`).
    AttestationReward,
    /// A failed attestation (`-50`).
    AttestationFailure,
    /// A slashing event (`-500`).
    Slashing,
}

impl ReputationSource {
    /// The fixed adjustment this source applies. `Initial` is `0` here — its
    /// amount is supplied explicitly via
    /// [`set_initial_score`](ReputationLedger::set_initial_score).
    pub const fn adjustment(self) -> i64 {
        match self {
            ReputationSource::Initial => 0,
            ReputationSource::AttestationReward => ATTESTATION_REWARD,
            ReputationSource::AttestationFailure => ATTESTATION_FAILURE_PENALTY,
            ReputationSource::Slashing => SLASHING_PENALTY,
        }
    }
}

/// A single recorded reputation adjustment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReputationEvent {
    pub source: ReputationSource,
    pub adjustment: i64,
}

/// Append-only reputation ledger.
#[derive(Clone, Debug, Default)]
pub struct ReputationLedger {
    events: BTreeMap<NodeId, Vec<ReputationEvent>>,
    slash_counts: BTreeMap<NodeId, u64>,
}

impl ReputationLedger {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Self {
            events: BTreeMap::new(),
            slash_counts: BTreeMap::new(),
        }
    }

    /// Seed a node's starting score as an initial event, so the summed score
    /// includes it.
    pub fn set_initial_score(&mut self, node: NodeId, score: i64) {
        self.push_event(
            node,
            ReputationEvent {
                source: ReputationSource::Initial,
                adjustment: score,
            },
        );
    }

    /// Record a reputation adjustment for `node` from `source`, returning the
    /// new (clamped) score. Slashing additionally bumps the node's monotonic
    /// slash counter.
    pub fn update_reputation(&mut self, node: NodeId, source: ReputationSource) -> i64 {
        if source == ReputationSource::Slashing {
            *self.slash_counts.entry(node).or_insert(0) += 1;
        }
        self.push_event(
            node,
            ReputationEvent {
                source,
                adjustment: source.adjustment(),
            },
        );
        self.score(node)
    }

    /// Apply a slashing event only if it is the expected next one.
    ///
    /// `expected_new_count` is the sequence number the caller believes this
    /// slash produces. If another slash already advanced the counter (so this
    /// is a duplicate), the call is skipped and returns `false`; otherwise the
    /// slash is applied and returns `true`.
    pub fn try_slash(&mut self, node: NodeId, expected_new_count: u64) -> bool {
        if expected_new_count != self.slash_count(node) + 1 {
            return false;
        }
        self.update_reputation(node, ReputationSource::Slashing);
        true
    }

    /// The node's current score: the sum of all recorded adjustments, clamped
    /// to `[REPUTATION_MIN, REPUTATION_MAX]`.
    pub fn score(&self, node: NodeId) -> i64 {
        let sum: i64 = self
            .events
            .get(&node)
            .map(|events| events.iter().map(|event| event.adjustment).sum())
            .unwrap_or(0);
        sum.clamp(REPUTATION_MIN, REPUTATION_MAX)
    }

    /// Number of slashing events recorded for `node`.
    pub fn slash_count(&self, node: NodeId) -> u64 {
        self.slash_counts.get(&node).copied().unwrap_or(0)
    }

    /// Number of recorded events for `node` (including the initial seed).
    pub fn event_count(&self, node: NodeId) -> usize {
        self.events.get(&node).map(|events| events.len()).unwrap_or(0)
    }

    fn push_event(&mut self, node: NodeId, event: ReputationEvent) {
        self.events.entry(node).or_insert_with(Vec::new).push(event);
    }
}
