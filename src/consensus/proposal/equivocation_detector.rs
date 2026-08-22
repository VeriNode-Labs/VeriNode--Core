//! Byzantine equivocation detector for consensus proposals (issue #137).
//!
//! A Byzantine primary may send two different block proposals at the same
//! height with valid signatures — called *equivocation*. This causes honest
//! replicas to lock on divergent proposals, preventing quorum and deadlocking
//! leader election.
//!
//! # Invariants
//!
//! * **Equivocation**: two conflicting proposals at the same `height` with
//!   distinct `block_hash` values, both carrying valid (non-empty) signatures
//!   from the same `proposer`.
//! * **Detection**: the detector stores the first proposal seen per
//!   `(height, proposer)` pair; on receiving a second, conflicting proposal
//!   it constructs and returns an [`EquivocationProof`].
//! * **Broadcast**: callers must broadcast the returned [`EquivocationProof`]
//!   to all peers so every honest replica can immediately advance its view
//!   without waiting for the timeout (see `timeout_leader`).

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::consensus::view_change::types::{AggregateSignature, BlockHash, PublicKey};

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

/// A block proposal from a primary/leader at a specific height.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    /// Consensus height (block number) this proposal is for.
    pub height: u64,
    /// Identity of the proposing replica.
    pub proposer: PublicKey,
    /// Hash of the proposed block.
    pub block_hash: BlockHash,
    /// Proposer's signature over `(height, block_hash)`.
    pub signature: AggregateSignature,
}

impl Proposal {
    /// Construct a new [`Proposal`].
    pub fn new(
        height: u64,
        proposer: PublicKey,
        block_hash: BlockHash,
        signature: AggregateSignature,
    ) -> Self {
        Self {
            height,
            proposer,
            block_hash,
            signature,
        }
    }
}

/// Proof of Byzantine equivocation: two conflicting proposals from the same
/// proposer at the same height, both carrying valid (non-empty) signatures.
///
/// Broadcasting this proof to all replicas allows them to immediately advance
/// to the next view without waiting for the timeout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EquivocationProof {
    /// The consensus height at which equivocation was detected.
    pub height: u64,
    /// The equivocating proposer's public key.
    pub proposer: PublicKey,
    /// First conflicting proposal.
    pub proposal_a: Proposal,
    /// Second conflicting proposal (distinct `block_hash` from `proposal_a`).
    pub proposal_b: Proposal,
}

/// Errors returned by [`EquivocationDetector::observe`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EquivocationError {
    /// The proposal carries a zero-byte (empty/unset) signature.
    InvalidSignature,
}

// ──────────────────────────────────────────────────────────────────────────────
// Detector
// ──────────────────────────────────────────────────────────────────────────────

/// Stateful equivocation detector.
///
/// Stores the first valid proposal seen per `(height, proposer)` key. When a
/// second proposal arrives for the same key with a different `block_hash` the
/// detector returns an [`EquivocationProof`] that callers must broadcast.
///
/// Proposals for an identical `(height, proposer, block_hash)` triple are
/// silently deduplicated.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EquivocationDetector {
    /// First proposal seen, keyed by `(height, proposer)`.
    seen: BTreeMap<(u64, PublicKey), Proposal>,
    /// Accumulated proofs emitted during this detector's lifetime.
    proofs: Vec<EquivocationProof>,
}

impl EquivocationDetector {
    /// Create a new, empty detector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe an incoming proposal.
    ///
    /// Returns:
    /// * `Ok(Some(proof))` — equivocation detected; callers **must** broadcast
    ///   the returned [`EquivocationProof`] to all peers.
    /// * `Ok(None)` — first proposal for this `(height, proposer)`, or an
    ///   identical duplicate; no action needed.
    /// * `Err(EquivocationError::InvalidSignature)` — proposal carries an
    ///   all-zero signature and is rejected.
    pub fn observe(
        &mut self,
        proposal: Proposal,
    ) -> Result<Option<EquivocationProof>, EquivocationError> {
        // Reject proposals with a zeroed (invalid) signature.
        if proposal.signature == [0u8; 96] {
            return Err(EquivocationError::InvalidSignature);
        }

        let key = (proposal.height, proposal.proposer);

        if let Some(existing) = self.seen.get(&key) {
            if existing.block_hash == proposal.block_hash {
                // Exact duplicate — idempotent, no proof needed.
                return Ok(None);
            }

            // Conflicting proposal at the same (height, proposer) → equivocation!
            let proof = EquivocationProof {
                height: proposal.height,
                proposer: proposal.proposer,
                proposal_a: existing.clone(),
                proposal_b: proposal,
            };
            self.proofs.push(proof.clone());
            return Ok(Some(proof));
        }

        // First time seeing this (height, proposer) — record it.
        self.seen.insert(key, proposal);
        Ok(None)
    }

    /// All equivocation proofs emitted by this detector so far.
    pub fn proofs(&self) -> &[EquivocationProof] {
        &self.proofs
    }

    /// Drain and return all accumulated equivocation proofs, clearing the log.
    pub fn drain_proofs(&mut self) -> Vec<EquivocationProof> {
        core::mem::take(&mut self.proofs)
    }

    /// Number of unique `(height, proposer)` entries currently tracked.
    pub fn tracked_count(&self) -> usize {
        self.seen.len()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut s = [1u8; 96]; // non-zero so it passes the signature check
        s[95] = id;
        s
    }

    fn proposal(height: u64, proposer_id: u8, block_id: u8) -> Proposal {
        Proposal::new(height, pk(proposer_id), hash(block_id), sig(block_id))
    }

    // ─── happy-path ───────────────────────────────────────────────────────────

    #[test]
    fn first_proposal_is_recorded_no_proof() {
        let mut det = EquivocationDetector::new();
        let result = det.observe(proposal(1, 1, 1)).unwrap();
        assert!(result.is_none());
        assert_eq!(det.tracked_count(), 1);
        assert!(det.proofs().is_empty());
    }

    #[test]
    fn duplicate_proposal_is_deduplicated_no_proof() {
        let mut det = EquivocationDetector::new();
        det.observe(proposal(1, 1, 1)).unwrap();
        let result = det.observe(proposal(1, 1, 1)).unwrap();
        assert!(result.is_none());
        assert_eq!(det.tracked_count(), 1);
        assert!(det.proofs().is_empty());
    }

    #[test]
    fn different_proposers_same_height_no_proof() {
        let mut det = EquivocationDetector::new();
        det.observe(proposal(5, 1, 10)).unwrap();
        let result = det.observe(proposal(5, 2, 20)).unwrap(); // different proposer
        assert!(result.is_none());
        assert_eq!(det.tracked_count(), 2);
    }

    // ─── equivocation detection ────────────────────────────────────────────────

    #[test]
    fn conflicting_proposals_produce_equivocation_proof() {
        let mut det = EquivocationDetector::new();
        let p1 = proposal(3, 7, 1);
        let p2 = proposal(3, 7, 2); // same (height=3, proposer=7), different block

        det.observe(p1.clone()).unwrap();
        let result = det.observe(p2.clone()).unwrap();

        let proof = result.expect("expected equivocation proof");
        assert_eq!(proof.height, 3);
        assert_eq!(proof.proposer, pk(7));
        assert_eq!(proof.proposal_a, p1);
        assert_eq!(proof.proposal_b, p2);

        assert_eq!(det.proofs().len(), 1);
    }

    #[test]
    fn multiple_equivocations_accumulate_proofs() {
        let mut det = EquivocationDetector::new();

        // Equivocation at height 1
        det.observe(proposal(1, 1, 10)).unwrap();
        det.observe(proposal(1, 1, 11)).unwrap();

        // Equivocation at height 2
        det.observe(proposal(2, 2, 20)).unwrap();
        det.observe(proposal(2, 2, 21)).unwrap();

        assert_eq!(det.proofs().len(), 2);

        let drained = det.drain_proofs();
        assert_eq!(drained.len(), 2);
        assert!(det.proofs().is_empty()); // drained
    }

    // ─── error paths ──────────────────────────────────────────────────────────

    #[test]
    fn zero_signature_is_rejected() {
        let mut det = EquivocationDetector::new();
        let bad = Proposal::new(1, pk(1), hash(1), [0u8; 96]);
        let err = det.observe(bad).unwrap_err();
        assert_eq!(err, EquivocationError::InvalidSignature);
        assert_eq!(det.tracked_count(), 0);
    }
}
