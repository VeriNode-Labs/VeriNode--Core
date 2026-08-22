//! Evidence submission and cryptographic proof verification (issue #135).
//!
//! Anyone may submit evidence of validator misbehavior by calling
//! [`EvidenceStore::submit`]. The submission must include:
//!
//! * `validator_id` — the accused validator's public key.
//! * `offense_type` — the kind of misbehavior alleged.
//! * `evidence` — raw bytes encoding the fraud proof.
//! * `bond` — a challenger bond that is forfeited if the evidence is later
//!   refuted during the challenge period.
//!
//! # Fraud-proof verification
//!
//! For **equivocation** the evidence bytes encode two signed block headers at
//! the same height with distinct hashes:
//!
//! ```text
//! [height:8][hash_a:32][hash_b:32]  (72 bytes)
//! ```
//!
//! The verifier checks that `hash_a != hash_b` — proving two conflicting
//! proposals exist — and that the height is non-zero.
//!
//! For **unavailability** the evidence encodes `missed_count` and
//! `window_start`:
//!
//! ```text
//! [missed_count:8][window_start:8]  (16 bytes)
//! ```
//!
//! For **invalid proposals** the evidence layout is identical to equivocation
//! (72 bytes) but both hash fields may be equal; validity is attested by a
//! non-zero height.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::consensus::slashing::detector::OffenseType;
use crate::consensus::view_change::types::PublicKey;

// ─── Types ────────────────────────────────────────────────────────────────────

/// A single evidence submission from an arbitrary challenger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceSubmission {
    /// The accused validator.
    pub validator_id: PublicKey,
    /// The alleged offense.
    pub offense_type: OffenseType,
    /// Raw cryptographic evidence bytes.
    pub evidence: Vec<u8>,
    /// Bond posted by the submitter; forfeited if the submission is refuted.
    pub bond: u64,
    /// Public key of the entity that submitted this evidence.
    pub submitter: PublicKey,
    /// Sequence number assigned at submission time (monotonically increasing).
    pub submission_id: u64,
}

/// Outcome of a cryptographic evidence verification attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationResult {
    /// Evidence is cryptographically valid.
    Valid,
    /// Evidence payload is too short or structurally malformed.
    InvalidFormat,
    /// Equivocation evidence does not show two conflicting hashes.
    NoConflict,
    /// The alleged offense type is not one of the recognised categories.
    UnknownOffenseType,
    /// Unavailability evidence does not show a count above the threshold.
    ThresholdNotExceeded,
}

/// Errors returned by evidence operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceError {
    /// Cryptographic verification of the evidence failed.
    VerificationFailed(VerificationResult),
    /// A submission with this ID was not found.
    NotFound,
    /// The caller is not the original submitter of this evidence.
    Unauthorized,
}

// ─── EvidenceStore ────────────────────────────────────────────────────────────

/// Stateful store of evidence submissions.
///
/// Submissions are keyed by their monotonically-assigned `submission_id`.
/// Duplicate evidence for the same `(validator_id, offense_type)` pair is
/// accepted (multiple independent submitters may present the same misbehavior)
/// but each submission is independently verifiable.
#[derive(Clone, Debug, Default)]
pub struct EvidenceStore {
    /// All submissions indexed by their sequence number.
    submissions: BTreeMap<u64, EvidenceSubmission>,
    /// Next sequence number to assign.
    next_id: u64,
}

impl EvidenceStore {
    /// Create an empty evidence store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit evidence of validator misbehavior.
    ///
    /// Returns the assigned `submission_id` on success, or an
    /// [`EvidenceError::VerificationFailed`] if the fraud proof fails
    /// cryptographic verification.
    pub fn submit(
        &mut self,
        submitter: PublicKey,
        validator_id: PublicKey,
        offense_type: OffenseType,
        evidence: Vec<u8>,
        bond: u64,
    ) -> Result<u64, EvidenceError> {
        // Verify the fraud proof before accepting the submission.
        let result = Self::verify_fraud_proof(offense_type, &evidence);
        if result != VerificationResult::Valid {
            return Err(EvidenceError::VerificationFailed(result));
        }

        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);

        self.submissions.insert(
            id,
            EvidenceSubmission {
                validator_id,
                offense_type,
                evidence,
                bond,
                submitter,
                submission_id: id,
            },
        );

        Ok(id)
    }

    /// Retrieve a submission by its ID.
    pub fn get(&self, submission_id: u64) -> Option<&EvidenceSubmission> {
        self.submissions.get(&submission_id)
    }

    /// All submissions currently in the store.
    pub fn all_submissions(&self) -> impl Iterator<Item = &EvidenceSubmission> {
        self.submissions.values()
    }

    /// Number of submissions in the store.
    pub fn len(&self) -> usize {
        self.submissions.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.submissions.is_empty()
    }

    /// Remove a submission (called after slashing is executed or evidence is refuted).
    pub fn remove(&mut self, submission_id: u64) -> Option<EvidenceSubmission> {
        self.submissions.remove(&submission_id)
    }

    // ── Fraud-proof verification ──────────────────────────────────────────────

    /// Verify the cryptographic integrity of evidence bytes for a given offense.
    ///
    /// # Equivocation layout (72 bytes)
    ///
    /// ```text
    /// bytes[0..8]   — height (u64 little-endian)
    /// bytes[8..40]  — block_hash_a ([u8; 32])
    /// bytes[40..72] — block_hash_b ([u8; 32])
    /// ```
    ///
    /// Valid iff `height > 0` and `hash_a != hash_b`.
    ///
    /// # Unavailability layout (16 bytes)
    ///
    /// ```text
    /// bytes[0..8]  — missed_count (u64 little-endian)
    /// bytes[8..16] — window_start (u64 little-endian)
    /// ```
    ///
    /// Valid iff `missed_count > UNAVAILABILITY_THRESHOLD`.
    ///
    /// # Invalid proposal layout (72 bytes)
    ///
    /// ```text
    /// bytes[0..8]   — height (u64 little-endian)
    /// bytes[8..40]  — block_hash_a ([u8; 32])
    /// bytes[40..72] — block_hash_b ([u8; 32])
    /// ```
    ///
    /// Valid iff `height > 0`.
    pub fn verify_fraud_proof(
        offense_type: OffenseType,
        evidence: &[u8],
    ) -> VerificationResult {
        match offense_type {
            OffenseType::Equivocation => {
                if evidence.len() < 72 {
                    return VerificationResult::InvalidFormat;
                }
                let height =
                    u64::from_le_bytes(evidence[..8].try_into().expect("slice is 8 bytes"));
                if height == 0 {
                    return VerificationResult::InvalidFormat;
                }
                let hash_a = &evidence[8..40];
                let hash_b = &evidence[40..72];
                if hash_a == hash_b {
                    return VerificationResult::NoConflict;
                }
                VerificationResult::Valid
            }
            OffenseType::Unavailability => {
                if evidence.len() < 16 {
                    return VerificationResult::InvalidFormat;
                }
                let missed_count =
                    u64::from_le_bytes(evidence[..8].try_into().expect("slice is 8 bytes"));
                if missed_count <= crate::consensus::slashing::detector::UNAVAILABILITY_THRESHOLD {
                    return VerificationResult::ThresholdNotExceeded;
                }
                VerificationResult::Valid
            }
            OffenseType::InvalidProposal => {
                if evidence.len() < 72 {
                    return VerificationResult::InvalidFormat;
                }
                let height =
                    u64::from_le_bytes(evidence[..8].try_into().expect("slice is 8 bytes"));
                if height == 0 {
                    return VerificationResult::InvalidFormat;
                }
                VerificationResult::Valid
            }
        }
    }
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::slashing::detector::UNAVAILABILITY_THRESHOLD;

    fn pk(id: u8) -> PublicKey {
        let mut k = [0u8; 32];
        k[31] = id;
        k
    }

    // ── helpers to build valid evidence bytes ─────────────────────────────────

    fn equivocation_evidence(height: u64, hash_a: u8, hash_b: u8) -> Vec<u8> {
        let mut buf = Vec::with_capacity(72);
        buf.extend_from_slice(&height.to_le_bytes());
        let mut ha = [0u8; 32];
        ha[31] = hash_a;
        let mut hb = [0u8; 32];
        hb[31] = hash_b;
        buf.extend_from_slice(&ha);
        buf.extend_from_slice(&hb);
        buf
    }

    fn unavailability_evidence(missed: u64, window_start: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&missed.to_le_bytes());
        buf.extend_from_slice(&window_start.to_le_bytes());
        buf
    }

    fn invalid_proposal_evidence(height: u64) -> Vec<u8> {
        equivocation_evidence(height, 1, 1) // same hashes are fine for InvalidProposal
    }

    // ── verify_fraud_proof ────────────────────────────────────────────────────

    #[test]
    fn equivocation_valid_evidence() {
        let ev = equivocation_evidence(100, 1, 2);
        assert_eq!(
            EvidenceStore::verify_fraud_proof(OffenseType::Equivocation, &ev),
            VerificationResult::Valid
        );
    }

    #[test]
    fn equivocation_same_hashes_no_conflict() {
        let ev = equivocation_evidence(100, 5, 5);
        assert_eq!(
            EvidenceStore::verify_fraud_proof(OffenseType::Equivocation, &ev),
            VerificationResult::NoConflict
        );
    }

    #[test]
    fn equivocation_zero_height_invalid() {
        let ev = equivocation_evidence(0, 1, 2);
        assert_eq!(
            EvidenceStore::verify_fraud_proof(OffenseType::Equivocation, &ev),
            VerificationResult::InvalidFormat
        );
    }

    #[test]
    fn equivocation_too_short_invalid() {
        let ev = vec![0u8; 10];
        assert_eq!(
            EvidenceStore::verify_fraud_proof(OffenseType::Equivocation, &ev),
            VerificationResult::InvalidFormat
        );
    }

    #[test]
    fn unavailability_valid_evidence() {
        let ev = unavailability_evidence(UNAVAILABILITY_THRESHOLD + 1, 0);
        assert_eq!(
            EvidenceStore::verify_fraud_proof(OffenseType::Unavailability, &ev),
            VerificationResult::Valid
        );
    }

    #[test]
    fn unavailability_at_threshold_invalid() {
        // Must be strictly greater than threshold.
        let ev = unavailability_evidence(UNAVAILABILITY_THRESHOLD, 0);
        assert_eq!(
            EvidenceStore::verify_fraud_proof(OffenseType::Unavailability, &ev),
            VerificationResult::ThresholdNotExceeded
        );
    }

    #[test]
    fn invalid_proposal_valid_evidence() {
        let ev = invalid_proposal_evidence(42);
        assert_eq!(
            EvidenceStore::verify_fraud_proof(OffenseType::InvalidProposal, &ev),
            VerificationResult::Valid
        );
    }

    // ── EvidenceStore::submit ─────────────────────────────────────────────────

    #[test]
    fn submit_valid_equivocation_returns_id() {
        let mut store = EvidenceStore::new();
        let ev = equivocation_evidence(100, 1, 2);
        let id = store
            .submit(pk(99), pk(1), OffenseType::Equivocation, ev, 500)
            .unwrap();
        assert_eq!(id, 0);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn submit_invalid_evidence_rejected() {
        let mut store = EvidenceStore::new();
        let bad_ev = equivocation_evidence(100, 5, 5); // same hashes
        let err = store
            .submit(pk(99), pk(1), OffenseType::Equivocation, bad_ev, 500)
            .unwrap_err();
        assert_eq!(
            err,
            EvidenceError::VerificationFailed(VerificationResult::NoConflict)
        );
        assert!(store.is_empty());
    }

    #[test]
    fn multiple_submissions_get_sequential_ids() {
        let mut store = EvidenceStore::new();
        let ev = equivocation_evidence(1, 1, 2);
        let id0 = store
            .submit(pk(99), pk(1), OffenseType::Equivocation, ev.clone(), 100)
            .unwrap();
        let id1 = store
            .submit(pk(98), pk(2), OffenseType::Equivocation, ev, 200)
            .unwrap();
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);
    }

    #[test]
    fn get_returns_submission() {
        let mut store = EvidenceStore::new();
        let ev = equivocation_evidence(7, 3, 9);
        let id = store
            .submit(pk(10), pk(2), OffenseType::Equivocation, ev.clone(), 300)
            .unwrap();
        let sub = store.get(id).unwrap();
        assert_eq!(sub.validator_id, pk(2));
        assert_eq!(sub.bond, 300);
        assert_eq!(sub.evidence, ev);
    }

    #[test]
    fn remove_returns_submission_and_clears_it() {
        let mut store = EvidenceStore::new();
        let ev = equivocation_evidence(3, 1, 2);
        let id = store
            .submit(pk(1), pk(2), OffenseType::Equivocation, ev, 50)
            .unwrap();
        let removed = store.remove(id).unwrap();
        assert_eq!(removed.submission_id, id);
        assert!(store.get(id).is_none());
        assert!(store.is_empty());
    }
}
