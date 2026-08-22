//! Core data structures and tie-breaking primitives for BFT view-change QCs (issue #142).
//!
//! Under network partitions, divergent Quorum Certificates (QCs) can be generated
//! for the same view by disconnected network partitions. When the partition heals,
//! nodes must deterministically resolve the conflict without split-brain or stall.
//!
//! # Conflict Resolution Rules
//!
//! 1. **Highest `qc_epoch` wins**: A monotonically incremented counter assigned
//!    at proposal time. Higher epochs reflect more recent network state.
//! 2. **Lexicographical hash of aggregated public-key set**: If `qc_epoch` is
//!    identical, compare the SHA-256 hash over the sorted, deduplicated set of
//!    signer public keys. The higher hash wins.
//! 3. **Lexicographical block hash**: If both epoch and public-key set hashes match,
//!    the higher `block_hash` breaks the tie deterministically.
//!
//! Conflicting QCs that lose the tie-break are placed in a [`QuarantineBuffer`]
//! for 2 view-change rounds before garbage collection, and a
//! [`QcConflictDetected`] event is emitted for observability.

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::crypto::sha256::sha256;

/// Number of view-change rounds conflicting QCs remain in quarantine before GC.
pub const QUARANTINE_ROUND_LIMIT: u64 = 2;

/// Maximum number of view-change rounds to guarantee deterministic convergence after partition heal.
pub const CONVERGENCE_ROUND_LIMIT: u64 = 3;

/// A 32-byte public key identifier representing a validator in the consensus committee.
pub type PublicKey = [u8; 32];

/// A 32-byte hash identifying a block proposal or payload.
pub type BlockHash = [u8; 32];

/// A 96-byte BLS aggregate signature.
pub type AggregateSignature = [u8; 96];

/// A BFT Quorum Certificate certifying 2/3+1 validator agreement for a view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumCertificate {
    /// Consensus view number this certificate applies to.
    pub view: u64,
    /// Monotonically incrementing proposal epoch counter.
    pub qc_epoch: u64,
    /// Digest of the block or payload certified by this QC.
    pub block_hash: BlockHash,
    /// Set of public keys of validators that signed this certificate.
    pub signers: Vec<PublicKey>,
    /// Aggregated BLS signature across all signers.
    pub signature: AggregateSignature,
}

/// Type alias for [`QuorumCertificate`].
pub type QC = QuorumCertificate;

impl QuorumCertificate {
    /// Construct a new [`QuorumCertificate`].
    pub fn new(
        view: u64,
        qc_epoch: u64,
        block_hash: BlockHash,
        signers: Vec<PublicKey>,
        signature: AggregateSignature,
    ) -> Self {
        Self {
            view,
            qc_epoch,
            block_hash,
            signers,
            signature,
        }
    }

    /// Compute the deterministic SHA-256 hash over the sorted, deduplicated
    /// public-key set.
    ///
    /// The public keys are first sorted in ascending lexicographical byte order
    /// and deduplicated so that the resulting hash is invariant under signer order.
    pub fn public_key_set_hash(&self) -> [u8; 32] {
        compute_public_key_set_hash(&self.signers)
    }

    /// Compare two QCs for the same view using deterministic tie-breaking rules.
    ///
    /// Order of precedence:
    /// 1. `qc_epoch`: higher epoch is `Greater` (wins).
    /// 2. Lexicographical hash of the aggregated public-key set: higher hash is `Greater` (wins).
    /// 3. Lexicographical `block_hash`: higher hash is `Greater` (wins).
    /// 4. Lexicographical `signature`: higher signature is `Greater` (wins).
    pub fn tie_break_cmp(&self, other: &Self) -> Ordering {
        // 1. Highest qc_epoch wins.
        match self.qc_epoch.cmp(&other.qc_epoch) {
            Ordering::Equal => {}
            non_eq => return non_eq,
        }

        // 2. Highest lexicographical hash of aggregated public-key set wins.
        let self_pk_hash = self.public_key_set_hash();
        let other_pk_hash = other.public_key_set_hash();
        match self_pk_hash.cmp(&other_pk_hash) {
            Ordering::Equal => {}
            non_eq => return non_eq,
        }

        // 3. Lexicographical block hash tie-breaker.
        match self.block_hash.cmp(&other.block_hash) {
            Ordering::Equal => {}
            non_eq => return non_eq,
        }

        // 4. Exact signature tie-breaker.
        self.signature.cmp(&other.signature)
    }

    /// Returns `true` if `other` conflicts with `self` for the same view
    /// (i.e. same view, but divergent `block_hash`, `qc_epoch`, `signers`, or `signature`).
    pub fn is_conflict(&self, other: &Self) -> bool {
        self.view == other.view && self != other
    }
}

/// Compute the SHA-256 hash of a list of public keys after lexicographical
/// sorting and deduplication.
pub fn compute_public_key_set_hash(keys: &[PublicKey]) -> [u8; 32] {
    let mut sorted_keys: Vec<PublicKey> = keys.to_vec();
    sorted_keys.sort_unstable();
    sorted_keys.dedup();

    let mut buf = Vec::with_capacity(sorted_keys.len() * 32);
    for key in &sorted_keys {
        buf.extend_from_slice(key);
    }
    sha256(&buf)
}

/// Observability event emitted when a QC conflict is detected during view change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QcConflictDetected {
    /// Consensus view in which the conflict occurred.
    pub view: u64,
    /// The `qc_epoch` of the first conflicting QC.
    pub qc_epoch_a: u64,
    /// The `qc_epoch` of the second conflicting QC.
    pub qc_epoch_b: u64,
}

/// Events emitted during view change and QC processing for telemetry and monitoring.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ViewChangeEvent {
    /// Divergent QCs detected for the same view.
    QcConflictDetected {
        /// The view where conflict was observed.
        view: u64,
        /// `qc_epoch` of the active/existing QC.
        qc_epoch_a: u64,
        /// `qc_epoch` of the incoming/competing QC.
        qc_epoch_b: u64,
    },
    /// A new QC was accepted as canonical for a view.
    QcAccepted {
        /// The view number.
        view: u64,
        /// The `qc_epoch` of the accepted QC.
        qc_epoch: u64,
    },
    /// A losing conflicting QC was placed into the quarantine buffer.
    QcQuarantined {
        /// The view number.
        view: u64,
        /// The `qc_epoch` of the quarantined QC.
        qc_epoch: u64,
        /// View-change round when placed in quarantine.
        quarantined_at_round: u64,
    },
    /// Expired QCs were purged from quarantine by garbage collection.
    QcGarbageCollected {
        /// Number of QCs evicted during this GC cycle.
        evicted_count: usize,
        /// View at which GC ran.
        at_view: u64,
    },
    /// View was advanced.
    ViewAdvanced {
        /// The new active view.
        new_view: u64,
    },
}

/// Errors returned by view change and QC processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewChangeError {
    /// QC view is older than the current view-change window.
    StaleView {
        /// View on the incoming QC.
        qc_view: u64,
        /// Current active view.
        current_view: u64,
    },
    /// Incoming QC has zero signers.
    EmptySigners,
    /// Monotonic epoch counter overflow.
    EpochOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pk(id: u8) -> PublicKey {
        let mut pk = [0u8; 32];
        pk[31] = id;
        pk
    }

    fn dummy_hash(id: u8) -> BlockHash {
        let mut h = [0u8; 32];
        h[31] = id;
        h
    }

    fn dummy_sig(id: u8) -> AggregateSignature {
        let mut sig = [0u8; 96];
        sig[95] = id;
        sig
    }

    #[test]
    fn test_public_key_set_hash_is_order_independent() {
        let pk1 = dummy_pk(1);
        let pk2 = dummy_pk(2);
        let pk3 = dummy_pk(3);

        let hash_a = compute_public_key_set_hash(&[pk1, pk2, pk3]);
        let hash_b = compute_public_key_set_hash(&[pk3, pk1, pk2]);
        let hash_c = compute_public_key_set_hash(&[pk2, pk3, pk1, pk1]); // with duplicate

        assert_eq!(hash_a, hash_b);
        assert_eq!(hash_a, hash_c);
    }

    #[test]
    fn test_tie_breaking_higher_qc_epoch_wins() {
        let qc1 = QC::new(10, 1, dummy_hash(1), alloc::vec![dummy_pk(1)], dummy_sig(1));
        let qc2 = QC::new(10, 2, dummy_hash(2), alloc::vec![dummy_pk(2)], dummy_sig(2));

        assert_eq!(qc2.tie_break_cmp(&qc1), Ordering::Greater);
        assert_eq!(qc1.tie_break_cmp(&qc2), Ordering::Less);
    }

    #[test]
    fn test_tie_breaking_equal_epoch_uses_public_key_hash() {
        let pk_a = dummy_pk(10);
        let pk_b = dummy_pk(20);

        let qc_a = QC::new(10, 5, dummy_hash(1), alloc::vec![pk_a], dummy_sig(1));
        let qc_b = QC::new(10, 5, dummy_hash(2), alloc::vec![pk_b], dummy_sig(2));

        let hash_a = qc_a.public_key_set_hash();
        let hash_b = qc_b.public_key_set_hash();
        assert_ne!(hash_a, hash_b);

        let expected_ord = hash_a.cmp(&hash_b);
        assert_eq!(qc_a.tie_break_cmp(&qc_b), expected_ord);
    }

    #[test]
    fn test_is_conflict_detection() {
        let qc1 = QC::new(10, 1, dummy_hash(1), alloc::vec![dummy_pk(1)], dummy_sig(1));
        let qc2 = QC::new(10, 2, dummy_hash(2), alloc::vec![dummy_pk(2)], dummy_sig(2));
        let qc3 = QC::new(11, 1, dummy_hash(1), alloc::vec![dummy_pk(1)], dummy_sig(1));

        assert!(qc1.is_conflict(&qc2));
        assert!(!qc1.is_conflict(&qc1));
        assert!(!qc1.is_conflict(&qc3)); // different view
    }
}
