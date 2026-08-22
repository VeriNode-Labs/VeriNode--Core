//! BFT View-Change Quorum Certificate Partition Resolver (issue #142).
//!
//! Under network partitions, disjoint validator subsets can produce divergent
//! Quorum Certificates for the same view. [`ViewChangeResolver`] orchestrates
//! proposal generation with monotonically increasing `qc_epoch` counters, evaluates
//! incoming QCs against deterministic tie-breaking rules, places conflicting
//! QCs into a 2-round quarantine buffer, and emits observability events.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::consensus::view_change::quarantine::QuarantineBuffer;
use crate::consensus::view_change::types::{
    AggregateSignature, BlockHash, PublicKey, QcConflictDetected, ViewChangeEvent, ViewChangeError,
    QC,
};

/// Result outcome of processing an incoming Quorum Certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QcProcessOutcome {
    /// QC accepted as the first canonical certificate for this view.
    AcceptedNew,
    /// QC is identical to the certificate already accepted for this view.
    AlreadyAccepted,
    /// QC conflicted with an existing certificate, won the tie-break, and replaced it.
    ConflictResolvedAccepted,
    /// QC conflicted with an existing certificate, lost the tie-break, and was quarantined.
    ConflictResolvedQuarantined,
}

/// State coordinator managing view changes, monotonic proposal epochs, QC conflict resolution,
/// and quarantine lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewChangeResolver {
    /// Active consensus view / round of this node.
    current_view: u64,
    /// Monotonically incrementing proposal epoch counter.
    current_qc_epoch: u64,
    /// Accepted canonical QCs keyed by view number.
    accepted_qcs: BTreeMap<u64, QC>,
    /// Quarantine buffer holding conflicting QCs for 2 rounds before GC.
    quarantine_buffer: QuarantineBuffer,
    /// Log of observability and lifecycle events emitted during operations.
    events: Vec<ViewChangeEvent>,
}

impl ViewChangeResolver {
    /// Create a new resolver starting at `initial_view` with `qc_epoch = 0`.
    pub fn new(initial_view: u64) -> Self {
        Self {
            current_view: initial_view,
            current_qc_epoch: 0,
            accepted_qcs: BTreeMap::new(),
            quarantine_buffer: QuarantineBuffer::new(),
            events: Vec::new(),
        }
    }

    /// Current active view number.
    pub fn current_view(&self) -> u64 {
        self.current_view
    }

    /// Current monotonic proposal epoch counter.
    pub fn current_qc_epoch(&self) -> u64 {
        self.current_qc_epoch
    }

    /// Create a new proposal QC for `view`.
    ///
    /// Monotonically increments the internal `qc_epoch` counter and assigns it to the proposal.
    pub fn create_proposal(
        &mut self,
        view: u64,
        block_hash: BlockHash,
        signers: Vec<PublicKey>,
        signature: AggregateSignature,
    ) -> Result<QC, ViewChangeError> {
        if signers.is_empty() {
            return Err(ViewChangeError::EmptySigners);
        }

        self.current_qc_epoch = self
            .current_qc_epoch
            .checked_add(1)
            .ok_or(ViewChangeError::EpochOverflow)?;

        let qc = QC::new(
            view,
            self.current_qc_epoch,
            block_hash,
            signers,
            signature,
        );

        Ok(qc)
    }

    /// Process an incoming Quorum Certificate against current view state and accepted QCs.
    ///
    /// If no QC exists for this view, it is accepted.
    /// If an identical QC exists, it is deduplicated.
    /// If a divergent QC exists for the same view:
    /// - An observability event [`ViewChangeEvent::QcConflictDetected`] is emitted.
    /// - Deterministic tie-breaking is evaluated (highest `qc_epoch` -> public key set hash -> block hash).
    /// - The winner becomes canonical; the loser is placed into the quarantine buffer for 2 rounds.
    pub fn process_qc(&mut self, incoming_qc: QC) -> Result<QcProcessOutcome, ViewChangeError> {
        if incoming_qc.signers.is_empty() {
            return Err(ViewChangeError::EmptySigners);
        }

        let view = incoming_qc.view;

        if let Some(existing) = self.accepted_qcs.get(&view).cloned() {
            if existing == incoming_qc {
                return Ok(QcProcessOutcome::AlreadyAccepted);
            }

            // Divergence detected for the same view!
            self.events.push(ViewChangeEvent::QcConflictDetected {
                view,
                qc_epoch_a: existing.qc_epoch,
                qc_epoch_b: incoming_qc.qc_epoch,
            });

            match existing.tie_break_cmp(&incoming_qc) {
                Ordering::Less => {
                    // Incoming QC wins the tie-break and supersedes existing QC.
                    self.quarantine_buffer
                        .quarantine(existing.clone(), self.current_view);
                    self.events.push(ViewChangeEvent::QcQuarantined {
                        view,
                        qc_epoch: existing.qc_epoch,
                        quarantined_at_round: self.current_view,
                    });

                    self.events.push(ViewChangeEvent::QcAccepted {
                        view,
                        qc_epoch: incoming_qc.qc_epoch,
                    });
                    self.accepted_qcs.insert(view, incoming_qc);
                    Ok(QcProcessOutcome::ConflictResolvedAccepted)
                }
                Ordering::Greater | Ordering::Equal => {
                    // Existing QC wins or ties (existing is retained). Incoming QC is quarantined.
                    self.quarantine_buffer
                        .quarantine(incoming_qc.clone(), self.current_view);
                    self.events.push(ViewChangeEvent::QcQuarantined {
                        view,
                        qc_epoch: incoming_qc.qc_epoch,
                        quarantined_at_round: self.current_view,
                    });
                    Ok(QcProcessOutcome::ConflictResolvedQuarantined)
                }
            }
        } else {
            // First QC for this view.
            self.events.push(ViewChangeEvent::QcAccepted {
                view,
                qc_epoch: incoming_qc.qc_epoch,
            });
            self.accepted_qcs.insert(view, incoming_qc);
            Ok(QcProcessOutcome::AcceptedNew)
        }
    }

    /// Advance the active view to `new_view` and run quarantine garbage collection.
    ///
    /// Purges all conflicting QCs that have resided in quarantine for >= 2 rounds.
    pub fn advance_view(&mut self, new_view: u64) -> Vec<QC> {
        self.current_view = new_view;
        let evicted = self.quarantine_buffer.gc(new_view);

        if !evicted.is_empty() {
            self.events.push(ViewChangeEvent::QcGarbageCollected {
                evicted_count: evicted.len(),
                at_view: new_view,
            });
        }

        self.events.push(ViewChangeEvent::ViewAdvanced { new_view });
        evicted
    }

    /// Look up the accepted canonical QC for a view.
    pub fn get_accepted_qc(&self, view: u64) -> Option<&QC> {
        self.accepted_qcs.get(&view)
    }

    /// Returns a map of all accepted canonical QCs.
    pub fn accepted_qcs(&self) -> &BTreeMap<u64, QC> {
        &self.accepted_qcs
    }

    /// Returns `true` if `qc` is currently held in the quarantine buffer.
    pub fn is_quarantined(&self, qc: &QC) -> bool {
        self.quarantine_buffer.contains(qc)
    }

    /// Reference to the underlying [`QuarantineBuffer`].
    pub fn quarantine_buffer(&self) -> &QuarantineBuffer {
        &self.quarantine_buffer
    }

    /// Drain and return all accumulated events.
    pub fn drain_events(&mut self) -> Vec<ViewChangeEvent> {
        core::mem::take(&mut self.events)
    }

    /// Slice of all currently accumulated events without draining.
    pub fn events(&self) -> &[ViewChangeEvent] {
        &self.events
    }
}

/// Helper function to create a conflict detection event directly.
pub fn create_conflict_event(view: u64, qc_epoch_a: u64, qc_epoch_b: u64) -> QcConflictDetected {
    QcConflictDetected {
        view,
        qc_epoch_a,
        qc_epoch_b,
    }
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
    fn test_proposal_increments_epoch_monotonically() {
        let mut resolver = ViewChangeResolver::new(1);
        assert_eq!(resolver.current_qc_epoch(), 0);

        let qc1 = resolver
            .create_proposal(1, dummy_hash(1), alloc::vec![dummy_pk(1)], dummy_sig(1))
            .unwrap();
        assert_eq!(qc1.qc_epoch, 1);
        assert_eq!(resolver.current_qc_epoch(), 1);

        let qc2 = resolver
            .create_proposal(1, dummy_hash(2), alloc::vec![dummy_pk(2)], dummy_sig(2))
            .unwrap();
        assert_eq!(qc2.qc_epoch, 2);
        assert_eq!(resolver.current_qc_epoch(), 2);
    }

    #[test]
    fn test_conflict_resolution_higher_epoch_supersedes() {
        let mut resolver = ViewChangeResolver::new(10);
        let qc1 = QC::new(10, 1, dummy_hash(1), alloc::vec![dummy_pk(1)], dummy_sig(1));
        let qc2 = QC::new(10, 3, dummy_hash(2), alloc::vec![dummy_pk(2)], dummy_sig(2));

        // Accept qc1 initially.
        assert_eq!(
            resolver.process_qc(qc1.clone()).unwrap(),
            QcProcessOutcome::AcceptedNew
        );
        assert_eq!(resolver.get_accepted_qc(10), Some(&qc1));

        // Process conflicting qc2 with higher epoch (3 > 1).
        let outcome = resolver.process_qc(qc2.clone()).unwrap();
        assert_eq!(outcome, QcProcessOutcome::ConflictResolvedAccepted);
        assert_eq!(resolver.get_accepted_qc(10), Some(&qc2));

        // qc1 is now quarantined.
        assert!(resolver.is_quarantined(&qc1));
        assert!(!resolver.is_quarantined(&qc2));

        // Verify conflict event was emitted.
        let events = resolver.events();
        assert!(events.iter().any(|e| matches!(
            e,
            ViewChangeEvent::QcConflictDetected {
                view: 10,
                qc_epoch_a: 1,
                qc_epoch_b: 3
            }
        )));
    }

    #[test]
    fn test_conflict_resolution_lower_epoch_quarantined() {
        let mut resolver = ViewChangeResolver::new(10);
        let qc1 = QC::new(10, 5, dummy_hash(1), alloc::vec![dummy_pk(1)], dummy_sig(1));
        let qc2 = QC::new(10, 2, dummy_hash(2), alloc::vec![dummy_pk(2)], dummy_sig(2));

        // Accept qc1 (epoch 5).
        assert_eq!(
            resolver.process_qc(qc1.clone()).unwrap(),
            QcProcessOutcome::AcceptedNew
        );

        // Process qc2 (epoch 2 < 5).
        let outcome = resolver.process_qc(qc2.clone()).unwrap();
        assert_eq!(outcome, QcProcessOutcome::ConflictResolvedQuarantined);
        assert_eq!(resolver.get_accepted_qc(10), Some(&qc1));
        assert!(resolver.is_quarantined(&qc2));
    }
}
