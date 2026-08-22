//! Quarantine buffer for conflicting Quorum Certificates (issue #142).
//!
//! When divergent QCs are received during a view-change partition resolution,
//! the losing QCs are stored in a [`QuarantineBuffer`]. They remain quarantined
//! for [`QUARANTINE_ROUND_LIMIT`] (2) view-change rounds before being purged by
//! garbage collection.
//!
//! Quarantining conflicting QCs prevents immediate reuse or flapping while
//! preserving evidence of partition divergence for auditing and slashing analysis.

extern crate alloc;

use alloc::vec::Vec;

use crate::consensus::view_change::types::{QuorumCertificate, QC, QUARANTINE_ROUND_LIMIT};

/// An entry in the quarantine buffer holding a conflicting QC and its quarantine timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedQc {
    /// The conflicting Quorum Certificate.
    pub qc: QC,
    /// The view-change round / view at which this QC entered quarantine.
    pub quarantined_at_round: u64,
}

/// A buffer holding conflicting QCs for [`QUARANTINE_ROUND_LIMIT`] rounds before garbage collection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QuarantineBuffer {
    entries: Vec<QuarantinedQc>,
}

impl QuarantineBuffer {
    /// Create an empty [`QuarantineBuffer`].
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Place a conflicting QC into quarantine at `current_round`.
    ///
    /// If the identical QC is already quarantined, this is an idempotent no-op and returns `false`.
    /// Otherwise, inserts the new entry and returns `true`.
    pub fn quarantine(&mut self, qc: QC, current_round: u64) -> bool {
        if self.contains(&qc) {
            return false;
        }
        self.entries.push(QuarantinedQc {
            qc,
            quarantined_at_round: current_round,
        });
        true
    }

    /// Run garbage collection for `current_round`.
    ///
    /// Evicts all quarantined QCs that have resided in quarantine for at least
    /// [`QUARANTINE_ROUND_LIMIT`] (2) view-change rounds
    /// (`current_round - entry.quarantined_at_round >= 2`).
    ///
    /// Returns the list of evicted QCs.
    pub fn gc(&mut self, current_round: u64) -> Vec<QC> {
        let mut evicted = Vec::new();
        self.entries.retain(|entry| {
            let rounds_in_quarantine = current_round.saturating_sub(entry.quarantined_at_round);
            if rounds_in_quarantine >= QUARANTINE_ROUND_LIMIT {
                evicted.push(entry.qc.clone());
                false
            } else {
                true
            }
        });
        evicted
    }

    /// Returns `true` if `qc` is currently in the quarantine buffer.
    pub fn contains(&self, qc: &QuorumCertificate) -> bool {
        self.entries.iter().any(|entry| &entry.qc == qc)
    }

    /// Number of QCs currently held in quarantine.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the quarantine buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Slice of all currently quarantined entries.
    pub fn entries(&self) -> &[QuarantinedQc] {
        &self.entries
    }

    /// Clears all entries from the quarantine buffer.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_qc(view: u64, epoch: u64) -> QC {
        let mut h = [0u8; 32];
        h[0] = view as u8;
        let mut pk = [0u8; 32];
        pk[0] = epoch as u8;
        QC::new(view, epoch, h, alloc::vec![pk], [0u8; 96])
    }

    #[test]
    fn test_quarantine_retention_and_gc_lifecycle() {
        let mut buffer = QuarantineBuffer::new();
        let qc1 = dummy_qc(10, 1);
        let qc2 = dummy_qc(10, 2);

        // Quarantine qc1 at round 10.
        assert!(buffer.quarantine(qc1.clone(), 10));
        assert_eq!(buffer.len(), 1);
        assert!(buffer.contains(&qc1));

        // Duplicate quarantine is idempotent.
        assert!(!buffer.quarantine(qc1.clone(), 10));
        assert_eq!(buffer.len(), 1);

        // Round 10 -> GC removes nothing (0 rounds elapsed).
        let evicted = buffer.gc(10);
        assert!(evicted.is_empty());
        assert_eq!(buffer.len(), 1);

        // Round 11 -> GC removes nothing (1 round elapsed < QUARANTINE_ROUND_LIMIT = 2).
        let evicted = buffer.gc(11);
        assert!(evicted.is_empty());
        assert_eq!(buffer.len(), 1);

        // Quarantine qc2 at round 11.
        assert!(buffer.quarantine(qc2.clone(), 11));
        assert_eq!(buffer.len(), 2);

        // Round 12 -> 2 rounds elapsed for qc1 (12 - 10 = 2 >= 2). qc1 is evicted; qc2 remains (12 - 11 = 1 < 2).
        let evicted = buffer.gc(12);
        assert_eq!(evicted, alloc::vec![qc1.clone()]);
        assert_eq!(buffer.len(), 1);
        assert!(!buffer.contains(&qc1));
        assert!(buffer.contains(&qc2));

        // Round 13 -> 2 rounds elapsed for qc2 (13 - 11 = 2 >= 2). qc2 is evicted.
        let evicted = buffer.gc(13);
        assert_eq!(evicted, alloc::vec![qc2]);
        assert!(buffer.is_empty());
    }
}
