//! Slashing condition detector for validator misbehavior (issue #135).
//!
//! Scans for the three slashable offenses:
//! 1. **Equivocation** — a validator proposed two conflicting blocks at the same height.
//! 2. **Unavailability** — a validator missed more than 100 attestations in a 24-hour window.
//! 3. **Invalid proposal** — a validator proposed a structurally invalid block.
//!
//! Detection is purely deterministic and side-effect-free; callers collect the
//! returned [`SlashingViolation`] values and forward them to the evidence layer.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::consensus::view_change::types::{BlockHash, PublicKey};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Attestation-unavailability threshold per 24-hour window.
/// A missed count strictly above this value triggers slashing.
pub const UNAVAILABILITY_THRESHOLD: u64 = 100;

/// 24 hours expressed in seconds — the observation window for missed attestations.
pub const ATTESTATION_WINDOW_SECS: u64 = 86_400;

// ─── Offense types ────────────────────────────────────────────────────────────

/// The three slashable offense categories defined by the protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OffenseType {
    /// Validator proposed two different blocks at the same height.
    Equivocation,
    /// Validator missed more than [`UNAVAILABILITY_THRESHOLD`] attestations in 24 h.
    Unavailability,
    /// Validator proposed an invalid (e.g., structurally malformed) block.
    InvalidProposal,
}

/// A confirmed slashing violation ready for evidence submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlashingViolation {
    /// Validator that committed the offense.
    pub validator_id: PublicKey,
    /// Category of the offense.
    pub offense_type: OffenseType,
    /// Raw cryptographic evidence (serialized proof bytes).
    pub evidence: Vec<u8>,
}

// ─── Proposal record ──────────────────────────────────────────────────────────

/// A single block proposal observed by the detector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedProposal {
    /// Consensus height at which the block was proposed.
    pub height: u64,
    /// Hash of the proposed block.
    pub block_hash: BlockHash,
    /// Whether this proposal is structurally valid.
    pub is_valid: bool,
}

// ─── Attestation miss record ──────────────────────────────────────────────────

/// Per-validator missed-attestation counter within a rolling 24-hour window.
#[derive(Clone, Debug, Default)]
struct AttestationRecord {
    /// Number of missed attestations within the current window.
    missed_count: u64,
    /// Unix timestamp (seconds) at which the current window started.
    window_start: u64,
}

// ─── SlashingConditionDetector ────────────────────────────────────────────────

/// Stateful detector that monitors validator proposals and attestation inclusion
/// for slashable misbehavior.
///
/// # Invariants
///
/// * Each `(height, validator)` pair stores at most one reference proposal; a
///   second proposal with a different `block_hash` is immediately flagged as
///   equivocation.
/// * Duplicate proposals (same height, same proposer, same hash) are silently
///   deduplicated.
/// * Missed-attestation counts are scoped to rolling 24-hour windows; the
///   window resets when `current_time >= window_start + ATTESTATION_WINDOW_SECS`.
#[derive(Clone, Debug, Default)]
pub struct SlashingConditionDetector {
    /// First valid proposal seen per `(height, validator_id)`.
    proposals: BTreeMap<(u64, PublicKey), ObservedProposal>,
    /// Missed-attestation tracking per validator.
    attestation_records: BTreeMap<PublicKey, AttestationRecord>,
    /// Accumulated violations awaiting evidence submission.
    violations: Vec<SlashingViolation>,
}

impl SlashingConditionDetector {
    /// Create a new, empty detector.
    pub fn new() -> Self {
        Self::default()
    }

    // ── Equivocation ─────────────────────────────────────────────────────────

    /// Observe a block proposal from `validator_id` at `height`.
    ///
    /// * `is_valid` — whether the proposal is structurally valid.
    ///
    /// Returns:
    /// * `Some(violation)` — equivocation or invalid-proposal offense detected.
    /// * `None` — first valid proposal for this `(height, validator_id)`, or duplicate.
    pub fn observe_proposal(
        &mut self,
        validator_id: PublicKey,
        height: u64,
        block_hash: BlockHash,
        is_valid: bool,
    ) -> Option<SlashingViolation> {
        // Invalid proposal — detect immediately, no equivocation check needed.
        if !is_valid {
            let evidence = Self::encode_proposal_evidence(height, &block_hash, &block_hash);
            let violation = SlashingViolation {
                validator_id,
                offense_type: OffenseType::InvalidProposal,
                evidence,
            };
            self.violations.push(violation.clone());
            return Some(violation);
        }

        let key = (height, validator_id);

        if let Some(existing) = self.proposals.get(&key) {
            if existing.block_hash == block_hash {
                // Exact duplicate — deduplicated silently.
                return None;
            }
            // Conflicting proposal at same (height, validator) → equivocation.
            let evidence = Self::encode_proposal_evidence(height, &existing.block_hash, &block_hash);
            let violation = SlashingViolation {
                validator_id,
                offense_type: OffenseType::Equivocation,
                evidence,
            };
            self.violations.push(violation.clone());
            return Some(violation);
        }

        // First valid proposal — record it.
        self.proposals.insert(
            key,
            ObservedProposal {
                height,
                block_hash,
                is_valid: true,
            },
        );
        None
    }

    // ── Unavailability ────────────────────────────────────────────────────────

    /// Record a missed attestation for `validator_id` at `current_time` (Unix seconds).
    ///
    /// Returns `Some(violation)` if the validator has now exceeded
    /// [`UNAVAILABILITY_THRESHOLD`] missed attestations within the rolling window.
    pub fn record_missed_attestation(
        &mut self,
        validator_id: PublicKey,
        current_time: u64,
    ) -> Option<SlashingViolation> {
        let record = self
            .attestation_records
            .entry(validator_id)
            .or_insert_with(|| AttestationRecord {
                missed_count: 0,
                window_start: current_time,
            });

        // Roll the window forward if 24 hours have elapsed.
        if current_time >= record.window_start.saturating_add(ATTESTATION_WINDOW_SECS) {
            record.missed_count = 0;
            record.window_start = current_time;
        }

        record.missed_count = record.missed_count.saturating_add(1);

        if record.missed_count > UNAVAILABILITY_THRESHOLD {
            let evidence =
                Self::encode_unavailability_evidence(record.missed_count, record.window_start);
            let violation = SlashingViolation {
                validator_id,
                offense_type: OffenseType::Unavailability,
                evidence,
            };
            self.violations.push(violation.clone());
            return Some(violation);
        }

        None
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// All violations accumulated so far.
    pub fn violations(&self) -> &[SlashingViolation] {
        &self.violations
    }

    /// Drain and return all accumulated violations, clearing the internal log.
    pub fn drain_violations(&mut self) -> Vec<SlashingViolation> {
        core::mem::take(&mut self.violations)
    }

    /// Missed-attestation count for `validator_id` in its current window.
    pub fn missed_count(&self, validator_id: &PublicKey) -> u64 {
        self.attestation_records
            .get(validator_id)
            .map(|r| r.missed_count)
            .unwrap_or(0)
    }

    /// Number of unique `(height, validator)` proposals currently tracked.
    pub fn tracked_proposal_count(&self) -> usize {
        self.proposals.len()
    }

    // ── Evidence encoding ─────────────────────────────────────────────────────

    /// Encode evidence bytes for a proposal offense.
    ///
    /// Layout: `[height:8][hash_a:32][hash_b:32]` = 72 bytes.
    fn encode_proposal_evidence(height: u64, hash_a: &BlockHash, hash_b: &BlockHash) -> Vec<u8> {
        let mut buf = Vec::with_capacity(72);
        buf.extend_from_slice(&height.to_le_bytes());
        buf.extend_from_slice(hash_a);
        buf.extend_from_slice(hash_b);
        buf
    }

    /// Encode evidence bytes for an unavailability offense.
    ///
    /// Layout: `[missed_count:8][window_start:8]` = 16 bytes.
    fn encode_unavailability_evidence(missed_count: u64, window_start: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&missed_count.to_le_bytes());
        buf.extend_from_slice(&window_start.to_le_bytes());
        buf
    }
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

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

    // ── equivocation ──────────────────────────────────────────────────────────

    #[test]
    fn first_proposal_recorded_no_violation() {
        let mut det = SlashingConditionDetector::new();
        let result = det.observe_proposal(pk(1), 10, hash(1), true);
        assert!(result.is_none());
        assert_eq!(det.tracked_proposal_count(), 1);
        assert!(det.violations().is_empty());
    }

    #[test]
    fn duplicate_proposal_deduplicated() {
        let mut det = SlashingConditionDetector::new();
        det.observe_proposal(pk(1), 10, hash(1), true);
        let result = det.observe_proposal(pk(1), 10, hash(1), true);
        assert!(result.is_none());
        assert!(det.violations().is_empty());
    }

    #[test]
    fn conflicting_proposal_triggers_equivocation() {
        let mut det = SlashingConditionDetector::new();
        det.observe_proposal(pk(1), 10, hash(1), true);
        let v = det.observe_proposal(pk(1), 10, hash(2), true).unwrap();
        assert_eq!(v.validator_id, pk(1));
        assert_eq!(v.offense_type, OffenseType::Equivocation);
        // evidence: 8 (height) + 32 + 32 = 72 bytes
        assert_eq!(v.evidence.len(), 72);
        // height encoded as little-endian at start
        assert_eq!(u64::from_le_bytes(v.evidence[..8].try_into().unwrap()), 10);
    }

    #[test]
    fn different_validators_same_height_no_equivocation() {
        let mut det = SlashingConditionDetector::new();
        det.observe_proposal(pk(1), 5, hash(1), true);
        let result = det.observe_proposal(pk(2), 5, hash(2), true);
        assert!(result.is_none());
    }

    // ── invalid proposal ──────────────────────────────────────────────────────

    #[test]
    fn invalid_proposal_triggers_violation() {
        let mut det = SlashingConditionDetector::new();
        let v = det.observe_proposal(pk(3), 7, hash(10), false).unwrap();
        assert_eq!(v.offense_type, OffenseType::InvalidProposal);
        assert_eq!(v.validator_id, pk(3));
    }

    // ── unavailability ────────────────────────────────────────────────────────

    #[test]
    fn missed_attestations_below_threshold_no_violation() {
        let mut det = SlashingConditionDetector::new();
        for i in 0..UNAVAILABILITY_THRESHOLD {
            let r = det.record_missed_attestation(pk(1), 1000 + i);
            assert!(r.is_none());
        }
        assert_eq!(det.missed_count(&pk(1)), UNAVAILABILITY_THRESHOLD);
    }

    #[test]
    fn missed_attestations_above_threshold_triggers_violation() {
        let mut det = SlashingConditionDetector::new();
        // Fill to exactly threshold — no violation yet.
        for i in 0..UNAVAILABILITY_THRESHOLD {
            det.record_missed_attestation(pk(1), 1000 + i);
        }
        // One more pushes it over.
        let v = det
            .record_missed_attestation(pk(1), 1000 + UNAVAILABILITY_THRESHOLD)
            .unwrap();
        assert_eq!(v.offense_type, OffenseType::Unavailability);
        assert_eq!(v.validator_id, pk(1));
        // evidence: 8 (count) + 8 (window_start) = 16 bytes
        assert_eq!(v.evidence.len(), 16);
    }

    #[test]
    fn attestation_window_resets_after_24h() {
        let mut det = SlashingConditionDetector::new();
        // Record UNAVAILABILITY_THRESHOLD misses.
        for i in 0..UNAVAILABILITY_THRESHOLD {
            det.record_missed_attestation(pk(1), i);
        }
        assert_eq!(det.missed_count(&pk(1)), UNAVAILABILITY_THRESHOLD);

        // Advance time past the 24-hour window — counter should reset.
        let new_time = ATTESTATION_WINDOW_SECS + 1;
        det.record_missed_attestation(pk(1), new_time);
        // After reset the count is 1 (just the new miss).
        assert_eq!(det.missed_count(&pk(1)), 1);
    }

    #[test]
    fn drain_violations_clears_log() {
        let mut det = SlashingConditionDetector::new();
        det.observe_proposal(pk(1), 1, hash(1), true);
        det.observe_proposal(pk(1), 1, hash(2), true); // equivocation
        assert_eq!(det.violations().len(), 1);
        let drained = det.drain_violations();
        assert_eq!(drained.len(), 1);
        assert!(det.violations().is_empty());
    }
}
