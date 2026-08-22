//! Challenge period and counter-evidence handling (issue #135).
//!
//! After evidence is submitted, the accused validator has a **7-day challenge
//! window** in which to submit counter-evidence. The challenge lifecycle is:
//!
//! 1. Evidence is submitted → a [`ChallengeRecord`] is created with status
//!    [`ChallengeStatus::Open`] and a deadline 7 days from submission.
//! 2. The accused may call [`ChallengeManager::submit_counter_evidence`] before
//!    the deadline. Counter-evidence is verified the same way as original
//!    evidence; if it passes, the challenge is resolved in favour of the
//!    defender and the **challenger's bond is slashed**.
//! 3. After the deadline passes without a successful counter-evidence submission,
//!    the challenge expires and slashing may proceed.
//!
//! # Counter-evidence winning condition
//!
//! For **equivocation**, the accused validator wins by providing a single valid
//! block signed at the alleged height that proves the challenger's two alleged
//! blocks are fabrications (i.e., the counter-evidence shows the pair of
//! hashes in the original evidence cannot both be valid because one matches
//! the validator's actual signed block). In this simplified model a
//! counter-evidence payload that parses as a valid single-block proof
//! (`height > 0`, 40 bytes: `[height:8][block_hash:32]`) is accepted.
//!
//! For **unavailability** and **invalid proposal**, the accused may provide
//! log evidence that the count is below the threshold or that the block was
//! valid; these are accepted as raw payloads of at least 8 bytes.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::consensus::slashing::detector::OffenseType;
use crate::consensus::view_change::types::PublicKey;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Challenge window duration in seconds (7 days).
pub const CHALLENGE_PERIOD_SECS: u64 = 7 * 24 * 3600; // 604 800 s

// ─── Status ───────────────────────────────────────────────────────────────────

/// Lifecycle state of a challenge record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeStatus {
    /// Challenge window is open; the accused may still submit counter-evidence.
    Open,
    /// The accused submitted valid counter-evidence; challenger's bond is slashed.
    DefenderWon,
    /// The window expired without successful counter-evidence; slashing may proceed.
    Expired,
}

// ─── Records ─────────────────────────────────────────────────────────────────

/// A challenge record created for each valid evidence submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeRecord {
    /// The sequence ID of the underlying evidence submission.
    pub submission_id: u64,
    /// The accused validator's public key.
    pub validator_id: PublicKey,
    /// The alleged offense type.
    pub offense_type: OffenseType,
    /// The challenger (evidence submitter)'s public key.
    pub challenger: PublicKey,
    /// Challenger's posted bond.
    pub challenger_bond: u64,
    /// Unix timestamp (seconds) when this challenge was opened.
    pub opened_at: u64,
    /// Deadline: `opened_at + CHALLENGE_PERIOD_SECS`.
    pub deadline: u64,
    /// Current lifecycle status.
    pub status: ChallengeStatus,
    /// Counter-evidence bytes if the defender submitted any.
    pub counter_evidence: Option<Vec<u8>>,
}

/// The outcome of processing counter-evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterEvidenceOutcome {
    /// Counter-evidence is valid; the defender wins and the challenger's bond
    /// should be slashed.
    DefenderWins {
        /// Amount of challenger bond to slash.
        bond_to_slash: u64,
    },
    /// Counter-evidence is invalid; the challenge remains open.
    Invalid,
}

/// Errors from challenge operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeError {
    /// No challenge with the given submission ID was found.
    NotFound,
    /// The challenge window has already expired.
    WindowExpired,
    /// The challenge has already been resolved.
    AlreadyResolved,
    /// The provided counter-evidence payload failed verification.
    InvalidCounterEvidence,
}

// ─── ChallengeManager ────────────────────────────────────────────────────────

/// Manages challenge records for all open evidence submissions.
#[derive(Clone, Debug, Default)]
pub struct ChallengeManager {
    /// Active and resolved challenges keyed by `submission_id`.
    records: BTreeMap<u64, ChallengeRecord>,
}

impl ChallengeManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new challenge record when evidence is submitted.
    ///
    /// * `submission_id` — sequence ID from the evidence store.
    /// * `validator_id` — the accused validator.
    /// * `offense_type` — the alleged offense.
    /// * `challenger` — the submitter of the evidence.
    /// * `challenger_bond` — the bond the challenger posted.
    /// * `current_time` — Unix timestamp (seconds) of submission.
    pub fn open(
        &mut self,
        submission_id: u64,
        validator_id: PublicKey,
        offense_type: OffenseType,
        challenger: PublicKey,
        challenger_bond: u64,
        current_time: u64,
    ) {
        let deadline = current_time.saturating_add(CHALLENGE_PERIOD_SECS);
        self.records.insert(
            submission_id,
            ChallengeRecord {
                submission_id,
                validator_id,
                offense_type,
                challenger,
                challenger_bond,
                opened_at: current_time,
                deadline,
                status: ChallengeStatus::Open,
                counter_evidence: None,
            },
        );
    }

    /// The accused validator submits counter-evidence before the deadline.
    ///
    /// # Returns
    ///
    /// * `Ok(CounterEvidenceOutcome::DefenderWins { bond_to_slash })` — the
    ///   counter-evidence is valid; the record is marked
    ///   [`ChallengeStatus::DefenderWon`] and the challenger's bond is returned
    ///   for slashing.
    /// * `Ok(CounterEvidenceOutcome::Invalid)` — the counter-evidence payload
    ///   did not pass verification; the challenge remains open.
    /// * `Err(ChallengeError)` — the challenge was not found, already resolved,
    ///   or the deadline has passed.
    pub fn submit_counter_evidence(
        &mut self,
        submission_id: u64,
        counter_evidence: Vec<u8>,
        current_time: u64,
    ) -> Result<CounterEvidenceOutcome, ChallengeError> {
        let record = self
            .records
            .get_mut(&submission_id)
            .ok_or(ChallengeError::NotFound)?;

        if record.status != ChallengeStatus::Open {
            return Err(ChallengeError::AlreadyResolved);
        }

        if current_time > record.deadline {
            record.status = ChallengeStatus::Expired;
            return Err(ChallengeError::WindowExpired);
        }

        if !Self::verify_counter_evidence(record.offense_type, &counter_evidence) {
            // Counter-evidence is invalid — challenge stays Open.
            return Ok(CounterEvidenceOutcome::Invalid);
        }

        // Defender wins.
        let bond = record.challenger_bond;
        record.status = ChallengeStatus::DefenderWon;
        record.counter_evidence = Some(counter_evidence);

        Ok(CounterEvidenceOutcome::DefenderWins { bond_to_slash: bond })
    }

    /// Advance all open challenges whose deadline has passed to
    /// [`ChallengeStatus::Expired`].
    ///
    /// Returns the `submission_id`s of newly-expired challenges so the caller
    /// can proceed with slashing execution.
    pub fn expire_elapsed(&mut self, current_time: u64) -> Vec<u64> {
        let mut expired = Vec::new();
        for record in self.records.values_mut() {
            if record.status == ChallengeStatus::Open && current_time > record.deadline {
                record.status = ChallengeStatus::Expired;
                expired.push(record.submission_id);
            }
        }
        expired
    }

    /// Look up a challenge record.
    pub fn get(&self, submission_id: u64) -> Option<&ChallengeRecord> {
        self.records.get(&submission_id)
    }

    /// Number of records (open + resolved).
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether there are no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    // ── Counter-evidence verification ─────────────────────────────────────────

    /// Verify counter-evidence against the alleged offense type.
    ///
    /// # Equivocation counter-evidence (40 bytes)
    ///
    /// ```text
    /// bytes[0..8]   — height (u64 little-endian, must be > 0)
    /// bytes[8..40]  — signed block hash ([u8; 32])
    /// ```
    ///
    /// The defender proves they only signed one block at that height.
    ///
    /// # Unavailability / InvalidProposal counter-evidence (≥ 8 bytes)
    ///
    /// Any payload of at least 8 bytes is accepted as a plausible log-based
    /// rebuttal; further on-chain validation is delegated to the arbitration layer.
    fn verify_counter_evidence(offense_type: OffenseType, counter_evidence: &[u8]) -> bool {
        match offense_type {
            OffenseType::Equivocation => {
                if counter_evidence.len() < 40 {
                    return false;
                }
                let height_bytes: [u8; 8] = counter_evidence[..8]
                    .try_into()
                    .expect("slice is 8 bytes");
                let height = u64::from_le_bytes(height_bytes);
                height > 0
            }
            OffenseType::Unavailability | OffenseType::InvalidProposal => {
                // Accept any non-trivial rebuttal payload.
                counter_evidence.len() >= 8
            }
        }
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

    fn open_challenge(mgr: &mut ChallengeManager, id: u64, now: u64) {
        mgr.open(id, pk(1), OffenseType::Equivocation, pk(99), 500, now);
    }

    fn valid_counter_evidence(height: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(&height.to_le_bytes());
        buf.extend_from_slice(&[7u8; 32]); // block hash
        buf
    }

    // ── open ──────────────────────────────────────────────────────────────────

    #[test]
    fn open_creates_record_with_correct_deadline() {
        let mut mgr = ChallengeManager::new();
        let now = 1_000_000u64;
        open_challenge(&mut mgr, 0, now);
        let rec = mgr.get(0).unwrap();
        assert_eq!(rec.status, ChallengeStatus::Open);
        assert_eq!(rec.deadline, now + CHALLENGE_PERIOD_SECS);
        assert_eq!(rec.challenger_bond, 500);
    }

    // ── counter-evidence: defender wins ───────────────────────────────────────

    #[test]
    fn valid_counter_evidence_makes_defender_win() {
        let mut mgr = ChallengeManager::new();
        let now = 1_000_000u64;
        open_challenge(&mut mgr, 0, now);

        let outcome = mgr
            .submit_counter_evidence(0, valid_counter_evidence(42), now + 3600)
            .unwrap();

        assert_eq!(
            outcome,
            CounterEvidenceOutcome::DefenderWins { bond_to_slash: 500 }
        );
        assert_eq!(mgr.get(0).unwrap().status, ChallengeStatus::DefenderWon);
    }

    #[test]
    fn invalid_counter_evidence_challenge_stays_open() {
        let mut mgr = ChallengeManager::new();
        let now = 1_000_000u64;
        open_challenge(&mut mgr, 0, now);

        // Too short — invalid.
        let outcome = mgr
            .submit_counter_evidence(0, vec![0u8; 5], now + 100)
            .unwrap();
        assert_eq!(outcome, CounterEvidenceOutcome::Invalid);
        assert_eq!(mgr.get(0).unwrap().status, ChallengeStatus::Open);
    }

    #[test]
    fn counter_evidence_after_deadline_returns_error() {
        let mut mgr = ChallengeManager::new();
        let now = 1_000_000u64;
        open_challenge(&mut mgr, 0, now);

        let after_deadline = now + CHALLENGE_PERIOD_SECS + 1;
        let err = mgr
            .submit_counter_evidence(0, valid_counter_evidence(1), after_deadline)
            .unwrap_err();
        assert_eq!(err, ChallengeError::WindowExpired);
        assert_eq!(mgr.get(0).unwrap().status, ChallengeStatus::Expired);
    }

    #[test]
    fn counter_evidence_on_resolved_challenge_returns_error() {
        let mut mgr = ChallengeManager::new();
        let now = 1_000_000u64;
        open_challenge(&mut mgr, 0, now);
        // Win once.
        mgr.submit_counter_evidence(0, valid_counter_evidence(10), now + 1)
            .unwrap();
        // Try again.
        let err = mgr
            .submit_counter_evidence(0, valid_counter_evidence(10), now + 2)
            .unwrap_err();
        assert_eq!(err, ChallengeError::AlreadyResolved);
    }

    // ── expire_elapsed ────────────────────────────────────────────────────────

    #[test]
    fn expire_elapsed_marks_past_deadline_challenges() {
        let mut mgr = ChallengeManager::new();
        let now = 1_000_000u64;
        open_challenge(&mut mgr, 0, now);
        open_challenge(&mut mgr, 1, now);

        // Advance past both deadlines.
        let expired = mgr.expire_elapsed(now + CHALLENGE_PERIOD_SECS + 1);
        assert_eq!(expired.len(), 2);
        assert_eq!(mgr.get(0).unwrap().status, ChallengeStatus::Expired);
        assert_eq!(mgr.get(1).unwrap().status, ChallengeStatus::Expired);
    }

    #[test]
    fn expire_elapsed_does_not_affect_open_challenges_within_window() {
        let mut mgr = ChallengeManager::new();
        let now = 1_000_000u64;
        open_challenge(&mut mgr, 0, now);

        // Not yet past deadline.
        let expired = mgr.expire_elapsed(now + 3600);
        assert!(expired.is_empty());
        assert_eq!(mgr.get(0).unwrap().status, ChallengeStatus::Open);
    }

    #[test]
    fn not_found_error_for_unknown_submission_id() {
        let mut mgr = ChallengeManager::new();
        let err = mgr
            .submit_counter_evidence(42, valid_counter_evidence(1), 0)
            .unwrap_err();
        assert_eq!(err, ChallengeError::NotFound);
    }

    // ── unavailability counter-evidence ──────────────────────────────────────

    #[test]
    fn unavailability_counter_evidence_accepted_with_8_bytes() {
        let mut mgr = ChallengeManager::new();
        mgr.open(0, pk(1), OffenseType::Unavailability, pk(99), 200, 0);
        let outcome = mgr
            .submit_counter_evidence(0, vec![0u8; 8], 100)
            .unwrap();
        assert_eq!(
            outcome,
            CounterEvidenceOutcome::DefenderWins { bond_to_slash: 200 }
        );
    }

    #[test]
    fn unavailability_counter_evidence_rejected_if_too_short() {
        let mut mgr = ChallengeManager::new();
        mgr.open(0, pk(1), OffenseType::Unavailability, pk(99), 200, 0);
        let outcome = mgr
            .submit_counter_evidence(0, vec![0u8; 7], 100)
            .unwrap();
        assert_eq!(outcome, CounterEvidenceOutcome::Invalid);
    }
}
