//! Validator stake slashing condition verification with fraud proofs (issue #135).
//!
//! Implements the full slashing pipeline:
//!
//! 1. **Detection** (`detector`) — scans for equivocation, unavailability, and
//!    invalid-block proposals.
//! 2. **Evidence** (`evidence`) — accepts and cryptographically verifies fraud
//!    proofs with a mandatory challenger bond.
//! 3. **Challenge** (`challenge`) — provides a 7-day window for the accused
//!    validator to submit counter-evidence; if successful the challenger loses
//!    their bond.
//! 4. **Execution** (`executor`) — burns 50 % of slashed stake and distributes
//!    50 % to active validators.

pub mod challenge;
pub mod detector;
pub mod evidence;
pub mod executor;

pub use challenge::{
    ChallengeError, ChallengeManager, ChallengeRecord, ChallengeStatus, CounterEvidenceOutcome,
    CHALLENGE_PERIOD_SECS,
};
pub use detector::{
    ObservedProposal, OffenseType, SlashingConditionDetector, SlashingViolation,
    UNAVAILABILITY_THRESHOLD,
};
pub use evidence::{EvidenceError, EvidenceStore, EvidenceSubmission, VerificationResult};
pub use executor::{ExecutorError, SlashingExecutor, SlashingResult, StakeRegistry};
