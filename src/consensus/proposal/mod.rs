//! Consensus proposal subsystem (issue #137).
//!
//! Handles proposal creation and Byzantine equivocation detection for the
//! consensus engine. When a Byzantine primary sends two conflicting proposals
//! at the same height with valid signatures, the equivocation detector
//! broadcasts an [`EquivocationProof`] to trigger immediate view advancement.

pub mod equivocation_detector;

pub use equivocation_detector::{
    EquivocationDetector, EquivocationError, EquivocationProof, Proposal,
};
