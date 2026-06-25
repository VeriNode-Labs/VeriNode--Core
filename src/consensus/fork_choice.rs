//! Fork-choice branch weighting.

use crate::attestation::inclusion_tracker::{delay_reward, Slot};

/// Attestation data needed to weight a branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IncludedAttestation {
    /// Slot the attestation was assigned to.
    pub attestation_slot: Slot,
    /// Slot of the block that included the attestation.
    pub inclusion_slot: Slot,
    /// Validator or aggregate vote weight before inclusion-delay adjustment.
    pub validator_weight: u64,
}

/// Compute a branch's total attestation weight after inclusion-delay rewards.
///
/// The calculation depends only on wall-clock attestation/inclusion slots, so
/// skipped-slot placement between them cannot make a branch appear heavier.
pub fn branch_weighting(attestations: &[IncludedAttestation], max_delay_reward: u64) -> u64 {
    attestations
        .iter()
        .map(|attestation| {
            attestation.validator_weight.saturating_add(delay_reward(
                attestation.attestation_slot,
                attestation.inclusion_slot,
                max_delay_reward,
            ))
        })
        .sum()
}
