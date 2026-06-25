//! Attestation inclusion-delay accounting.
//!
//! Inclusion delay is measured in wall-clock slots: the difference between the
//! slot an attestation was assigned to and the slot of the beacon block that
//! includes it. Skipped slots still count toward this delay even though no block
//! exists for those slots.

/// Consensus slot number.
pub type Slot = u64;

/// Minimum valid attestation inclusion delay, in slots.
pub const MIN_ATTESTATION_INCLUSION_DELAY: u64 = 1;

/// Delay at which the inclusion-delay reward reaches zero.
pub const MAX_ATTESTATION_INCLUSION_DELAY: u64 = 32;

/// Return the number of wall-clock slots from `start` to `end`.
///
/// This intentionally does not inspect produced blocks. A skipped slot advances
/// wall-clock time and therefore increases attestation inclusion delay.
pub fn wall_slots_between(start: Slot, end: Slot) -> u64 {
    end.saturating_sub(start)
}

/// Compute the inclusion delay for an attestation assigned to
/// `attestation_slot` and included in a block at `block_slot`.
pub fn compute_inclusion_delay(attestation_slot: Slot, block_slot: Slot) -> u64 {
    wall_slots_between(attestation_slot, block_slot)
}

/// Compute the inclusion-delay reward for `delay` from `max_reward`.
///
/// Rewards are maximal at delay 1 and linearly decrease to zero at delay 32.
pub fn update_delay_rewards(delay: u64, max_reward: u64) -> u64 {
    if delay < MIN_ATTESTATION_INCLUSION_DELAY {
        return 0;
    }

    if delay >= MAX_ATTESTATION_INCLUSION_DELAY {
        return 0;
    }

    let remaining = MAX_ATTESTATION_INCLUSION_DELAY - delay;
    let reward_span = MAX_ATTESTATION_INCLUSION_DELAY - MIN_ATTESTATION_INCLUSION_DELAY;
    max_reward.saturating_mul(remaining) / reward_span
}

/// Convenience helper for callers that have attestation and inclusion slots.
pub fn delay_reward(attestation_slot: Slot, block_slot: Slot, max_reward: u64) -> u64 {
    update_delay_rewards(
        compute_inclusion_delay(attestation_slot, block_slot),
        max_reward,
    )
}
