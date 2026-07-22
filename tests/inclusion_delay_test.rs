use sorosusu_contracts::attestation::inclusion_tracker::{
    compute_inclusion_delay, delay_reward, update_delay_rewards, wall_slots_between,
};
use sorosusu_contracts::consensus::fork_choice::{branch_weighting, IncludedAttestation};

#[test]
fn inclusion_delay_counts_wall_clock_slots_across_skips() {
    // Slot 10 attestation is included at slot 15. Slots 12, 13, and 14 were
    // skipped, but they still count as elapsed wall-clock slots.
    assert_eq!(wall_slots_between(10, 15), 5);
    assert_eq!(compute_inclusion_delay(10, 15), 5);
}

#[test]
fn delay_reward_uses_wall_clock_delay() {
    let max_reward = 31;

    assert_eq!(delay_reward(10, 11, max_reward), max_reward);
    assert_eq!(
        delay_reward(10, 15, max_reward),
        update_delay_rewards(5, max_reward)
    );
    assert_eq!(delay_reward(10, 42, max_reward), 0);
}

#[test]
fn fork_choice_weight_is_independent_of_skipped_slot_distribution() {
    let first_branch = [
        IncludedAttestation {
            attestation_slot: 10,
            inclusion_slot: 15,
            validator_weight: 2,
        },
        IncludedAttestation {
            attestation_slot: 11,
            inclusion_slot: 15,
            validator_weight: 3,
        },
    ];
    let same_wall_clock_delays_with_different_skipped_slots = [
        IncludedAttestation {
            attestation_slot: 20,
            inclusion_slot: 25,
            validator_weight: 2,
        },
        IncludedAttestation {
            attestation_slot: 21,
            inclusion_slot: 25,
            validator_weight: 3,
        },
    ];

    assert_eq!(
        branch_weighting(&first_branch, 31),
        branch_weighting(&same_wall_clock_delays_with_different_skipped_slots, 31)
    );
}
