#![cfg(test)]

use proptest::prelude::*;
use sorosusu_contracts::reputation::{ema_update, EmaWeights, MAX_REPUTATION};

#[test]
fn long_gap_reinitializes_score_to_observation() {
    let weights = EmaWeights::default();
    let prev_score = 750_000;
    let observation = 500_000;

    let score = ema_update(prev_score, observation, 4096, weights);

    assert_eq!(score, observation);
}

#[test]
fn elapsed_equal_to_window_reinitializes_score_to_observation() {
    let weights = EmaWeights::default();
    let prev_score = 250_000;
    let observation = 900_000;

    let score = ema_update(prev_score, observation, 2048, weights);

    assert_eq!(score, observation);
}

proptest! {
    #[test]
    fn random_elapsed_values_never_exceed_max_reputation(
        prev_score in 0_u64..=MAX_REPUTATION,
        observation in 0_u64..=MAX_REPUTATION,
        elapsed_epochs in 0_u64..=16_384,
    ) {
        let score = ema_update(prev_score, observation, elapsed_epochs, EmaWeights::default());

        prop_assert!(score <= MAX_REPUTATION);
    }
}
