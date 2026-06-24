use super::types::{EmaWeights, TimeSinceLastUpdate, MAX_REPUTATION};

/// Updates a reputation score using a bounded exponential moving average.
///
/// For gaps greater than or equal to the configured window, the historical
/// value is fully expired and the score is re-initialized from the latest
/// observation. For shorter gaps, alpha is clamped into `[0.0, 1.0]` before
/// applying `alpha * observation + (1 - alpha) * prev_score`.
pub fn ema_update(
    prev_score: u64,
    observation: u64,
    elapsed_epochs: TimeSinceLastUpdate,
    weights: EmaWeights,
) -> u64 {
    debug_assert!(
        prev_score <= MAX_REPUTATION,
        "previous reputation score is outside [0, MAX_REPUTATION]"
    );
    debug_assert!(
        observation <= MAX_REPUTATION,
        "reputation observation is outside [0, MAX_REPUTATION]"
    );

    let bounded_observation = observation.min(MAX_REPUTATION);
    let bounded_prev_score = prev_score.min(MAX_REPUTATION);

    let score = if weights.window_epochs == 0 || elapsed_epochs >= weights.window_epochs {
        bounded_observation
    } else {
        let alpha = (elapsed_epochs as f64 / weights.window_epochs as f64).clamp(0.0, 1.0);
        let updated =
            alpha * bounded_observation as f64 + (1.0 - alpha) * bounded_prev_score as f64;

        updated.round() as u64
    };

    debug_assert!(
        score <= MAX_REPUTATION,
        "EMA reputation score is outside [0, MAX_REPUTATION]"
    );

    score
}

/// Converts a reputation score into a validator-selection weight.
pub fn reputation_weight(score: u64) -> u64 {
    score.min(MAX_REPUTATION)
}
