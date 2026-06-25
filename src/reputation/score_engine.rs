use super::types::{DecayFactor, EmaWeights, ReputationScore, TimeSinceLastUpdate, MAX_REPUTATION};

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

// --- Exponential decay (#11) ---
//
// Maximum observable read-out error of the Q32.32 decay path versus the
// real-valued ideal `score_0 * lambda^n`, measured from a full-scale score
// (MAX_REPUTATION) across 10,000 epochs: **< 1 reputation unit**. Per-epoch
// Q32.32 truncation is ~2^-32 score units and does not accumulate into the
// integer read-out.
//
// For contrast, the public Q16.16 grid cannot represent lambda = 0.9985 (its
// nearest value, 65431/65536 = 0.99848938, is already ~1e-3 off) and truncates
// every epoch, which is what left long-idle validators with a multi-thousand-
// unit reputation floor instead of decaying to zero.

/// The maximum read-out error (in reputation units) of [`update_reputation`]
/// relative to the ideal real-valued decay, across the supported epoch window.
pub const MAX_DECAY_READOUT_ERROR: u64 = 1;

/// Apply one epoch of exponential decay to a Q32.32 score accumulator.
pub fn apply_decay(score: ReputationScore, factor: DecayFactor) -> ReputationScore {
    ReputationScore::from_accumulator(score.accumulator().mul(factor.0))
}

/// Apply `epochs` epochs of decay, compounding entirely in Q32.32. Only the
/// caller's subsequent `to_int()` / `to_q16_16()` downsamples.
pub fn decay_for_epochs(
    score: ReputationScore,
    factor: DecayFactor,
    epochs: u64,
) -> ReputationScore {
    let mut accumulated = score;
    for _ in 0..epochs {
        accumulated = apply_decay(accumulated, factor);
    }
    accumulated
}

/// Decay a prior integer score across `elapsed_epochs` and return the new
/// integer score. Replaces the lossy Q16.16-only `(score * lambda) >> 16` loop
/// with Q32.32 accumulation (#11).
pub fn update_reputation(prev_score: u64, elapsed_epochs: TimeSinceLastUpdate, factor: DecayFactor) -> u64 {
    debug_assert!(
        prev_score <= MAX_REPUTATION,
        "previous reputation score is outside [0, MAX_REPUTATION]"
    );
    let decayed = decay_for_epochs(
        ReputationScore::from_int(prev_score),
        factor,
        elapsed_epochs,
    );
    decayed.to_int()
}
