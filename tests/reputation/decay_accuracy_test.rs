//! Decay accuracy benchmarks for the Q32.32 reputation decay path (#11).

use proptest::prelude::*;
use sorosusu_contracts::reputation::{update_reputation, DecayFactor, MAX_REPUTATION};

/// The real-valued decay factor the engine targets.
const LAMBDA: f64 = 0.9985;

/// Ideal real-valued decay rounded to an integer score.
fn ideal(score0: u64, epochs: u32) -> u64 {
    (score0 as f64 * LAMBDA.powi(epochs as i32)).round() as u64
}

/// Naive Q16.16-only repeated decay — the pre-#11 path. Uses the nearest
/// Q16.16 representation of lambda (65431/65536) and truncates each epoch.
fn naive_q16_decay(mut score: i64, epochs: u32) -> i64 {
    const LAMBDA_Q16: i64 = 65431;
    for _ in 0..epochs {
        score = (score * LAMBDA_Q16) >> 16;
    }
    score
}

/// Blueprint step 4: 10,000 decay steps from a full-scale score stay within one
/// unit of the mathematical ideal.
#[test]
fn ten_thousand_epochs_within_one_unit() {
    let score0 = MAX_REPUTATION;
    let got = update_reputation(score0, 10_000, DecayFactor::default());
    let want = ideal(score0, 10_000);
    let diff = got.abs_diff(want);
    assert!(diff <= 1, "10k-epoch decay off by {diff} (got {got}, want {want})");
}

/// Accuracy holds across the whole curve, not just at the tail.
#[test]
fn tracks_ideal_at_checkpoints() {
    for &score0 in &[MAX_REPUTATION, 750_000, 123_456, 10_000] {
        for &epochs in &[1u32, 10, 100, 1_000, 5_000, 10_000] {
            let got = update_reputation(score0, epochs as u64, DecayFactor::default());
            let want = ideal(score0, epochs);
            let diff = got.abs_diff(want);
            assert!(
                diff <= 1,
                "score0={score0} epochs={epochs}: off by {diff} (got {got}, want {want})"
            );
        }
    }
}

/// The fixed path decays a long-idle score all the way to zero.
#[test]
fn long_idle_decays_to_zero() {
    let got = update_reputation(MAX_REPUTATION, 20_000, DecayFactor::default());
    assert_eq!(got, 0);
}

/// Demonstrates #11: mid-curve, the naive Q16.16-only path diverges from the
/// ideal by far more than one unit (it cannot even represent lambda = 0.9985),
/// while the Q32.32 path stays within one unit.
#[test]
fn naive_q16_path_loses_precision_versus_fix() {
    let score0 = MAX_REPUTATION;
    let epochs = 2_000u32;

    let want = ideal(score0, epochs);
    let naive = naive_q16_decay(score0 as i64, epochs) as u64;
    let fixed = update_reputation(score0, epochs as u64, DecayFactor::default());

    assert!(
        naive.abs_diff(want) > 1,
        "expected the naive Q16.16 path to be off by >1 (naive {naive}, want {want})"
    );
    assert!(
        fixed.abs_diff(want) <= 1,
        "expected the Q32.32 path within 1 (fixed {fixed}, want {want})"
    );
}

proptest! {
    /// For any starting score and epoch count up to 10,000, the Q32.32 read-out
    /// is within one unit of the ideal.
    #[test]
    fn prop_within_one_unit(
        score0 in 0_u64..=MAX_REPUTATION,
        epochs in 0_u32..=10_000,
    ) {
        let got = update_reputation(score0, epochs as u64, DecayFactor::default());
        let want = ideal(score0, epochs);
        prop_assert!(got.abs_diff(want) <= 1, "off by {} (got {got}, want {want})", got.abs_diff(want));
    }
}
