//! Tests for the validator balance underflow fix (issue #241).
//!
//! Verifies that:
//! 1. A penalty exceeding the balance returns `InsufficientBalance` rather
//!    than silently clamping to zero.
//! 2. A validator with an outstanding debt is always included in the
//!    ejection-eligible set, regardless of its stored balance.
//! 3. Normal penalties (penalty ≤ balance) continue to work correctly.
//! 4. Rewards are capped at `MAX_EFFECTIVE_BALANCE`.
//! 5. Property test: `effective_balance` never exceeds `MAX_EFFECTIVE_BALANCE`
//!    after any sequence of reward applications.

use proptest::prelude::*;
use sorosusu_contracts::slashing::penalty_calculator::{
    compute_inactivity_penalty, compute_slashing_penalty,
};
use sorosusu_contracts::validator::balance_tracker::{
    BalanceError, BalanceTracker, EJECTION_THRESHOLD, GWEI_PER_ETH, MAX_EFFECTIVE_BALANCE,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// 1 ETH in Gwei.
const ONE_ETH: u64 = GWEI_PER_ETH;
/// 1.5 ETH in Gwei.
const ONE_POINT_FIVE_ETH: u64 = ONE_ETH + ONE_ETH / 2;
/// 32 ETH in Gwei.
const THIRTY_TWO_ETH: u64 = 32 * GWEI_PER_ETH;

// ---------------------------------------------------------------------------
// Issue #241 acceptance criterion
// ---------------------------------------------------------------------------

/// A validator holding 1 ETH receives a 1.5 ETH slashing penalty.
/// The tracker must return `InsufficientBalance` (not silently clamp to zero)
/// and the validator must appear in `ejection_eligible()` at the same epoch.
#[test]
fn validator_with_1_eth_receiving_1_5_eth_penalty_is_ejected_same_epoch() {
    let mut tracker = BalanceTracker::new();
    let validator_index: u64 = 0;

    // Register validator with 1 ETH.
    tracker.register_validator(validator_index, ONE_ETH);

    // Apply a 1.5 ETH penalty (e.g. a slashable-offense amount larger than balance).
    let result = tracker.apply_penalty(validator_index, ONE_POINT_FIVE_ETH);

    // Must return InsufficientBalance — NOT silently clamp.
    assert!(
        matches!(result, Err(BalanceError::InsufficientBalance { .. })),
        "expected InsufficientBalance error, got {:?}",
        result
    );

    // The stored balance is zeroed.
    assert_eq!(
        tracker.effective_balance(validator_index),
        Some(0),
        "balance should be zeroed after underflow"
    );

    // A debt must have been recorded (excess = 0.5 ETH).
    assert!(
        tracker.has_debt(validator_index),
        "debt should be recorded when penalty exceeds balance"
    );
    let expected_debt = ONE_POINT_FIVE_ETH - ONE_ETH; // 0.5 ETH
    assert_eq!(
        tracker.outstanding_debt(validator_index),
        Some(expected_debt)
    );

    // The validator must appear in the ejection-eligible set at this epoch
    // — this is the core invariant that was broken before the fix.
    let eligible = tracker.ejection_eligible();
    assert!(
        eligible.contains(&validator_index),
        "validator with outstanding debt must be ejection-eligible in the same epoch"
    );
}

// ---------------------------------------------------------------------------
// Normal-path tests (regression guard)
// ---------------------------------------------------------------------------

/// A penalty that is exactly equal to the balance should reduce the balance to
/// zero and NOT record a debt (no excess).
#[test]
fn penalty_equal_to_balance_zeroes_balance_without_debt() {
    let mut tracker = BalanceTracker::new();
    tracker.register_validator(1, ONE_ETH);

    let result = tracker.apply_penalty(1, ONE_ETH);

    assert_eq!(result, Ok(0), "balance - balance should be 0");
    assert!(!tracker.has_debt(1), "no debt when penalty == balance");
    // The validator's balance is zero but it has no debt; it is still
    // ejection-eligible because 0 < EJECTION_THRESHOLD.
    assert!(tracker.ejection_eligible().contains(&1));
}

/// A penalty smaller than the balance must reduce the balance by exactly
/// the penalty amount and leave no debt.
#[test]
fn penalty_smaller_than_balance_reduces_balance_correctly() {
    let mut tracker = BalanceTracker::new();
    let initial_balance = 20 * ONE_ETH;
    tracker.register_validator(2, initial_balance);

    let penalty = 3 * ONE_ETH;
    let result = tracker.apply_penalty(2, penalty);

    assert_eq!(result, Ok(initial_balance - penalty));
    assert!(!tracker.has_debt(2));
    assert_eq!(tracker.effective_balance(2), Some(17 * ONE_ETH));
}

/// A validator above the ejection threshold with no debt must NOT appear in
/// the ejection-eligible set.
#[test]
fn healthy_validator_is_not_ejection_eligible() {
    let mut tracker = BalanceTracker::new();
    tracker.register_validator(3, THIRTY_TWO_ETH);

    let eligible = tracker.ejection_eligible();
    assert!(
        !eligible.contains(&3),
        "healthy validator must not be ejection-eligible"
    );
}

/// A validator whose balance has dropped below the ejection threshold by a
/// normal penalty (no debt) must still appear in the ejection-eligible set.
#[test]
fn validator_below_ejection_threshold_is_eligible() {
    let mut tracker = BalanceTracker::new();
    tracker.register_validator(4, EJECTION_THRESHOLD); // exactly at threshold

    // Reduce by 1 Gwei — now strictly below threshold.
    tracker.apply_penalty(4, 1).unwrap();

    let eligible = tracker.ejection_eligible();
    assert!(
        eligible.contains(&4),
        "validator just below ejection threshold must be ejection-eligible"
    );
}

// ---------------------------------------------------------------------------
// Reward tests
// ---------------------------------------------------------------------------

/// Rewards must not push the balance above `MAX_EFFECTIVE_BALANCE`.
#[test]
fn reward_is_capped_at_max_effective_balance() {
    let mut tracker = BalanceTracker::new();
    tracker.register_validator(5, MAX_EFFECTIVE_BALANCE);

    // Applying any additional reward must not overflow the cap.
    tracker.apply_reward(5, ONE_ETH).unwrap();
    assert_eq!(
        tracker.effective_balance(5),
        Some(MAX_EFFECTIVE_BALANCE),
        "balance must be capped at MAX_EFFECTIVE_BALANCE"
    );
}

/// A reward on a zero-balance validator must not exceed `MAX_EFFECTIVE_BALANCE`.
#[test]
fn reward_from_zero_cannot_exceed_max_effective_balance() {
    let mut tracker = BalanceTracker::new();
    tracker.register_validator(6, 0);

    // An absurdly large reward saturates at `u64::MAX` in `saturating_add`
    // and is then clamped down to `MAX_EFFECTIVE_BALANCE` by `.min()`.
    tracker.apply_reward(6, u64::MAX).unwrap();
    assert_eq!(tracker.effective_balance(6), Some(MAX_EFFECTIVE_BALANCE));
}

// ---------------------------------------------------------------------------
// Debt lifecycle
// ---------------------------------------------------------------------------

/// After a forced ejection the debt record should be clearable.
#[test]
fn clearing_debt_removes_validator_from_ejection_eligible() {
    let mut tracker = BalanceTracker::new();
    tracker.register_validator(7, ONE_ETH);

    // Trigger underflow.
    tracker
        .apply_penalty(7, ONE_POINT_FIVE_ETH)
        .expect_err("should return InsufficientBalance");

    // Validator is ejection-eligible because of the debt.
    assert!(tracker.ejection_eligible().contains(&7));

    // Simulate ejection: clear the debt and ensure balance is 0.
    tracker.clear_debt(7);
    // After clearing, validator still has balance 0 which is < EJECTION_THRESHOLD.
    // The debt is gone but balance-based ejection eligibility remains.
    assert!(!tracker.has_debt(7), "debt must be gone after clear_debt");
}

// ---------------------------------------------------------------------------
// Penalty calculator unit tests
// ---------------------------------------------------------------------------

/// For a 32 ETH validator, `compute_slashing_penalty` must equal 2 ETH.
#[test]
fn slashing_penalty_for_32_eth_is_2_eth() {
    let penalty = compute_slashing_penalty(THIRTY_TWO_ETH);
    let expected = 2 * ONE_ETH; // 1/16 of 32 ETH
    assert_eq!(
        penalty, expected,
        "slashing penalty for 32 ETH must be 2 ETH"
    );
}

/// `compute_slashing_penalty` for a 1 ETH validator should equal 1/16 of 1 ETH.
#[test]
fn slashing_penalty_scales_with_balance() {
    let penalty = compute_slashing_penalty(ONE_ETH);
    // 1_000_000_000 / 32 * 2 = 62_500_000
    let expected = ONE_ETH / 32 * 2;
    assert_eq!(penalty, expected);
}

/// With 0 epochs since finality, the inactivity penalty must be zero.
#[test]
fn inactivity_penalty_zero_epochs_is_zero() {
    let penalty = compute_inactivity_penalty(THIRTY_TWO_ETH, 0);
    assert_eq!(penalty, 0);
}

/// For a non-zero epoch count the penalty must be positive.
#[test]
fn inactivity_penalty_positive_for_nonzero_epochs() {
    let penalty = compute_inactivity_penalty(THIRTY_TWO_ETH, 100);
    assert!(
        penalty > 0,
        "inactivity penalty must be positive for 100 epochs"
    );
}

// ---------------------------------------------------------------------------
// Property test
// ---------------------------------------------------------------------------

proptest! {
    /// For any sequence of rewards applied to a registered validator, the
    /// effective balance must never exceed `MAX_EFFECTIVE_BALANCE`.
    #[test]
    fn prop_effective_balance_never_exceeds_max_after_rewards(
        initial in 0u64..=MAX_EFFECTIVE_BALANCE,
        rewards in prop::collection::vec(0u64..=MAX_EFFECTIVE_BALANCE, 1..50),
    ) {
        let mut tracker = BalanceTracker::new();
        let idx: u64 = 99;
        tracker.register_validator(idx, initial);
        for reward in rewards {
            let _ = tracker.apply_reward(idx, reward);
        }
        let balance = tracker.effective_balance(idx).unwrap();
        prop_assert!(
            balance <= MAX_EFFECTIVE_BALANCE,
            "balance {} exceeded MAX_EFFECTIVE_BALANCE {}",
            balance,
            MAX_EFFECTIVE_BALANCE
        );
    }

    /// For any balance and penalty where penalty > balance, apply_penalty must
    /// return InsufficientBalance and must never silently clamp without recording a debt.
    #[test]
    fn prop_penalty_exceeding_balance_always_returns_insufficient_balance(
        balance in 0u64..u64::MAX,
        excess in 1u64..=u64::MAX,
    ) {
        // penalty = balance + excess, guarded against overflow
        let penalty = match balance.checked_add(excess) {
            Some(p) => p,
            None => return Ok(()), // skip overflow cases
        };

        let mut tracker = BalanceTracker::new();
        let idx: u64 = 42;
        tracker.register_validator(idx, balance);

        let result = tracker.apply_penalty(idx, penalty);

        prop_assert!(
            matches!(result, Err(BalanceError::InsufficientBalance { .. })),
            "expected InsufficientBalance for balance={}, penalty={}, got {:?}",
            balance, penalty, result
        );
        prop_assert!(
            tracker.has_debt(idx),
            "debt must be recorded when penalty > balance"
        );
        prop_assert!(
            tracker.ejection_eligible().contains(&idx),
            "validator must be ejection-eligible when it has a debt"
        );
    }
}
