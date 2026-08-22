//! Slashing and inactivity-leak penalty calculators.
//!
//! Implements the penalty formulae referenced by issue #241:
//!
//! * **Slashing penalty** – whistleblower reward (`1/32` of effective balance)
//!   plus correlation penalty (`1/32` of effective balance), giving `1/16` of
//!   the validator's effective balance in total.
//! * **Inactivity leak penalty** – proportional to
//!   `epochs_since_finality² × effective_balance / INACTIVITY_PENALTY_QUOTIENT`.
//!
//! All arithmetic is performed in `u64` (Gwei). Overflow-safe helpers use
//! `saturating_*` and `checked_*` where appropriate; the penalty values
//! themselves are returned as `u64` and are never negative.

use crate::validator::balance_tracker::MAX_EFFECTIVE_BALANCE;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Divisor for each of the two components of the slashing penalty
/// (whistleblower + correlation). Each component is `effective_balance / 32`,
/// so the total slashing penalty is `effective_balance / 16`.
pub const SLASHING_PENALTY_QUOTIENT: u64 = 32;

/// Divisor used in the inactivity-leak penalty formula.
/// `penalty = epochs_since_finality² × effective_balance / INACTIVITY_PENALTY_QUOTIENT`.
pub const INACTIVITY_PENALTY_QUOTIENT: u64 = 1 << 24; // 16_777_216

// ---------------------------------------------------------------------------
// Penalty computations
// ---------------------------------------------------------------------------

/// Compute the total slashing penalty for a validator with the given
/// `effective_balance` (Gwei).
///
/// Formula:
/// ```text
/// whistleblower = effective_balance / SLASHING_PENALTY_QUOTIENT   (1/32)
/// correlation   = effective_balance / SLASHING_PENALTY_QUOTIENT   (1/32)
/// total         = whistleblower + correlation                      (1/16)
/// ```
///
/// Integer division floors the result. For a 32 ETH validator the penalty is
/// exactly 2 ETH (2_000_000_000 Gwei). For validators with a balance already
/// below 32 ETH the penalty scales proportionally.
///
/// # Panics
///
/// Does not panic; all arithmetic is safe for any `u64` input.
pub fn compute_slashing_penalty(effective_balance: u64) -> u64 {
    let whistleblower = effective_balance / SLASHING_PENALTY_QUOTIENT;
    let correlation = effective_balance / SLASHING_PENALTY_QUOTIENT;
    whistleblower.saturating_add(correlation)
}

/// Compute the inactivity-leak penalty for a validator.
///
/// Formula:
/// ```text
/// penalty = (epochs_since_finality² × effective_balance) / INACTIVITY_PENALTY_QUOTIENT
/// ```
///
/// `u128` intermediate arithmetic prevents the multiplication from wrapping
/// for realistic `epochs_since_finality` values. The result is then clamped
/// back to `u64` (if it somehow exceeds `u64::MAX` it saturates, but this
/// cannot occur for valid effective balances capped at [`MAX_EFFECTIVE_BALANCE`]
/// within any realistic chain lifetime).
///
/// # Panics
///
/// Does not panic.
pub fn compute_inactivity_penalty(effective_balance: u64, epochs_since_finality: u64) -> u64 {
    // Use u128 to avoid intermediate overflow when squaring large epoch counts.
    let epochs_sq = (epochs_since_finality as u128).saturating_mul(epochs_since_finality as u128);
    let numerator = epochs_sq.saturating_mul(effective_balance as u128);
    let penalty_wide = numerator / (INACTIVITY_PENALTY_QUOTIENT as u128);
    // Clamp to u64; for any realistic effective_balance <= MAX_EFFECTIVE_BALANCE
    // and chain lifetime this will not saturate.
    penalty_wide.min(u64::MAX as u128) as u64
}

/// Clamp `balance` so it never exceeds [`MAX_EFFECTIVE_BALANCE`].
/// Used after reward application to enforce the protocol invariant.
#[inline]
pub fn cap_effective_balance(balance: u64) -> u64 {
    balance.min(MAX_EFFECTIVE_BALANCE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::balance_tracker::GWEI_PER_ETH;

    #[test]
    fn test_compute_slashing_penalty() {
        let max_balance = 32 * GWEI_PER_ETH;
        let expected_penalty = (max_balance / 32) + (max_balance / 32);
        assert_eq!(compute_slashing_penalty(max_balance), expected_penalty);

        let zero_balance = 0;
        assert_eq!(compute_slashing_penalty(zero_balance), 0);
    }

    #[test]
    fn test_compute_inactivity_penalty() {
        let max_balance = 32 * GWEI_PER_ETH;
        let epochs = 10;
        let expected = (100 * (max_balance as u128) / (INACTIVITY_PENALTY_QUOTIENT as u128)) as u64;
        assert_eq!(compute_inactivity_penalty(max_balance, epochs), expected);

        assert_eq!(compute_inactivity_penalty(max_balance, 0), 0);
    }

    #[test]
    fn test_cap_effective_balance() {
        assert_eq!(
            cap_effective_balance(33 * GWEI_PER_ETH),
            MAX_EFFECTIVE_BALANCE
        );
        assert_eq!(cap_effective_balance(10 * GWEI_PER_ETH), 10 * GWEI_PER_ETH);
    }
}
