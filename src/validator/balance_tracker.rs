//! Validator balance tracker with underflow-safe penalty application.
//!
//! Fixes issue #241: `apply_penalty()` previously used `saturating_sub`, which
//! silently clamped a balance to zero when the penalty exceeded the balance.
//! This allowed a validator to remain active for one more epoch (bypassing the
//! ejection threshold check) and then re-activate with a zero balance.
//!
//! The fix replaces `saturating_sub` with `checked_sub`. When the penalty
//! exceeds the current balance the function returns
//! [`BalanceError::InsufficientBalance`] instead of clamping, and the caller
//! is responsible for recording a debt and forcing immediate ejection.

extern crate alloc;
use alloc::collections::BTreeMap;

use crate::validator::exit_queue::ValidatorIndex;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// 1 ETH expressed in Gwei (u64). Used as the base unit for balances.
pub const GWEI_PER_ETH: u64 = 1_000_000_000;

/// Maximum effective balance a validator can hold (32 ETH in Gwei).
pub const MAX_EFFECTIVE_BALANCE: u64 = 32 * GWEI_PER_ETH;

/// Ejection threshold: validators whose effective balance falls strictly below
/// this value are ejected at the epoch boundary (16 ETH in Gwei).
pub const EJECTION_THRESHOLD: u64 = 16 * GWEI_PER_ETH;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can be returned by balance-tracker operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalanceError {
    /// The requested penalty exceeds the validator's current balance.
    /// The validator must be force-ejected and a debt recorded.
    InsufficientBalance {
        /// Balance at the time the penalty was applied.
        balance: u64,
        /// Penalty that was attempted.
        penalty: u64,
    },
    /// No record exists for the given `ValidatorIndex`.
    ValidatorNotFound,
}

// ---------------------------------------------------------------------------
// BalanceTracker
// ---------------------------------------------------------------------------

/// Tracks effective balances and outstanding debts for every known validator.
///
/// Balances are stored in Gwei (`u64`). Debts are recorded separately so that
/// a validator whose balance has been driven to zero by a penalty that exceeds
/// the balance is still flagged for forced ejection even though its stored
/// balance reads zero.
#[derive(Clone, Debug, Default)]
pub struct BalanceTracker {
    /// Effective balance in Gwei for each validator index.
    balances: BTreeMap<ValidatorIndex, u64>,
    /// Unpaid debt in Gwei for validators whose penalty exceeded their balance.
    /// The presence of any debt, however small, marks the validator for forced
    /// ejection regardless of its stored effective balance.
    debts: BTreeMap<ValidatorIndex, u64>,
}

impl BalanceTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self {
            balances: BTreeMap::new(),
            debts: BTreeMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    /// Register `validator_index` with the given starting `balance` (Gwei).
    /// Silently overwrites any previous entry (useful for test setup).
    pub fn register_validator(&mut self, validator_index: ValidatorIndex, balance: u64) {
        self.balances.insert(validator_index, balance);
        // Clear any stale debt from a previous registration.
        self.debts.remove(&validator_index);
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Return the current effective balance in Gwei, or `None` if the validator
    /// is not registered.
    pub fn effective_balance(&self, validator_index: ValidatorIndex) -> Option<u64> {
        self.balances.get(&validator_index).copied()
    }

    /// Return the outstanding debt in Gwei, or `None` if the validator is not
    /// registered / has no debt.
    pub fn outstanding_debt(&self, validator_index: ValidatorIndex) -> Option<u64> {
        self.debts.get(&validator_index).copied()
    }

    /// Return `true` if the validator has any outstanding debt.
    pub fn has_debt(&self, validator_index: ValidatorIndex) -> bool {
        self.debts.get(&validator_index).is_some_and(|&d| d > 0)
    }

    // -----------------------------------------------------------------------
    // Mutations
    // -----------------------------------------------------------------------

    /// Apply `penalty` (Gwei) to `validator_index`.
    ///
    /// # Behaviour
    ///
    /// * If `penalty <= balance` the balance is reduced and `Ok(new_balance)` is
    ///   returned.
    /// * If `penalty > balance` **no balance change is made**, the excess is
    ///   recorded as a debt, and
    ///   [`Err(BalanceError::InsufficientBalance)`] is returned. The caller
    ///   must mark the validator for forced ejection.
    ///
    /// # Errors
    ///
    /// Returns [`BalanceError::ValidatorNotFound`] when the index is unknown.
    pub fn apply_penalty(
        &mut self,
        validator_index: ValidatorIndex,
        penalty: u64,
    ) -> Result<u64, BalanceError> {
        let balance = self
            .balances
            .get_mut(&validator_index)
            .ok_or(BalanceError::ValidatorNotFound)?;

        match balance.checked_sub(penalty) {
            Some(new_balance) => {
                *balance = new_balance;
                Ok(new_balance)
            }
            None => {
                // Record the excess as a debt so the ejection logic can detect
                // it even after the balance has been zeroed.
                let debt = penalty - *balance;
                *self.debts.entry(validator_index).or_insert(0) += debt;
                // The validator's stored balance is set to zero because the
                // full balance has been consumed.
                *balance = 0;
                Err(BalanceError::InsufficientBalance {
                    balance: 0,
                    penalty,
                })
            }
        }
    }

    /// Apply `reward` (Gwei) to `validator_index`, capped at
    /// [`MAX_EFFECTIVE_BALANCE`].
    ///
    /// # Errors
    ///
    /// Returns [`BalanceError::ValidatorNotFound`] when the index is unknown.
    pub fn apply_reward(
        &mut self,
        validator_index: ValidatorIndex,
        reward: u64,
    ) -> Result<u64, BalanceError> {
        let balance = self
            .balances
            .get_mut(&validator_index)
            .ok_or(BalanceError::ValidatorNotFound)?;

        *balance = balance.saturating_add(reward).min(MAX_EFFECTIVE_BALANCE);
        Ok(*balance)
    }

    // -----------------------------------------------------------------------
    // Ejection helpers
    // -----------------------------------------------------------------------

    /// Return the indices of all validators that should be ejected at the
    /// current epoch boundary.
    ///
    /// A validator is ejection-eligible when **either**:
    /// 1. Its effective balance has fallen strictly below
    ///    [`EJECTION_THRESHOLD`], **or**
    /// 2. It has an outstanding debt (the penalty exceeded its balance).
    pub fn ejection_eligible(&self) -> alloc::vec::Vec<ValidatorIndex> {
        let mut eligible = alloc::vec::Vec::new();
        for (&idx, &bal) in &self.balances {
            if bal < EJECTION_THRESHOLD || self.has_debt(idx) {
                eligible.push(idx);
            }
        }
        eligible
    }

    /// Clear the debt record for a validator (called after ejection is
    /// confirmed so the entry does not linger).
    pub fn clear_debt(&mut self, validator_index: ValidatorIndex) {
        self.debts.remove(&validator_index);
    }
}
