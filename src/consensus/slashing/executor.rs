//! Stake slashing and fund distribution executor (issue #135).
//!
//! After a challenge period expires without successful counter-evidence, the
//! executor applies the slashing penalty to the offending validator's stake:
//!
//! * **50 %** of the slashed amount is burned (removed from circulation).
//! * **50 %** is distributed equally among all active validators.
//!
//! # Slashing amounts
//!
//! | Offense type   | Slashing amount                                              |
//! |----------------|--------------------------------------------------------------|
//! | Equivocation   | 100 % of stake                                              |
//! | Unavailability | 0.1 % per missed attestation (max 10 %) of stake            |
//! | Invalid proposal | 2 % of stake                                             |
//!
//! All arithmetic is performed with `u64` in Gwei. Intermediate multiplications
//! use `u128` to avoid overflow.

extern crate alloc;

use alloc::collections::BTreeMap;

use crate::consensus::slashing::detector::OffenseType;
use crate::consensus::view_change::types::PublicKey;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Fraction of slashed funds that is burned (50 %).
pub const BURN_FRACTION_NUMERATOR: u128 = 1;
pub const BURN_FRACTION_DENOMINATOR: u128 = 2;

/// Unavailability penalty per missed attestation: 0.1 % = 1/1000.
pub const UNAVAILABILITY_PENALTY_PER_MISS_NUMERATOR: u128 = 1;
pub const UNAVAILABILITY_PENALTY_PER_MISS_DENOMINATOR: u128 = 1_000;

/// Maximum unavailability penalty as a fraction of stake: 10 % = 1/10.
pub const UNAVAILABILITY_MAX_PENALTY_NUMERATOR: u128 = 1;
pub const UNAVAILABILITY_MAX_PENALTY_DENOMINATOR: u128 = 10;

/// Invalid-proposal penalty: 2 % of stake = 2/100.
pub const INVALID_PROPOSAL_PENALTY_NUMERATOR: u128 = 2;
pub const INVALID_PROPOSAL_PENALTY_DENOMINATOR: u128 = 100;

// ─── Slashing result ──────────────────────────────────────────────────────────

/// The result of a slashing execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlashingResult {
    /// Validator whose stake was slashed.
    pub validator_id: PublicKey,
    /// The offense that triggered slashing.
    pub offense_type: OffenseType,
    /// Total amount slashed from the validator's stake.
    pub total_slashed: u64,
    /// Amount burned (≈ 50 % of `total_slashed`).
    pub burned: u64,
    /// Amount distributed to active validators (≈ 50 % of `total_slashed`).
    pub distributed: u64,
    /// Per-validator reward distributed to each active validator.
    /// `0` if there are no active validators.
    pub reward_per_active_validator: u64,
    /// Final remaining stake of the slashed validator (may be 0).
    pub remaining_stake: u64,
}

/// Errors returned by the executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorError {
    /// No stake record exists for the specified validator.
    ValidatorNotFound,
    /// The slashing has already been applied (idempotency guard).
    AlreadySlashed,
}

// ─── StakeRegistry ────────────────────────────────────────────────────────────

/// Minimal in-memory stake registry used by the executor.
///
/// In production this would be backed by persistent on-chain storage.
/// Here it is a plain `BTreeMap` so the module is `no_std`-compatible
/// and fully testable without a Soroban harness.
#[derive(Clone, Debug, Default)]
pub struct StakeRegistry {
    /// Stake balance (Gwei) per validator public key.
    stakes: BTreeMap<PublicKey, u64>,
    /// Set of validators that have already been slashed (idempotency guard).
    slashed: BTreeMap<PublicKey, bool>,
}

impl StakeRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a validator with an initial stake.
    pub fn register(&mut self, validator_id: PublicKey, stake: u64) {
        self.stakes.insert(validator_id, stake);
        self.slashed.insert(validator_id, false);
    }

    /// Current stake of `validator_id`, or `None` if not registered.
    pub fn stake(&self, validator_id: &PublicKey) -> Option<u64> {
        self.stakes.get(validator_id).copied()
    }

    /// Whether `validator_id` has already been slashed.
    pub fn is_slashed(&self, validator_id: &PublicKey) -> bool {
        self.slashed.get(validator_id).copied().unwrap_or(false)
    }

    /// All registered validator IDs.
    pub fn all_validators(&self) -> impl Iterator<Item = &PublicKey> {
        self.stakes.keys()
    }

    // Internal: deduct stake and mark slashed.
    fn apply_slash(&mut self, validator_id: &PublicKey, amount: u64) -> u64 {
        let stake = self.stakes.get_mut(validator_id).expect("validator exists");
        let actual = (*stake).min(amount);
        *stake = stake.saturating_sub(actual);
        let remaining = *stake;
        self.slashed.insert(*validator_id, true);
        remaining
    }
}

// ─── SlashingExecutor ────────────────────────────────────────────────────────

/// Applies computed slashing penalties and distributes funds.
#[derive(Clone, Debug, Default)]
pub struct SlashingExecutor {
    registry: StakeRegistry,
}

impl SlashingExecutor {
    /// Create an executor backed by the given registry.
    pub fn new(registry: StakeRegistry) -> Self {
        Self { registry }
    }

    /// Create an executor with an empty registry (useful for testing).
    pub fn empty() -> Self {
        Self {
            registry: StakeRegistry::new(),
        }
    }

    /// Access to the stake registry for inspection / setup.
    pub fn registry(&self) -> &StakeRegistry {
        &self.registry
    }

    /// Mutable access to the registry (for registration during setup).
    pub fn registry_mut(&mut self) -> &mut StakeRegistry {
        &mut self.registry
    }

    /// Execute slashing for `validator_id` with the given `offense_type` and
    /// optional `missed_attestations` count (only relevant for
    /// [`OffenseType::Unavailability`]).
    ///
    /// `active_validators` is the list of all active validators that will share
    /// the 50 % distribution reward (the slashed validator itself may be
    /// excluded by the caller).
    ///
    /// # Idempotency
    ///
    /// The executor refuses to slash a validator more than once.
    ///
    /// # Returns
    ///
    /// * `Ok(SlashingResult)` — slashing applied successfully.
    /// * `Err(ExecutorError::ValidatorNotFound)` — no stake record.
    /// * `Err(ExecutorError::AlreadySlashed)` — idempotency guard triggered.
    pub fn execute(
        &mut self,
        validator_id: PublicKey,
        offense_type: OffenseType,
        missed_attestations: u64,
        active_validators: &[PublicKey],
    ) -> Result<SlashingResult, ExecutorError> {
        let stake = self
            .registry
            .stake(&validator_id)
            .ok_or(ExecutorError::ValidatorNotFound)?;

        if self.registry.is_slashed(&validator_id) {
            return Err(ExecutorError::AlreadySlashed);
        }

        let total_slashed =
            Self::compute_slash_amount(offense_type, stake, missed_attestations);

        // Split: 50 % burn, 50 % distribute.
        let burned = (total_slashed as u128)
            .saturating_mul(BURN_FRACTION_NUMERATOR)
            / BURN_FRACTION_DENOMINATOR;
        let burned = burned as u64;
        let distributed = total_slashed.saturating_sub(burned);

        // Per-active-validator reward (integer division; any remainder is burned).
        let reward_per = if active_validators.is_empty() {
            0u64
        } else {
            (distributed as u128 / active_validators.len() as u128) as u64
        };

        // Apply stake deduction and mark validator slashed.
        let remaining = self.registry.apply_slash(&validator_id, total_slashed);

        Ok(SlashingResult {
            validator_id,
            offense_type,
            total_slashed,
            burned,
            distributed,
            reward_per_active_validator: reward_per,
            remaining_stake: remaining,
        })
    }

    /// Compute the slashing amount given the offense type and current stake.
    ///
    /// | Offense        | Formula                                    |
    /// |----------------|--------------------------------------------|
    /// | Equivocation   | 100 % of stake                            |
    /// | Unavailability | min(missed × 0.1 %, 10 %) of stake       |
    /// | InvalidProposal| 2 % of stake                              |
    pub fn compute_slash_amount(
        offense_type: OffenseType,
        stake: u64,
        missed_attestations: u64,
    ) -> u64 {
        match offense_type {
            OffenseType::Equivocation => stake,

            OffenseType::Unavailability => {
                // per-miss penalty: stake * (1/1000) per miss
                let raw = (stake as u128)
                    .saturating_mul(UNAVAILABILITY_PENALTY_PER_MISS_NUMERATOR)
                    .saturating_mul(missed_attestations as u128)
                    / UNAVAILABILITY_PENALTY_PER_MISS_DENOMINATOR;

                // cap at 10 % of stake
                let cap = (stake as u128)
                    .saturating_mul(UNAVAILABILITY_MAX_PENALTY_NUMERATOR)
                    / UNAVAILABILITY_MAX_PENALTY_DENOMINATOR;

                raw.min(cap) as u64
            }

            OffenseType::InvalidProposal => {
                let amount = (stake as u128)
                    .saturating_mul(INVALID_PROPOSAL_PENALTY_NUMERATOR)
                    / INVALID_PROPOSAL_PENALTY_DENOMINATOR;
                amount as u64
            }
        }
    }
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(id: u8) -> PublicKey {
        let mut k = [0u8; 32];
        k[31] = id;
        k
    }

    /// 32 ETH expressed in Gwei.
    const STAKE_32_ETH: u64 = 32_000_000_000;

    fn executor_with_validator(validator_id: PublicKey, stake: u64) -> SlashingExecutor {
        let mut exec = SlashingExecutor::empty();
        exec.registry_mut().register(validator_id, stake);
        exec
    }

    // ── compute_slash_amount ──────────────────────────────────────────────────

    #[test]
    fn equivocation_slashes_full_stake() {
        let amount = SlashingExecutor::compute_slash_amount(
            OffenseType::Equivocation,
            STAKE_32_ETH,
            0,
        );
        assert_eq!(amount, STAKE_32_ETH);
    }

    #[test]
    fn unavailability_scales_per_miss() {
        // 100 misses × 0.1 % = 10 % (exactly at cap)
        let amount = SlashingExecutor::compute_slash_amount(
            OffenseType::Unavailability,
            STAKE_32_ETH,
            100,
        );
        let expected_cap = STAKE_32_ETH / 10;
        assert_eq!(amount, expected_cap);
    }

    #[test]
    fn unavailability_below_cap() {
        // 50 misses × 0.1 % = 5 % < 10 % cap
        let amount = SlashingExecutor::compute_slash_amount(
            OffenseType::Unavailability,
            STAKE_32_ETH,
            50,
        );
        let expected = STAKE_32_ETH as u128 * 50 / 1_000;
        assert_eq!(amount, expected as u64);
    }

    #[test]
    fn unavailability_above_100_misses_capped_at_10_percent() {
        // 200 misses would be 20 %, but it's capped at 10 %.
        let amount = SlashingExecutor::compute_slash_amount(
            OffenseType::Unavailability,
            STAKE_32_ETH,
            200,
        );
        let cap = STAKE_32_ETH / 10;
        assert_eq!(amount, cap);
    }

    #[test]
    fn invalid_proposal_slashes_two_percent() {
        let amount = SlashingExecutor::compute_slash_amount(
            OffenseType::InvalidProposal,
            STAKE_32_ETH,
            0,
        );
        let expected = STAKE_32_ETH as u128 * 2 / 100;
        assert_eq!(amount, expected as u64);
    }

    // ── execute ───────────────────────────────────────────────────────────────

    #[test]
    fn execute_equivocation_burns_half_distributes_half() {
        let mut exec = executor_with_validator(pk(1), STAKE_32_ETH);
        let actives = alloc::vec![pk(2), pk(3), pk(4)];
        let result = exec
            .execute(pk(1), OffenseType::Equivocation, 0, &actives)
            .unwrap();

        assert_eq!(result.total_slashed, STAKE_32_ETH);
        // 50 % burned
        assert_eq!(result.burned, STAKE_32_ETH / 2);
        // 50 % distributed
        assert_eq!(result.distributed, STAKE_32_ETH / 2);
        // 3 active validators
        assert_eq!(
            result.reward_per_active_validator,
            (STAKE_32_ETH / 2) / 3
        );
        // Validator stake is zero after equivocation
        assert_eq!(result.remaining_stake, 0);
    }

    #[test]
    fn execute_unavailability_correct_amounts() {
        let stake = STAKE_32_ETH;
        let mut exec = executor_with_validator(pk(1), stake);
        let actives = alloc::vec![pk(2)];
        // 50 misses → 5 % of stake
        let result = exec
            .execute(pk(1), OffenseType::Unavailability, 50, &actives)
            .unwrap();

        let expected_slash = (stake as u128 * 50 / 1_000) as u64;
        assert_eq!(result.total_slashed, expected_slash);
        assert_eq!(result.burned, expected_slash / 2);
        assert_eq!(result.distributed, expected_slash - expected_slash / 2);
        assert_eq!(result.remaining_stake, stake - expected_slash);
    }

    #[test]
    fn execute_invalid_proposal_correct_amounts() {
        let stake = STAKE_32_ETH;
        let mut exec = executor_with_validator(pk(1), stake);
        let actives: Vec<PublicKey> = alloc::vec![];
        let result = exec
            .execute(pk(1), OffenseType::InvalidProposal, 0, &actives)
            .unwrap();

        let expected = (stake as u128 * 2 / 100) as u64;
        assert_eq!(result.total_slashed, expected);
        // No active validators → reward_per is 0
        assert_eq!(result.reward_per_active_validator, 0);
    }

    #[test]
    fn execute_idempotency_guard_rejects_double_slash() {
        let mut exec = executor_with_validator(pk(1), STAKE_32_ETH);
        exec.execute(pk(1), OffenseType::Equivocation, 0, &[])
            .unwrap();

        let err = exec
            .execute(pk(1), OffenseType::Equivocation, 0, &[])
            .unwrap_err();
        assert_eq!(err, ExecutorError::AlreadySlashed);
    }

    #[test]
    fn execute_validator_not_found_returns_error() {
        let mut exec = SlashingExecutor::empty();
        let err = exec
            .execute(pk(255), OffenseType::Equivocation, 0, &[])
            .unwrap_err();
        assert_eq!(err, ExecutorError::ValidatorNotFound);
    }

    #[test]
    fn no_active_validators_distributed_is_zero_per_validator() {
        let mut exec = executor_with_validator(pk(1), STAKE_32_ETH);
        let result = exec
            .execute(pk(1), OffenseType::Equivocation, 0, &[])
            .unwrap();
        assert_eq!(result.reward_per_active_validator, 0);
        // Distributed amount still reflects the 50 % share; it is simply
        // not rewardable (could be burned by the caller).
        assert_eq!(result.distributed, STAKE_32_ETH / 2);
    }
}
