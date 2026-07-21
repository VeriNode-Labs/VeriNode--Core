use soroban_sdk::{contracttype, symbol_short, Address, Env};

use super::ReentrancyGuard;

// --- CONSTANTS ---

/// Minimum bond amount a tenant must lock (in LUM tokens).
pub const MIN_BOND_AMOUNT: i128 = 100;

/// Maximum bond amount a tenant can lock (in LUM tokens).
pub const MAX_BOND_AMOUNT: i128 = 10_000;

/// Minimum lock duration in seconds (7 days).
pub const MIN_LOCK_DURATION: u64 = 7 * 24 * 60 * 60;

// --- STORAGE KEYS ---

/// Storage keys for tenant bond operations.
#[contracttype]
#[derive(Clone)]
pub enum TenantBondKey {
    /// Bond ledger entry for a tenant: amount locked and timestamp.
    TenantBond(Address),
    /// Total bonded across all tenants.
    TotalBonded,
}

// --- TYPES ---

/// Ledger entry tracking a tenant's locked bond.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct TenantBondEntry {
    /// Address of the tenant.
    pub tenant: Address,
    /// Amount of LUM tokens locked.
    pub amount: i128,
    /// Ledger timestamp when the bond was locked.
    pub locked_at: u64,
    /// Whether the bond is currently locked (false = unlocked/withdrawn).
    pub is_locked: bool,
}

// --- ERRORS ---

/// Errors returned by TenantBondManager operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BondError {
    /// Bond amount is below the minimum or above the maximum.
    InvalidBondAmount,
    /// No bond found for this tenant.
    BondNotFound,
    /// The bond is not in a locked state (already unlocked).
    BondNotLocked,
    /// Lock duration has not yet elapsed.
    LockDurationNotElapsed,
    /// A bond already exists for this tenant.
    BondAlreadyExists,
}

/// The TenantBondManager handles locking and unlocking tenant bonds.
///
/// # Reentrancy Protection
///
/// This manager uses [`ReentrancyGuard`] on all state-mutating functions
/// (`lock_tenant_bond`, `unlock_tenant_bond`, `claim_slashed_bond`).
///
/// # Checks-Effects-Interactions Pattern
///
/// The `unlock_tenant_bond` function strictly follows CEI:
/// 1. **Checks**: Validate the bond exists, is locked, and the lock duration elapsed.
/// 2. **Effects**: Update bond ledger (mark as unlocked) and emit `BondUnlocked` event.
/// 3. **Interactions**: Perform the external token transfer last.
///
/// This ordering is the key fix: the internal state is updated BEFORE any
/// external call, preventing an attacker from re-entering during the token
/// transfer callback and exploiting stale state.
pub struct TenantBondManager;

impl TenantBondManager {
    /// Lock a tenant bond.
    ///
    /// Protected by [`ReentrancyGuard`] to prevent reentrant calls.
    ///
    /// # Errors
    ///
    /// - [`BondError::BondAlreadyExists`] if the tenant already has a locked bond.
    /// - [`BondError::InvalidBondAmount`] if amount is outside [MIN_BOND_AMOUNT, MAX_BOND_AMOUNT].
    pub fn lock_tenant_bond(
        env: &Env,
        tenant: &Address,
        amount: i128,
    ) -> Result<(), BondError> {
        // REENTRANCY GUARD — must be first statement before any logic
        let _guard = ReentrancyGuard::new(env);

        // --- CHECKS ---
        if amount < MIN_BOND_AMOUNT || amount > MAX_BOND_AMOUNT {
            return Err(BondError::InvalidBondAmount);
        }

        let bond_key = TenantBondKey::TenantBond(tenant.clone());
        let existing: Option<TenantBondEntry> = env.storage().instance().get(&bond_key);
        if existing.map(|b| b.is_locked).unwrap_or(false) {
            return Err(BondError::BondAlreadyExists);
        }

        // --- EFFECTS ---
        let entry = TenantBondEntry {
            tenant: tenant.clone(),
            amount,
            locked_at: env.ledger().timestamp(),
            is_locked: true,
        };
        env.storage().instance().set(&bond_key, &entry);

        // Update total bonded
        let total: i128 = env
            .storage()
            .instance()
            .get(&TenantBondKey::TotalBonded)
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&TenantBondKey::TotalBonded, &(total + amount));

        // Emit BondLocked event
        env.events().publish(
            (symbol_short!("BondLock"), tenant.clone()),
            (amount, env.ledger().timestamp()),
        );

        // --- INTERACTIONS ---
        // Token transfer from tenant to contract would happen here in a full
        // on-chain implementation (e.g., token_client.transfer_from(...)).

        Ok(())
    }

    /// Unlock a tenant bond and return the tokens to the tenant.
    ///
    /// # Security: Reentrancy Fix
    ///
    /// This function uses the Checks-Effects-Interactions (CEI) pattern:
    /// 1. **Checks**: validate existence, lock status, and lock duration.
    /// 2. **Effects**: mark bond as unlocked and update total bonded BEFORE transfer.
    ///    Emit the `BondUnlocked` event before the external call.
    /// 3. **Interactions**: perform external token transfer LAST.
    ///
    /// Additionally, [`ReentrancyGuard`] prevents a malicious tenant from
    /// re-entering this function during the ERC-20/token transfer callback.
    ///
    /// # Errors
    ///
    /// - [`BondError::BondNotFound`] if no bond exists for this tenant.
    /// - [`BondError::BondNotLocked`] if the bond is already unlocked.
    /// - [`BondError::LockDurationNotElapsed`] if the 7-day lock period has not passed.
    pub fn unlock_tenant_bond(env: &Env, tenant: &Address) -> Result<i128, BondError> {
        // REENTRANCY GUARD — must be first statement before any logic
        let _guard = ReentrancyGuard::new(env);

        // --- CHECKS ---
        let bond_key = TenantBondKey::TenantBond(tenant.clone());
        let entry: TenantBondEntry = env
            .storage()
            .instance()
            .get(&bond_key)
            .ok_or(BondError::BondNotFound)?;

        if !entry.is_locked {
            return Err(BondError::BondNotLocked);
        }

        let current_time = env.ledger().timestamp();
        if current_time.saturating_sub(entry.locked_at) < MIN_LOCK_DURATION {
            return Err(BondError::LockDurationNotElapsed);
        }

        let amount = entry.amount;

        // --- EFFECTS ---
        // Update bond ledger to mark as unlocked BEFORE any external interaction.
        // This is the core security fix: internal state is updated first so that
        // any reentrant call sees the bond as already unlocked and cannot drain
        // the pool a second time.
        let unlocked_entry = TenantBondEntry {
            is_locked: false,
            ..entry
        };
        env.storage().instance().set(&bond_key, &unlocked_entry);

        // Decrement total bonded
        let total: i128 = env
            .storage()
            .instance()
            .get(&TenantBondKey::TotalBonded)
            .unwrap_or(0);
        let new_total = total.saturating_sub(amount);
        env.storage()
            .instance()
            .set(&TenantBondKey::TotalBonded, &new_total);

        // Emit BondUnlocked event BEFORE external call (per issue requirement)
        env.events().publish(
            (symbol_short!("BondUnlk"), tenant.clone()),
            (amount, current_time),
        );

        // --- INTERACTIONS ---
        // External token transfer to tenant happens here, AFTER all state updates.
        // In a full on-chain implementation this would be:
        //   token_client.transfer(&env.current_contract_address(), tenant, &amount);
        // The state is already updated above, so any callback into this contract
        // (reentrancy attempt) will find the bond marked as unlocked and fail.

        Ok(amount)
    }

    /// Claim slashed bond tokens after a node has been slashed.
    ///
    /// Protected by [`ReentrancyGuard`] to prevent reentrant calls.
    ///
    /// Returns the claimed amount on success.
    ///
    /// # Errors
    ///
    /// - [`BondError::BondNotFound`] if no bond exists for this tenant.
    /// - [`BondError::BondNotLocked`] if the bond is not in a locked state.
    pub fn claim_slashed_bond(env: &Env, tenant: &Address) -> Result<i128, BondError> {
        // REENTRANCY GUARD — must be first statement before any logic
        let _guard = ReentrancyGuard::new(env);

        // --- CHECKS ---
        let bond_key = TenantBondKey::TenantBond(tenant.clone());
        let entry: TenantBondEntry = env
            .storage()
            .instance()
            .get(&bond_key)
            .ok_or(BondError::BondNotFound)?;

        if !entry.is_locked {
            return Err(BondError::BondNotLocked);
        }

        let amount = entry.amount;

        // --- EFFECTS ---
        // Mark bond as unlocked and zero out the amount before any transfer
        let slashed_entry = TenantBondEntry {
            is_locked: false,
            amount: 0,
            ..entry
        };
        env.storage().instance().set(&bond_key, &slashed_entry);

        // Decrement total bonded
        let total: i128 = env
            .storage()
            .instance()
            .get(&TenantBondKey::TotalBonded)
            .unwrap_or(0);
        let new_total = total.saturating_sub(amount);
        env.storage()
            .instance()
            .set(&TenantBondKey::TotalBonded, &new_total);

        // Emit SlashClaim event before external interaction
        env.events().publish(
            (symbol_short!("SlshClm"), tenant.clone()),
            (amount, env.ledger().timestamp()),
        );

        // --- INTERACTIONS ---
        // Distribute slashed tokens to slashing reporters would happen here.

        Ok(amount)
    }

    /// Query the bond entry for a tenant.
    pub fn get_bond(env: &Env, tenant: &Address) -> Option<TenantBondEntry> {
        env.storage()
            .instance()
            .get(&TenantBondKey::TenantBond(tenant.clone()))
    }

    /// Query the total amount bonded across all tenants.
    pub fn total_bonded(env: &Env) -> i128 {
        env.storage()
            .instance()
            .get(&TenantBondKey::TotalBonded)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    // ---------------------------------------------------------------------------
    // Lock tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_lock_valid_bond() {
        let env = Env::default();
        let tenant = Address::generate(&env);

        TenantBondManager::lock_tenant_bond(&env, &tenant, MIN_BOND_AMOUNT)
            .expect("lock should succeed");

        let entry = TenantBondManager::get_bond(&env, &tenant).expect("bond should exist");
        assert!(entry.is_locked);
        assert_eq!(entry.amount, MIN_BOND_AMOUNT);
        assert_eq!(TenantBondManager::total_bonded(&env), MIN_BOND_AMOUNT);
    }

    #[test]
    fn test_lock_rejects_below_minimum() {
        let env = Env::default();
        let tenant = Address::generate(&env);

        let result = TenantBondManager::lock_tenant_bond(&env, &tenant, MIN_BOND_AMOUNT - 1);
        assert_eq!(result, Err(BondError::InvalidBondAmount));
    }

    #[test]
    fn test_lock_rejects_above_maximum() {
        let env = Env::default();
        let tenant = Address::generate(&env);

        let result = TenantBondManager::lock_tenant_bond(&env, &tenant, MAX_BOND_AMOUNT + 1);
        assert_eq!(result, Err(BondError::InvalidBondAmount));
    }

    #[test]
    fn test_lock_rejects_duplicate_bond() {
        let env = Env::default();
        let tenant = Address::generate(&env);

        TenantBondManager::lock_tenant_bond(&env, &tenant, MIN_BOND_AMOUNT)
            .expect("first lock should succeed");

        let result = TenantBondManager::lock_tenant_bond(&env, &tenant, MIN_BOND_AMOUNT);
        assert_eq!(result, Err(BondError::BondAlreadyExists));
    }

    // ---------------------------------------------------------------------------
    // Unlock tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_unlock_rejects_missing_bond() {
        let env = Env::default();
        let tenant = Address::generate(&env);

        let result = TenantBondManager::unlock_tenant_bond(&env, &tenant);
        assert_eq!(result, Err(BondError::BondNotFound));
    }

    #[test]
    fn test_unlock_rejects_before_lock_duration() {
        let env = Env::default();
        let tenant = Address::generate(&env);

        TenantBondManager::lock_tenant_bond(&env, &tenant, MIN_BOND_AMOUNT)
            .expect("lock should succeed");

        // Attempt unlock immediately (lock duration not elapsed)
        let result = TenantBondManager::unlock_tenant_bond(&env, &tenant);
        assert_eq!(result, Err(BondError::LockDurationNotElapsed));
    }

    #[test]
    fn test_unlock_succeeds_after_lock_duration() {
        let env = Env::default();
        let tenant = Address::generate(&env);

        TenantBondManager::lock_tenant_bond(&env, &tenant, MIN_BOND_AMOUNT)
            .expect("lock should succeed");

        // Advance ledger time past the minimum lock duration
        env.ledger().with_mut(|l| {
            l.timestamp = MIN_LOCK_DURATION + 1;
        });

        let unlocked = TenantBondManager::unlock_tenant_bond(&env, &tenant)
            .expect("unlock should succeed");
        assert_eq!(unlocked, MIN_BOND_AMOUNT);

        // Bond should now be marked as unlocked
        let entry = TenantBondManager::get_bond(&env, &tenant).expect("entry should exist");
        assert!(!entry.is_locked);

        // Total bonded should be zero
        assert_eq!(TenantBondManager::total_bonded(&env), 0);
    }

    #[test]
    fn test_unlock_rejects_already_unlocked() {
        let env = Env::default();
        let tenant = Address::generate(&env);

        TenantBondManager::lock_tenant_bond(&env, &tenant, MIN_BOND_AMOUNT)
            .expect("lock should succeed");

        env.ledger().with_mut(|l| {
            l.timestamp = MIN_LOCK_DURATION + 1;
        });

        TenantBondManager::unlock_tenant_bond(&env, &tenant)
            .expect("first unlock should succeed");

        // Second unlock attempt should fail
        let result = TenantBondManager::unlock_tenant_bond(&env, &tenant);
        assert_eq!(result, Err(BondError::BondNotLocked));
    }

    // ---------------------------------------------------------------------------
    // Reentrancy invariant tests
    // ---------------------------------------------------------------------------

    /// Fuzz-style invariant test: after N sequential lock+unlock cycles,
    /// `total_bonded` must equal the sum of all currently active bonds.
    ///
    /// This verifies that the CEI pattern keeps internal accounting consistent
    /// even across multiple operations.
    #[test]
    fn test_invariant_total_bonded_equals_sum_of_active_bonds() {
        let env = Env::default();
        const N: usize = 100;
        let mut tenants: Vec<Address> = Vec::with_capacity(N);
        let amount: i128 = 500; // within [MIN_BOND_AMOUNT, MAX_BOND_AMOUNT]

        // Lock bonds for N tenants
        for _ in 0..N {
            let tenant = Address::generate(&env);
            TenantBondManager::lock_tenant_bond(&env, &tenant, amount)
                .expect("lock should succeed");
            tenants.push(tenant);
        }

        // Advance time past lock duration
        env.ledger().with_mut(|l| {
            l.timestamp = MIN_LOCK_DURATION + 1;
        });

        // Verify invariant before unlocking: totalBonded == sum(activeBonds)
        let total = TenantBondManager::total_bonded(&env);
        assert_eq!(total, amount * N as i128, "invariant broken before unlock");

        // Unlock all tenants one by one and verify invariant at each step
        for (i, tenant) in tenants.iter().enumerate() {
            TenantBondManager::unlock_tenant_bond(&env, tenant)
                .expect("unlock should succeed");

            let expected_remaining = amount * (N - i - 1) as i128;
            let actual_total = TenantBondManager::total_bonded(&env);
            assert_eq!(
                actual_total, expected_remaining,
                "invariant broken at step {i}: totalBonded={actual_total}, expected={expected_remaining}"
            );
        }

        assert_eq!(TenantBondManager::total_bonded(&env), 0, "pool should be empty");
    }

    /// Simulate 100 reentrant call patterns: verify the reentrancy guard
    /// consistently prevents double-entry into unlock_tenant_bond.
    ///
    /// In Soroban, true reentrancy via contract callbacks is blocked by the
    /// VM. This test verifies our guard catches any attempt to call into a
    /// guarded function while the guard is active within the same invocation.
    #[test]
    fn test_reentrancy_guard_prevents_reentry_100_patterns() {
        let env = Env::default();

        for pattern in 0..100u32 {
            // Attempt to acquire a guard while one is already active.
            // We test this by directly exercising the guard rather than
            // going through TenantBondManager, as Soroban's WASM sandbox
            // serializes all external calls.
            let guard_acquired = std::panic::catch_unwind(|| {
                let _guard1 = ReentrancyGuard::new(&env);
                // Inner guard should panic
                let _guard2 = ReentrancyGuard::new(&env);
            });

            assert!(
                guard_acquired.is_err(),
                "reentrant pattern {pattern}: guard should have rejected double entry"
            );

            // The outer guard dropped in the catch_unwind, so the flag is cleared.
            // Verify we can enter again after the guard is released.
            let sequential_ok = std::panic::catch_unwind(|| {
                let _g = ReentrancyGuard::new(&env);
            });
            assert!(
                sequential_ok.is_ok(),
                "pattern {pattern}: guard should allow entry after release"
            );
        }
    }

    // ---------------------------------------------------------------------------
    // claim_slashed_bond tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_claim_slashed_bond_succeeds() {
        let env = Env::default();
        let tenant = Address::generate(&env);

        TenantBondManager::lock_tenant_bond(&env, &tenant, 1000)
            .expect("lock should succeed");

        let claimed = TenantBondManager::claim_slashed_bond(&env, &tenant)
            .expect("claim should succeed");
        assert_eq!(claimed, 1000);

        let entry = TenantBondManager::get_bond(&env, &tenant).expect("entry should exist");
        assert!(!entry.is_locked);
        assert_eq!(entry.amount, 0);
        assert_eq!(TenantBondManager::total_bonded(&env), 0);
    }

    #[test]
    fn test_claim_slashed_bond_rejects_missing_bond() {
        let env = Env::default();
        let tenant = Address::generate(&env);

        let result = TenantBondManager::claim_slashed_bond(&env, &tenant);
        assert_eq!(result, Err(BondError::BondNotFound));
    }

    #[test]
    fn test_claim_slashed_bond_rejects_already_unlocked() {
        let env = Env::default();
        let tenant = Address::generate(&env);

        TenantBondManager::lock_tenant_bond(&env, &tenant, 500)
            .expect("lock should succeed");

        env.ledger().with_mut(|l| {
            l.timestamp = MIN_LOCK_DURATION + 1;
        });

        TenantBondManager::unlock_tenant_bond(&env, &tenant)
            .expect("unlock should succeed");

        let result = TenantBondManager::claim_slashed_bond(&env, &tenant);
        assert_eq!(result, Err(BondError::BondNotLocked));
    }
}
