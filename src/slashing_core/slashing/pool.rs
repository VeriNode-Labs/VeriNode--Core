use soroban_sdk::{Address, Env, Vec};

use super::SlashingDataKey;

/// Race-free slashing reward pool (#4).
///
/// ## The bug
///
/// The previous design stored a `pool_remaining` balance and an `unclaimed`
/// reporter count separately, and `claim_reward()` computed each share
/// dynamically as `pool_remaining / unclaimed`. Two reporters claiming for the
/// same event would both read the same `pool_remaining` (e.g. 1000) and the
/// same `unclaimed` (e.g. 5), both compute `200`, and both transfer — debiting
/// the pool by 400 for a single 200-token share. The pool then ran dry before
/// every reporter was paid.
///
/// ## The fix
///
/// Two reinforcing measures from the resolution blueprint:
///
/// 1. **Amortized payout** — `reward_per_validator = initial_pool /
///    reporter_count` is computed once at pool creation and stored immutably.
///    The share no longer depends on a mutable `unclaimed` count, so no two
///    claimants can derive a stale-but-different amount.
/// 2. **Per-claimant tracking set** — each claim records the caller in a
///    [`SlashingDataKey::PoolClaimed`] marker and rejects a second claim. The
///    pool balance is decremented atomically within the same invocation as the
///    marker write and the claimed-count bump, so the read-modify-write cannot
///    interleave.
///
/// The final claimant sweeps any indivisible remainder, so the invariant
/// `Σ(claimed_rewards) == initial_pool` holds exactly once everyone has
/// claimed, and `Σ(claimed_rewards) <= initial_pool` holds at every step.
pub struct SlashingRewardPool;

/// Errors returned by [`SlashingRewardPool::claim_reward`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimError {
    /// No reward pool exists for this event id.
    PoolNotFound,
    /// The caller is not a registered reporter for this event.
    NotAReporter,
    /// The caller has already claimed for this event.
    AlreadyClaimed,
    /// The pool lacks the funds for this payout (should be unreachable given
    /// the amortized reward; returned defensively rather than overdrawing).
    PoolExhausted,
}

impl SlashingRewardPool {
    /// Create the reward pool for a slashing event.
    ///
    /// Fixes `reward_per_validator` and registers the reporter set. Returns
    /// `false` if a pool already exists for `event_id` (idempotency guard), or
    /// if the inputs are degenerate (`initial_pool <= 0` or no reporters).
    pub fn create_pool(
        env: &Env,
        event_id: u64,
        initial_pool: i128,
        reporters: &Vec<Address>,
    ) -> bool {
        let pool_key = SlashingDataKey::RewardPool(event_id);
        if env.storage().instance().has(&pool_key) {
            return false;
        }

        let reporter_count = reporters.len();
        if reporter_count == 0 || initial_pool <= 0 {
            return false;
        }

        let reward_per_validator = initial_pool / (reporter_count as i128);

        let storage = env.storage().instance();
        storage.set(&pool_key, &initial_pool);
        storage.set(
            &SlashingDataKey::RewardPerValidator(event_id),
            &reward_per_validator,
        );
        storage.set(&SlashingDataKey::PoolReporterCount(event_id), &reporter_count);
        storage.set(&SlashingDataKey::PoolClaimedCount(event_id), &0u32);

        for reporter in reporters.iter() {
            storage.set(&SlashingDataKey::PoolReporter(event_id, reporter.clone()), &true);
        }

        true
    }

    /// Claim a reporter's reward for `event_id`. Returns the payout amount.
    ///
    /// The marker write, claimed-count bump, and pool decrement happen together
    /// in a single invocation, so concurrent (serialized) claims each observe a
    /// consistent pool and can never double-withdraw.
    pub fn claim_reward(
        env: &Env,
        event_id: u64,
        validator: &Address,
    ) -> Result<i128, ClaimError> {
        let pool_key = SlashingDataKey::RewardPool(event_id);
        let pool_remaining: i128 = match env.storage().instance().get(&pool_key) {
            Some(balance) => balance,
            None => return Err(ClaimError::PoolNotFound),
        };

        // Must be a registered reporter.
        let reporter_key = SlashingDataKey::PoolReporter(event_id, validator.clone());
        let is_reporter: bool = env.storage().instance().get(&reporter_key).unwrap_or(false);
        if !is_reporter {
            return Err(ClaimError::NotAReporter);
        }

        // Double-claim guard.
        let claimed_key = SlashingDataKey::PoolClaimed(event_id, validator.clone());
        let already_claimed: bool = env.storage().instance().get(&claimed_key).unwrap_or(false);
        if already_claimed {
            return Err(ClaimError::AlreadyClaimed);
        }

        let reporter_count: u32 = env
            .storage()
            .instance()
            .get(&SlashingDataKey::PoolReporterCount(event_id))
            .unwrap_or(0);
        let claimed_count: u32 = env
            .storage()
            .instance()
            .get(&SlashingDataKey::PoolClaimedCount(event_id))
            .unwrap_or(0);
        let reward_per_validator: i128 = env
            .storage()
            .instance()
            .get(&SlashingDataKey::RewardPerValidator(event_id))
            .unwrap_or(0);

        // The final claimant sweeps any indivisible remainder so the pool ends
        // at exactly zero and Σ(claims) == initial_pool.
        let is_final_claim = claimed_count + 1 == reporter_count;
        let payout = if is_final_claim {
            pool_remaining
        } else {
            reward_per_validator
        };

        if payout > pool_remaining {
            return Err(ClaimError::PoolExhausted);
        }

        // --- Atomic update block ---
        let storage = env.storage().instance();
        storage.set(&claimed_key, &true);
        storage.set(
            &SlashingDataKey::PoolClaimedCount(event_id),
            &(claimed_count + 1),
        );
        storage.set(&pool_key, &(pool_remaining - payout));

        Ok(payout)
    }

    /// Remaining (unclaimed) balance in the event's reward pool.
    pub fn pool_remaining(env: &Env, event_id: u64) -> i128 {
        env.storage()
            .instance()
            .get(&SlashingDataKey::RewardPool(event_id))
            .unwrap_or(0)
    }

    /// The immutable per-validator reward fixed at pool creation.
    pub fn reward_per_validator(env: &Env, event_id: u64) -> i128 {
        env.storage()
            .instance()
            .get(&SlashingDataKey::RewardPerValidator(event_id))
            .unwrap_or(0)
    }

    /// Number of reporters that have already claimed.
    pub fn claimed_count(env: &Env, event_id: u64) -> u32 {
        env.storage()
            .instance()
            .get(&SlashingDataKey::PoolClaimedCount(event_id))
            .unwrap_or(0)
    }

    /// Whether `validator` has already claimed for `event_id`.
    pub fn has_claimed(env: &Env, event_id: u64, validator: &Address) -> bool {
        env.storage()
            .instance()
            .get(&SlashingDataKey::PoolClaimed(event_id, validator.clone()))
            .unwrap_or(false)
    }
}
