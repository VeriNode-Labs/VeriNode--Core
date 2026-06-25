use soroban_sdk::{testutils::Address as _, Address, Env, Vec};

use crate::slashing_core::slashing::pool::{ClaimError, SlashingRewardPool};
use crate::SoroSusu;

fn setup_contract(env: &Env) -> Address {
    env.register_contract(None, SoroSusu)
}

fn make_reporters(env: &Env, n: u32) -> Vec<Address> {
    let mut reporters = Vec::new(env);
    for _ in 0..n {
        reporters.push_back(Address::generate(env));
    }
    reporters
}

/// Blueprint step 5: 10 validators claiming for the same event distribute the
/// pool exactly once and in full, with no double-claim.
#[test]
fn ten_validators_fully_distribute_pool_without_double_claim() {
    let env = Env::default();
    let contract_id = setup_contract(&env);

    env.as_contract(&contract_id, || {
        let event_id = 1u64;
        let initial_pool: i128 = 1000;
        let reporters = make_reporters(&env, 10);

        assert!(SlashingRewardPool::create_pool(
            &env,
            event_id,
            initial_pool,
            &reporters
        ));

        let mut total_claimed: i128 = 0;
        for reporter in reporters.iter() {
            let payout = SlashingRewardPool::claim_reward(&env, event_id, &reporter)
                .expect("registered reporter should claim");
            total_claimed += payout;

            // A second claim by the same reporter is always rejected.
            assert_eq!(
                SlashingRewardPool::claim_reward(&env, event_id, &reporter),
                Err(ClaimError::AlreadyClaimed)
            );
        }

        // Invariant: the whole pool is distributed, exactly once.
        assert_eq!(total_claimed, initial_pool);
        assert_eq!(SlashingRewardPool::pool_remaining(&env, event_id), 0);
        assert_eq!(SlashingRewardPool::claimed_count(&env, event_id), 10);
    });
}

/// Each non-final claim debits exactly the fixed reward — the pool can never be
/// over-debited the way the stale-read race allowed (1000/5 = 200 per claim,
/// not 400 for a racing pair).
#[test]
fn fixed_reward_debits_pool_by_exact_share() {
    let env = Env::default();
    let contract_id = setup_contract(&env);

    env.as_contract(&contract_id, || {
        let event_id = 7u64;
        let initial_pool: i128 = 1000;
        let reporters = make_reporters(&env, 5);
        SlashingRewardPool::create_pool(&env, event_id, initial_pool, &reporters);

        assert_eq!(SlashingRewardPool::reward_per_validator(&env, event_id), 200);

        let mut remaining = initial_pool;
        for (i, reporter) in reporters.iter().enumerate() {
            let payout = SlashingRewardPool::claim_reward(&env, event_id, &reporter).unwrap();
            assert_eq!(payout, 200);
            remaining -= payout;
            assert_eq!(SlashingRewardPool::pool_remaining(&env, event_id), remaining);
            assert!(SlashingRewardPool::pool_remaining(&env, event_id) >= 0, "claim {i}");
        }
        assert_eq!(remaining, 0);
    });
}

/// An indivisible pool still sums to the initial amount: the last claimant
/// sweeps the remainder.
#[test]
fn indivisible_pool_remainder_goes_to_final_claimant() {
    let env = Env::default();
    let contract_id = setup_contract(&env);

    env.as_contract(&contract_id, || {
        let event_id = 9u64;
        let initial_pool: i128 = 1000; // 1000 / 3 = 333, remainder 1
        let reporters = make_reporters(&env, 3);
        SlashingRewardPool::create_pool(&env, event_id, initial_pool, &reporters);

        let payouts: Vec<i128> = {
            let mut p = Vec::new(&env);
            for reporter in reporters.iter() {
                p.push_back(SlashingRewardPool::claim_reward(&env, event_id, &reporter).unwrap());
            }
            p
        };

        assert_eq!(payouts.get(0).unwrap(), 333);
        assert_eq!(payouts.get(1).unwrap(), 333);
        assert_eq!(payouts.get(2).unwrap(), 334); // final claimant sweeps remainder
        assert_eq!(SlashingRewardPool::pool_remaining(&env, event_id), 0);
    });
}

/// Non-reporters cannot claim.
#[test]
fn non_reporter_cannot_claim() {
    let env = Env::default();
    let contract_id = setup_contract(&env);

    env.as_contract(&contract_id, || {
        let event_id = 3u64;
        let reporters = make_reporters(&env, 4);
        SlashingRewardPool::create_pool(&env, event_id, 1000, &reporters);

        let outsider = Address::generate(&env);
        assert_eq!(
            SlashingRewardPool::claim_reward(&env, event_id, &outsider),
            Err(ClaimError::NotAReporter)
        );
        assert_eq!(
            SlashingRewardPool::claim_reward(&env, 999, &reporters.get(0).unwrap()),
            Err(ClaimError::PoolNotFound)
        );
    });
}

/// Pool creation is idempotent — a second create for the same event is rejected.
#[test]
fn create_pool_is_idempotent() {
    let env = Env::default();
    let contract_id = setup_contract(&env);

    env.as_contract(&contract_id, || {
        let event_id = 5u64;
        let reporters = make_reporters(&env, 2);
        assert!(SlashingRewardPool::create_pool(&env, event_id, 1000, &reporters));
        assert!(!SlashingRewardPool::create_pool(&env, event_id, 1000, &reporters));
    });
}
