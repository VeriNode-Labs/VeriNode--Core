use soroban_sdk::testutils::Address as _;
use soroban_sdk::{contract, contractimpl, token, Address, Env};
use sorosusu_contracts::{SoroSusu, SoroSusuClient, DataKey, CollateralStatus, MemberStatus};

#[contract]
pub struct MockNft;

#[contractimpl]
impl MockNft {
    pub fn mint(_env: Env, _to: Address, _id: u128) {}
    pub fn burn(_env: Env, _from: Address, _id: u128) {}
}

#[test]
fn test_collateral_required_for_high_value_circles() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = Address::generate(&env);

    client.init(&admin);

    let high_amount = 2_000_000_0i128; // 2000 XLM
    let max_members = 5u32;
    let circle_id = client.create_circle(
        &creator,
        &high_amount,
        &max_members,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );

    let circle_key = DataKey::Circle(circle_id);
    let (requires_collateral, collateral_bps, total_cycle_value) =
        env.as_contract(&contract_id, || {
            let ci = env
                .storage()
                .instance()
                .get::<_, sorosusu_contracts::CircleInfo>(&circle_key)
                .unwrap();
            (ci.requires_collateral, ci.collateral_bps, ci.total_cycle_value)
        });
    assert!(requires_collateral);
    assert_eq!(collateral_bps, 2000); // 20%
    assert_eq!(total_cycle_value, high_amount * 5);
}

#[test]
fn test_collateral_not_required_for_low_value_circles() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = Address::generate(&env);

    client.init(&admin);

    let low_amount = 100_000_0i128; // 100 XLM
    let max_members = 5u32;
    let circle_id = client.create_circle(
        &creator,
        &low_amount,
        &max_members,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );

    let circle_key = DataKey::Circle(circle_id);
    let (requires_collateral, collateral_bps) = env.as_contract(&contract_id, || {
        let ci = env
            .storage()
            .instance()
            .get::<_, sorosusu_contracts::CircleInfo>(&circle_key)
            .unwrap();
        (ci.requires_collateral, ci.collateral_bps)
    });
    assert!(!requires_collateral);
    assert_eq!(collateral_bps, 0);
}

#[test]
fn test_stake_collateral() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let user = Address::generate(&env);
    let token_admin = Address::generate(&env);
    let nft_contract = Address::generate(&env);

    client.init(&admin);

    let token_id = env.register_stellar_asset_contract(token_admin.clone());
    let token_sac = token::StellarAssetClient::new(&env, &token_id);

    let high_amount = 2_000_000_0i128; // 2000 XLM
    let max_members = 5u32;
    let circle_id = client.create_circle(
        &creator,
        &high_amount,
        &max_members,
        &token_id,
        &86400u64,
        &100u32,
        &nft_contract,
    );

    let total_cycle_value = high_amount * max_members as i128;
    let required_collateral = (total_cycle_value * 2000) / 10000; // 20%

    token_sac.mint(&user, &required_collateral);
    client.stake_collateral(&user, &circle_id, &required_collateral);

    let collateral_key = DataKey::CollateralVault(user, circle_id);
    let (status, amount) = env.as_contract(&contract_id, || {
        let ci = env
            .storage()
            .instance()
            .get::<_, sorosusu_contracts::CollateralInfo>(&collateral_key)
            .unwrap();
        (ci.status, ci.amount)
    });
    assert_eq!(status, CollateralStatus::Staked);
    assert_eq!(amount, required_collateral);
}

#[test]
fn test_join_circle_requires_collateral() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let user = Address::generate(&env);
    let token_admin = Address::generate(&env);
    let nft_contract = Address::generate(&env);

    client.init(&admin);

    let token_id = env.register_stellar_asset_contract(token_admin.clone());
    let token_sac = token::StellarAssetClient::new(&env, &token_id);

    let high_amount = 2_000_000_0i128; // 2000 XLM
    let max_members = 5u32;
    let circle_id = client.create_circle(
        &creator,
        &high_amount,
        &max_members,
        &token_id,
        &86400u64,
        &100u32,
        &nft_contract,
    );

    // Try to join without staking collateral - should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.join_circle(&user, &circle_id, &1u32, &Option::<Address>::None);
    }));
    assert!(result.is_err());

    // Stake collateral and verify it succeeds
    let total_cycle_value = high_amount * max_members as i128;
    let required_collateral = (total_cycle_value * 2000) / 10000;
    token_sac.mint(&user, &required_collateral);
    client.stake_collateral(&user, &circle_id, &required_collateral);
}

#[test]
fn test_mark_member_defaulted_and_slash_collateral() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let user = Address::generate(&env);
    let token_admin = Address::generate(&env);
    let nft_contract = Address::generate(&env);

    client.init(&admin);

    let token_id = env.register_stellar_asset_contract(token_admin.clone());
    let token_sac = token::StellarAssetClient::new(&env, &token_id);

    let high_amount = 2_000_000_0i128; // 2000 XLM
    let max_members = 5u32;
    let circle_id = client.create_circle(
        &creator,
        &high_amount,
        &max_members,
        &token_id,
        &86400u64,
        &100u32,
        &nft_contract,
    );

    let total_cycle_value = high_amount * max_members as i128;
    let required_collateral = (total_cycle_value * 2000) / 10000;
    token_sac.mint(&user, &required_collateral);
    client.stake_collateral(&user, &circle_id, &required_collateral);

    // mark_member_defaulted requires Member in storage; inject it via as_contract
    let member_key = DataKey::Member(user.clone());
    env.as_contract(&contract_id, || {
        env.storage().instance().set(
            &member_key,
            &sorosusu_contracts::Member {
                address: user.clone(),
                index: 0,
                contribution_count: 0,
                last_contribution_time: env.ledger().timestamp(),
                status: MemberStatus::Active,
                tier_multiplier: 1,
                referrer: None,
                buddy: None,
            },
        );
    });

    client.mark_member_defaulted(&creator, &circle_id, &user);

    let member_key = DataKey::Member(user.clone());
    let collateral_key = DataKey::CollateralVault(user, circle_id);
    let (member_status, collateral_status, reserve) = env.as_contract(&contract_id, || {
        let mi = env
            .storage()
            .instance()
            .get::<_, sorosusu_contracts::Member>(&member_key)
            .unwrap();
        let ci = env
            .storage()
            .instance()
            .get::<_, sorosusu_contracts::CollateralInfo>(&collateral_key)
            .unwrap();
        let reserve: i128 = env
            .storage()
            .instance()
            .get(&DataKey::GroupReserve)
            .unwrap_or(0);
        (mi.status, ci.status, reserve)
    });
    assert_eq!(member_status, MemberStatus::Defaulted);
    assert_eq!(collateral_status, CollateralStatus::Slashed);
    assert_eq!(reserve, required_collateral);
}

#[test]
fn test_release_collateral_after_completion() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let user = Address::generate(&env);
    let token_admin = Address::generate(&env);
    let nft_contract = Address::generate(&env);

    client.init(&admin);

    let token_id = env.register_stellar_asset_contract(token_admin.clone());
    let token_sac = token::StellarAssetClient::new(&env, &token_id);

    let high_amount = 2_000_000_0i128; // 2000 XLM
    let max_members = 5u32;
    let circle_id = client.create_circle(
        &creator,
        &high_amount,
        &max_members,
        &token_id,
        &86400u64,
        &100u32,
        &nft_contract,
    );

    let total_cycle_value = high_amount * max_members as i128;
    let required_collateral = (total_cycle_value * 2000) / 10000;
    token_sac.mint(&user, &required_collateral);
    client.stake_collateral(&user, &circle_id, &required_collateral);

    // Simulate member completing all contributions via as_contract
    let member_key = DataKey::Member(user.clone());
    env.as_contract(&contract_id, || {
        env.storage().instance().set(
            &member_key,
            &sorosusu_contracts::Member {
                address: user.clone(),
                index: 0,
                contribution_count: max_members, // completed all contributions
                last_contribution_time: env.ledger().timestamp(),
                status: MemberStatus::Active,
                tier_multiplier: 1,
                referrer: None,
                buddy: None,
            },
        );
    });

    client.release_collateral(&user, &circle_id, &user);

    let collateral_key = DataKey::CollateralVault(user, circle_id);
    let (status, has_release_timestamp) = env.as_contract(&contract_id, || {
        let ci = env
            .storage()
            .instance()
            .get::<_, sorosusu_contracts::CollateralInfo>(&collateral_key)
            .unwrap();
        (ci.status, ci.release_timestamp.is_some())
    });
    assert_eq!(status, CollateralStatus::Released);
    assert!(has_release_timestamp);
}

#[test]
fn test_insufficient_collateral_amount() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let user = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = Address::generate(&env);

    client.init(&admin);

    let high_amount = 2_000_000_0i128; // 2000 XLM
    let max_members = 5u32;
    let circle_id = client.create_circle(
        &creator,
        &high_amount,
        &max_members,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );

    let total_cycle_value = high_amount * max_members as i128;
    let required_collateral = (total_cycle_value * 2000) / 10000;
    let insufficient_amount = required_collateral - 100_000_0i128; // Less than required

    // Contract panics before reaching token transfer, so no token setup needed
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.stake_collateral(&user, &circle_id, &insufficient_amount);
    }));
    assert!(result.is_err());
}

#[test]
fn test_double_collateral_staking() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let user = Address::generate(&env);
    let token_admin = Address::generate(&env);
    let nft_contract = Address::generate(&env);

    client.init(&admin);

    let token_id = env.register_stellar_asset_contract(token_admin.clone());
    let token_sac = token::StellarAssetClient::new(&env, &token_id);

    let high_amount = 2_000_000_0i128; // 2000 XLM
    let max_members = 5u32;
    let circle_id = client.create_circle(
        &creator,
        &high_amount,
        &max_members,
        &token_id,
        &86400u64,
        &100u32,
        &nft_contract,
    );

    let total_cycle_value = high_amount * max_members as i128;
    let required_collateral = (total_cycle_value * 2000) / 10000;

    // Mint enough for the first stake
    token_sac.mint(&user, &required_collateral);
    client.stake_collateral(&user, &circle_id, &required_collateral);

    // Try to stake again - should fail (contract rejects before any token call)
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.stake_collateral(&user, &circle_id, &required_collateral);
    }));
    assert!(result.is_err());
}
