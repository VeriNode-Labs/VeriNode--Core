//! Landlord-Tenant Susu Escrow Integration tests (#105).
//!
//! Verifies the inter-contract hook that lets a tenant who wins the pot
//! authorise SoroSusu to redirect their payout directly to a
//! LeaseInstance contract address ("Automated Rent-Drip"), and that the
//! redirect is opt-in / cancellable / non-default.

use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Ledger as _},
    token, Address, Env,
};
use sorosusu_contracts::{LeasePayoutConfig, SoroSusu, SoroSusuClient};

#[contract]
pub struct MockNft;

#[contractimpl]
impl MockNft {
    pub fn mint(_env: Env, _to: Address, _id: u128) {}
    pub fn burn(_env: Env, _from: Address, _id: u128) {}
}

/// Smallest viable circle: creator joins their own 1-member circle, deposits,
/// finalises, time travels past the payout window, and is ready to claim.
///
/// Returns `(client, tenant, lease_contract_addr, token, token_client, circle_id, pot_amount)`.
fn setup_payable_pot<'a>(env: &'a Env) -> (
    SoroSusuClient<'a>,
    Address,
    Address,
    Address,
    token::StellarAssetClient<'a>,
    u64,
    i128,
) {
    env.mock_all_auths();

    let admin = Address::generate(env);
    let tenant = Address::generate(env);
    let lease_contract_addr = Address::generate(env);

    let token_admin = Address::generate(env);
    let token = env.register_stellar_asset_contract(token_admin.clone());
    let token_client = token::StellarAssetClient::new(env, &token);
    let nft_contract = env.register_contract(None, MockNft);

    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(env, &contract_id);
    client.init(&admin);

    // Small contribution + 1-member circle so we stay under the
    // HIGH_VALUE_THRESHOLD and avoid the collateral requirement.
    let circle_id = client.create_circle(
        &tenant, // creator == tenant; finalize_round currently sets pot recipient = creator
        &100,
        &1,
        &token,
        &604_800,
        &0,
        &nft_contract,
    );

    client.join_circle(&tenant, &circle_id, &1, &None);

    // Mint plenty so deposit + downstream redirect both succeed,
    // and seed the contract with the pot balance so claim_pot can transfer.
    token_client.mint(&tenant, &10_000);
    token_client.mint(&contract_id, &10_000);

    client.deposit(&tenant, &circle_id);
    client.finalize_round(&tenant, &circle_id);

    // Jump past the scheduled payout window (finalize_round adds 1h).
    env.ledger().with_mut(|li| {
        li.timestamp += 3700;
    });

    let pot_amount = 100i128 * 1i128; // contribution_amount * member_count
    (
        client,
        tenant,
        lease_contract_addr,
        token,
        token_client,
        circle_id,
        pot_amount,
    )
}

#[test]
fn claim_pot_defaults_to_tenant_when_no_lease_payout_registered() {
    let env = Env::default();
    let (client, tenant, lease_contract_addr, token, _token_client, circle_id, pot_amount) =
        setup_payable_pot(&env);

    let token_read = token::Client::new(&env, &token);
    let tenant_balance_before = token_read.balance(&tenant);
    let lease_balance_before = token_read.balance(&lease_contract_addr);

    client.claim_pot(&tenant, &circle_id);

    assert_eq!(
        token_read.balance(&tenant) - tenant_balance_before,
        pot_amount,
        "default path: full pot lands in the tenant's address"
    );
    assert_eq!(
        token_read.balance(&lease_contract_addr) - lease_balance_before,
        0,
        "default path: no funds touch the lease contract"
    );
}

#[test]
fn claim_pot_redirects_to_lease_contract_when_registered() {
    let env = Env::default();
    let (client, tenant, lease_contract_addr, token, _token_client, circle_id, pot_amount) =
        setup_payable_pot(&env);

    client.register_lease_payout(&tenant, &circle_id, &lease_contract_addr);

    let cfg = client
        .get_lease_payout(&tenant, &circle_id)
        .expect("registered config should be readable");
    assert_eq!(cfg.tenant, tenant);
    assert_eq!(cfg.circle_id, circle_id);
    assert_eq!(cfg.lease_contract, lease_contract_addr);

    let token_read = token::Client::new(&env, &token);
    let tenant_balance_before = token_read.balance(&tenant);
    let lease_balance_before = token_read.balance(&lease_contract_addr);

    client.claim_pot(&tenant, &circle_id);

    assert_eq!(
        token_read.balance(&lease_contract_addr) - lease_balance_before,
        pot_amount,
        "redirect path: pot lands in the lease contract address"
    );
    assert_eq!(
        token_read.balance(&tenant) - tenant_balance_before,
        0,
        "redirect path: tenant never receives the pot funds"
    );
}

#[test]
fn cancel_lease_payout_restores_default_tenant_payout() {
    let env = Env::default();
    let (client, tenant, lease_contract_addr, token, _token_client, circle_id, pot_amount) =
        setup_payable_pot(&env);

    client.register_lease_payout(&tenant, &circle_id, &lease_contract_addr);
    client.cancel_lease_payout(&tenant, &circle_id);

    let config_after_cancel: Option<LeasePayoutConfig> =
        client.get_lease_payout(&tenant, &circle_id);
    assert!(
        config_after_cancel.is_none(),
        "cancellation must clear the stored config"
    );

    let token_read = token::Client::new(&env, &token);
    let tenant_balance_before = token_read.balance(&tenant);
    let lease_balance_before = token_read.balance(&lease_contract_addr);

    client.claim_pot(&tenant, &circle_id);

    assert_eq!(
        token_read.balance(&tenant) - tenant_balance_before,
        pot_amount,
        "after cancel: pot reverts to the tenant"
    );
    assert_eq!(
        token_read.balance(&lease_contract_addr) - lease_balance_before,
        0
    );
}

#[test]
#[should_panic(expected = "Lease payout already registered")]
fn duplicate_register_lease_payout_panics() {
    let env = Env::default();
    let (client, tenant, lease_contract_addr, _token, _token_client, circle_id, _pot) =
        setup_payable_pot(&env);

    client.register_lease_payout(&tenant, &circle_id, &lease_contract_addr);
    // A second registration without cancel should fail to make the user's
    // active rent-drip target explicit.
    client.register_lease_payout(&tenant, &circle_id, &lease_contract_addr);
}

#[test]
#[should_panic(expected = "Lease payout not registered")]
fn cancel_without_registration_panics() {
    let env = Env::default();
    let (client, tenant, _lease, _token, _token_client, circle_id, _pot) =
        setup_payable_pot(&env);

    client.cancel_lease_payout(&tenant, &circle_id);
}

#[test]
fn get_lease_payout_returns_none_when_not_registered() {
    let env = Env::default();
    let (client, tenant, _lease, _token, _token_client, circle_id, _pot) =
        setup_payable_pot(&env);
    assert!(client.get_lease_payout(&tenant, &circle_id).is_none());
}
