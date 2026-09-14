#![cfg(test)]

use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{
    symbol_short, Address, BytesN, Env, IntoVal, String, Symbol, TryIntoVal, Val, Vec,
};

use crate::types::ContractError;
use crate::{LuminaContract, LuminaContractClient};

const ANCHOR_TS: u64 = 1_700_000_000;

struct Ctx {
    env: Env,
    contract_id: Address,
    client: LuminaContractClient<'static>,
    creator: Address,
    client_addr: Address,
}

fn fingerprint(env: &Env, seed: u8) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[31] = seed;
    BytesN::from_array(env, &bytes)
}

fn setup() -> Ctx {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(ANCHOR_TS);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let client_addr = Address::generate(&env);

    let contract_id = env.register(LuminaContract, ());
    let client = LuminaContractClient::new(&env, &contract_id);
    client.initialize(&admin);

    Ctx {
        env,
        contract_id,
        client,
        creator,
        client_addr,
    }
}

#[test]
fn test_asset_registration_and_hash_anchoring() {
    let ctx = setup();
    let fp = fingerprint(&ctx.env, 7);
    let uri = String::from_str(&ctx.env, "ipfs://bafybeig/odrl-license.json");
    let fee: i128 = 250;

    let asset_id = ctx.client.register_asset(&ctx.creator, &fp, &uri, &fee);
    assert_eq!(asset_id, 0);

    // The ip_anchor event (from the last invocation) carries the exact
    // fingerprint + timestamp and creator attribution.
    let events = ctx.env.events().all();
    assert_eq!(events.len(), 1, "expected exactly one ip_anchor event");
    let (contract_id, topics, data) = events.get(0).unwrap();
    assert_eq!(contract_id, ctx.contract_id);
    let topic: Symbol = topics.get(0).unwrap().try_into_val(&ctx.env).unwrap();
    assert_eq!(topic, symbol_short!("ip_anchor"));
    let topic_creator: Address = topics.get(1).unwrap().try_into_val(&ctx.env).unwrap();
    assert_eq!(topic_creator, ctx.creator);
    let payload: Vec<Val> = data.try_into_val(&ctx.env).expect("event payload");
    let e_id: u64 = payload.get(0).unwrap().try_into_val(&ctx.env).unwrap();
    let e_fp: BytesN<32> = payload.get(1).unwrap().try_into_val(&ctx.env).unwrap();
    let e_ts: u64 = payload.get(2).unwrap().try_into_val(&ctx.env).unwrap();
    assert_eq!(e_id, asset_id);
    assert_eq!(e_fp, fp);
    assert_eq!(e_ts, ANCHOR_TS);

    // Monotonic counter: a second asset advances the id.
    let second_id = ctx
        .client
        .register_asset(&ctx.creator, &fingerprint(&ctx.env, 9), &uri, &fee);
    assert_eq!(second_id, 1);

    let asset = ctx.client.get_asset(&asset_id);
    assert_eq!(asset.asset_id, asset_id);
    assert_eq!(asset.creator, ctx.creator);
    assert_eq!(asset.fingerprint, fp);
    assert_eq!(asset.metadata_uri, uri);
    assert_eq!(asset.licensing_fee, fee);
    assert!(asset.is_active);
    assert_eq!(asset.registered_at, ANCHOR_TS);
    assert_eq!(asset.registered_at, ctx.env.ledger().timestamp());
}

#[test]
fn test_escrow_milestone_settlement() {
    let ctx = setup();
    let total: i128 = 1_000;
    let milestones: u32 = 4;

    let escrow_id = ctx
        .client
        .create_escrow(&ctx.client_addr, &ctx.creator, &total, &milestones);
    assert_eq!(escrow_id, 0);

    let escrow = ctx.client.get_escrow(&escrow_id);
    assert_eq!(escrow.escrow_id, 0);
    assert_eq!(escrow.client, ctx.client_addr);
    assert_eq!(escrow.creator, ctx.creator);
    assert_eq!(escrow.total_amount, total);
    assert_eq!(escrow.remaining_balance, total);
    assert_eq!(escrow.total_milestones, milestones);
    assert_eq!(escrow.completed_milestones, 0);
    assert!(!escrow.is_settled);

    ctx.client.release_milestone(&escrow_id, &250);
    let escrow = ctx.client.get_escrow(&escrow_id);
    assert_eq!(escrow.remaining_balance, 750);
    assert_eq!(escrow.completed_milestones, 1);
    assert!(!escrow.is_settled);

    // Payout exceeding the remaining balance must be rejected.
    let res = ctx.client.try_release_milestone(&escrow_id, &999);
    assert_eq!(res, Err(Ok(ContractError::InsufficientFunds)));

    ctx.client.release_milestone(&escrow_id, &250);
    ctx.client.release_milestone(&escrow_id, &250);
    ctx.client.release_milestone(&escrow_id, &250);
    let escrow = ctx.client.get_escrow(&escrow_id);
    assert_eq!(escrow.remaining_balance, 0);
    assert_eq!(escrow.completed_milestones, 4);
    assert!(escrow.is_settled);

    // Once settled the escrow rejects further releases.
    let res = ctx.client.try_release_milestone(&escrow_id, &10);
    assert_eq!(res, Err(Ok(ContractError::EscrowAlreadySettled)));

    // A second escrow is issued a fresh monotonic id.
    let second = ctx
        .client
        .create_escrow(&ctx.client_addr, &ctx.creator, &total, &milestones);
    assert_eq!(second, 1);
}

#[test]
fn test_unauthorized_milestone_release() {
    let env = Env::default();
    env.ledger().set_timestamp(ANCHOR_TS);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let client_addr = Address::generate(&env);
    let stranger = Address::generate(&env);

    let contract_id = env.register(LuminaContract, ());
    let client = LuminaContractClient::new(&env, &contract_id);
    client.initialize(&admin);

    let total: i128 = 100;
    let milestones: u32 = 2;

    // Only `client_addr` is authorized for the escrow creation invocation.
    env.mock_auths(&[MockAuth {
        address: &client_addr,
        invoke: &MockAuthInvoke {
            contract: &contract_id,
            fn_name: "create_escrow",
            args: (&client_addr, &creator, &total, &milestones).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    let escrow_id = client.create_escrow(&client_addr, &creator, &total, &milestones);

    // `stranger` is not the escrow client: `client.require_auth()` must reject.
    env.mock_auths(&[MockAuth {
        address: &stranger,
        invoke: &MockAuthInvoke {
            contract: &contract_id,
            fn_name: "release_milestone",
            args: (&escrow_id, &25_i128).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    let res = client.try_release_milestone(&escrow_id, &25);
    assert!(res.is_err());
}
