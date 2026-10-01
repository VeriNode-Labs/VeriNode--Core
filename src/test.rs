#![cfg(test)]

use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Events as _},
    Address,
    BytesN,
    Env,
    TryIntoVal,
};

use crate::storage::{PersistentKey, TemporaryKey};
use crate::types::{SessionState, WorkflowProofRecord};
use crate::{VeriNodeContract, VeriNodeContractClient};

fn setup() -> (Env, Address, Address, BytesN<32>, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let node = Address::generate(&env);
    let node_pubkey = BytesN::from_array(&env, &[7u8; 32]);

    let contract_id = env.register(VeriNodeContract, ());

    (env, admin, node, node_pubkey, contract_id)
}

fn client<'a>(env: &'a Env, contract_id: &Address) -> VeriNodeContractClient<'a> {
    VeriNodeContractClient::new(env, contract_id)
}

#[test]
fn initialize_and_register_node() {
    let (env, admin, node, node_pubkey, contract_id) = setup();
    let client = client(&env, &contract_id);

    client.initialize(&admin);
    client.register_node(&node, &node_pubkey);

    let record = client.get_node(&node).expect("node should be present");
    assert_eq!(record.owner, node.clone());
    assert_eq!(record.public_key, node_pubkey);
    assert!(record.is_active);
    assert_eq!(record.registered_at, env.ledger().timestamp());

    assert!(client.get_node(&Address::generate(&env)).is_none());
}

#[test]
#[should_panic]
fn initialize_twice_rejects_already_initialized() {
    let (env, admin, _node, _pk, contract_id) = setup();
    let client = client(&env, &contract_id);

    client.initialize(&admin);
    client.initialize(&admin);
}

#[test]
#[should_panic]
fn register_node_before_initialize_rejects_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();

    let node = Address::generate(&env);
    let pk = BytesN::from_array(&env, &[3u8; 32]);

    let contract_id = env.register(VeriNodeContract, ());
    let client = client(&env, &contract_id);

    client.register_node(&node, &pk);
}

#[test]
fn open_telemetry_session_stores_temporary_state_and_extends_ttl() {
    let (env, _admin, node, _pk, contract_id) = setup();
    let client = client(&env, &contract_id);
    let session_id = BytesN::from_array(&env, &[9u8; 32]);

    client.open_telemetry_session(&node, &session_id, &10000u32);

    let state: SessionState = env
        .as_contract(&contract_id, || {
            env.storage()
                .temporary()
                .get(&TemporaryKey::TelemetrySession(session_id.clone()))
                .expect("session should be stored ephemerally")
        });
    assert_eq!(state.session_id, session_id);
    assert_eq!(state.total_packets, 0);

    client.open_telemetry_session(&node, &session_id, &50000u32);

    let refreshed: SessionState = env
        .as_contract(&contract_id, || {
            env.storage()
                .temporary()
                .get(&TemporaryKey::TelemetrySession(session_id.clone()))
                .expect("session remains present after TTL extension")
        });
    assert_eq!(refreshed.session_id, session_id);
}

#[test]
fn anchor_workflow_proof_promotes_to_persistent_storage_and_emits_event() {
    use soroban_sdk::testutils::Ledger as _;

    let (env, _admin, node, _pk, contract_id) = setup();
    let client = client(&env, &contract_id);
    let session_id = BytesN::from_array(&env, &[1u8; 32]);
    let proof_hash = BytesN::from_array(&env, &[2u8; 32]);

env.ledger().set_timestamp(1_700_000_000);
    client.open_telemetry_session(&node, &session_id, &100000u32);
    client.anchor_workflow_proof(&node, &proof_hash, &session_id);

    let event = env.events().all().pop_front().expect("event emitted");
    let topics = event.1;
    assert_eq!(topics.len(), 2);
    let topic_symbol: soroban_sdk::Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
    assert_eq!(topic_symbol, symbol_short!("proof"));
    let actor: Address = topics.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(actor, node.clone());

    let (emitted_hash, emitted_ts): (BytesN<32>, u64) = event.2.try_into_val(&env).unwrap();
    assert_eq!(emitted_hash, proof_hash);
    assert_eq!(emitted_ts, 1_700_000_000);

    let record: WorkflowProofRecord = client.get_proof(&proof_hash).expect("proof anchored");
    assert_eq!(record.proof_hash, proof_hash);
    assert_eq!(record.actor, node.clone());
    assert_eq!(record.timestamp, 1_700_000_000);
    assert!(!record.settled);

    let session: Option<SessionState> = env.as_contract(&contract_id, || {
        env.storage()
            .temporary()
            .get(&TemporaryKey::TelemetrySession(session_id.clone()))
    });
    assert!(session.is_none(), "ephemeral session should be consumed");
}

#[test]
#[should_panic]
fn open_telemetry_session_requires_node_auth() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let node = Address::generate(&env);
    let session_id = BytesN::from_array(&env, &[5u8; 32]);

    let contract_id = env.register(VeriNodeContract, ());
    let client = client(&env, &contract_id);

    env.as_contract(&contract_id, || {
        env.storage().persistent().set(&PersistentKey::Admin, &admin);
    });

    client.open_telemetry_session(&node, &session_id, &1000u32);
}

#[test]
#[should_panic]
fn register_node_requires_admin_auth() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let node = Address::generate(&env);
    let node_pubkey = BytesN::from_array(&env, &[3u8; 32]);

    let contract_id = env.register(VeriNodeContract, ());
    let client = client(&env, &contract_id);

    env.as_contract(&contract_id, || {
        env.storage().persistent().set(&PersistentKey::Admin, &admin);
    });

    client.register_node(&node, &node_pubkey);
}

#[test]
#[should_panic]
fn anchor_workflow_proof_rejects_unknown_session() {
    let (env, _admin, node, _pk, contract_id) = setup();
    let client = client(&env, &contract_id);
    let session_id = BytesN::from_array(&env, &[4u8; 32]);
    let proof_hash = BytesN::from_array(&env, &[5u8; 32]);

    client.anchor_workflow_proof(&node, &proof_hash, &session_id);
}

#[test]
#[should_panic]
fn anchor_workflow_proof_rejects_expired_session() {
    use soroban_sdk::testutils::Ledger as _;

    let (env, _admin, node, _pk, contract_id) = setup();
    let client = client(&env, &contract_id);
    let session_id = BytesN::from_array(&env, &[6u8; 32]);
    let proof_hash = BytesN::from_array(&env, &[7u8; 32]);

    env.ledger().set_timestamp(1_000_000);
    client.open_telemetry_session(&node, &session_id, &0u32);

    env.ledger().set_timestamp(1_000_100);
    client.anchor_workflow_proof(&node, &proof_hash, &session_id);
}