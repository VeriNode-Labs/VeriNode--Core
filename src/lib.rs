#![no_std]

use soroban_sdk::{contract, contractimpl, symbol_short, Address, BytesN, Env};

use storage::{PersistentKey, TemporaryKey};
use types::{ContractError, NodeRecord, SessionState, WorkflowProofRecord};

pub mod storage;
pub mod types;

mod test;

#[contract]
pub struct VeriNodeContract;

#[contractimpl]
impl VeriNodeContract {
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        admin.require_auth();
        if env.storage().persistent().has(&PersistentKey::Admin) {
            return Err(ContractError::AlreadyInitialized);
        }
        env.storage().persistent().set(&PersistentKey::Admin, &admin);
        Ok(())
    }

    pub fn register_node(
        env: Env,
        node_address: Address,
        node_pubkey: BytesN<32>,
    ) -> Result<(), ContractError> {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&PersistentKey::Admin)
            .ok_or(ContractError::NotInitialized)?;
        admin.require_auth();

        let record = NodeRecord {
            owner: node_address.clone(),
            public_key: node_pubkey,
            registered_at: env.ledger().timestamp(),
            is_active: true,
        };
        env.storage()
            .persistent()
            .set(&PersistentKey::NodeRegistry(node_address), &record);
        Ok(())
    }

    pub fn open_telemetry_session(
        env: Env,
        node: Address,
        session_id: BytesN<32>,
        ttl_ledgers: u32,
    ) -> Result<(), ContractError> {
        node.require_auth();

        let key = TemporaryKey::TelemetrySession(session_id.clone());
        let expires_at = env.ledger().timestamp().saturating_add(ttl_ledgers as u64);

        let state = match env
            .storage()
            .temporary()
            .get::<TemporaryKey, SessionState>(&key)
        {
            Some(mut existing) => {
                existing.total_packets = 0;
                existing.expires_at = expires_at;
                existing
            }
            None => SessionState {
                session_id: session_id.clone(),
                total_packets: 0,
                last_checksum: BytesN::from_array(&env, &[0u8; 32]),
                expires_at,
            },
        };

        env.storage().temporary().set(&key, &state);
        env.storage().temporary().extend_ttl(&key, ttl_ledgers, ttl_ledgers);

        Ok(())
    }

    pub fn anchor_workflow_proof(
        env: Env,
        node: Address,
        proof_hash: BytesN<32>,
        session_id: BytesN<32>,
    ) -> Result<(), ContractError> {
        node.require_auth();

        let key = TemporaryKey::TelemetrySession(session_id.clone());
        let state: SessionState = env
            .storage()
            .temporary()
            .get(&key)
            .ok_or(ContractError::InvalidProof)?;

        if state.expires_at < env.ledger().timestamp() {
            return Err(ContractError::SessionExpired);
        }

        if env
            .storage()
            .persistent()
            .get::<PersistentKey, WorkflowProofRecord>(&PersistentKey::WorkflowProof(proof_hash.clone()))
            .is_some()
        {
            return Err(ContractError::InvalidProof);
        }

        let timestamp = env.ledger().timestamp();
        let record = WorkflowProofRecord {
            proof_hash: proof_hash.clone(),
            actor: node.clone(),
            timestamp,
            settled: false,
        };
        env.storage()
            .persistent()
            .set(&PersistentKey::WorkflowProof(proof_hash.clone()), &record);

        env.events()
            .publish((symbol_short!("proof"), node.clone()), (proof_hash.clone(), timestamp));

        env.storage().temporary().remove(&key);

        Ok(())
    }

    pub fn get_proof(env: Env, proof_hash: BytesN<32>) -> Option<WorkflowProofRecord> {
        env.storage()
            .persistent()
            .get(&PersistentKey::WorkflowProof(proof_hash))
    }

    pub fn get_node(env: Env, node_address: Address) -> Option<NodeRecord> {
        env.storage()
            .persistent()
            .get(&PersistentKey::NodeRegistry(node_address))
    }
}