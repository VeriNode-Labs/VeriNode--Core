use soroban_sdk::{contracterror, contracttype, Address, BytesN};

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeRecord {
    pub owner: Address,
    pub public_key: BytesN<32>,
    pub registered_at: u64,
    pub is_active: bool,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowProofRecord {
    pub proof_hash: BytesN<32>,
    pub actor: Address,
    pub timestamp: u64,
    pub settled: bool,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionState {
    pub session_id: BytesN<32>,
    pub total_packets: u32,
    pub last_checksum: BytesN<32>,
    pub expires_at: u64,
}

#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ContractError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    NodeNotFound = 4,
    SessionExpired = 5,
    InvalidProof = 6,
}