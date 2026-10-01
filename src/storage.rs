use soroban_sdk::{contracttype, Address, BytesN};

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PersistentKey {
    Admin,
    WorkflowProof(BytesN<32>),
    NodeRegistry(Address),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TemporaryKey {
    TelemetrySession(BytesN<32>),
}