use soroban_sdk::{contracterror, contracttype, Address, BytesN, String};

/// Persistent instance storage keys used by the Lumina contracts.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    /// Protocol admin address (single-time initialization).
    Admin,
    /// Monotonic counter of registered assets (next `asset_id`).
    AssetCount,
    /// Crystallized IP registration record, keyed by `asset_id`.
    Asset(u64),
    /// Milestone escrow record, keyed by `escrow_id`.
    Escrow(u64),
    /// Monotonic counter of created escrows (next `escrow_id`).
    EscrowCount,
}

/// On-chain record of a hash-anchored intellectual property timestamp.
///
/// `fingerprint` is the SHA-256/Keccak digest of the work itself, so the
/// creator can later prove existence and possession of the work without
/// revealing it. `metadata_uri` points to an IPFS payload carrying the ODRL
/// license expression and sanitized asset metadata.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetRecord {
    /// Monotonic asset identifier assigned at registration time.
    pub asset_id: u64,
    /// Address of the author/provenance owner who registered the work.
    pub creator: Address,
    /// Hash of the work used as the cryptographic anchor.
    pub fingerprint: BytesN<32>,
    /// IPFS URI of the ODRL license and sanitized metadata.
    pub metadata_uri: String,
    /// Fee in stroops demanded for a license grant.
    pub licensing_fee: i128,
    /// Ledger timestamp captured when the asset was registered.
    pub registered_at: u64,
    /// False once the asset is removed/lapsed; new registrations default true.
    pub is_active: bool,
}

/// Autonomous milestone escrow between a funding `client` and a `creator`.
///
/// Funds are locked in contract custody as an internal balance recorded by
/// `remaining_balance`; each authorized milestone release decrements the
/// balance, increments the completion counter, and records a payout to the
/// `creator`. The escrow is settled once the final milestone is completed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowRecord {
    /// Monotonic escrow identifier.
    pub escrow_id: u64,
    /// Funding party; the only address authorized to release milestones.
    pub client: Address,
    /// Creative counterparty that receives milestone payouts.
    pub creator: Address,
    /// Total amount locked into the escrow at creation.
    pub total_amount: i128,
    /// Outstanding balance not yet released.
    pub remaining_balance: i128,
    /// Total number of milestones the escrow tracks.
    pub total_milestones: u32,
    /// Number of milestones released so far.
    pub completed_milestones: u32,
    /// True once every milestone has been released.
    pub is_settled: bool,
}

/// Protocol-level error codes surfaced to callers.
#[contracterror]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    /// `initialize` was called more than once.
    AlreadyInitialized = 1,
    /// A precondition depends on an un-initialized protocol.
    NotInitialized = 2,
    /// The caller/authorizing address is not permitted for the operation.
    Unauthorized = 3,
    /// No asset exists for the given `asset_id`.
    AssetNotFound = 4,
    /// No escrow exists for the given `escrow_id`.
    EscrowNotFound = 5,
    /// Payout exceeds the escrow's remaining balance.
    InsufficientFunds = 6,
    /// Every milestone has already been completed.
    AllMilestonesCompleted = 7,
    /// The escrow has already been fully settled.
    EscrowAlreadySettled = 8,
}
