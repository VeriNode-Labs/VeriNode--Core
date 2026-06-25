pub mod monitor;
pub mod executor;
pub mod event_store;
pub mod pool;

#[cfg(test)]
pub mod tests;

use soroban_sdk::{contracttype, Address, Vec};

// --- CONSTANTS ---

/// Scan interval: 6 hours in seconds
pub const SCAN_INTERVAL_SECONDS: u64 = 21600;

/// Maximum bond per node (in tokens)
pub const NODE_BOND_AMOUNT: i128 = 1000;

/// Slashing penalty amount (full bond)
pub const SLASHING_PENALTY: i128 = 1000;

// --- SLASHING TYPES ---

/// Reasons a node can be slashed
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SlashingReason {
    DoubleSigning,
    ExtendedDowntime,
    FraudProof,
}

/// Status of a slashing event
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SlashingEventStatus {
    Pending,
    Executed,
    Rejected,
    Failed,
}

/// A single slashing event that consolidates ALL triggered conditions for a
/// node within a single scan epoch. This is the core fix: only ONE event per
/// node per scan, with a `reasons` vector listing all triggered conditions.
#[contracttype]
#[derive(Clone)]
pub struct SlashingEvent {
    pub node_id: Address,
    pub scan_epoch: u64,
    pub reasons: Vec<SlashingReason>,
    pub penalty_amount: i128,
    pub created_at: u64,
    pub status: SlashingEventStatus,
}

/// Node state tracked by the slashing monitor
#[contracttype]
#[derive(Clone)]
pub struct NodeState {
    pub node_id: Address,
    pub is_active: bool,
    pub bond_amount: i128,
    pub slashed: bool,
    pub last_slash_time: Option<u64>,
    pub last_activity_time: u64,
    pub double_sign_detected: bool,
    pub fraud_proof_submitted: bool,
    pub slashing_in_progress: bool,
}

/// Storage keys for the slashing module
#[contracttype]
#[derive(Clone)]
pub enum SlashingDataKey {
    /// Node state: SlashingDataKey::Node(node_id)
    Node(Address),
    /// Slashing event: SlashingDataKey::Event(node_id, scan_epoch)
    Event(Address, u64),
    /// Current scan epoch counter
    ScanEpoch,
    /// Last scan timestamp
    LastScanTime,
    /// Bond pool balance for a node
    BondPool(Address),
    /// Slashing-in-progress flag: prevents duplicate processing
    SlashingLock(Address),

    // --- Reward pool keys (see `pool.rs`) ---
    /// Remaining reward balance for a slashing event: `slashing:{event_id}:pool`
    RewardPool(u64),
    /// Immutable per-validator reward, fixed at pool creation
    RewardPerValidator(u64),
    /// Number of registered reporters for the event
    PoolReporterCount(u64),
    /// Number of reporters that have already claimed: `slashing:{event_id}:claimed_count`
    PoolClaimedCount(u64),
    /// Membership marker: this address is a registered reporter for the event
    PoolReporter(u64, Address),
    /// Per-claimant marker: this address has already claimed for the event
    PoolClaimed(u64, Address),
}
