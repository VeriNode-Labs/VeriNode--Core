//! Batch bond-settlement via Merkle-proof commit-reveal (issue #57).
//!
//! # Why this exists
//!
//! A settler needs to slash many nodes' bonds in one call, proving each
//! slash against a Merkle root rather than writing every `(node, amount)`
//! pair to calldata/storage individually. Submitting `(root, proofs)`
//! directly and executing in the same call would let anyone watching the
//! pending submission copy it and race to submit first — see
//! [`pool_manager`] module docs for the concrete grief this enables and why
//! commit-reveal closes it.
//!
//! # Why self-contained
//!
//! This does not extend `crate::SoroSusu` (a ROSCA contract with no bond or
//! Merkle-batch concept) or wrap `crate::slashing_core::slashing`'s
//! `Monitor`/`Executor`/`EventStore` pipeline (built around a periodic scan
//! producing one `SlashingEvent` per node per epoch — a different trigger
//! model than an externally-supplied batch proof). It *does* share
//! `slashing_core::slashing::SlashingDataKey::BondPool`, the underlying bond
//! balance ledger, so the two subsystems can never disagree about how much
//! bond a node has left — see [`pool_manager::PoolManager::reveal_settlement`].
//!
//! # Timing model: seconds, not block/ledger count
//!
//! The issue specifies a 2-10 *block* reveal delay. Every existing
//! time-bound invariant in this codebase (`RATE_LIMIT_SECONDS`,
//! `VOTING_PERIOD`, `SCAN_INTERVAL_SECONDS`, the 48-hour downtime threshold
//! in `slashing_core::slashing::monitor`) is a wall-clock
//! `env.ledger().timestamp()` delta; `env.ledger().sequence()` (Soroban's
//! ledger-count analogue of a block number) is not used anywhere in this
//! codebase. [`pool_manager::MIN_REVEAL_DELAY_SECONDS`] and
//! [`pool_manager::MAX_REVEAL_DELAY_SECONDS`] follow that precedent instead
//! of introducing block-count timing as a one-off. See the module docs on
//! those constants for how the "2-10 blocks" figure was converted to
//! seconds, and why that conversion is only approximate.

pub mod merkle;
pub mod pool_manager;

#[cfg(test)]
pub mod tests;

use soroban_sdk::{contracttype, Address, BytesN, Vec};

/// Merkle tree depth bound: rejects proofs longer than this, capping the
/// tree at 2^20 = 1,048,576 leaves and bounding per-leaf verification cost.
/// Enforced in [`merkle::verify_proof`].
pub const MAX_PROOF_DEPTH: u32 = 20;

/// Maximum leaves settled per batch. Enforced on both
/// [`pool_manager::PoolManager::commit_settlement`] (rejects an oversized
/// `leaf_count` before anything is stored) and
/// [`pool_manager::PoolManager::reveal_settlement`] (the revealed leaf count
/// must equal what was committed, so it's implicitly bounded too).
///
/// 32, not the issue's literal 256: chosen empirically, not from the issue
/// text, because Soroban meters CPU instructions and memory per transaction
/// rather than EVM gas per block, and a full 256-leaf reveal measured
/// ~1.79B CPU instructions — about 18x the SDK's default 100M-instruction
/// envelope (`env.budget().reset_default()`), driven by 256 sequential
/// `instance()` storage writes in the bond-debit loop (see
/// [`pool_manager::PoolManager::reveal_settlement`]) on top of proof
/// verification itself. 32 is the largest power-of-two batch size (so the
/// worst case — a full, exactly-at-cap batch — is also the deepest proof
/// tree this cap allows, at depth 5) whose full reveal measures
/// comfortably under that envelope: ~34% of the CPU budget and ~4% of the
/// memory budget in `pool_manager::tests`' benchmark. The next power-of-two
/// tier up (64, depth 6) already exceeds the CPU budget by ~22%, so there
/// is no gentler intermediate step available while proof depth stays fixed
/// at a whole tree level — see the `reveal_settlement_full_batch_fits_default_resource_limits`
/// benchmark test for the measured numbers behind this choice.
pub const MAX_BATCH_SIZE: u32 = 32;

/// One leaf of a settlement batch: the node being slashed, the amount, its
/// position in the tree, and its own sibling path. Bundling the proof and
/// index into the leaf (rather than three parallel `Vec`s) means a
/// length-mismatch between "leaves" and "their proofs" is not a state that
/// can be constructed at all.
#[contracttype]
#[derive(Clone)]
pub struct SettlementLeaf {
    pub node_id: Address,
    pub penalty_amount: i128,
    pub index: u32,
    pub proof: Vec<BytesN<32>>,
}

/// A commit-phase record. Deliberately does **not** store `root` or `salt`
/// in the clear — only the opaque [`Commitment::hash`] — so a batch's
/// contents stay hidden for the life of the commitment, not just until the
/// next block. See [`pool_manager`] module docs for the full binding
/// rationale.
#[contracttype]
#[derive(Clone)]
pub struct Commitment {
    /// The address that committed this batch. Bound into `hash` and
    /// re-checked (via `require_auth`) on reveal, so a batch committed by
    /// one party cannot be revealed — or its outcome claimed — by another.
    pub settler: Address,
    /// Leaf count committed to. Bound into `hash` and re-checked against
    /// the revealed leaf count, so a reveal cannot smuggle in a
    /// different-sized batch than was committed.
    pub leaf_count: u32,
    /// `sha256(batch_id || sha256(settler_xdr) || root || leaf_count ||
    /// salt)`. See [`pool_manager::compute_commitment_hash`] for why every
    /// field is fixed-width before hashing (the Rust-appropriate analogue of
    /// avoiding `abi.encodePacked`'s dynamic-array collision hazard).
    pub hash: BytesN<32>,
    /// Ledger timestamp at commit; the reveal window is measured from this.
    pub committed_at: u64,
    /// Set `true` once revealed. Blocks both replay of this batch and
    /// re-commit under the same `batch_id` forever — see
    /// [`pool_manager::PoolManager::commit_settlement`] docs on why re-commit
    /// is otherwise allowed for an expired-but-never-revealed batch.
    pub settled: bool,
}

/// Storage keys for this module.
#[contracttype]
#[derive(Clone)]
pub enum SettlementDataKey {
    /// The single address authorized to commit and reveal batch
    /// settlements. Set once via
    /// [`pool_manager::PoolManager::init_settler`] (idempotent, mirrors
    /// `crate::DataKey::Admin`). There is no rotation function: the settler
    /// is fixed for the module's lifetime, and operational key rotation is
    /// out of scope for this issue.
    Settler,
    /// Monotonically increasing counter; the source of every `batch_id`.
    /// Never caller-supplied, so no `batch_id` can be squatted or
    /// grief-committed ahead of the legitimate settler — every commit gets
    /// an unused, freshly incremented id.
    NextBatchId,
    /// A commitment, keyed by its `batch_id`.
    Commitment(u64),
}

/// Errors returned by [`pool_manager::PoolManager`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementError {
    /// `leaf_count` was 0 or exceeded [`MAX_BATCH_SIZE`].
    InvalidBatchSize,
    /// A leaf's `penalty_amount` was negative.
    InvalidPenaltyAmount,
    /// No commitment exists for this `batch_id`.
    CommitmentNotFound,
    /// This `batch_id` has already been revealed and settled.
    AlreadySettled,
    /// `caller` does not match the address that committed this batch.
    Unauthorized,
    /// Reveal attempted before `MIN_REVEAL_DELAY_SECONDS` elapsed.
    RevealTooEarly,
    /// Reveal attempted after `MAX_REVEAL_DELAY_SECONDS` elapsed. The
    /// commitment is now permanently unrevealable (see
    /// `PoolManager::commit_settlement` docs on re-commit behavior).
    RevealWindowExpired,
    /// The revealed `(batch_id, settler, root, leaf_count, salt)` does not
    /// hash to the stored commitment.
    CommitmentMismatch,
    /// The revealed leaf count did not match the committed `leaf_count`.
    LeafCountMismatch,
    /// A Merkle proof was longer than [`MAX_PROOF_DEPTH`].
    ProofTooDeep,
    /// A Merkle proof did not verify against the revealed root.
    InvalidProof,
}
