//! Two-phase batch settlement: `commit_settlement` then `reveal_settlement`.
//!
//! # The attack this closes
//!
//! A single-call `batch_settle(root, leaves_with_proofs)` — anyone-can-call,
//! executing immediately — would put `root` and every `(node, penalty,
//! proof)` in the clear the moment the transaction is submitted, before it
//! is included. Even with the commit's `require_auth`/`settler` check
//! ensuring only the legitimate settler's *own* commitment can ever be
//! revealed (so an outsider cannot redirect whose bond gets slashed or by
//! how much — the root alone fixes that), a still-pending, publicly visible
//! reveal transaction leaks its exact calldata before it lands. Because
//! `batch_id` in this design is never caller-supplied (see
//! [`PoolManager::commit_settlement`]), an outsider cannot use that leaked
//! calldata to front-run anything meaningful — there's no unclaimed slot
//! left to race for. Splitting into commit (hides `root`/`salt` behind an
//! opaque hash) and reveal (executes atomically, in the same call that
//! finally exposes them) removes the window during which a batch's contents
//! are both public and not yet acted upon, which is what front-running
//! requires in the first place.
//!
//! # What `Commitment::hash` binds, and why
//!
//! `sha256(batch_id || sha256(settler.to_xdr) || root || leaf_count ||
//! salt)`:
//! - `batch_id` — ties the commitment to one specific auto-allocated slot.
//! - `settler` — so revealing requires the same identity that committed
//!   (`require_auth`'d on both ends); an outside party can never reveal a
//!   commitment it didn't create, even holding the plaintext.
//! - `root` — the actual settlement content.
//! - `leaf_count` — bound *and* stored in the clear on `Commitment` (see
//!   `mod.rs`), so an undersized or oversized substitute batch is rejected
//!   before any proof is even checked.
//! - `salt` — without it, `root`/`leaf_count`/`batch_id`/`settler` are all
//!   either public or brute-forceable (batch_id and settler are directly
//!   readable from `Commitment` itself), so the commitment would be
//!   guessable from public data alone and the "hidden until reveal"
//!   property would be void from the moment of commit. `salt` is supplied
//!   by the settler and never stored — only its effect on `hash` persists.
//!
//! Every field above is fixed-width (`u64`/`u32` raw big-endian bytes, or a
//! 32-byte digest/`BytesN<32>`) before the final concatenation. This is the
//! Rust-appropriate version of the issue blueprint's `abi.encode` vs.
//! `abi.encodePacked` correction: Solidity's hazard is packing a
//! *variable-length* array (`leafIndices`) next to other fields, so two
//! different index sets can produce identical packed bytes. This design
//! never concatenates a variable-length array into the hash input at all —
//! `leaf_count` (fixed-width) plus `root` (the tree's own succinct
//! commitment to its exact leaf set) stand in for it — so there is no
//! packed-array collision surface to fix in the first place. See
//! `mod::tests` / `pool_manager::tests` for a test that each field
//! independently changes the resulting hash, the direct analogue of the
//! blueprint's collision test.
//!
//! # Reveal timing window
//!
//! `MIN_REVEAL_DELAY_SECONDS` / `MAX_REVEAL_DELAY_SECONDS` approximate the
//! issue's "2-10 block" delay in wall-clock seconds (see `mod.rs` module
//! docs for why this codebase uses seconds, not block/ledger count, for
//! every timing invariant). Stellar's ledger close target is roughly 5
//! seconds, so 2-10 ledgers is approximated as 10-50 seconds. This is a
//! rough conversion, not a protocol guarantee: Soroban ledger close time is
//! not fixed the way Ethereum's block time is, so the *actual* front-running
//! window this buys on any given network is whatever wall-clock time
//! transactions realistically sit unconfirmed on that network — this is
//! flagged explicitly rather than presented as an exact equivalent.
//!
//! # Re-commit and expiry
//!
//! A commitment that is never revealed within the window is not
//! automatically retried — [`PoolManager::commit_settlement`] always
//! allocates a *new* `batch_id`, so an expired, never-revealed commitment is
//! simply abandoned in storage and the settler commits again to try a fresh
//! batch. A `batch_id` that *was* successfully revealed (`settled == true`)
//! can never be reused: [`PoolManager::reveal_settlement`] is the only
//! writer of `settled`, and it is checked on every reveal attempt. There is
//! no re-commit *to the same `batch_id`* at all, expired or not — batch_id
//! reuse is simply not part of this design, which sidesteps the "can a
//! grief-committed batch_id block the real settler" question the issue
//! raises: nobody but the single authorized settler can ever call
//! `commit_settlement` (`require_auth` + address equality), so no batch_id
//! is ever at risk of being squatted before the settler gets to it.

use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Address, Bytes, BytesN, Env, Vec};

use super::merkle;
use super::{Commitment, SettlementDataKey, SettlementError, SettlementLeaf, MAX_BATCH_SIZE};
use crate::slashing_core::slashing::SlashingDataKey;

/// Minimum age (seconds) a commitment must reach before it can be revealed.
/// See module docs for the block-to-seconds conversion this approximates.
pub const MIN_REVEAL_DELAY_SECONDS: u64 = 10;

/// Maximum age (seconds) a commitment can reach and still be revealed.
/// Older than this, it is permanently unrevealable (see module docs on
/// re-commit behavior).
pub const MAX_REVEAL_DELAY_SECONDS: u64 = 50;

pub struct PoolManager;

impl PoolManager {
    /// One-time initialization of the authorized settler address. Idempotent
    /// — a second call is a no-op if a settler is already set — mirroring
    /// `SoroSusu::init`'s guarded `CircleCount` initialization.
    pub fn init_settler(env: &Env, settler: &Address) {
        if !env.storage().instance().has(&SettlementDataKey::Settler) {
            env.storage()
                .instance()
                .set(&SettlementDataKey::Settler, settler);
        }
    }

    /// The currently configured settler, if initialized.
    pub fn settler(env: &Env) -> Option<Address> {
        env.storage().instance().get(&SettlementDataKey::Settler)
    }

    /// Phase 1: commit to a batch settlement without revealing its content.
    ///
    /// Returns the auto-allocated `batch_id`. Panics with `"settler not
    /// initialized"` if [`PoolManager::init_settler`] was never called —
    /// this is a genuine deployment precondition, not a recoverable runtime
    /// condition, so it is treated the same way `SoroSusu::set_lending_pool`
    /// treats a missing `Admin`.
    pub fn commit_settlement(
        env: &Env,
        settler: &Address,
        root: &BytesN<32>,
        leaf_count: u32,
        salt: &BytesN<32>,
    ) -> Result<u64, SettlementError> {
        settler.require_auth();

        let stored_settler: Address = Self::settler(env).expect("settler not initialized");
        if *settler != stored_settler {
            return Err(SettlementError::Unauthorized);
        }

        if leaf_count == 0 || leaf_count > MAX_BATCH_SIZE {
            return Err(SettlementError::InvalidBatchSize);
        }

        let batch_id = Self::allocate_batch_id(env);
        let hash = compute_commitment_hash(env, batch_id, settler, root, leaf_count, salt);

        let commitment = Commitment {
            settler: settler.clone(),
            leaf_count,
            hash,
            committed_at: env.ledger().timestamp(),
            settled: false,
        };
        env.storage()
            .instance()
            .set(&SettlementDataKey::Commitment(batch_id), &commitment);

        Ok(batch_id)
    }

    /// Phase 2: reveal a committed batch and settle it atomically.
    ///
    /// On success, every leaf's Merkle proof has been verified against
    /// `root` and its `penalty_amount` has been debited from that node's
    /// bond pool (see the debit loop below for the insufficient-balance
    /// handling). Returns the total amount actually slashed across the
    /// batch.
    ///
    /// All proofs are verified *before* any bond is debited: an invalid
    /// proof anywhere in the batch reverts the whole reveal, so a
    /// settlement never partially applies.
    pub fn reveal_settlement(
        env: &Env,
        caller: &Address,
        batch_id: u64,
        root: &BytesN<32>,
        salt: &BytesN<32>,
        leaves: &Vec<SettlementLeaf>,
    ) -> Result<i128, SettlementError> {
        caller.require_auth();

        let key = SettlementDataKey::Commitment(batch_id);
        let mut commitment: Commitment = env
            .storage()
            .instance()
            .get(&key)
            .ok_or(SettlementError::CommitmentNotFound)?;

        if commitment.settled {
            return Err(SettlementError::AlreadySettled);
        }

        // Sender-binding: only the address that committed this batch can
        // reveal it, even though it also holds the only valid `require_auth`
        // signature for that address — this keeps the check meaningful if
        // the module is ever extended to support multiple settlers.
        if *caller != commitment.settler {
            return Err(SettlementError::Unauthorized);
        }

        let elapsed = env
            .ledger()
            .timestamp()
            .saturating_sub(commitment.committed_at);
        if elapsed < MIN_REVEAL_DELAY_SECONDS {
            return Err(SettlementError::RevealTooEarly);
        }
        if elapsed > MAX_REVEAL_DELAY_SECONDS {
            return Err(SettlementError::RevealWindowExpired);
        }

        let leaf_count = leaves.len();
        if leaf_count != commitment.leaf_count {
            return Err(SettlementError::LeafCountMismatch);
        }

        let hash = compute_commitment_hash(env, batch_id, caller, root, leaf_count, salt);
        if hash != commitment.hash {
            return Err(SettlementError::CommitmentMismatch);
        }

        // Verify every proof before settling anything (all-or-nothing).
        for leaf in leaves.iter() {
            if leaf.penalty_amount < 0 {
                return Err(SettlementError::InvalidPenaltyAmount);
            }
            if leaf.proof.len() > merkle::MAX_PROOF_DEPTH {
                return Err(SettlementError::ProofTooDeep);
            }

            let leaf_hash =
                merkle::hash_leaf(env, &encode_leaf(env, &leaf.node_id, leaf.penalty_amount));
            if !merkle::verify_proof(env, &leaf_hash, &leaf.proof, leaf.index, root) {
                return Err(SettlementError::InvalidProof);
            }
        }

        // Apply the settlement. Debits `slashing_core::slashing`'s
        // `BondPool` — the same storage key the periodic monitor/executor
        // pipeline uses — so both settlement paths share one ledger of bond
        // balances rather than two that could silently diverge. If a node's
        // bond was already partially or fully consumed (e.g. by that
        // pipeline, between commit and reveal), the debit is capped at
        // whatever remains rather than reverting the entire batch over one
        // already-reduced node.
        let mut total_slashed: i128 = 0;
        for leaf in leaves.iter() {
            let pool_key = SlashingDataKey::BondPool(leaf.node_id.clone());
            let pool_balance: i128 = env.storage().instance().get(&pool_key).unwrap_or(0);
            let debited = leaf.penalty_amount.min(pool_balance).max(0);
            if debited > 0 {
                env.storage()
                    .instance()
                    .set(&pool_key, &(pool_balance - debited));
            }
            total_slashed += debited;
        }

        commitment.settled = true;
        env.storage().instance().set(&key, &commitment);

        Ok(total_slashed)
    }

    fn allocate_batch_id(env: &Env) -> u64 {
        let next: u64 = env
            .storage()
            .instance()
            .get(&SettlementDataKey::NextBatchId)
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&SettlementDataKey::NextBatchId, &(next + 1));
        next
    }
}

/// `sha256(batch_id || sha256(settler.to_xdr) || root || leaf_count ||
/// salt)`. See module docs for why every field is fixed-width before
/// concatenation.
pub fn compute_commitment_hash(
    env: &Env,
    batch_id: u64,
    settler: &Address,
    root: &BytesN<32>,
    leaf_count: u32,
    salt: &BytesN<32>,
) -> BytesN<32> {
    let settler_digest: Bytes = env.crypto().sha256(&settler.clone().to_xdr(env)).into();

    let mut buf = Bytes::from_array(env, &batch_id.to_be_bytes());
    buf.append(&settler_digest);
    buf.append(&Bytes::from(root.clone()));
    buf.extend_from_array(&leaf_count.to_be_bytes());
    buf.append(&Bytes::from(salt.clone()));

    env.crypto().sha256(&buf).to_bytes()
}

/// Leaf content hashed into the tree: the node being slashed and its
/// penalty amount. `index` is *not* included here — it is proven by the
/// proof's own left/right structure (see `merkle::verify_proof`), not by
/// being embedded in the leaf.
fn encode_leaf(env: &Env, node_id: &Address, penalty_amount: i128) -> Bytes {
    let mut buf: Bytes = node_id.clone().to_xdr(env);
    buf.extend_from_array(&penalty_amount.to_be_bytes());
    buf
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared test scaffolding for `settlement`'s own unit tests and the
    //! top-level `tests/settlement/front_running_test.rs` integration test.
    extern crate alloc;

    use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, Vec};

    use super::encode_leaf;
    use crate::settlement::merkle;
    use crate::SoroSusu;

    pub fn setup_contract(env: &Env) -> Address {
        env.register_contract(None, SoroSusu)
    }

    /// Build a balanced tree over `entries` (power-of-two length) and return
    /// `(root, per_leaf_proofs)`, where `per_leaf_proofs[i]` is the sibling
    /// path for `entries[i]` at index `i`.
    pub fn build_batch_tree(
        env: &Env,
        entries: &[(Address, i128)],
    ) -> (BytesN<32>, alloc::vec::Vec<Vec<BytesN<32>>>) {
        let leaf_hashes: alloc::vec::Vec<BytesN<32>> = entries
            .iter()
            .map(|(node_id, amount)| merkle::hash_leaf(env, &encode_leaf(env, node_id, *amount)))
            .collect();

        let n = leaf_hashes.len();
        let mut proofs: alloc::vec::Vec<Vec<BytesN<32>>> = alloc::vec::Vec::with_capacity(n);
        let mut root = leaf_hashes
            .first()
            .cloned()
            .unwrap_or_else(|| merkle::hash_leaf(env, &Bytes::from_array(env, &[])));

        for target in 0..n {
            let mut level = leaf_hashes.clone();
            let mut proof = Vec::new(env);
            let mut idx = target;
            while level.len() > 1 {
                let sibling_idx = idx ^ 1;
                proof.push_back(level[sibling_idx].clone());
                let mut next = alloc::vec::Vec::new();
                let mut i = 0;
                while i < level.len() {
                    next.push(merkle::hash_node(env, &level[i], &level[i + 1]));
                    i += 2;
                }
                level = next;
                idx /= 2;
            }
            root = level[0].clone();
            proofs.push(proof);
        }

        (root, proofs)
    }

    pub fn generated(env: &Env) -> Address {
        Address::generate(env)
    }
}
