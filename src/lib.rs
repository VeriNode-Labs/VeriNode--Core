//! Lumina Network protocol contracts.
//!
//! Decentralized intellectual property anchoring and autonomous milestone
//! settlement built on Soroban:
//!
//! * [`register_asset`] records a cryptographic fingerprint (SHA-256 of the
//!   work) plus an IPFS ODRL license URI as an immutable, timestamped
//!   provenance anchor on the Stellar ledger.
//! * [`create_escrow`] locks a milestone budget for a creator; the funding
//!   client authorizes staged payouts via [`release_milestone`] against the
//!   escrowed balance, which settles automatically when the final milestone
//!   completes.
//!
//! Financial balances are held as deterministic internal accounting within the
//! escrow ledger (`remaining_balance`); every state mutation is mirrored as a
//! contract event so off-chain indexers can reconstruct cryptographically
//! verifiable payout history.

#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

use soroban_sdk::{contract, contractimpl, symbol_short, Address, BytesN, Env, String, Symbol};

use crate::types::{AssetRecord, ContractError, DataKey, EscrowRecord};

mod test;
mod types;

#[contract]
pub struct LuminaContract;

#[contractimpl]
impl LuminaContract {
    /// Single-time protocol initialization. Captures the privileged `admin`.
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        let storage = env.storage().instance();
        if storage.has(&DataKey::Admin) {
            return Err(ContractError::AlreadyInitialized);
        }
        storage.set(&DataKey::Admin, &admin);
        Ok(())
    }

    /// Register a work with its cryptographic fingerprint and ODRL/IPFS
    /// metadata, anchoring a provable IP timestamp to the ledger.
    ///
    /// # Arguments
    /// * `creator`      - Author/provenance owner (must authorize the call).
    /// * `fingerprint`  - SHA-256 hash of the work's canonical bytes.
    /// * `metadata_uri` - IPFS URI of the ODRL license & sanitized metadata.
    /// * `licensing_fee`- Fee in stroops demanded for a license grant.
    ///
    /// Returns the assigned monotonic `asset_id`.
    pub fn register_asset(
        env: Env,
        creator: Address,
        fingerprint: BytesN<32>,
        metadata_uri: String,
        licensing_fee: i128,
    ) -> Result<u64, ContractError> {
        creator.require_auth();

        let storage = env.storage().instance();
        let asset_id = storage.get(&DataKey::AssetCount).unwrap_or(0);

        let registered_at = env.ledger().timestamp();
        let asset = AssetRecord {
            asset_id,
            creator: creator.clone(),
            fingerprint: fingerprint.clone(),
            metadata_uri: metadata_uri.clone(),
            licensing_fee,
            registered_at,
            is_active: true,
        };

        storage.set(&DataKey::Asset(asset_id), &asset);
        storage.set(&DataKey::AssetCount, &asset_id.saturating_add(1));

        env.events().publish(
            (symbol_short!("ip_anchor"), creator),
            (asset_id, fingerprint, registered_at),
        );

        Ok(asset_id)
    }

    /// Create a milestone escrow that locks `total_amount` for `creator`.
    ///
    /// # Arguments
    /// * `client`          - Funding party (must authorize the call).
    /// * `creator`         - Recipient of milestone payouts.
    /// * `total_amount`    - Whole escrow budget locked in custody.
    /// * `total_milestones`- Number of staged deliverables to release against.
    ///
    /// Returns the assigned monotonic `escrow_id`.
    pub fn create_escrow(
        env: Env,
        client: Address,
        creator: Address,
        total_amount: i128,
        total_milestones: u32,
    ) -> Result<u64, ContractError> {
        client.require_auth();

        let storage = env.storage().instance();
        let escrow_id = storage.get(&DataKey::EscrowCount).unwrap_or(0);

        let escrow = EscrowRecord {
            escrow_id,
            client: client.clone(),
            creator: creator.clone(),
            total_amount,
            remaining_balance: total_amount,
            total_milestones,
            completed_milestones: 0,
            is_settled: false,
        };

        storage.set(&DataKey::Escrow(escrow_id), &escrow);
        storage.set(&DataKey::EscrowCount, &escrow_id.saturating_add(1));

        env.events().publish(
            // 10-char topic exceeds the symbol_short! limit, so build it
            // explicitly to keep the exact `escrow_new` topic on chain.
            (Symbol::new(&env, "escrow_new"), client),
            (escrow_id, creator, total_amount),
        );

        Ok(escrow_id)
    }

    /// Release a single milestone payout to the creator.
    ///
    /// Only the escrow `client` may authorize releases. Requires
    /// `remaining_balance >= payout_amount` and at least one milestone
    /// outstanding. Decrements the locked balance, bumps the completion
    /// counter, and records the payout on chain.
    pub fn release_milestone(
        env: Env,
        escrow_id: u64,
        payout_amount: i128,
    ) -> Result<(), ContractError> {
        let storage = env.storage().instance();
        let mut escrow: EscrowRecord = storage
            .get(&DataKey::Escrow(escrow_id))
            .ok_or(ContractError::EscrowNotFound)?;

        escrow.client.require_auth();

        if escrow.is_settled {
            return Err(ContractError::EscrowAlreadySettled);
        }
        if escrow.completed_milestones >= escrow.total_milestones {
            return Err(ContractError::AllMilestonesCompleted);
        }
        if payout_amount > escrow.remaining_balance {
            return Err(ContractError::InsufficientFunds);
        }

        escrow.remaining_balance -= payout_amount;
        escrow.completed_milestones += 1;
        if escrow.completed_milestones == escrow.total_milestones {
            escrow.is_settled = true;
        }

        storage.set(&DataKey::Escrow(escrow_id), &escrow);

        env.events().publish(
            (symbol_short!("pay_rel"), escrow_id),
            (payout_amount, escrow.completed_milestones),
        );

        Ok(())
    }

    /// Read the canonical asset registration for `asset_id`.
    pub fn get_asset(env: Env, asset_id: u64) -> Result<AssetRecord, ContractError> {
        env.storage()
            .instance()
            .get(&DataKey::Asset(asset_id))
            .ok_or(ContractError::AssetNotFound)
    }

    /// Read the canonical escrow state for `escrow_id`.
    pub fn get_escrow(env: Env, escrow_id: u64) -> Result<EscrowRecord, ContractError> {
        env.storage()
            .instance()
            .get(&DataKey::Escrow(escrow_id))
            .ok_or(ContractError::EscrowNotFound)
    }
}
