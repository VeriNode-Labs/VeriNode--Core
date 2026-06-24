use soroban_sdk::{contract, contractimpl, BytesN, Env};
use crate::storage_layout::{ConstantsStore, BEACON_CONSTANTS_V1_SLOT};

#[contract]
pub struct UpgradeBeacon;

#[contractimpl]
impl UpgradeBeacon {
    pub fn upgrade_implementation(env: Env, new_wasm_hash: BytesN<32>, max_validators: u32, shard_count: u32) {
        // Define all constants in dedicated ConstantsStore struct
        let store = ConstantsStore {
            max_validators,
            shard_count,
        };
        
        // Write the ConstantsStore to the deterministic slot
        let key = BytesN::from_array(&env, &BEACON_CONSTANTS_V1_SLOT);
        env.storage().instance().set(&key, &store);
        
        // Upgrade current contract WASM hash
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
