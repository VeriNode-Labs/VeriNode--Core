use soroban_sdk::{contract, contractimpl, BytesN, Env};
use crate::storage_layout::{ConstantsStore, BEACON_CONSTANTS_V1_SLOT};

#[contract]
pub struct BeaconState;

#[contractimpl]
impl BeaconState {
    pub fn init_constants(env: Env) -> ConstantsStore {
        let key = BytesN::from_array(&env, &BEACON_CONSTANTS_V1_SLOT);
        if env.storage().instance().has(&key) {
            env.storage().instance().get(&key).unwrap()
        } else {
            // Default or fallback constants
            let default_store = ConstantsStore {
                max_validators: 1000,
                shard_count: 64,
            };
            env.storage().instance().set(&key, &default_store);
            default_store
        }
    }

    pub fn get_max_validators(env: Env) -> u32 {
        let store = Self::init_constants(env);
        store.max_validators
    }

    pub fn get_shard_count(env: Env) -> u32 {
        let store = Self::init_constants(env);
        store.shard_count
    }
}
