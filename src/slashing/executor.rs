use soroban_sdk::{Address, Env};
use crate::DataKey;

pub fn execute_slashing(env: &Env, node_id: Address) -> bool {
    let lock_key = DataKey::SlashingInProgress(node_id.clone());
    if !env.storage().instance().has(&lock_key) {
        return false;
    }
    true
}
