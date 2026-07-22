#![cfg(test)]
use soroban_sdk::{BytesN, Env};
use sorosusu_contracts::beacon_state::{BeaconState, BeaconStateClient};
use sorosusu_contracts::storage_layout::{ConstantsStore, BEACON_CONSTANTS_V1_SLOT};
use sorosusu_contracts::upgrade_beacon::{UpgradeBeacon, UpgradeBeaconClient};

#[test]
fn test_upgrade_storage_preservation() {
    let env = Env::default();
    env.mock_all_auths();

    // Register UpgradeBeacon contract
    let contract_id = env.register_contract(None, UpgradeBeacon);
    let client = UpgradeBeaconClient::new(&env, &contract_id);

    // Set constants via the upgrade_implementation call
    let mock_wasm_hash = BytesN::from_array(&env, &[0; 32]);
    client.upgrade_implementation(&mock_wasm_hash, &2000, &128);

    // Verify they are written in the deterministic slot
    let key = BytesN::from_array(&env, &BEACON_CONSTANTS_V1_SLOT);
    assert!(env.storage().instance().has(&key));
    let store: ConstantsStore = env.storage().instance().get(&key).unwrap();
    assert_eq!(store.max_validators, 2000);
    assert_eq!(store.shard_count, 128);

    // Now instantiate BeaconState client at the same contract ID to simulate the upgraded state
    let beacon_client = BeaconStateClient::new(&env, &contract_id);
    let upgraded_store = beacon_client.init_constants();
    assert_eq!(upgraded_store.max_validators, 2000);
    assert_eq!(upgraded_store.shard_count, 128);

    assert_eq!(beacon_client.get_max_validators(), 2000);
    assert_eq!(beacon_client.get_shard_count(), 128);
}
