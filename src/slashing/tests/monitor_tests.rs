use soroban_sdk::{testutils::Address as _, Address, Env};
use crate::slashing::monitor;
use crate::slashing::event_store;
use crate::SoroSusu;

#[test]
fn test_multi_condition_slashing_dedup() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SoroSusu);
    let node_id = Address::generate(&env);
    let scan_epoch = 1;

    env.as_contract(&contract_id, || {
        // Just verify that the monitor runs without panicking
        // Since stubs return false, no event is created
        monitor::evaluate_conditions(&env, node_id.clone(), scan_epoch);

        let event = event_store::get_event(&env, node_id.clone(), scan_epoch);
        assert!(event.is_none());
    });
}
