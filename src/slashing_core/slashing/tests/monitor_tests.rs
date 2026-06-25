use soroban_sdk::{testutils::{Address as _, Ledger}, Address, Env, Vec};

use crate::slashing_core::slashing::{
    event_store::SlashingEventStore,
    executor::SlashingExecutor,
    monitor::SlashingMonitor,
    NodeState, SlashingDataKey, SlashingEvent, SlashingEventStatus, SlashingReason,
    NODE_BOND_AMOUNT, SCAN_INTERVAL_SECONDS, SLASHING_PENALTY,
};
use crate::SoroSusu;

/// Helper: register a contract and return the contract_id for use with as_contract.
fn setup_contract(env: &Env) -> Address {
    env.register_contract(None, SoroSusu)
}

/// Helper: set up a node with specified violations within a contract context.
fn setup_node_with_violations(
    env: &Env,
    contract_id: &Address,
    double_signing: bool,
    extended_downtime: bool,
    fraud_proof: bool,
) -> Address {
    let node_id = Address::generate(env);

    env.as_contract(contract_id, || {
        // Register node with bond
        SlashingMonitor::register_node(env, &node_id, NODE_BOND_AMOUNT);

        // Set up violations
        if double_signing {
            SlashingMonitor::report_double_signing(env, &node_id);
        }

        if fraud_proof {
            SlashingMonitor::report_fraud_proof(env, &node_id);
        }

        // For downtime, set last_activity_time far in the past
        if extended_downtime {
            let node_key = SlashingDataKey::Node(node_id.clone());
            let mut node: NodeState = env.storage().instance().get(&node_key).unwrap();
            let current_time = env.ledger().timestamp();
            node.last_activity_time = current_time.saturating_sub(259200); // 72 hours ago
            env.storage().instance().set(&node_key, &node);
        }
    });

    node_id
}

// ============================================================================
// CORE BUG FIX TEST: Multi-condition triggers exactly one event
// ============================================================================

/// This is the primary test for the race condition fix.
/// A node triggers BOTH double-signing AND extended downtime in the same scan.
/// The invariant: exactly ONE SlashingEvent is created with BOTH reasons, and
/// the bond is deducted exactly ONCE.
#[test]
fn test_multi_condition_creates_single_event_with_all_reasons() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = setup_contract(&env);
    let node_id = setup_node_with_violations(&env, &contract_id, true, true, false);

    env.as_contract(&contract_id, || {
        // Record initial bond balance
        let initial_balance = SlashingExecutor::get_bond_balance(&env, &node_id);
        assert_eq!(initial_balance, NODE_BOND_AMOUNT);

        // Run the monitor scan
        let mut nodes = Vec::new(&env);
        nodes.push_back(node_id.clone());
        let events = SlashingMonitor::evaluate_conditions(&env, &nodes);

        // INVARIANT: Exactly ONE event created
        assert_eq!(events.len(), 1);

        let event = events.get(0).unwrap();

        // INVARIANT: Event contains BOTH reasons
        assert_eq!(event.reasons.len(), 2);
        assert_eq!(event.reasons.get(0).unwrap(), SlashingReason::DoubleSigning);
        assert_eq!(event.reasons.get(1).unwrap(), SlashingReason::ExtendedDowntime);

        // INVARIANT: Penalty applied exactly once
        let final_balance = SlashingExecutor::get_bond_balance(&env, &node_id);
        assert_eq!(final_balance, initial_balance - SLASHING_PENALTY);

        // INVARIANT: Event status is Executed
        assert_eq!(event.status, SlashingEventStatus::Executed);
    });
}

/// Triple condition: double-signing + downtime + fraud proof, still one event.
#[test]
fn test_triple_condition_creates_single_event() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = setup_contract(&env);
    let node_id = setup_node_with_violations(&env, &contract_id, true, true, true);

    env.as_contract(&contract_id, || {
        let mut nodes = Vec::new(&env);
        nodes.push_back(node_id.clone());
        let events = SlashingMonitor::evaluate_conditions(&env, &nodes);

        assert_eq!(events.len(), 1);

        let event = events.get(0).unwrap();
        assert_eq!(event.reasons.len(), 3);
        assert_eq!(event.reasons.get(0).unwrap(), SlashingReason::DoubleSigning);
        assert_eq!(event.reasons.get(1).unwrap(), SlashingReason::ExtendedDowntime);
        assert_eq!(event.reasons.get(2).unwrap(), SlashingReason::FraudProof);

        // Bond deducted exactly once
        let final_balance = SlashingExecutor::get_bond_balance(&env, &node_id);
        assert_eq!(final_balance, NODE_BOND_AMOUNT - SLASHING_PENALTY);
    });
}

// ============================================================================
// PRE-CHECK GATE TESTS
// ============================================================================

/// If a node was slashed within the current scan interval, it should be skipped.
#[test]
fn test_pre_check_gate_skips_recently_slashed_node() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = setup_contract(&env);
    let node_id = setup_node_with_violations(&env, &contract_id, true, false, false);

    env.as_contract(&contract_id, || {
        let mut nodes = Vec::new(&env);
        nodes.push_back(node_id.clone());

        // First scan: should slash successfully
        let events = SlashingMonitor::evaluate_conditions(&env, &nodes);
        assert_eq!(events.len(), 1);

        // Re-add violations (simulating a new report within the same interval)
        SlashingMonitor::report_double_signing(&env, &node_id);

        // Second scan within the same interval: node should be SKIPPED
        let events2 = SlashingMonitor::evaluate_conditions(&env, &nodes);
        assert_eq!(events2.len(), 0);

        // Bond should only have been deducted once
        let final_balance = SlashingExecutor::get_bond_balance(&env, &node_id);
        assert_eq!(final_balance, NODE_BOND_AMOUNT - SLASHING_PENALTY);
    });
}

/// After the scan interval passes, a node can be slashed again.
#[test]
fn test_node_can_be_slashed_again_after_interval() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = setup_contract(&env);
    let node_id = setup_node_with_violations(&env, &contract_id, true, false, false);

    env.as_contract(&contract_id, || {
        let mut nodes = Vec::new(&env);
        nodes.push_back(node_id.clone());

        // First scan
        let events = SlashingMonitor::evaluate_conditions(&env, &nodes);
        assert_eq!(events.len(), 1);
    });

    // Advance time beyond the scan interval
    env.ledger().set_timestamp(1_000_000 + SCAN_INTERVAL_SECONDS + 1);

    env.as_contract(&contract_id, || {
        // Reset slashed status for re-activation (simulating node re-bonding)
        let node_key = SlashingDataKey::Node(node_id.clone());
        let mut node: NodeState = env.storage().instance().get(&node_key).unwrap();
        node.slashed = false;
        node.double_sign_detected = true;
        env.storage().instance().set(&node_key, &node);

        // Replenish bond pool
        let pool_key = SlashingDataKey::BondPool(node_id.clone());
        env.storage().instance().set(&pool_key, &NODE_BOND_AMOUNT);

        let mut nodes = Vec::new(&env);
        nodes.push_back(node_id.clone());

        // Second scan after interval: should process again
        let events2 = SlashingMonitor::evaluate_conditions(&env, &nodes);
        assert_eq!(events2.len(), 1);
    });
}

// ============================================================================
// UNIQUE CONSTRAINT TESTS
// ============================================================================

/// Event store rejects duplicate events for the same node+epoch.
#[test]
fn test_event_store_unique_constraint() {
    let env = Env::default();
    let contract_id = setup_contract(&env);
    let node_id = Address::generate(&env);
    let scan_epoch: u64 = 1;

    env.as_contract(&contract_id, || {
        let mut reasons = Vec::new(&env);
        reasons.push_back(SlashingReason::DoubleSigning);

        let event = SlashingEvent {
            node_id: node_id.clone(),
            scan_epoch,
            reasons: reasons.clone(),
            penalty_amount: SLASHING_PENALTY,
            created_at: 100,
            status: SlashingEventStatus::Pending,
        };

        // First store: succeeds
        let stored1 = SlashingEventStore::store_event(&env, &event);
        assert!(stored1);

        // Second store (same node+epoch): rejected
        let stored2 = SlashingEventStore::store_event(&env, &event);
        assert!(!stored2);

        // Verify only one event exists
        let retrieved = SlashingEventStore::get_event(&env, &node_id, scan_epoch).unwrap();
        assert_eq!(retrieved.reasons.len(), 1);
    });
}

// ============================================================================
// IDEMPOTENCY TESTS
// ============================================================================

/// Executor refuses to slash an already-slashed node.
#[test]
fn test_executor_idempotency_already_slashed() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = setup_contract(&env);
    let node_id = Address::generate(&env);

    env.as_contract(&contract_id, || {
        // Register node but mark as already slashed
        SlashingMonitor::register_node(&env, &node_id, NODE_BOND_AMOUNT);
        let node_key = SlashingDataKey::Node(node_id.clone());
        let mut node: NodeState = env.storage().instance().get(&node_key).unwrap();
        node.slashed = true;
        env.storage().instance().set(&node_key, &node);

        let mut reasons = Vec::new(&env);
        reasons.push_back(SlashingReason::DoubleSigning);

        let event = SlashingEvent {
            node_id: node_id.clone(),
            scan_epoch: 1,
            reasons,
            penalty_amount: SLASHING_PENALTY,
            created_at: 1_000_000,
            status: SlashingEventStatus::Pending,
        };

        SlashingEventStore::store_event(&env, &event);

        // Attempt execution: should be rejected
        let result = SlashingExecutor::execute_slashing(&env, &event);
        assert!(!result);

        // Bond pool unchanged
        let balance = SlashingExecutor::get_bond_balance(&env, &node_id);
        assert_eq!(balance, NODE_BOND_AMOUNT);
    });
}

/// Executor refuses to slash if bond pool has insufficient balance.
#[test]
fn test_executor_insufficient_pool_balance() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = setup_contract(&env);
    let node_id = Address::generate(&env);

    env.as_contract(&contract_id, || {
        // Register node with zero bond (simulating depleted pool)
        SlashingMonitor::register_node(&env, &node_id, 0);

        let mut reasons = Vec::new(&env);
        reasons.push_back(SlashingReason::DoubleSigning);

        let event = SlashingEvent {
            node_id: node_id.clone(),
            scan_epoch: 1,
            reasons,
            penalty_amount: SLASHING_PENALTY,
            created_at: 1_000_000,
            status: SlashingEventStatus::Pending,
        };

        SlashingEventStore::store_event(&env, &event);

        // Attempt execution: should fail due to insufficient balance
        let result = SlashingExecutor::execute_slashing(&env, &event);
        assert!(!result);

        // Balance stays at zero
        let balance = SlashingExecutor::get_bond_balance(&env, &node_id);
        assert_eq!(balance, 0);
    });
}

// ============================================================================
// SINGLE CONDITION TESTS (sanity checks)
// ============================================================================

#[test]
fn test_single_double_signing_condition() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = setup_contract(&env);
    let node_id = setup_node_with_violations(&env, &contract_id, true, false, false);

    env.as_contract(&contract_id, || {
        let mut nodes = Vec::new(&env);
        nodes.push_back(node_id.clone());
        let events = SlashingMonitor::evaluate_conditions(&env, &nodes);

        assert_eq!(events.len(), 1);
        let event = events.get(0).unwrap();
        assert_eq!(event.reasons.len(), 1);
        assert_eq!(event.reasons.get(0).unwrap(), SlashingReason::DoubleSigning);
        assert_eq!(event.status, SlashingEventStatus::Executed);
    });
}

#[test]
fn test_single_extended_downtime_condition() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = setup_contract(&env);
    let node_id = setup_node_with_violations(&env, &contract_id, false, true, false);

    env.as_contract(&contract_id, || {
        let mut nodes = Vec::new(&env);
        nodes.push_back(node_id.clone());
        let events = SlashingMonitor::evaluate_conditions(&env, &nodes);

        assert_eq!(events.len(), 1);
        let event = events.get(0).unwrap();
        assert_eq!(event.reasons.len(), 1);
        assert_eq!(event.reasons.get(0).unwrap(), SlashingReason::ExtendedDowntime);
    });
}

#[test]
fn test_no_conditions_triggered_no_event() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = setup_contract(&env);
    let node_id = setup_node_with_violations(&env, &contract_id, false, false, false);

    env.as_contract(&contract_id, || {
        let mut nodes = Vec::new(&env);
        nodes.push_back(node_id.clone());
        let events = SlashingMonitor::evaluate_conditions(&env, &nodes);

        assert_eq!(events.len(), 0);
    });
}

/// Multiple nodes: each gets at most one event.
#[test]
fn test_multiple_nodes_independent_events() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = setup_contract(&env);
    let node_a = setup_node_with_violations(&env, &contract_id, true, true, false); // 2 reasons
    let node_b = setup_node_with_violations(&env, &contract_id, false, false, true); // 1 reason
    let node_c = setup_node_with_violations(&env, &contract_id, false, false, false); // no reasons

    env.as_contract(&contract_id, || {
        let mut nodes = Vec::new(&env);
        nodes.push_back(node_a.clone());
        nodes.push_back(node_b.clone());
        nodes.push_back(node_c.clone());

        let events = SlashingMonitor::evaluate_conditions(&env, &nodes);

        // Only 2 events (node_c has no violations)
        assert_eq!(events.len(), 2);

        // node_a: 2 reasons
        let event_a = events.get(0).unwrap();
        assert_eq!(event_a.node_id, node_a);
        assert_eq!(event_a.reasons.len(), 2);

        // node_b: 1 reason
        let event_b = events.get(1).unwrap();
        assert_eq!(event_b.node_id, node_b);
        assert_eq!(event_b.reasons.len(), 1);
        assert_eq!(event_b.reasons.get(0).unwrap(), SlashingReason::FraudProof);
    });
}
