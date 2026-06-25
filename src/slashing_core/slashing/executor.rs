use soroban_sdk::{Address, Env};

use super::{
    event_store::SlashingEventStore, NodeState, SlashingDataKey, SlashingEvent,
    SlashingEventStatus,
};

/// The slashing executor. Responsible for actually applying the penalty
/// (deducting from the bond pool) after the monitor creates a SlashingEvent.
///
/// KEY FIX: Includes an idempotency check — if the node is already slashed
/// (`node.slashed == true`) OR if there's a finalized event for this epoch,
/// the executor refuses to slash again, preventing the double-deduction bug.
pub struct SlashingExecutor;

impl SlashingExecutor {
    /// Execute a slashing event. Returns `true` if the slashing was successfully
    /// applied, `false` if it was skipped (idempotency) or failed.
    ///
    /// Idempotency checks:
    /// 1. Node must not already be slashed (`node.slashed == false`)
    /// 2. Event must be in `Pending` status (not already executed)
    /// 3. Bond pool must have sufficient balance
    pub fn execute_slashing(env: &Env, event: &SlashingEvent) -> bool {
        let node_key = SlashingDataKey::Node(event.node_id.clone());

        // Load current node state
        let node: NodeState = match env.storage().instance().get(&node_key) {
            Some(n) => n,
            None => return false,
        };

        // IDEMPOTENCY CHECK 1: node must not already be slashed
        if node.slashed {
            SlashingEventStore::update_event_status(
                env,
                &event.node_id,
                event.scan_epoch,
                SlashingEventStatus::Rejected,
            );
            return false;
        }

        // IDEMPOTENCY CHECK 2: verify the event is still pending
        if let Some(stored_event) =
            SlashingEventStore::get_event(env, &event.node_id, event.scan_epoch)
        {
            if stored_event.status != SlashingEventStatus::Pending {
                return false;
            }
        }

        // IDEMPOTENCY CHECK 3: verify bond pool has sufficient balance
        let pool_key = SlashingDataKey::BondPool(event.node_id.clone());
        let pool_balance: i128 = env.storage().instance().get(&pool_key).unwrap_or(0);

        if pool_balance < event.penalty_amount {
            SlashingEventStore::update_event_status(
                env,
                &event.node_id,
                event.scan_epoch,
                SlashingEventStatus::Failed,
            );
            return false;
        }

        // EXECUTE: Deduct penalty from bond pool (exactly once)
        let new_balance = pool_balance - event.penalty_amount;
        env.storage().instance().set(&pool_key, &new_balance);

        // Mark event as executed
        SlashingEventStore::update_event_status(
            env,
            &event.node_id,
            event.scan_epoch,
            SlashingEventStatus::Executed,
        );

        true
    }

    /// Query the current bond pool balance for a node.
    pub fn get_bond_balance(env: &Env, node_id: &Address) -> i128 {
        let pool_key = SlashingDataKey::BondPool(node_id.clone());
        env.storage().instance().get(&pool_key).unwrap_or(0)
    }
}
