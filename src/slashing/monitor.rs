use soroban_sdk::{Address, Env, Vec};
use crate::slashing::event_store::{self, SlashingEvent, SlashingReason};
use crate::slashing::executor;
use crate::{DataKey, SCAN_INTERVAL};

pub fn evaluate_conditions(env: &Env, node_id: Address, scan_epoch: u64) {
    if let Some(slashed_at) = env.storage().instance().get::<_, u64>(&DataKey::SlashedAt(node_id.clone())) {
        if env.ledger().timestamp() < slashed_at + SCAN_INTERVAL {
            return;
        }
    }

    let lock_key = DataKey::SlashingInProgress(node_id.clone());
    if env.storage().instance().has(&lock_key) {
        return;
    }
    env.storage().instance().set(&lock_key, &true);

    let mut reasons = Vec::new(env);

    if detect_double_signing(env, &node_id) {
        reasons.push_back(SlashingReason::DoubleSigning);
    }

    if detect_downtime(env, &node_id) {
        reasons.push_back(SlashingReason::Downtime);
    }

    if reasons.len() > 0 {
        let event = SlashingEvent {
            node_id: node_id.clone(),
            scan_epoch,
            reasons,
            timestamp: env.ledger().timestamp(),
        };

        if event_store::record_event(env, event) {
            if executor::execute_slashing(env, node_id.clone()) {
                env.storage().instance().set(&DataKey::SlashedAt(node_id.clone()), &env.ledger().timestamp());
            }
        }
    }

    env.storage().instance().remove(&lock_key);
}

fn detect_double_signing(_env: &Env, _node_id: &Address) -> bool {
    // Placeholder for actual detection logic
    false
}

fn detect_downtime(_env: &Env, _node_id: &Address) -> bool {
    // Placeholder for actual detection logic
    false
}
