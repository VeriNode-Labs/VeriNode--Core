use soroban_sdk::{contracttype, Address, Env, Vec};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SlashingReason {
    DoubleSigning,
    Downtime,
    Fraud,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SlashingEvent {
    pub node_id: Address,
    pub scan_epoch: u64,
    pub reasons: Vec<SlashingReason>,
    pub timestamp: u64,
}

#[contracttype]
pub enum SlashingDataKey {
    SlashingEvent(Address, u64), // (node_id, scan_epoch)
}

pub fn record_event(env: &Env, event: SlashingEvent) -> bool {
    let key = SlashingDataKey::SlashingEvent(event.node_id.clone(), event.scan_epoch);

    if env.storage().persistent().has(&key) {
        return false; // Already processed
    }

    env.storage().persistent().set(&key, &event);
    true
}

pub fn get_event(env: &Env, node_id: Address, scan_epoch: u64) -> Option<SlashingEvent> {
    let key = SlashingDataKey::SlashingEvent(node_id, scan_epoch);
    env.storage().persistent().get(&key)
}
