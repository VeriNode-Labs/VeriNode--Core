use soroban_sdk::{Address, Env};

use super::{SlashingDataKey, SlashingEvent, SlashingEventStatus};

/// The slashing event store. Manages persistence of SlashingEvents with a
/// unique constraint on (node_id, scan_epoch).
///
/// KEY FIX: Enforces that at most one SlashingEvent can exist per node per
/// scan epoch. If a duplicate insert is attempted (same node_id + scan_epoch),
/// it is rejected — the slashing was already processed for this scan.
///
/// This is the logical equivalent of:
///   CREATE UNIQUE INDEX idx_slashing_event_node_epoch
///   ON slashing_events(node_id, scan_epoch)
pub struct SlashingEventStore;

impl SlashingEventStore {
    /// Check if a slashing event already exists for the given node and epoch.
    /// This enforces the unique constraint before insertion.
    pub fn event_exists(env: &Env, node_id: &Address, scan_epoch: u64) -> bool {
        let key = SlashingDataKey::Event(node_id.clone(), scan_epoch);
        env.storage().instance().has(&key)
    }

    /// Store a slashing event. Returns `true` if stored successfully, `false`
    /// if an event already exists for this (node_id, scan_epoch) pair.
    ///
    /// This is the core uniqueness enforcement — the equivalent of a database
    /// unique constraint. If the key already exists, the insert is rejected.
    pub fn store_event(env: &Env, event: &SlashingEvent) -> bool {
        let key = SlashingDataKey::Event(event.node_id.clone(), event.scan_epoch);

        // UNIQUE CONSTRAINT: reject if event already exists for this node+epoch
        if env.storage().instance().has(&key) {
            return false;
        }

        env.storage().instance().set(&key, event);
        true
    }

    /// Retrieve a slashing event by node_id and scan_epoch.
    pub fn get_event(env: &Env, node_id: &Address, scan_epoch: u64) -> Option<SlashingEvent> {
        let key = SlashingDataKey::Event(node_id.clone(), scan_epoch);
        env.storage().instance().get(&key)
    }

    /// Update the status of an existing slashing event.
    pub fn update_event_status(
        env: &Env,
        node_id: &Address,
        scan_epoch: u64,
        new_status: SlashingEventStatus,
    ) {
        let key = SlashingDataKey::Event(node_id.clone(), scan_epoch);
        if let Some(mut event) = env
            .storage()
            .instance()
            .get::<SlashingDataKey, SlashingEvent>(&key)
        {
            event.status = new_status;
            env.storage().instance().set(&key, &event);
        }
    }
}
