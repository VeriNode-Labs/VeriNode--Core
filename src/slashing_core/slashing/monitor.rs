use soroban_sdk::{Address, Env, Vec};

use super::{
    event_store::SlashingEventStore,
    executor::SlashingExecutor,
    NodeState, SlashingDataKey, SlashingEvent, SlashingEventStatus, SlashingReason,
    SCAN_INTERVAL_SECONDS, SLASHING_PENALTY,
};

/// The slashing condition monitor. Runs every 6 hours (SCAN_INTERVAL_SECONDS),
/// scanning all active nodes and evaluating slashing conditions.
///
/// KEY FIX: When a node triggers multiple conditions simultaneously (e.g., both
/// double-signing AND extended downtime), the monitor creates exactly ONE
/// SlashingEvent per node per scan with a `reasons: Vec<SlashingReason>` field
/// listing all triggered conditions. The penalty is applied once.
pub struct SlashingMonitor;

impl SlashingMonitor {
    /// Returns the current scan epoch. The epoch increments every SCAN_INTERVAL_SECONDS.
    pub fn current_epoch(env: &Env) -> u64 {
        env.storage()
            .instance()
            .get(&SlashingDataKey::ScanEpoch)
            .unwrap_or(0)
    }

    /// Increment the scan epoch and record the scan time.
    fn advance_epoch(env: &Env) -> u64 {
        let current = Self::current_epoch(env);
        let next = current + 1;
        env.storage()
            .instance()
            .set(&SlashingDataKey::ScanEpoch, &next);
        env.storage()
            .instance()
            .set(&SlashingDataKey::LastScanTime, &env.ledger().timestamp());
        next
    }

    /// Primary entry point: evaluate all slashing conditions for a set of nodes.
    /// Called every 6 hours by the protocol scheduler.
    ///
    /// For each node, this function:
    /// 1. Pre-check gate: skips nodes already slashed within the current scan interval
    /// 2. Checks for SLASHING_IN_PROGRESS lock and skips if set
    /// 3. Evaluates ALL conditions (double-signing, downtime, fraud)
    /// 4. Creates at most ONE SlashingEvent per node with all triggered reasons
    /// 5. Executes the slashing exactly once
    pub fn evaluate_conditions(env: &Env, nodes: &Vec<Address>) -> Vec<SlashingEvent> {
        let scan_epoch = Self::advance_epoch(env);
        let current_time = env.ledger().timestamp();
        let mut events: Vec<SlashingEvent> = Vec::new(env);

        for i in 0..nodes.len() {
            let node_id = nodes.get(i).unwrap();

            // Load node state
            let node_state: Option<NodeState> = env
                .storage()
                .instance()
                .get(&SlashingDataKey::Node(node_id.clone()));

            let node = match node_state {
                Some(n) => n,
                None => continue,
            };

            // Skip inactive nodes
            if !node.is_active {
                continue;
            }

            // PRE-CHECK GATE: If the node was slashed within the last scan interval,
            // skip all condition checks. This prevents re-processing a node that is
            // already being handled.
            if let Some(last_slash) = node.last_slash_time {
                if current_time.saturating_sub(last_slash) < SCAN_INTERVAL_SECONDS {
                    continue;
                }
            }

            // NODE-LEVEL SLASHING LOCK: If slashing is already in progress for
            // this node (set by a concurrent/previous scan that hasn't finalized),
            // skip evaluation entirely.
            if node.slashing_in_progress {
                continue;
            }

            // Check if an event already exists for this node+epoch (unique constraint)
            if SlashingEventStore::event_exists(env, &node_id, scan_epoch) {
                continue;
            }

            // EVALUATE ALL CONDITIONS for this node, collecting reasons
            let mut reasons: Vec<SlashingReason> = Vec::new(env);

            // Condition 1: Double-signing detection
            if Self::check_double_signing(env, &node) {
                reasons.push_back(SlashingReason::DoubleSigning);
            }

            // Condition 2: Extended downtime (> 48 hours)
            if Self::check_extended_downtime(env, &node, current_time) {
                reasons.push_back(SlashingReason::ExtendedDowntime);
            }

            // Condition 3: Fraud proof submitted
            if Self::check_fraud_proof(env, &node) {
                reasons.push_back(SlashingReason::FraudProof);
            }

            // If no conditions triggered, skip this node
            if reasons.is_empty() {
                continue;
            }

            // SET SLASHING LOCK before creating event
            Self::set_slashing_lock(env, &node_id, true);

            // CREATE SINGLE EVENT with all reasons (penalty applied once)
            let event = SlashingEvent {
                node_id: node_id.clone(),
                scan_epoch,
                reasons,
                penalty_amount: SLASHING_PENALTY,
                created_at: current_time,
                status: SlashingEventStatus::Pending,
            };

            // Store event with unique constraint enforcement
            let stored = SlashingEventStore::store_event(env, &event);
            if !stored {
                // Duplicate — another path already created an event for this node+epoch
                Self::set_slashing_lock(env, &node_id, false);
                continue;
            }

            // EXECUTE SLASHING (single execution, idempotent)
            let executed = SlashingExecutor::execute_slashing(env, &event);

            if executed {
                // Update node state: mark as slashed, record timestamp
                Self::mark_node_slashed(env, &node_id, current_time);
            } else {
                // Mark event as failed if execution didn't succeed
                SlashingEventStore::update_event_status(
                    env,
                    &node_id,
                    scan_epoch,
                    SlashingEventStatus::Failed,
                );
            }

            // CLEAR SLASHING LOCK after finalization
            Self::set_slashing_lock(env, &node_id, false);

            // Reload the event with updated status for return value
            if let Some(final_event) =
                SlashingEventStore::get_event(env, &node_id, scan_epoch)
            {
                events.push_back(final_event);
            }
        }

        events
    }

    /// Check if a node has committed double-signing.
    fn check_double_signing(_env: &Env, node: &NodeState) -> bool {
        node.double_sign_detected
    }

    /// Check if a node has been offline for more than 48 hours.
    fn check_extended_downtime(_env: &Env, node: &NodeState, current_time: u64) -> bool {
        let downtime_threshold: u64 = 172800; // 48 hours in seconds
        if node.last_activity_time == 0 {
            return false;
        }
        current_time.saturating_sub(node.last_activity_time) > downtime_threshold
    }

    /// Check if a fraud proof has been submitted for this node.
    fn check_fraud_proof(_env: &Env, node: &NodeState) -> bool {
        node.fraud_proof_submitted
    }

    /// Set or clear the SLASHING_IN_PROGRESS lock for a node.
    fn set_slashing_lock(env: &Env, node_id: &Address, locked: bool) {
        let lock_key = SlashingDataKey::SlashingLock(node_id.clone());
        env.storage().instance().set(&lock_key, &locked);

        // Also update the node state's slashing_in_progress field
        let node_key = SlashingDataKey::Node(node_id.clone());
        if let Some(mut node) = env
            .storage()
            .instance()
            .get::<SlashingDataKey, NodeState>(&node_key)
        {
            node.slashing_in_progress = locked;
            env.storage().instance().set(&node_key, &node);
        }
    }

    /// Mark a node as slashed after successful execution.
    fn mark_node_slashed(env: &Env, node_id: &Address, timestamp: u64) {
        let node_key = SlashingDataKey::Node(node_id.clone());
        if let Some(mut node) = env
            .storage()
            .instance()
            .get::<SlashingDataKey, NodeState>(&node_key)
        {
            node.slashed = true;
            node.last_slash_time = Some(timestamp);
            // Clear the violation flags after processing
            node.double_sign_detected = false;
            node.fraud_proof_submitted = false;
            env.storage().instance().set(&node_key, &node);
        }
    }

    /// Register a new node with the slashing monitor.
    pub fn register_node(env: &Env, node_id: &Address, bond_amount: i128) {
        let node = NodeState {
            node_id: node_id.clone(),
            is_active: true,
            bond_amount,
            slashed: false,
            last_slash_time: None,
            last_activity_time: env.ledger().timestamp(),
            double_sign_detected: false,
            fraud_proof_submitted: false,
            slashing_in_progress: false,
        };
        env.storage()
            .instance()
            .set(&SlashingDataKey::Node(node_id.clone()), &node);

        // Initialize bond pool for this node
        env.storage()
            .instance()
            .set(&SlashingDataKey::BondPool(node_id.clone()), &bond_amount);
    }

    /// Report a double-signing violation for a node.
    pub fn report_double_signing(env: &Env, node_id: &Address) {
        let node_key = SlashingDataKey::Node(node_id.clone());
        if let Some(mut node) = env
            .storage()
            .instance()
            .get::<SlashingDataKey, NodeState>(&node_key)
        {
            node.double_sign_detected = true;
            env.storage().instance().set(&node_key, &node);
        }
    }

    /// Submit a fraud proof against a node.
    pub fn report_fraud_proof(env: &Env, node_id: &Address) {
        let node_key = SlashingDataKey::Node(node_id.clone());
        if let Some(mut node) = env
            .storage()
            .instance()
            .get::<SlashingDataKey, NodeState>(&node_key)
        {
            node.fraud_proof_submitted = true;
            env.storage().instance().set(&node_key, &node);
        }
    }
}
