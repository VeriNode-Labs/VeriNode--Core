//! Global capacity coordinator (issue #139).
//!
//! The coordinator aggregates per-node [`LocalEstimatorSnapshot`]s received
//! every [`GLOBAL_COORDINATOR_SYNC_INTERVAL_S`] seconds and produces a
//! corrected global capacity estimate for scheduling.
//!
//! # Divergence correction
//!
//! Because the coordinator's linear model is simpler than the local non-linear
//! model, the two can produce different estimates for the same underlying
//! measurements. The coordinator applies a correction factor derived from the
//! difference that the local estimator already computed:
//!
//! ```text
//! capacity_global = capacity_local * (1 - |estimate_local - estimate_linear|)
//! ```
//!
//! This pulls the global estimate toward the more conservative local estimate
//! when the two models disagree.
//!
//! # Sustained-divergence warning
//!
//! If the divergence between `estimate_local` and `estimate_linear` exceeds
//! [`DIVERGENCE_TOLERANCE`] (10%) for [`DIVERGENCE_CONSECUTIVE_CYCLES`]
//! (3) consecutive sync cycles, the coordinator logs a
//! [`CapacityEvent::ModelDivergenceWarning`] and switches to using the more
//! conservative (lower) of the two estimates for that node.

use crate::pool::capacity::local_estimator::LocalEstimatorSnapshot;

/// Global coordinator sync interval (5 seconds, per issue invariant).
pub const GLOBAL_COORDINATOR_SYNC_INTERVAL_S: u64 = 5;

/// Maximum divergence between the local and global model estimates before a
/// warning is issued, expressed as an absolute fraction (`0.10` = 10%).
pub const DIVERGENCE_TOLERANCE: f64 = 0.10;

/// Number of consecutive sync cycles with divergence above tolerance before the
/// coordinator switches to the conservative estimate and logs a warning.
pub const DIVERGENCE_CONSECUTIVE_CYCLES: u32 = 3;

/// Events emitted by the global coordinator for monitoring and alerting.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CapacityEvent {
    /// A node's local and linear estimates have diverged beyond tolerance for
    /// [`DIVERGENCE_CONSECUTIVE_CYCLES`] consecutive cycles.
    ModelDivergenceWarning {
        /// The node that triggered the warning.
        node_id: u64,
        /// Absolute divergence magnitude at the time the warning fired.
        divergence: f64,
        /// The conservative (lower) estimate used after the warning.
        conservative_estimate: f64,
    },
    /// A node's divergence dropped back within tolerance after a warning.
    ModelConverged {
        /// The node that converged.
        node_id: u64,
    },
}

/// Per-node state tracked by the coordinator across sync cycles.
#[derive(Clone, Debug, Default)]
struct NodeState {
    /// Number of consecutive cycles in which divergence exceeded tolerance.
    consecutive_divergence_cycles: u32,
    /// Whether the coordinator is currently using the conservative estimate for
    /// this node.
    using_conservative: bool,
    /// Most-recent corrected capacity estimate for this node.
    corrected_capacity: f64,
}

/// Global capacity coordinator.
///
/// Call [`sync_node`] once per [`GLOBAL_COORDINATOR_SYNC_INTERVAL_S`]-second
/// sync cycle for each node whose snapshot arrived. The coordinator returns the
/// corrected global capacity estimate for that node and any events that fired.
#[derive(Clone, Debug, Default)]
pub struct GlobalCoordinator {
    /// Per-node tracking state, indexed by node ID.
    nodes: alloc::collections::BTreeMap<u64, NodeState>,
}

extern crate alloc;

impl GlobalCoordinator {
    /// Creates a new coordinator with no registered nodes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Processes a node's [`LocalEstimatorSnapshot`] for one sync cycle and
    /// returns the corrected global capacity estimate plus any events that fired.
    ///
    /// # Arguments
    ///
    /// * `node_id` — unique identifier for the shard node.
    /// * `snapshot` — the snapshot the node forwarded, containing both its raw
    ///   measurements and both model estimates.
    ///
    /// # Returns
    ///
    /// `(corrected_capacity, events)` where `corrected_capacity` is the global
    /// estimate for this node and `events` contains any
    /// [`CapacityEvent`]s triggered this cycle.
    pub fn sync_node(
        &mut self,
        node_id: u64,
        snapshot: &LocalEstimatorSnapshot,
    ) -> (f64, alloc::vec::Vec<CapacityEvent>) {
        let state = self.nodes.entry(node_id).or_default();
        let mut events = alloc::vec::Vec::new();

        // --- Divergence ---
        let abs_divergence = (snapshot.estimate_local - snapshot.estimate_linear).abs();
        let exceeded_tolerance = abs_divergence > DIVERGENCE_TOLERANCE;

        if exceeded_tolerance {
            state.consecutive_divergence_cycles += 1;
        } else {
            // Convergence: reset counter and clear conservative mode.
            if state.using_conservative {
                events.push(CapacityEvent::ModelConverged { node_id });
                state.using_conservative = false;
            }
            state.consecutive_divergence_cycles = 0;
        }

        // Emit warning and switch to conservative mode after 3 consecutive cycles.
        if state.consecutive_divergence_cycles >= DIVERGENCE_CONSECUTIVE_CYCLES
            && !state.using_conservative
        {
            let conservative_estimate = snapshot
                .estimate_local
                .min(snapshot.estimate_linear)
                .clamp(0.0, 1.0);
            events.push(CapacityEvent::ModelDivergenceWarning {
                node_id,
                divergence: abs_divergence,
                conservative_estimate,
            });
            state.using_conservative = true;
        }

        // --- Corrected capacity ---
        let corrected = if state.using_conservative {
            // Use the more conservative of the two estimates.
            snapshot
                .estimate_local
                .min(snapshot.estimate_linear)
                .clamp(0.0, 1.0)
        } else {
            // Apply correction factor based on model divergence:
            // capacity_global = capacity_local * (1 - |estimate_local - estimate_linear|)
            (snapshot.estimate_local * (1.0 - abs_divergence)).clamp(0.0, 1.0)
        };

        state.corrected_capacity = corrected;
        (corrected, events)
    }

    /// Returns the most-recent corrected capacity estimate for a node, or
    /// `None` if the node has not synced yet.
    pub fn corrected_capacity(&self, node_id: u64) -> Option<f64> {
        self.nodes.get(&node_id).map(|s| s.corrected_capacity)
    }

    /// Number of consecutive divergence cycles recorded for a node.
    pub fn consecutive_divergence_cycles(&self, node_id: u64) -> u32 {
        self.nodes
            .get(&node_id)
            .map_or(0, |s| s.consecutive_divergence_cycles)
    }

    /// Whether the coordinator is currently using the conservative estimate for
    /// a node.
    pub fn is_conservative(&self, node_id: u64) -> bool {
        self.nodes
            .get(&node_id)
            .map_or(false, |s| s.using_conservative)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::capacity::model_linear::ResourceMeasurements;

    fn snap(estimate_local: f64, estimate_linear: f64) -> LocalEstimatorSnapshot {
        LocalEstimatorSnapshot {
            measurements: ResourceMeasurements::default(),
            estimate_local,
            estimate_linear,
            timestamp_s: 0,
        }
    }

    #[test]
    fn no_divergence_uses_corrected_estimate() {
        let mut coord = GlobalCoordinator::new();
        // Both estimates equal → divergence = 0 → correction factor = 1.0
        let (cap, events) = coord.sync_node(1, &snap(0.8, 0.8));
        assert!((cap - 0.8).abs() < 1e-9);
        assert!(events.is_empty());
    }

    #[test]
    fn small_divergence_below_tolerance_does_not_warn() {
        let mut coord = GlobalCoordinator::new();
        let (_, events) = coord.sync_node(1, &snap(0.8, 0.75)); // diff = 0.05 < 0.10
        assert!(events.is_empty());
        assert_eq!(coord.consecutive_divergence_cycles(1), 0);
    }

    #[test]
    fn divergence_applies_correction_factor() {
        let mut coord = GlobalCoordinator::new();
        // estimate_local=0.8, estimate_linear=0.6 → |diff|=0.2
        // correction = 0.8 * (1 - 0.2) = 0.64
        let (cap, _) = coord.sync_node(1, &snap(0.8, 0.6));
        assert!((cap - 0.64).abs() < 1e-9);
    }

    #[test]
    fn three_consecutive_cycles_trigger_warning() {
        let mut coord = GlobalCoordinator::new();
        let s = snap(0.8, 0.6); // |diff| = 0.2 > 0.10

        let (_, ev1) = coord.sync_node(1, &s);
        assert!(ev1.is_empty()); // cycle 1
        let (_, ev2) = coord.sync_node(1, &s);
        assert!(ev2.is_empty()); // cycle 2
        let (_, ev3) = coord.sync_node(1, &s);
        // cycle 3 — warning fires
        assert_eq!(ev3.len(), 1);
        assert!(matches!(
            ev3[0],
            CapacityEvent::ModelDivergenceWarning { node_id: 1, .. }
        ));
        assert!(coord.is_conservative(1));
    }

    #[test]
    fn conservative_mode_uses_minimum_of_two_estimates() {
        let mut coord = GlobalCoordinator::new();
        let s = snap(0.8, 0.6);
        // Push into conservative mode.
        for _ in 0..DIVERGENCE_CONSECUTIVE_CYCLES {
            coord.sync_node(1, &s);
        }
        assert!(coord.is_conservative(1));
        // min(0.8, 0.6) = 0.6
        let (cap, _) = coord.sync_node(1, &s);
        assert!((cap - 0.6).abs() < 1e-9);
    }

    #[test]
    fn convergence_after_warning_emits_converged_event_and_clears_conservative() {
        let mut coord = GlobalCoordinator::new();
        let diverged = snap(0.8, 0.6);
        for _ in 0..DIVERGENCE_CONSECUTIVE_CYCLES {
            coord.sync_node(1, &diverged);
        }
        assert!(coord.is_conservative(1));

        // Convergence: both estimates within tolerance.
        let converged = snap(0.75, 0.73); // |diff| = 0.02 < 0.10
        let (_, events) = coord.sync_node(1, &converged);
        assert!(events
            .iter()
            .any(|e| matches!(e, CapacityEvent::ModelConverged { node_id: 1 })));
        assert!(!coord.is_conservative(1));
        assert_eq!(coord.consecutive_divergence_cycles(1), 0);
    }

    #[test]
    fn multiple_nodes_are_tracked_independently() {
        let mut coord = GlobalCoordinator::new();
        let diverged = snap(0.9, 0.5);
        // Push node 1 into conservative mode.
        for _ in 0..DIVERGENCE_CONSECUTIVE_CYCLES {
            coord.sync_node(1, &diverged);
        }
        // Node 2 has never synced.
        assert!(coord.is_conservative(1));
        assert!(!coord.is_conservative(2));
        coord.sync_node(2, &snap(0.8, 0.8));
        assert!(!coord.is_conservative(2));
        // Node 1 still conservative.
        assert!(coord.is_conservative(1));
    }
}
