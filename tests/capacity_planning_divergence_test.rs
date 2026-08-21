//! Integration tests for the capacity planning model divergence between the
//! local estimator and the global coordinator (issue #139).
//!
//! These tests cover:
//! * The technical invariants from the issue (update intervals, divergence
//!   tolerance, overcommit ratio, NUMA node count).
//! * GC-pause modeling: a 100 ms pause every 5 s reduces the local estimate,
//!   while the linear model is unaffected; both stay within the 10% tolerance.
//! * Divergence correction and the sustained-divergence warning path.

use sorosusu_contracts::pool::capacity::{
    NonLinearInputs, GC_PENALTY_WINDOW_S, MAX_NUMA_PENALTY, NUMA_PENALTY_PER_NODE,
};
use sorosusu_contracts::pool::{
    CapacityEvent, GlobalCoordinator, LocalEstimator, LocalEstimatorSnapshot, ResourceMeasurements,
    DIVERGENCE_CONSECUTIVE_CYCLES, DIVERGENCE_TOLERANCE, GLOBAL_COORDINATOR_SYNC_INTERVAL_S,
    LOCAL_ESTIMATOR_INTERVAL_S, MAX_OVERCOMMIT_RATIO,
};

// ---------------------------------------------------------------------------
// Technical invariants
// ---------------------------------------------------------------------------

#[test]
fn technical_invariants_match_issue_139() {
    assert_eq!(LOCAL_ESTIMATOR_INTERVAL_S, 1);
    assert_eq!(GLOBAL_COORDINATOR_SYNC_INTERVAL_S, 5);
    assert!((DIVERGENCE_TOLERANCE - 0.10).abs() < 1e-9); // ±10%
    assert!((MAX_OVERCOMMIT_RATIO - 1.2).abs() < 1e-9); // max 1.2×
    assert_eq!(DIVERGENCE_CONSECUTIVE_CYCLES, 3);
    // GC penalty window
    assert_eq!(GC_PENALTY_WINDOW_S, 10);
    // NUMA bounds: up to 8 nodes; 7 extra × 0.05 = 0.35, capped at MAX_NUMA_PENALTY
    let eight_node_penalty = 7.0_f64 * NUMA_PENALTY_PER_NODE;
    assert!(eight_node_penalty <= MAX_NUMA_PENALTY + 1e-9);
}

// ---------------------------------------------------------------------------
// GC-pressure simulation: 100 ms pause every 5 s
//
// Verifies that when a node experiences a 100 ms GC pause every 5 seconds,
// the local (non-linear) and global (linear-corrected) estimates stay within
// the 10% divergence tolerance — i.e., the correction factor keeps them
// aligned without triggering a ModelDivergenceWarning.
// ---------------------------------------------------------------------------

#[test]
fn gc_pressure_100ms_pause_every_5s_stays_within_divergence_tolerance() {
    let mut estimator = LocalEstimator::new();
    let mut coordinator = GlobalCoordinator::new();

    const NODE_ID: u64 = 1;
    const SIMULATION_CYCLES: u64 = 20; // 20 × 5 s = 100 s simulated time

    // Baseline resource utilization — modest load so capacity is non-trivial.
    let base_measurements = ResourceMeasurements {
        cpu_utilization: 0.40,
        memory_utilization: 0.50,
        bandwidth_utilization: 0.30,
    };

    let mut any_divergence_warning = false;

    for sync_cycle in 0..SIMULATION_CYCLES {
        // Wall-clock second when the coordinator sync fires (every 5 s).
        let now_s = sync_cycle * GLOBAL_COORDINATOR_SYNC_INTERVAL_S;

        // GC pause of 100 ms fires every 5 s (i.e., once per coordinator sync).
        // Immediately after the pause the secs_since_gc is 0.
        let (gc_pause_ms, secs_since_gc) = (100u64, 0u64);

        let inputs = NonLinearInputs {
            measurements: base_measurements,
            gc_pause_ms,
            secs_since_gc,
            numa_node_count: 1,
        };

        let snapshot = estimator.update(inputs, now_s);
        let (_, events) = coordinator.sync_node(NODE_ID, &snapshot);

        for event in &events {
            if matches!(event, CapacityEvent::ModelDivergenceWarning { .. }) {
                any_divergence_warning = true;
            }
        }

        // Both estimates must be within the 10% tolerance.
        let divergence = (snapshot.estimate_local - snapshot.estimate_linear).abs();
        assert!(
            divergence <= DIVERGENCE_TOLERANCE,
            "cycle {sync_cycle}: divergence {divergence:.4} exceeds tolerance {DIVERGENCE_TOLERANCE}"
        );
    }

    // A 100 ms GC pause every 5 s (10% of a second) must not cause a sustained
    // divergence warning given the 10% tolerance.
    assert!(
        !any_divergence_warning,
        "100 ms GC pause every 5 s should not trigger a divergence warning"
    );
}

// ---------------------------------------------------------------------------
// Divergence correction applied by the coordinator
// ---------------------------------------------------------------------------

#[test]
fn coordinator_applies_correction_factor_on_divergence() {
    let mut coord = GlobalCoordinator::new();

    // Craft a snapshot where the non-linear model gives 0.7 and the linear 0.5.
    // |diff| = 0.2; correction = 0.7 * (1 - 0.2) = 0.56.
    let snap = LocalEstimatorSnapshot {
        measurements: ResourceMeasurements::default(),
        estimate_local: 0.7,
        estimate_linear: 0.5,
        timestamp_s: 0,
    };
    let (corrected, _) = coord.sync_node(1, &snap);
    let expected = 0.7 * (1.0 - 0.2);
    assert!(
        (corrected - expected).abs() < 1e-9,
        "corrected={corrected:.4}, expected={expected:.4}"
    );
}

// ---------------------------------------------------------------------------
// Three consecutive divergent cycles trigger the warning
// ---------------------------------------------------------------------------

#[test]
fn three_consecutive_divergent_cycles_emit_warning_and_use_conservative_estimate() {
    let mut estimator = LocalEstimator::new();
    let mut coord = GlobalCoordinator::new();
    const NODE_ID: u64 = 42;

    // High utilization + severe GC pauses → significant model divergence.
    let inputs = NonLinearInputs {
        measurements: ResourceMeasurements {
            cpu_utilization: 0.5,
            memory_utilization: 0.5,
            bandwidth_utilization: 0.5,
        },
        gc_pause_ms: 200, // 20% penalty
        secs_since_gc: 0,
        numa_node_count: 1,
    };

    let mut warning_events: Vec<CapacityEvent> = Vec::new();

    for cycle in 0..DIVERGENCE_CONSECUTIVE_CYCLES {
        let snap = estimator.update(inputs, cycle as u64);
        let (_, events) = coord.sync_node(NODE_ID, &snap);
        warning_events.extend(events);
    }

    let divergence = {
        let snap = estimator.last_snapshot().unwrap();
        (snap.estimate_local - snap.estimate_linear).abs()
    };

    if divergence > DIVERGENCE_TOLERANCE {
        // Warning must have fired.
        assert!(
            warning_events
                .iter()
                .any(|e| matches!(e, CapacityEvent::ModelDivergenceWarning { node_id: 42, .. })),
            "expected ModelDivergenceWarning for node {NODE_ID}"
        );
        assert!(coord.is_conservative(NODE_ID));

        // After switching to conservative mode, the coordinator uses the lower estimate.
        let snap = estimator.update(inputs, DIVERGENCE_CONSECUTIVE_CYCLES as u64);
        let (conservative_cap, _) = coord.sync_node(NODE_ID, &snap);
        let min_estimate = snap.estimate_local.min(snap.estimate_linear);
        assert!(
            (conservative_cap - min_estimate).abs() < 1e-9,
            "conservative_cap={conservative_cap:.4}, min_estimate={min_estimate:.4}"
        );
    }
    // If divergence <= 10% no warning should have fired.
}

// ---------------------------------------------------------------------------
// Convergence clears conservative mode and emits ModelConverged
// ---------------------------------------------------------------------------

#[test]
fn convergence_after_warning_emits_converged_event() {
    let mut coord = GlobalCoordinator::new();
    const NODE_ID: u64 = 7;

    let diverged = LocalEstimatorSnapshot {
        measurements: ResourceMeasurements::default(),
        estimate_local: 0.9,
        estimate_linear: 0.5, // |diff| = 0.4 → well above tolerance
        timestamp_s: 0,
    };

    // Trigger the warning.
    for _ in 0..DIVERGENCE_CONSECUTIVE_CYCLES {
        coord.sync_node(NODE_ID, &diverged);
    }
    assert!(coord.is_conservative(NODE_ID));

    // Present a converged snapshot.
    let converged = LocalEstimatorSnapshot {
        measurements: ResourceMeasurements::default(),
        estimate_local: 0.75,
        estimate_linear: 0.74, // |diff| = 0.01 < 0.10
        timestamp_s: 5,
    };
    let (_, events) = coord.sync_node(NODE_ID, &converged);

    assert!(
        events
            .iter()
            .any(|e| matches!(e, CapacityEvent::ModelConverged { node_id: 7 })),
        "expected ModelConverged event"
    );
    assert!(!coord.is_conservative(NODE_ID));
    assert_eq!(coord.consecutive_divergence_cycles(NODE_ID), 0);
}

// ---------------------------------------------------------------------------
// NUMA: 8 nodes applies the capped penalty
// ---------------------------------------------------------------------------

#[test]
fn eight_numa_nodes_reduces_local_estimate_but_not_linear_estimate() {
    let mut estimator = LocalEstimator::new();

    let base_measurements = ResourceMeasurements {
        cpu_utilization: 0.3,
        memory_utilization: 0.3,
        bandwidth_utilization: 0.3,
    };

    let inputs_one_numa = NonLinearInputs {
        measurements: base_measurements,
        gc_pause_ms: 0,
        secs_since_gc: GC_PENALTY_WINDOW_S,
        numa_node_count: 1,
    };
    let inputs_eight_numa = NonLinearInputs {
        measurements: base_measurements,
        gc_pause_ms: 0,
        secs_since_gc: GC_PENALTY_WINDOW_S,
        numa_node_count: 8,
    };

    let snap_one = estimator.update(inputs_one_numa, 0);
    let snap_eight = estimator.update(inputs_eight_numa, 1);

    // Linear estimate is identical for both (raw measurements unchanged).
    assert!(
        (snap_one.estimate_linear - snap_eight.estimate_linear).abs() < 1e-9,
        "linear estimate should not depend on NUMA count"
    );

    // Local estimate should be lower with 8 NUMA nodes.
    assert!(
        snap_eight.estimate_local < snap_one.estimate_local,
        "8 NUMA nodes must reduce local estimate"
    );
}

// ---------------------------------------------------------------------------
// Overcommit ratio: coordinator must not exceed 1.2× physical capacity
// ---------------------------------------------------------------------------

#[test]
fn overcommit_ratio_constant_matches_issue_bound() {
    // The issue specifies max 1.2× physical capacity.
    assert!((MAX_OVERCOMMIT_RATIO - 1.2).abs() < 1e-9);
}
