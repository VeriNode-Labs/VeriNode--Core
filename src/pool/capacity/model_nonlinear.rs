//! Non-linear capacity model used by the local estimator (issue #139).
//!
//! The local estimator uses a richer model than the global coordinator's simple
//! linear average. It accounts for:
//!
//! * **GC-pause penalty** — a recent garbage-collection pause reduces reported
//!   available capacity by `(gc_pause_ms / 1000)` for the following
//!   [`GC_PENALTY_WINDOW_S`] seconds, reflecting that the node's throughput was
//!   reduced during the pause and may still be recovering.
//! * **NUMA penalty** — when tenants are spread across multiple NUMA nodes
//!   (`numa_node_count > 1`), cross-NUMA memory traffic inflates effective
//!   memory pressure non-linearly.  Each additional NUMA node above the first
//!   adds [`NUMA_PENALTY_PER_NODE`] to the model's memory overhead estimate,
//!   capped at a maximum total penalty of [`MAX_NUMA_PENALTY`].
//!
//! All arithmetic is integer-free where possible and the type depends only on
//! `alloc`, so it compiles under `no_std` / WASM.

use crate::pool::capacity::model_linear::ResourceMeasurements;

/// Duration (in seconds) over which a GC pause continues to reduce the
/// available-capacity estimate.
pub const GC_PENALTY_WINDOW_S: u64 = 10;

/// Per-extra-NUMA-node penalty added to effective memory utilization.
/// Two NUMA nodes → +5 % memory overhead; eight nodes → +35 % (capped).
pub const NUMA_PENALTY_PER_NODE: f64 = 0.05;

/// Maximum NUMA overhead penalty applied to memory utilization.
/// Caps at eight extra nodes (the issue's bound of 8 NUMA nodes per machine).
pub const MAX_NUMA_PENALTY: f64 = 0.35;

/// Output of the non-linear local capacity model.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct NonLinearCapacityEstimate {
    /// Estimated available capacity fraction in `[0.0, 1.0]`.
    pub available: f64,
    /// GC-pause penalty applied to this estimate (fractional capacity reduction).
    pub gc_penalty_applied: f64,
    /// NUMA penalty applied to effective memory utilization.
    pub numa_penalty_applied: f64,
}

/// Inputs to the non-linear local estimator.
#[derive(Clone, Copy, Debug)]
pub struct NonLinearInputs {
    /// Raw resource measurements from the node.
    pub measurements: ResourceMeasurements,
    /// Duration of the most recent GC pause, in milliseconds.
    pub gc_pause_ms: u64,
    /// Seconds elapsed since the most recent GC pause completed.
    pub secs_since_gc: u64,
    /// Number of NUMA nodes on this machine (`1..=8`).
    pub numa_node_count: u32,
}

/// Computes the non-linear local capacity estimate.
///
/// # GC-pause modeling
///
/// If `secs_since_gc < GC_PENALTY_WINDOW_S`, the estimate is reduced by
/// `gc_pause_ms / 1000` (clamped to `[0.0, 1.0]`), representing the fraction
/// of a full second the CPU was stalled.  This penalty applies for the next
/// `GC_PENALTY_WINDOW_S` seconds.
///
/// # NUMA penalty
///
/// Each NUMA node beyond the first contributes `NUMA_PENALTY_PER_NODE` to
/// effective memory utilization, capped at `MAX_NUMA_PENALTY`.
pub fn estimate_nonlinear(inputs: &NonLinearInputs) -> NonLinearCapacityEstimate {
    // --- GC penalty ---
    let gc_penalty = if inputs.secs_since_gc < GC_PENALTY_WINDOW_S {
        ((inputs.gc_pause_ms as f64) / 1000.0).clamp(0.0, 1.0)
    } else {
        0.0
    };

    // --- NUMA penalty on memory utilization ---
    let extra_nodes = inputs.numa_node_count.saturating_sub(1) as f64;
    let numa_penalty = (extra_nodes * NUMA_PENALTY_PER_NODE).min(MAX_NUMA_PENALTY);
    let effective_memory_util =
        (inputs.measurements.memory_utilization + numa_penalty).clamp(0.0, 1.0);

    // --- Weighted headroom (same weights as the linear model) ---
    const CPU_WEIGHT: f64 = 1.0 / 3.0;
    const MEM_WEIGHT: f64 = 1.0 / 3.0;
    const BW_WEIGHT: f64 = 1.0 / 3.0;

    let cpu_headroom = (1.0 - inputs.measurements.cpu_utilization).clamp(0.0, 1.0);
    let mem_headroom = (1.0 - effective_memory_util).clamp(0.0, 1.0);
    let bw_headroom = (1.0 - inputs.measurements.bandwidth_utilization).clamp(0.0, 1.0);

    let base_available =
        (CPU_WEIGHT * cpu_headroom + MEM_WEIGHT * mem_headroom + BW_WEIGHT * bw_headroom)
            .clamp(0.0, 1.0);

    // Apply GC penalty on top of the headroom-based estimate.
    let available = (base_available - gc_penalty).clamp(0.0, 1.0);

    NonLinearCapacityEstimate {
        available,
        gc_penalty_applied: gc_penalty,
        numa_penalty_applied: numa_penalty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_inputs() -> NonLinearInputs {
        NonLinearInputs {
            measurements: ResourceMeasurements {
                cpu_utilization: 0.0,
                memory_utilization: 0.0,
                bandwidth_utilization: 0.0,
            },
            gc_pause_ms: 0,
            secs_since_gc: GC_PENALTY_WINDOW_S, // outside window — no penalty
            numa_node_count: 1,
        }
    }

    #[test]
    fn idle_node_with_no_gc_reports_full_capacity() {
        let est = estimate_nonlinear(&base_inputs());
        assert!((est.available - 1.0).abs() < 1e-9);
        assert_eq!(est.gc_penalty_applied, 0.0);
        assert_eq!(est.numa_penalty_applied, 0.0);
    }

    #[test]
    fn gc_pause_inside_window_reduces_capacity() {
        let mut inp = base_inputs();
        inp.gc_pause_ms = 100;
        inp.secs_since_gc = 0; // just happened
        let est = estimate_nonlinear(&inp);
        // penalty = 100/1000 = 0.1; base = 1.0 → available = 0.9
        assert!((est.available - 0.9).abs() < 1e-9);
        assert!((est.gc_penalty_applied - 0.1).abs() < 1e-9);
    }

    #[test]
    fn gc_pause_outside_window_has_no_effect() {
        let mut inp = base_inputs();
        inp.gc_pause_ms = 500;
        inp.secs_since_gc = GC_PENALTY_WINDOW_S; // exactly at boundary — no penalty
        let est = estimate_nonlinear(&inp);
        assert!((est.available - 1.0).abs() < 1e-9);
        assert_eq!(est.gc_penalty_applied, 0.0);
    }

    #[test]
    fn eight_numa_nodes_applies_capped_penalty() {
        let mut inp = base_inputs();
        inp.numa_node_count = 8;
        let est = estimate_nonlinear(&inp);
        // 7 extra nodes * 0.05 = 0.35, capped at MAX_NUMA_PENALTY = 0.35
        assert!((est.numa_penalty_applied - MAX_NUMA_PENALTY).abs() < 1e-9);
        // memory headroom = 1.0 - 0.35 = 0.65; cpu+bw headroom = 1.0
        let expected_available = ((1.0f64 + 0.65 + 1.0) / 3.0).clamp(0.0, 1.0);
        assert!((est.available - expected_available).abs() < 1e-9);
    }

    #[test]
    fn single_numa_node_has_no_numa_penalty() {
        let inp = base_inputs(); // numa_node_count = 1
        let est = estimate_nonlinear(&inp);
        assert_eq!(est.numa_penalty_applied, 0.0);
    }

    #[test]
    fn gc_penalty_clamped_to_zero_at_bottom() {
        let mut inp = base_inputs();
        // 100% utilisation on all resources + large gc pause
        inp.measurements = ResourceMeasurements {
            cpu_utilization: 1.0,
            memory_utilization: 1.0,
            bandwidth_utilization: 1.0,
        };
        inp.gc_pause_ms = 2000; // penalty = 2.0, clamped to 1.0
        inp.secs_since_gc = 0;
        let est = estimate_nonlinear(&inp);
        assert_eq!(est.available, 0.0);
    }
}
