//! Local capacity estimator running on each shard node (issue #139).
//!
//! The local estimator runs every [`LOCAL_ESTIMATOR_INTERVAL_S`] second,
//! collects raw resource measurements (CPU, memory, bandwidth), applies the
//! non-linear model (GC-pause and NUMA corrections), and packages both the raw
//! measurements and the locally-computed non-linear estimate into a
//! [`LocalEstimatorSnapshot`] for forwarding to the global coordinator.
//!
//! Sending both raw measurements and the locally-computed estimate to the
//! coordinator is the core design change: it lets the coordinator detect how
//! much the two models have diverged and apply a correction factor rather than
//! using only the linear estimate.

use crate::pool::capacity::model_linear::{estimate_linear, ResourceMeasurements};
use crate::pool::capacity::model_nonlinear::{estimate_nonlinear, NonLinearInputs};

/// Local estimator update interval (1 second, per issue invariant).
pub const LOCAL_ESTIMATOR_INTERVAL_S: u64 = 1;

/// The maximum overcommit ratio: the coordinator will not assign more than
/// `1.2×` the reported physical capacity.
pub const MAX_OVERCOMMIT_RATIO: f64 = 1.2;

/// A snapshot produced by the local estimator and forwarded to the global
/// coordinator at each sync interval.
#[derive(Clone, Copy, Debug)]
pub struct LocalEstimatorSnapshot {
    /// Raw resource measurements at the time of sampling.
    pub measurements: ResourceMeasurements,
    /// Capacity estimate produced by the local non-linear model.
    pub estimate_local: f64,
    /// Capacity estimate produced by the linear model applied to the same raw
    /// measurements (provided so the coordinator can compute divergence without
    /// re-running the measurements).
    pub estimate_linear: f64,
    /// Timestamp (in seconds since some epoch) when the snapshot was produced.
    pub timestamp_s: u64,
}

/// Lightweight local capacity estimator.
///
/// Collects raw measurements on each call to [`update`] and produces a
/// [`LocalEstimatorSnapshot`] containing both the non-linear and linear
/// estimates of the same measurement set.
#[derive(Clone, Debug, Default)]
pub struct LocalEstimator {
    /// Most-recent snapshot (populated after the first call to `update`).
    last_snapshot: Option<LocalEstimatorSnapshot>,
}

impl LocalEstimator {
    /// Creates a new estimator with no prior snapshot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Samples current resource utilization and returns a [`LocalEstimatorSnapshot`]
    /// containing both the non-linear and linear capacity estimates.
    ///
    /// `inputs` carries the raw measurements plus GC-pause and NUMA metadata
    /// needed by the non-linear model. `now_s` is the current time in seconds.
    pub fn update(&mut self, inputs: NonLinearInputs, now_s: u64) -> LocalEstimatorSnapshot {
        let nonlinear = estimate_nonlinear(&inputs);
        let linear = estimate_linear(&inputs.measurements);

        let snapshot = LocalEstimatorSnapshot {
            measurements: inputs.measurements,
            estimate_local: nonlinear.available,
            estimate_linear: linear.available,
            timestamp_s: now_s,
        };
        self.last_snapshot = Some(snapshot);
        snapshot
    }

    /// Returns the most recently produced snapshot, if any.
    pub fn last_snapshot(&self) -> Option<LocalEstimatorSnapshot> {
        self.last_snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::capacity::model_nonlinear::GC_PENALTY_WINDOW_S;

    fn idle_inputs(_now_s: u64) -> NonLinearInputs {
        NonLinearInputs {
            measurements: ResourceMeasurements {
                cpu_utilization: 0.0,
                memory_utilization: 0.0,
                bandwidth_utilization: 0.0,
            },
            gc_pause_ms: 0,
            secs_since_gc: GC_PENALTY_WINDOW_S,
            numa_node_count: 1,
        }
    }

    #[test]
    fn idle_node_reports_full_capacity_for_both_models() {
        let mut est = LocalEstimator::new();
        let snap = est.update(idle_inputs(0), 0);
        assert!((snap.estimate_local - 1.0).abs() < 1e-9);
        assert!((snap.estimate_linear - 1.0).abs() < 1e-9);
    }

    #[test]
    fn snapshot_carries_raw_measurements() {
        let mut est = LocalEstimator::new();
        let mut inp = idle_inputs(10);
        inp.measurements.cpu_utilization = 0.4;
        let snap = est.update(inp, 10);
        assert!((snap.measurements.cpu_utilization - 0.4).abs() < 1e-9);
        assert_eq!(snap.timestamp_s, 10);
    }

    #[test]
    fn gc_pressure_makes_local_estimate_lower_than_linear() {
        let mut est = LocalEstimator::new();
        let inp = NonLinearInputs {
            measurements: ResourceMeasurements {
                cpu_utilization: 0.3,
                memory_utilization: 0.3,
                bandwidth_utilization: 0.3,
            },
            gc_pause_ms: 100, // 0.1 s pause penalty
            secs_since_gc: 0, // inside penalty window
            numa_node_count: 1,
        };
        let snap = est.update(inp, 5);
        // Linear model ignores GC; local model subtracts gc_penalty.
        assert!(snap.estimate_local < snap.estimate_linear);
    }

    #[test]
    fn last_snapshot_returns_most_recent() {
        let mut est = LocalEstimator::new();
        assert!(est.last_snapshot().is_none());
        est.update(idle_inputs(0), 0);
        assert!(est.last_snapshot().is_some());
        est.update(idle_inputs(1), 1);
        assert_eq!(est.last_snapshot().unwrap().timestamp_s, 1);
    }
}
