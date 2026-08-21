//! Linear capacity model used by the global coordinator (issue #139).
//!
//! The coordinator uses a simple linear model: available capacity is the sum of
//! each resource's headroom scaled by a fixed weight, with no non-linear
//! correction terms. This is fast and predictable but diverges from the local
//! estimator when GC pauses, NUMA topology, or other non-linear overheads
//! dominate.

/// Resources measured per shard node.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ResourceMeasurements {
    /// CPU utilization fraction in `[0.0, 1.0]`.
    pub cpu_utilization: f64,
    /// Memory utilization fraction in `[0.0, 1.0]`.
    pub memory_utilization: f64,
    /// Bandwidth utilization fraction in `[0.0, 1.0]`.
    pub bandwidth_utilization: f64,
}

/// Output of the linear capacity model: a capacity estimate in `[0.0, 1.0]`
/// representing the fraction of physical capacity currently available.
///
/// `1.0` is completely idle (full capacity); `0.0` is fully saturated.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct LinearCapacityEstimate {
    /// Estimated available capacity fraction.
    pub available: f64,
}

/// Estimates available capacity using a simple weighted-average linear model.
///
/// Weights for CPU, memory, and bandwidth are equal by default. The estimate is
/// the weighted average of each resource's headroom (`1.0 - utilization`),
/// clamped to `[0.0, 1.0]`.
pub fn estimate_linear(measurements: &ResourceMeasurements) -> LinearCapacityEstimate {
    // Equal weights for all three resource dimensions.
    const CPU_WEIGHT: f64 = 1.0 / 3.0;
    const MEM_WEIGHT: f64 = 1.0 / 3.0;
    const BW_WEIGHT: f64 = 1.0 / 3.0;

    let cpu_headroom = (1.0 - measurements.cpu_utilization).clamp(0.0, 1.0);
    let mem_headroom = (1.0 - measurements.memory_utilization).clamp(0.0, 1.0);
    let bw_headroom = (1.0 - measurements.bandwidth_utilization).clamp(0.0, 1.0);

    let available =
        (CPU_WEIGHT * cpu_headroom + MEM_WEIGHT * mem_headroom + BW_WEIGHT * bw_headroom)
            .clamp(0.0, 1.0);

    LinearCapacityEstimate { available }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_node_reports_full_capacity() {
        let m = ResourceMeasurements {
            cpu_utilization: 0.0,
            memory_utilization: 0.0,
            bandwidth_utilization: 0.0,
        };
        let est = estimate_linear(&m);
        assert!((est.available - 1.0).abs() < 1e-9);
    }

    #[test]
    fn saturated_node_reports_zero_capacity() {
        let m = ResourceMeasurements {
            cpu_utilization: 1.0,
            memory_utilization: 1.0,
            bandwidth_utilization: 1.0,
        };
        let est = estimate_linear(&m);
        assert!(est.available.abs() < 1e-9);
    }

    #[test]
    fn fifty_percent_utilization_gives_half_capacity() {
        let m = ResourceMeasurements {
            cpu_utilization: 0.5,
            memory_utilization: 0.5,
            bandwidth_utilization: 0.5,
        };
        let est = estimate_linear(&m);
        assert!((est.available - 0.5).abs() < 1e-9);
    }

    #[test]
    fn out_of_bounds_utilization_is_clamped() {
        let m = ResourceMeasurements {
            cpu_utilization: 1.5,
            memory_utilization: -0.1,
            bandwidth_utilization: 0.5,
        };
        let est = estimate_linear(&m);
        // cpu_headroom = 0.0, mem_headroom = 1.0, bw_headroom = 0.5
        let expected = (0.0f64 + 1.0 + 0.5) / 3.0;
        assert!((est.available - expected).abs() < 1e-9);
    }
}
