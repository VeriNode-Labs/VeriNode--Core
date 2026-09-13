//! Automated Performance Regression Detection in CI Pipeline (issue #133).
//!
//! This module provides deterministic, dependency-free primitives for detecting
//! performance regressions across all VeriNode services in CI pipelines and
//! canary rollouts. All math is pure Rust — no external runtimes or network I/O —
//! so on-chain contracts, off-chain monitoring agents, CI runners, and blue-green
//! deployment gates share exactly the same thresholds and evaluation logic.
//!
//! # Design overview
//!
//! ```text
//!  ┌─────────────────────────┐  perf samples  ┌──────────────────────────────┐
//!  │   PerformanceSample     │ ─────────────▶  RegressionDetector             │
//!  │   (per service & path)  │                 │  • evaluate_sample()         │
//!  │                         │                 │  • evaluate_suite()          │
//!  └─────────────────────────┘                 └──────────────┬───────────────┘
//!                                                             │ PerfRegressionReport
//!                                                             ▼
//!                                              ┌──────────────────────────────┐
//!                                              │  CanaryPerformanceGate       │
//!                                              │  • evaluate_gate()           │
//!                                              │  • Blue-Green / Canary gates │
//!                                              └──────────────┬───────────────┘
//!                                                             │ GateDecision
//!                                                             ▼
//!                                              ┌──────────────────────────────┐
//!                                              │  PerformanceDashboard       │
//!                                              │  • AlertSignal: Pager / Ticket│
//!                                              └──────────────────────────────┘
//! ```
//!
//! # Technical Bounds (mandated by Issue #133)
//!
//! * Critical-path latency target: P99 < 100 ms ([`CRITICAL_PATH_P99_TARGET_MS`])
//! * Platform availability target: 99.99% ([`AVAILABILITY_TARGET_BPS`])
//! * Scope: System-wide implementation affecting all services
//! * Security: All changes must pass security review before canary promotion

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Operational Constants
// ---------------------------------------------------------------------------

/// P99 latency SLA limit for critical paths, in milliseconds.
pub const CRITICAL_PATH_P99_TARGET_MS: u64 = 100;

/// Availability target expressed in basis points: 99.99% (9_999 bps).
pub const AVAILABILITY_TARGET_BPS: u32 = 9_999;

/// Default allowable regression tolerance before raising a warning, in basis points (5.00%).
pub const DEFAULT_MAX_REGRESSION_BPS: u32 = 500;

/// Regression tolerance threshold that immediately blocks CI / deployment, in basis points (15.00%).
pub const BLOCKER_REGRESSION_BPS: u32 = 1_500;

/// Minimum number of samples required for statistically valid evaluation.
pub const MIN_SAMPLE_COUNT: u64 = 50;

/// Maximum number of distinct service paths tracked concurrently.
pub const MAX_TRACKED_PATHS: usize = 512;

// ---------------------------------------------------------------------------
// Metric and Path Identifiers
// ---------------------------------------------------------------------------

/// Canonical critical paths across the VeriNode architecture.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum CriticalPath {
    /// Consensus block proposal and validation path.
    BlockProposal,
    /// BLS attestation signature aggregation path.
    AttestationAggregation,
    /// Mempool transaction validation and priority queueing.
    MempoolIngestion,
    /// Beacon state epoch transition and slashing evaluation.
    StateEpochTransition,
    /// Cross-chain light-client header verification and finality check.
    CrossChainVerification,
    /// Custom path identifier for service-specific critical paths.
    Custom(String),
}

impl CriticalPath {
    /// Human-readable identifier for the critical path.
    pub fn as_str(&self) -> &str {
        match self {
            CriticalPath::BlockProposal => "consensus.block_proposal",
            CriticalPath::AttestationAggregation => "attestation.aggregation",
            CriticalPath::MempoolIngestion => "mempool.ingestion",
            CriticalPath::StateEpochTransition => "state.epoch_transition",
            CriticalPath::CrossChainVerification => "cross_chain.verification",
            CriticalPath::Custom(s) => s.as_str(),
        }
    }

    /// Whether this path is subject to the hard <100ms P99 SLA.
    pub fn is_critical_path(&self) -> bool {
        true
    }
}

/// Performance metric kinds tracked by regression detection.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum MetricKind {
    /// P50 median latency in milliseconds.
    LatencyP50,
    /// P95 latency in milliseconds.
    LatencyP95,
    /// P99 tail latency in milliseconds (hard bound: <100ms).
    LatencyP99,
    /// Processing throughput in operations per second.
    ThroughputOps,
    /// Heap memory allocation in bytes.
    AllocatedBytes,
    /// CPU utilization in basis points (100% = 10,000 bps).
    CpuUtilizationBps,
}

impl MetricKind {
    /// Human-readable metric name.
    pub fn as_str(&self) -> &str {
        match self {
            MetricKind::LatencyP50 => "latency_p50_ms",
            MetricKind::LatencyP95 => "latency_p95_ms",
            MetricKind::LatencyP99 => "latency_p99_ms",
            MetricKind::ThroughputOps => "throughput_ops_per_sec",
            MetricKind::AllocatedBytes => "memory_allocated_bytes",
            MetricKind::CpuUtilizationBps => "cpu_utilization_bps",
        }
    }

    /// Whether an increase in value indicates a regression (true for latency/memory/cpu, false for throughput).
    pub fn higher_is_worse(&self) -> bool {
        match self {
            MetricKind::LatencyP50
            | MetricKind::LatencyP95
            | MetricKind::LatencyP99
            | MetricKind::AllocatedBytes
            | MetricKind::CpuUtilizationBps => true,
            MetricKind::ThroughputOps => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Performance Samples and Baselines
// ---------------------------------------------------------------------------

/// Point-in-time performance observation for a specific path and service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerformanceSample {
    /// Service name (e.g., "consensus", "mempool", "indexer").
    pub service: String,
    /// Critical path being evaluated.
    pub path: CriticalPath,
    /// Metric being measured.
    pub metric: MetricKind,
    /// Observed metric value.
    pub value: u64,
    /// Number of observations collected to produce this value.
    pub sample_count: u64,
    /// Unix timestamp when sample was gathered.
    pub timestamp_secs: u64,
}

impl PerformanceSample {
    /// Generates a unique tracking key for baseline map indexing.
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.service,
            self.path.as_str(),
            self.metric.as_str()
        )
    }
}

/// Approved baseline performance profile against which candidate runs are evaluated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaselineProfile {
    /// Service name.
    pub service: String,
    /// Critical path.
    pub path: CriticalPath,
    /// Metric kind.
    pub metric: MetricKind,
    /// Baseline target value.
    pub baseline_value: u64,
    /// Maximum allowable regression in basis points (e.g., 500 = 5.00%).
    pub tolerance_bps: u32,
    /// Optional hard ceiling limit (e.g., 100ms for P99).
    pub hard_ceiling: Option<u64>,
    /// Last update timestamp.
    pub updated_at_secs: u64,
}

impl BaselineProfile {
    /// Creates a baseline profile with default tolerances.
    pub fn new(service: &str, path: CriticalPath, metric: MetricKind, baseline_value: u64) -> Self {
        let hard_ceiling = if metric == MetricKind::LatencyP99 && path.is_critical_path() {
            Some(CRITICAL_PATH_P99_TARGET_MS)
        } else {
            None
        };

        Self {
            service: String::from(service),
            path,
            metric,
            baseline_value,
            tolerance_bps: DEFAULT_MAX_REGRESSION_BPS,
            hard_ceiling,
            updated_at_secs: 0,
        }
    }

    /// Tracking key for the baseline profile.
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.service,
            self.path.as_str(),
            self.metric.as_str()
        )
    }
}

// ---------------------------------------------------------------------------
// Regression Evaluation and Verdicts
// ---------------------------------------------------------------------------

/// Severity level of a detected performance regression.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RegressionSeverity {
    /// Within allowable baseline tolerance (no regression).
    None,
    /// Minor drift (exceeds tolerance but within blocker limits).
    Warning,
    /// Severe degradation requiring engineer attention.
    Critical,
    /// Fatal violation (P99 >= 100ms or regression > blocker threshold); halts CI and rollout.
    Blocker,
}

/// Evaluation verdict for a single performance sample against its baseline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegressionVerdict {
    /// Service name.
    pub service: String,
    /// Critical path evaluated.
    pub path: CriticalPath,
    /// Metric evaluated.
    pub metric: MetricKind,
    /// Approved baseline value.
    pub baseline_value: u64,
    /// Observed value in candidate run.
    pub observed_value: u64,
    /// Percentage delta in basis points (+ is regression, - is improvement).
    pub delta_bps: i64,
    /// Assigned severity.
    pub severity: RegressionSeverity,
    /// Whether this sample constitutes a regression.
    pub is_regression: bool,
    /// Detailed diagnostic message.
    pub details: String,
}

/// Consolidated regression detection report across a complete CI test or canary run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfRegressionReport {
    /// Total samples evaluated.
    pub total_evaluated: usize,
    /// Total regressions detected (Warning, Critical, Blocker).
    pub regressions_found: usize,
    /// Total blocking regressions (severity == Blocker).
    pub blockers_found: usize,
    /// Maximum observed P99 latency on critical paths.
    pub max_critical_p99_ms: u64,
    /// Individual verdicts for each evaluated path.
    pub verdicts: Vec<RegressionVerdict>,
    /// Whether the overall CI evaluation passed.
    pub ci_passed: bool,
}

// ---------------------------------------------------------------------------
// Regression Detector Core Engine
// ---------------------------------------------------------------------------

/// Core engine managing baselines and evaluating candidate performance samples.
#[derive(Clone, Debug, Default)]
pub struct RegressionDetector {
    baselines: BTreeMap<String, BaselineProfile>,
}

impl RegressionDetector {
    /// Creates a new detector instance.
    pub fn new() -> Self {
        Self {
            baselines: BTreeMap::new(),
        }
    }

    /// Registers or updates a baseline profile.
    pub fn register_baseline(&mut self, profile: BaselineProfile) {
        self.baselines.insert(profile.key(), profile);
    }

    /// Seeds standard critical paths for a service with realistic default baselines.
    pub fn register_default_critical_paths(&mut self, service: &str) {
        let defaults = [
            (CriticalPath::BlockProposal, 45),
            (CriticalPath::AttestationAggregation, 35),
            (CriticalPath::MempoolIngestion, 20),
            (CriticalPath::StateEpochTransition, 60),
            (CriticalPath::CrossChainVerification, 50),
        ];

        for (path, baseline_ms) in defaults {
            let profile = BaselineProfile::new(service, path, MetricKind::LatencyP99, baseline_ms);
            self.register_baseline(profile);
        }
    }

    /// Returns the number of registered baselines.
    pub fn baseline_count(&self) -> usize {
        self.baselines.len()
    }

    /// Evaluates a single performance sample against registered baselines.
    pub fn evaluate_sample(&self, sample: &PerformanceSample) -> RegressionVerdict {
        let key = sample.key();
        let baseline = match self.baselines.get(&key) {
            Some(b) => b,
            None => {
                // No baseline found; cannot determine regression, mark as neutral None.
                return RegressionVerdict {
                    service: sample.service.clone(),
                    path: sample.path.clone(),
                    metric: sample.metric,
                    baseline_value: sample.value,
                    observed_value: sample.value,
                    delta_bps: 0,
                    severity: RegressionSeverity::None,
                    is_regression: false,
                    details: format!(
                        "No baseline registered for {}; established new observation point",
                        key
                    ),
                };
            }
        };

        let base_val = baseline.baseline_value;
        let obs_val = sample.value;

        // Calculate delta in basis points (100% = 10,000 bps)
        let delta_bps: i64 = if base_val == 0 {
            0
        } else if baseline.metric.higher_is_worse() {
            ((obs_val as i128 - base_val as i128) * 10_000i128 / base_val as i128) as i64
        } else {
            // Lower throughput is worse
            ((base_val as i128 - obs_val as i128) * 10_000i128 / base_val as i128) as i64
        };

        // Enforce hard P99 bounds (<100ms) for critical paths
        let hard_limit_breached = if let Some(limit) = baseline.hard_ceiling {
            obs_val >= limit
        } else {
            false
        };

        // Determine severity
        let (severity, is_regression, details) = if hard_limit_breached {
            (
                RegressionSeverity::Blocker,
                true,
                format!(
                    "CRITICAL SLA BREACH: Observed {}ms exceeds hard SLA limit of {}ms (delta: +{} bps)",
                    obs_val,
                    baseline.hard_ceiling.unwrap_or(CRITICAL_PATH_P99_TARGET_MS),
                    delta_bps
                ),
            )
        } else if delta_bps >= BLOCKER_REGRESSION_BPS as i64 {
            (
                RegressionSeverity::Blocker,
                true,
                format!(
                    "BLOCKER REGRESSION: Observed delta +{} bps exceeds blocker threshold of {} bps (baseline: {}, observed: {})",
                    delta_bps, BLOCKER_REGRESSION_BPS, base_val, obs_val
                ),
            )
        } else if delta_bps >= (baseline.tolerance_bps as i64 * 2) {
            (
                RegressionSeverity::Critical,
                true,
                format!(
                    "CRITICAL REGRESSION: Observed delta +{} bps exceeds 2x tolerance (baseline: {}, observed: {})",
                    delta_bps, base_val, obs_val
                ),
            )
        } else if delta_bps > baseline.tolerance_bps as i64 {
            (
                RegressionSeverity::Warning,
                true,
                format!(
                    "WARNING REGRESSION: Observed delta +{} bps exceeds tolerance of {} bps",
                    delta_bps, baseline.tolerance_bps
                ),
            )
        } else {
            (
                RegressionSeverity::None,
                false,
                format!(
                    "HEALTHY: Observed delta {} bps within acceptable limits (baseline: {}, observed: {})",
                    delta_bps, base_val, obs_val
                ),
            )
        };

        RegressionVerdict {
            service: sample.service.clone(),
            path: sample.path.clone(),
            metric: sample.metric,
            baseline_value: base_val,
            observed_value: obs_val,
            delta_bps,
            severity,
            is_regression,
            details,
        }
    }

    /// Evaluates a suite of candidate performance samples and compiles a consolidated report.
    pub fn evaluate_suite(&self, samples: &[PerformanceSample]) -> PerfRegressionReport {
        let mut verdicts = Vec::with_capacity(samples.len());
        let mut regressions_found = 0;
        let mut blockers_found = 0;
        let mut max_critical_p99_ms = 0;

        for sample in samples {
            let verdict = self.evaluate_sample(sample);
            if verdict.is_regression {
                regressions_found += 1;
            }
            if verdict.severity == RegressionSeverity::Blocker {
                blockers_found += 1;
            }
            if sample.metric == MetricKind::LatencyP99
                && sample.path.is_critical_path()
                && sample.value > max_critical_p99_ms
            {
                max_critical_p99_ms = sample.value;
            }
            verdicts.push(verdict);
        }

        // CI passes only when zero blockers are found and max P99 latency is below target
        let ci_passed = blockers_found == 0 && max_critical_p99_ms < CRITICAL_PATH_P99_TARGET_MS;

        PerfRegressionReport {
            total_evaluated: samples.len(),
            regressions_found,
            blockers_found,
            max_critical_p99_ms,
            verdicts,
            ci_passed,
        }
    }
}

// ---------------------------------------------------------------------------
// Blue-Green & Canary Deployment Gates
// ---------------------------------------------------------------------------

/// Decision rendered by the Canary Performance Gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GateDecision {
    /// All gates passed; proceed with promotion to 100% production traffic.
    Promote,
    /// Minor warnings observed; hold canary at current traffic share for observation.
    HoldCanary(String),
    /// Critical regressions, SLA breach, or unreviewed security state; trigger immediate rollback to Blue.
    RollbackBlueGreen(String),
}

/// Blue-Green and Canary deployment gate evaluator.
#[derive(Clone, Debug)]
pub struct CanaryPerformanceGate {
    /// Availability threshold in basis points.
    pub availability_threshold_bps: u32,
    /// Critical path P99 ceiling in ms.
    pub critical_p99_ceiling_ms: u64,
}

impl Default for CanaryPerformanceGate {
    fn default() -> Self {
        Self {
            availability_threshold_bps: AVAILABILITY_TARGET_BPS,
            critical_p99_ceiling_ms: CRITICAL_PATH_P99_TARGET_MS,
        }
    }
}

impl CanaryPerformanceGate {
    /// Creates a gate with standard production constraints.
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluates whether a canary deployment is safe to promote.
    pub fn evaluate_gate(
        &self,
        report: &PerfRegressionReport,
        observed_availability_bps: u32,
        security_reviewed: bool,
    ) -> GateDecision {
        // 1. Security Gate: Mandatory security sign-off per Technical Bounds
        if !security_reviewed {
            return GateDecision::RollbackBlueGreen(String::from(
                "SECURITY GATE REJECTION: Changes have not completed mandatory security review",
            ));
        }

        // 2. Availability Gate: Must meet 99.99% target
        if observed_availability_bps < self.availability_threshold_bps {
            return GateDecision::RollbackBlueGreen(format!(
                "AVAILABILITY SLA VIOLATION: Observed {} bps below required {} bps (99.99%)",
                observed_availability_bps, self.availability_threshold_bps
            ));
        }

        // 3. Blocker Regressions or Hard P99 Violations
        if report.blockers_found > 0 || report.max_critical_p99_ms >= self.critical_p99_ceiling_ms {
            return GateDecision::RollbackBlueGreen(format!(
                "PERFORMANCE SLA BREACH: {} blockers detected, max critical P99 was {}ms (ceiling: <{}ms)",
                report.blockers_found, report.max_critical_p99_ms, self.critical_p99_ceiling_ms
            ));
        }

        // 4. Non-blocking Warnings: Hold canary for extended soaking
        if report.regressions_found > 0 {
            return GateDecision::HoldCanary(format!(
                "CANARY HOLD: {} non-blocking performance warnings detected; soaking required",
                report.regressions_found
            ));
        }

        GateDecision::Promote
    }
}

// ---------------------------------------------------------------------------
// Monitoring, Alerting & Dashboard Exporters
// ---------------------------------------------------------------------------

/// Alert signal emitted based on performance regression evaluations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AlertSignal {
    /// All critical paths within SLO and baseline tolerances.
    Healthy,
    /// Moderate drift detected; open a tracking ticket for engineering investigation.
    WarningTicket(String),
    /// Critical breach or P99 >= 100ms; trigger immediate on-call pager.
    PagingPagerDuty(String),
}

/// Point-in-time snapshot for system-wide performance dashboards.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerformanceDashboardSnapshot {
    /// Overall health classification.
    pub overall_status: String,
    /// Alert signal output.
    pub alert_signal: AlertSignal,
    /// Total paths tracked.
    pub paths_tracked: usize,
    /// Maximum critical P99 latency in ms.
    pub peak_critical_p99_ms: u64,
    /// Availability status in basis points.
    pub availability_bps: u32,
    /// Active blocker count.
    pub active_blockers: usize,
    /// Active warning count.
    pub active_warnings: usize,
}

impl PerformanceDashboardSnapshot {
    /// Generates a dashboard snapshot from a regression report.
    pub fn from_report(report: &PerfRegressionReport, availability_bps: u32) -> Self {
        let (overall_status, alert_signal) = if report.blockers_found > 0
            || report.max_critical_p99_ms >= CRITICAL_PATH_P99_TARGET_MS
            || availability_bps < AVAILABILITY_TARGET_BPS
        {
            (
                String::from("CRITICAL_OUTAGE"),
                AlertSignal::PagingPagerDuty(format!(
                    "Performance regression paging alert: {} blockers, max P99 {}ms",
                    report.blockers_found, report.max_critical_p99_ms
                )),
            )
        } else if report.regressions_found > 0 {
            (
                String::from("DEGRADED_PERFORMANCE"),
                AlertSignal::WarningTicket(format!(
                    "Performance warning ticket: {} paths drifted beyond tolerance",
                    report.regressions_found
                )),
            )
        } else {
            (String::from("HEALTHY"), AlertSignal::Healthy)
        };

        Self {
            overall_status,
            alert_signal,
            paths_tracked: report.total_evaluated,
            peak_critical_p99_ms: report.max_critical_p99_ms,
            availability_bps,
            active_blockers: report.blockers_found,
            active_warnings: report
                .regressions_found
                .saturating_sub(report.blockers_found),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit Tests (Co-located)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_technical_constants_match_issue_133() {
        assert_eq!(CRITICAL_PATH_P99_TARGET_MS, 100);
        assert_eq!(AVAILABILITY_TARGET_BPS, 9_999);
        assert_eq!(DEFAULT_MAX_REGRESSION_BPS, 500);
        assert_eq!(BLOCKER_REGRESSION_BPS, 1_500);
        assert_eq!(MIN_SAMPLE_COUNT, 50);
    }

    #[test]
    fn test_critical_path_properties() {
        let p = CriticalPath::BlockProposal;
        assert_eq!(p.as_str(), "consensus.block_proposal");
        assert!(p.is_critical_path());

        let custom = CriticalPath::Custom(String::from("indexer.query"));
        assert_eq!(custom.as_str(), "indexer.query");
    }

    #[test]
    fn test_metric_kind_properties() {
        assert!(MetricKind::LatencyP99.higher_is_worse());
        assert!(!MetricKind::ThroughputOps.higher_is_worse());
        assert_eq!(MetricKind::LatencyP99.as_str(), "latency_p99_ms");
    }

    #[test]
    fn test_detector_baseline_registration() {
        let mut detector = RegressionDetector::new();
        assert_eq!(detector.baseline_count(), 0);

        detector.register_default_critical_paths("consensus");
        assert_eq!(detector.baseline_count(), 5);
    }

    #[test]
    fn test_healthy_sample_within_tolerance() {
        let mut detector = RegressionDetector::new();
        detector.register_baseline(BaselineProfile::new(
            "consensus",
            CriticalPath::BlockProposal,
            MetricKind::LatencyP99,
            50,
        ));

        // 51ms is a 2% increase (200 bps), well within 5% tolerance (500 bps)
        let sample = PerformanceSample {
            service: String::from("consensus"),
            path: CriticalPath::BlockProposal,
            metric: MetricKind::LatencyP99,
            value: 51,
            sample_count: 100,
            timestamp_secs: 1000,
        };

        let verdict = detector.evaluate_sample(&sample);
        assert_eq!(verdict.severity, RegressionSeverity::None);
        assert!(!verdict.is_regression);
        assert_eq!(verdict.delta_bps, 200);
    }

    #[test]
    fn test_warning_regression_detected() {
        let mut detector = RegressionDetector::new();
        detector.register_baseline(BaselineProfile::new(
            "consensus",
            CriticalPath::BlockProposal,
            MetricKind::LatencyP99,
            50,
        ));

        // 54ms is an 8% increase (800 bps), exceeds 500 bps tolerance but below blocker
        let sample = PerformanceSample {
            service: String::from("consensus"),
            path: CriticalPath::BlockProposal,
            metric: MetricKind::LatencyP99,
            value: 54,
            sample_count: 100,
            timestamp_secs: 1000,
        };

        let verdict = detector.evaluate_sample(&sample);
        assert_eq!(verdict.severity, RegressionSeverity::Warning);
        assert!(verdict.is_regression);
        assert_eq!(verdict.delta_bps, 800);
    }

    #[test]
    fn test_critical_regression_detected() {
        let mut detector = RegressionDetector::new();
        detector.register_baseline(BaselineProfile::new(
            "consensus",
            CriticalPath::BlockProposal,
            MetricKind::LatencyP99,
            50,
        ));

        // 56ms is a 12% increase (1200 bps), exceeds 2x tolerance (1000 bps)
        let sample = PerformanceSample {
            service: String::from("consensus"),
            path: CriticalPath::BlockProposal,
            metric: MetricKind::LatencyP99,
            value: 56,
            sample_count: 100,
            timestamp_secs: 1000,
        };

        let verdict = detector.evaluate_sample(&sample);
        assert_eq!(verdict.severity, RegressionSeverity::Critical);
        assert!(verdict.is_regression);
    }

    #[test]
    fn test_blocker_percentage_regression() {
        let mut detector = RegressionDetector::new();
        detector.register_baseline(BaselineProfile::new(
            "consensus",
            CriticalPath::BlockProposal,
            MetricKind::LatencyP99,
            40,
        ));

        // 50ms is a 25% increase (2500 bps), exceeds BLOCKER_REGRESSION_BPS (1500 bps)
        let sample = PerformanceSample {
            service: String::from("consensus"),
            path: CriticalPath::BlockProposal,
            metric: MetricKind::LatencyP99,
            value: 50,
            sample_count: 100,
            timestamp_secs: 1000,
        };

        let verdict = detector.evaluate_sample(&sample);
        assert_eq!(verdict.severity, RegressionSeverity::Blocker);
        assert!(verdict.is_regression);
    }

    #[test]
    fn test_hard_p99_ceiling_breach_is_blocker() {
        let mut detector = RegressionDetector::new();
        detector.register_baseline(BaselineProfile::new(
            "consensus",
            CriticalPath::BlockProposal,
            MetricKind::LatencyP99,
            90,
        ));

        // 101ms breaches the hard 100ms ceiling!
        let sample = PerformanceSample {
            service: String::from("consensus"),
            path: CriticalPath::BlockProposal,
            metric: MetricKind::LatencyP99,
            value: 101,
            sample_count: 100,
            timestamp_secs: 1000,
        };

        let verdict = detector.evaluate_sample(&sample);
        assert_eq!(verdict.severity, RegressionSeverity::Blocker);
        assert!(verdict.details.contains("CRITICAL SLA BREACH"));
    }

    #[test]
    fn test_throughput_regression_detection() {
        let mut detector = RegressionDetector::new();
        detector.register_baseline(BaselineProfile::new(
            "mempool",
            CriticalPath::MempoolIngestion,
            MetricKind::ThroughputOps,
            10_000,
        ));

        // Drop from 10,000 to 8,000 ops/sec is a 20% regression (2000 bps)
        let sample = PerformanceSample {
            service: String::from("mempool"),
            path: CriticalPath::MempoolIngestion,
            metric: MetricKind::ThroughputOps,
            value: 8_000,
            sample_count: 100,
            timestamp_secs: 1000,
        };

        let verdict = detector.evaluate_sample(&sample);
        assert_eq!(verdict.severity, RegressionSeverity::Blocker);
        assert_eq!(verdict.delta_bps, 2000);
    }

    #[test]
    fn test_suite_evaluation_ci_pass() {
        let mut detector = RegressionDetector::new();
        detector.register_default_critical_paths("consensus");

        let samples = vec![
            PerformanceSample {
                service: String::from("consensus"),
                path: CriticalPath::BlockProposal,
                metric: MetricKind::LatencyP99,
                value: 46, // 45 -> 46 is +2.2% (< 5%)
                sample_count: 100,
                timestamp_secs: 1000,
            },
            PerformanceSample {
                service: String::from("consensus"),
                path: CriticalPath::AttestationAggregation,
                metric: MetricKind::LatencyP99,
                value: 36, // 35 -> 36 is +2.8% (< 5%)
                sample_count: 100,
                timestamp_secs: 1000,
            },
        ];

        let report = detector.evaluate_suite(&samples);
        assert!(report.ci_passed);
        assert_eq!(report.blockers_found, 0);
        assert_eq!(report.regressions_found, 0);
        assert_eq!(report.max_critical_p99_ms, 46);
    }

    #[test]
    fn test_canary_gate_promote() {
        let gate = CanaryPerformanceGate::new();
        let report = PerfRegressionReport {
            total_evaluated: 5,
            regressions_found: 0,
            blockers_found: 0,
            max_critical_p99_ms: 70,
            verdicts: Vec::new(),
            ci_passed: true,
        };

        let decision = gate.evaluate_gate(&report, 9_999, true);
        assert_eq!(decision, GateDecision::Promote);
    }

    #[test]
    fn test_canary_gate_security_rejection() {
        let gate = CanaryPerformanceGate::new();
        let report = PerfRegressionReport {
            total_evaluated: 5,
            regressions_found: 0,
            blockers_found: 0,
            max_critical_p99_ms: 70,
            verdicts: Vec::new(),
            ci_passed: true,
        };

        // security_reviewed = false must trigger immediate rollback
        let decision = gate.evaluate_gate(&report, 9_999, false);
        match decision {
            GateDecision::RollbackBlueGreen(reason) => {
                assert!(reason.contains("SECURITY GATE REJECTION"));
            }
            _ => panic!("Expected RollbackBlueGreen on missing security review"),
        }
    }

    #[test]
    fn test_canary_gate_availability_rejection() {
        let gate = CanaryPerformanceGate::new();
        let report = PerfRegressionReport {
            total_evaluated: 5,
            regressions_found: 0,
            blockers_found: 0,
            max_critical_p99_ms: 70,
            verdicts: Vec::new(),
            ci_passed: true,
        };

        // 99.90% (9,990 bps) is below required 99.99% (9,999 bps)
        let decision = gate.evaluate_gate(&report, 9_990, true);
        match decision {
            GateDecision::RollbackBlueGreen(reason) => {
                assert!(reason.contains("AVAILABILITY SLA VIOLATION"));
            }
            _ => panic!("Expected RollbackBlueGreen on availability drop"),
        }
    }

    #[test]
    fn test_canary_gate_hold_on_warning() {
        let gate = CanaryPerformanceGate::new();
        let report = PerfRegressionReport {
            total_evaluated: 5,
            regressions_found: 1,
            blockers_found: 0,
            max_critical_p99_ms: 85,
            verdicts: Vec::new(),
            ci_passed: true,
        };

        let decision = gate.evaluate_gate(&report, 9_999, true);
        match decision {
            GateDecision::HoldCanary(reason) => {
                assert!(reason.contains("CANARY HOLD"));
            }
            _ => panic!("Expected HoldCanary on non-blocking warning"),
        }
    }

    #[test]
    fn test_dashboard_snapshot_generation() {
        let report = PerfRegressionReport {
            total_evaluated: 10,
            regressions_found: 0,
            blockers_found: 0,
            max_critical_p99_ms: 65,
            verdicts: Vec::new(),
            ci_passed: true,
        };

        let snapshot = PerformanceDashboardSnapshot::from_report(&report, 9_999);
        assert_eq!(snapshot.overall_status, "HEALTHY");
        assert_eq!(snapshot.alert_signal, AlertSignal::Healthy);
        assert_eq!(snapshot.peak_critical_p99_ms, 65);
    }
}
