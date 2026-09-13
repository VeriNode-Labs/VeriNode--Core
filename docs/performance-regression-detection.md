# Automated Performance Regression Detection in CI Pipeline

**Tracking Issue**: [#133](https://github.com/VeriNode-Labs/VeriNode--Core/issues/133)  
**System Scope**: System-wide performance regression gating across all VeriNode services  
**Critical Path Latency Target**: P99 < 100 ms  
**Availability Target**: 99.99% uptime (9,999 bps)  
**Security Review**: Mandatory sign-off gate before canary promotion  

---

## 1. Solution Architecture

The automated performance regression detection system provides deterministic, dependency-free evaluation of candidate commits in CI pipelines and live deployment rollouts.

```text
 ┌──────────────────────────┐  Execution Metrics  ┌─────────────────────────────────┐
 │   Candidate Benchmark    │ ───────────────────▶ │   RegressionDetector            │
 │   & Integration Tests    │                      │   • Baseline Comparison         │
 └──────────────────────────┘                      │   • Hard P99 Ceiling (<100ms)   │
                                                   │   • Drift Tolerance (5.00%)     │
                                                   └────────────────┬────────────────┘
                                                                    │ PerfRegressionReport
                                                                    ▼
 ┌──────────────────────────┐                      ┌─────────────────────────────────┐
 │   Canary / Blue-Green    │ ◀─────────────────── │   CanaryPerformanceGate         │
 │   Deployment Orchestrator│     GateDecision     │   • Availability Gate (99.99%)  │
 └──────────────────────────┘                      │   • Security Review Gate        │
                                                   └────────────────┬────────────────┘
                                                                    │ AlertSignal
                                                                    ▼
                                                   ┌─────────────────────────────────┐
                                                   │   Monitoring & Dashboards       │
                                                   │   • PagerDuty (Outage / Blocker)│
                                                   │   • Warning Tickets (Drift)     │
                                                   └─────────────────────────────────┘
```

---

## 2. Technical Invariants & Bounds

| Parameter | Bound | Description |
|-----------|-------|-------------|
| `CRITICAL_PATH_P99_TARGET_MS` | `< 100 ms` | Hard ceiling for critical paths (Block Proposal, Attestation, Mempool, Epoch Transition). |
| `AVAILABILITY_TARGET_BPS` | `9,999 bps` | 99.99% availability required for canary promotion. |
| `DEFAULT_MAX_REGRESSION_BPS` | `500 bps` (5.00%) | Maximum allowable drift before emitting a warning. |
| `BLOCKER_REGRESSION_BPS` | `1,500 bps` (15.00%) | Regression magnitude that immediately fails CI and halts deployment. |
| `MIN_SAMPLE_COUNT` | `50 samples` | Minimum statistical sample count for valid evaluation. |
| `SECURITY_REVIEWED` | `true` | Required sign-off prior to production traffic promotion. |

---

## 3. Critical Paths Covered

1. **`consensus.block_proposal`**: Validator leader block packing, execution preview, and proposal dispatch.
2. **`attestation.aggregation`**: BLS attestation signature verification and bitfield bitwise aggregation.
3. **`mempool.ingestion`**: Admission control, fee-auction ordering, and account nonce validation.
4. **`state.epoch_transition`**: State root calculation, committee shuffling, and slashing accumulator roll-overs.
5. **`cross_chain.verification`**: Heterogeneous finality header proof verification.

---

## 4. Blue-Green Strategy and Canary Analysis

The `CanaryPerformanceGate` enforces progressive verification:
1. **Canary Deployment (10% Traffic)**:
   - Evaluates observed P99 latency and error budgets against the active Blue baseline.
   - If any critical path exceeds 100ms P99 or availability drops below 99.99%, an automated rollback to Blue is triggered immediately.
2. **Soaking Period**:
   - If performance warnings (5–15% drift) are detected without hard SLA breaches, the gate issues `GateDecision::HoldCanary` for further observation.
3. **Promotion**:
   - Promotion to 100% traffic requires `GateDecision::Promote`, confirming 0 blockers, P99 < 100ms, >= 99.99% availability, and verified security sign-off.

---

## 5. Runbooks and Remediation

### Runbook A: CI Performance Regression Failure
1. **Identify Breached Path**: Inspect the CI summary table from `detect_perf_regression.py` or the `PerfRegressionReport`.
2. **Check Tail Latency**: Verify if the failure is due to a hard SLA breach (`P99 >= 100ms`) or relative delta (`> 15%`).
3. **Profile Flamegraphs**: Run localized benchmarks:
   ```bash
   cargo test --test perf_regression_detection_test
   python3 scripts/detect_perf_regression.py
   ```
4. **Remediation**: Eliminate locking contention, excessive allocations, or redundant serialization in the critical path before merging.

### Runbook B: Canary Rollback Triggered in Production
1. **Automated Action**: Traffic immediately routes 100% back to Blue.
2. **Incident Notification**: PagerDuty alert dispatched with P99 metrics and delta basis points.
3. **Diagnostic Snapshot**: Review `PerformanceDashboardSnapshot` to pinpoint offending service and metric.
