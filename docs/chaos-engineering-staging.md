# Chaos Engineering Testing Blueprint for Staging

This blueprint defines how VeriNode runs controlled, system-wide chaos experiments in staging without violating the critical-path target of **P99 < 100 ms**, the **99.99% availability** target, or security-review requirements.

## Architecture

1. **Experiment catalog:** `src::chaos::STAGING_CHAOS_EXPERIMENTS` is the source of truth for approved staging faults, service surfaces, rollback metrics, blast radius, and duration.
2. **Orchestrator:** an off-chain staging job reads the catalog, applies faults with the infrastructure provider's chaos tooling, and records every run as an auditable deployment event.
3. **Safety gate:** no experiment starts unless the latest health snapshot passes latency, availability, error-budget, healthy-zone, and security-approval checks.
4. **Telemetry pipeline:** contract tracing events, service metrics, logs, and canary analysis are shipped to the staging observability stack before, during, and after each run.
5. **Rollback controller:** if a rollback metric breaches its threshold, the orchestrator removes the fault, flips traffic back to the blue deployment, and pages the staging incident channel.

## Experiment Scope

The staging catalog covers the full service surface:

| Surface | Fault | Rollback metric |
| --- | --- | --- |
| Consensus | Latency injection | `consensus_critical_path_p99_ms` |
| Mempool | Packet loss | `mempool_tx_propagation_errors_total` |
| Attestation | Pod kill | `attestation_inclusion_delay_slots` |
| Slashing | Dependency blackhole | `slashing_false_positive_total` |
| Settlement | Resource pressure | `settlement_finalization_lag_seconds` |
| Network | Clock skew | `network_peer_disconnects_total` |
| Observability | Trace ingestion blackhole | `trace_ingestion_gap_seconds` |

Each experiment is limited to a maximum **10% blast radius** and **15 minutes** unless a separate security review approves a narrower temporary exception.

## Safety Gates

Before every run, staging automation must verify:

- Critical-path P99 latency is below 100 ms.
- Availability is at least 99.99%.
- Canary error-budget burn is no more than 1 basis point.
- At least two zones are healthy.
- At least two security reviewers have approved the fault template.

During the run, the same gate is evaluated continuously. A single failed gate triggers rollback.

## Monitoring, Alerting, and Dashboards

Dashboards must show:

- P50/P95/P99 latency for consensus, mempool, attestation, slashing, settlement, network, and tracing ingestion.
- Availability and error-budget burn by deployment color and canary cohort.
- Fault start, fault stop, rollback, and promotion annotations.
- Service-specific rollback metrics from the catalog.
- Security events, unexpected authorization failures, and dependency-denial signals.

Alerts must page the staging incident channel for any rollback metric breach, failed safety gate, missing telemetry for more than 60 seconds, or canary regression against the blue baseline.

## Blue-Green and Canary Deployment Flow

1. **Design review:** document hypothesis, blast radius, rollback metric, and expected user impact.
2. **Security review:** confirm the fault cannot escape staging, weaken production controls, or expose secrets.
3. **Blue-green shadow:** deploy the chaos-enabled green stack with no user traffic and compare telemetry against blue.
4. **1% canary:** route a small synthetic workload cohort to green and run the shortest approved fault window.
5. **10% canary:** expand only if the safety gate remains healthy and canary analysis shows no regression.
6. **Full staging:** run the experiment against the approved blast radius, then automatically remove the fault and archive results.

## Runbook

1. Confirm the experiment ID exists in `STAGING_CHAOS_EXPERIMENTS`.
2. Confirm the safety gate passes and security approvals are attached to the change record.
3. Announce the run in the staging incident channel with start time, owner, rollback metric, and expected duration.
4. Start the green deployment in shadow mode, then advance through the rollout phases only after canary analysis passes.
5. Watch dashboards for rollback metric breaches, latency above the 100 ms P99 target, availability below 99.99%, and telemetry gaps.
6. On breach, stop the fault, shift traffic to blue, collect traces/logs/metrics, and open a follow-up issue before retrying.
7. After success, publish a summary with hypothesis, observed impact, remediation actions, and any catalog changes.
