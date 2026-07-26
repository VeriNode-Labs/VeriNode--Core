# Multi-Region Replication and Disaster Recovery Runbook

## Architecture

VeriNode operators should run at least three regions: one primary writer and
multiple read replicas. Replication health is modeled in
`src/replication/mod.rs` by `ReplicationTopology` and `RegionStatus` so every
service evaluates the same deterministic gates before traffic movement.

## SLOs and release gates

- Critical paths must remain at or below 100 ms P99.
- Availability target is 99.99%.
- Replication lag must remain at or below 100 ms for every failover candidate.
- Canary promotion requires a passed security review, at least 99.99% request
  success, and P99 latency at or below 100 ms.

## Blue-green and canary deployment

1. Deploy the inactive color to all replica regions.
2. Run schema and storage-layout checks before enabling writes.
3. Shift 1%, 10%, 25%, 50%, then 100% of traffic while recording
   `CanaryAnalysis` samples.
4. Promote only if `passes_release_gate()` succeeds.
5. Roll back to the previous color immediately on latency, availability, or
   security-review failures.

## Disaster recovery exercise

1. Capture a `ReplicationTopology` snapshot from monitoring.
2. Require `validate_dr_posture()` to pass before the exercise begins.
3. Generate a `failover_plan()` and freeze writes during DNS cutover.
4. Verify read-after-write behavior in the target region.
5. Record a `DisasterRecoveryTestReport`; the report passes only when canary,
   RTO (<= 300 seconds), and RPO (<= 100 ms lag) requirements are satisfied.

## Monitoring and alerts

Dashboard panels should display the fields from `ReplicationMetrics`:
configured regions, healthy regions, max replication lag, max critical-path P99,
availability target, P99 target, and DR readiness. Page operators when
`dr_ready` is false, when max replication lag exceeds 100 ms, or when P99
latency exceeds 100 ms.
