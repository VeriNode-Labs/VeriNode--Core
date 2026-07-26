# Incident Response Runbook Automation with PagerDuty

This design keeps incident automation deterministic inside VeriNode Core while
leaving PagerDuty HTTP delivery, authentication, and secret storage to a hardened
operator process.

## Architecture

1. Monitoring emits an `IncidentSignal` with service, metric, threshold, observed
   value, and severity.
2. `incident_response::build_incident_plan` selects a runbook, monitoring
   queries, PagerDuty event model, and deployment gate.
3. The operator serializes `PagerDutyEvent` to the PagerDuty Events API v2 JSON
   shape and sends it with a routing key from secret storage.
4. Remediation deploys to a green environment, sends a small canary, and promotes
   only when canary success is at least 99.95% with no error-budget burn.

## SLOs and Security Bounds

- Critical automation paths target less than 100ms P99.
- Service availability target is 99.99%.
- PagerDuty routing keys must never be committed; pass them at runtime from a
  secret manager.
- All runbook commands are data, not shell execution. Operators must enforce
  allow lists, audit logging, and peer review before execution.

## Runbook

1. Trigger or acknowledge the PagerDuty incident using the deterministic dedup
   key `verinode:<service>:<metric>:<severity>`.
2. Check the generated latency, availability, and PagerDuty event queries.
3. Deploy to the green environment with canary traffic.
4. Roll back to blue if canary success drops below 99.95%, any error-budget burn
   is detected, or the incident is SEV1.
5. Collect security evidence and attach it to the post-incident review.
