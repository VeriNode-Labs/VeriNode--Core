# Runbook: Runtime Configuration Drift

## Detection

A drift incident starts when either:

- `verinode_config_critical_drift_total > 0`, or
- `verinode_config_drift_total > 0` persists through the configured warning window.

## Triage

1. Identify the affected baseline version, deployment stage, service, and key from the audit report.
2. Compare the reported baseline digest with the digest approved for the active release.
3. Classify the finding:
   - `Missing`: the service did not expose an expected configuration key.
   - `Unexpected`: the service exposed a key that is absent from the approved baseline.
   - `ValueChanged`: the live value hash differs from the baseline hash.
   - `SeverityChanged`: the live severity differs from the baseline severity.
4. For critical drift, freeze canary expansion and stop blue-green promotion immediately.

## Remediation

- If the runtime configuration is wrong, roll back the affected service or re-apply the approved configuration.
- If the baseline is stale, generate a new baseline, complete security review, and redeploy through canary before production promotion.
- If report records are capped, collect a scoped snapshot for the affected service group before closing the incident.

## Verification

1. Run the auditor against the corrected snapshot.
2. Confirm `critical_drift_count == 0` before unblocking rollout.
3. Confirm all accepted non-critical drift has an owner, expiration date, and ticket reference.
4. Attach the final baseline digest and audit report to the incident or deployment record.
