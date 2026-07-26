# Runtime Configuration Auditing and Drift Detection

## Architecture

The runtime configuration auditor compares an approved deployment baseline with a runtime snapshot collected from all services. The core implementation lives in `src/config_audit.rs` and is intentionally independent from network and storage calls so it can run in rollout controllers, service startup hooks, or canary analyzers without adding latency to consensus-critical paths.

### Components

1. **Baseline generator**
   - Produces a `ConfigBaseline` for each blue, green, canary, or production stage.
   - Hashes secret values before they leave the owning service.
   - Sorts entries by `(service, key)` and computes a stable SHA-256 digest for audit trails.
2. **Runtime snapshot collector**
   - Collects the same `ConfigEntry` shape from live services.
   - Uses hashed values to avoid logging raw secrets.
3. **Config auditor**
   - Runs a deterministic merge scan over sorted baseline and snapshot entries.
   - Emits missing, unexpected, value-changed, and severity-changed drift findings.
   - Caps stored findings while preserving total drift counters for alert accuracy.
4. **Rollout gate**
   - Blocks blue-green promotion or canary expansion when critical drift is present.
   - Allows informational and warning drift to continue only if the release owner explicitly accepts the risk.
5. **Monitoring sink**
   - Converts `AuditReport` fields into metrics, logs, and alert annotations.

## Performance and Availability Bounds

- Critical-path audit work is an in-memory linear scan after construction-time sorting.
- No network calls, storage calls, or dynamic service discovery occur during `ConfigAuditor::audit`.
- Rollout automation should execute audits outside request serving paths and fail closed only for critical drift so availability remains aligned with the 99.99% target.

## Security Review Notes

- Raw configuration values are not stored in `ConfigEntry`; only SHA-256 digests are compared.
- Critical security toggles such as authentication, authorization, key-rotation, and TLS settings must be marked `ConfigSeverity::Critical`.
- The baseline digest should be attached to deployment approvals and incident reports.

## Monitoring and Alerting

Export these fields from every `AuditReport`:

| Metric | Type | Alert |
| --- | --- | --- |
| `verinode_config_drift_total` | counter/gauge | Warning when `> 0` for 5 minutes |
| `verinode_config_critical_drift_total` | counter/gauge | Page immediately when `> 0` |
| `verinode_config_audit_records_capped` | gauge | Warning when records equal the cap |
| `verinode_config_baseline_version` | gauge/label | Include in all annotations |
| `verinode_config_rollout_safe` | gauge | Block promotion when `0` |

Dashboard panels should include drift count by service, critical drift by deployment stage, baseline digest/version, and recent capped-report events.
