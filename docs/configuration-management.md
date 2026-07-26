# Configuration Management Architecture

VeriNode Core uses a schema-first configuration subsystem that validates every
candidate configuration before activation. `ConfigManager` owns the active
`SystemConfig`, applies monotonic version checks, rejects invalid service and
operational settings, and records a compact change event for monitoring.

## Hot-reload flow

1. Load a candidate configuration from the operator source of truth.
2. Run `validate_reload(current, candidate)`.
3. Reject changes that fail schema validation, version monotonicity, or attempt
   to mutate a service whose `hot_reload` flag is disabled.
4. Activate the candidate atomically and emit a `ConfigChangeEvent`.
5. Let deployment automation progress blue-green/canary rollout according to
   the validated `DeploymentConfig`.

## Operational bounds

- Critical-path P99 target must be between 1 and 100 ms.
- Availability target must be 99.99% or higher.
- Metrics and alerting must remain enabled for every accepted configuration.
- Security review is represented by the `security_review_required` schema flag
  and must not be disabled.
