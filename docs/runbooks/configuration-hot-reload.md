# Configuration Hot-Reload Runbook

## Pre-checks

- Confirm the candidate version is greater than the active version.
- Confirm security review approval is attached to the change request.
- Confirm metrics, alerting, and dashboards are healthy.

## Rollout

1. Apply the candidate to a green environment.
2. Run schema validation and hot-reload validation.
3. Start canary at the configured percentage.
4. Watch P99 latency and error budget alerts for at least one dashboard refresh
   interval.
5. Promote green to blue only when canary analysis stays within budget.

## Rollback

If validation fails or alerts fire, keep the active configuration unchanged,
stop the canary, and open an incident with the rejected config version and
validation error.
