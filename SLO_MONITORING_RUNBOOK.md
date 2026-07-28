# Service Level Objective Monitoring and Burn Rate Alerts

## Objectives

VeriNode services share these system-wide SLOs:

- **Availability:** 99.99% successful requests over the objective window.
- **Critical-path latency:** P99 latency must remain below 100 ms.
- **Critical-path performance:** SLO evaluation is constant-time counter math and does not add request-path I/O.

## Architecture

1. Services aggregate rolling-window counters: total requests, failed requests, and P99 latency.
2. The shared `slo` module evaluates counters against `SloTarget::default_system()`.
3. Services publish `slo/eval` events with service ID, observed error basis points, burn rate, latency violation state, and alert signal.
4. Off-chain monitoring consumes those events to populate dashboards and trigger alert-manager routes.

## Alert policy

- **Page:** burn rate is at least 14x the 99.99% error budget or P99 latency exceeds 100 ms.
- **Ticket:** burn rate is at least 2x the error budget.
- **Healthy:** all lower severities.

## Dashboard panels

Every service dashboard should include:

- Request volume and failure count by rolling window.
- Observed error basis points.
- Error-budget burn rate.
- Critical-path P99 latency.
- Current SLO signal: healthy, ticket, or page.

## Blue-green and canary deployment checks

Before shifting production traffic:

1. Deploy the green environment with SLO event publishing enabled.
2. Send canary traffic and compare green burn rate, failure count, and P99 latency against blue.
3. Continue only when green remains healthy and is not worse than blue for the canary interval.
4. Roll back immediately if canary evaluation pages or latency exceeds the 100 ms target.

## Incident response

1. Confirm whether the alert was triggered by burn rate, latency, or both.
2. Check recent deploys and canary status first.
3. Reduce traffic to the unhealthy version using the blue-green controller.
4. Capture dashboard snapshots and event IDs for the security review and postmortem.
5. Keep the incident open until burn rate returns below ticket threshold and latency is within target.
