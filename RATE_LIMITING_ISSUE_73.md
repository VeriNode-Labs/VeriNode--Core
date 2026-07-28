# API Rate Limiting with Per-Tenant Token Buckets (Issue #73)

## Architecture

VeriNode Core now exposes an embeddable per-tenant token-bucket limiter in
`src/rate_limit.rs`. API gateways and service front doors should call
`TenantRateLimiter::check(tenant_id, now, cost)` before dispatching work to
critical paths. Each tenant has an isolated bucket, so one tenant cannot exhaust
another tenant's capacity.

The implementation is dependency-free and deterministic. The hot path performs a
single `BTreeMap` lookup plus saturating integer arithmetic, keeping it suitable
for the issue target of `< 100ms` P99. Default tenant policy is:

- sustained refill: 100 tokens/second;
- burst capacity: 1,000 tokens;
- availability objective: 99.99%.

## Monitoring and Alerts

`TenantRateLimiter::snapshot` provides tenant-level dashboard data:

- available tokens;
- burst capacity;
- refill rate;
- last refill timestamp;
- accepted request count;
- rejected request count.

`TenantRateLimiter::metrics` aggregates tenants tracked, accepted requests, and
rejected requests. Alert when rejection rate sharply increases for canary tenants
or when the API gateway's limiter check latency approaches the 100ms P99 budget.

## Deployment Runbook

1. Deploy limiter code darkly with metrics-only checks.
2. Blue-green deploy gateways with enforcement disabled in blue and enabled for a
   small green canary.
3. Compare canary rejection rate, latency P99, and error budgets.
4. Gradually increase canary traffic if metrics remain healthy.
5. Roll back by switching traffic to blue or setting request costs to zero.

## Security Notes

- Tenant IDs must be derived from authenticated tenancy claims, never request
  headers alone.
- Use non-zero burst and refill configurations; invalid zero-value policies are
  rejected by `RateLimitConfig::new`.
- Saturating arithmetic prevents timestamp regressions or large elapsed windows
  from underflowing or overflowing counters.
