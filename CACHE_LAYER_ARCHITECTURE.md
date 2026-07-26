# In-memory Cache Layer with Redis and Configurable TTL

## Architecture

The cache layer lives in `src/db/cache.rs` and exposes a deterministic `TtlCache<K, V>` for in-process critical paths. The same `CacheConfig` structure carries Redis deployment settings through `RedisCacheConfig`, allowing off-chain services to swap the in-memory implementation for a Redis client without changing cache policy at call sites.

```text
service call path
  -> CacheConfig { default_ttl_ms, namespace, operation_budget_ms, redis }
  -> TtlCache<K,V> for local execution/tests
  -> Redis adapter in services when CacheConfig.redis is Some(...)
```

## TTL Policy

- `CacheConfig::default_ttl_ms` is the system-wide default TTL.
- `TtlCache::insert(..., ttl_ms)` accepts per-entry overrides for hot keys that need shorter or longer retention.
- Expiry is checked on reads and during writes, ensuring stale data is not returned.
- `saturating_add` is used for expiry timestamps so malformed large TTL values cannot overflow.

## Redis Deployment Guidance

- Use the `namespace` field as a key prefix, e.g. `verinode:committee:<epoch>`.
- Prefer `rediss://` endpoints and keep `RedisCacheConfig::require_tls` enabled.
- Set Redis client operation timeouts at or below `operation_budget_ms` so cache degradation cannot exceed the critical-path latency budget.
- Run Redis in a replicated/high-availability topology and keep the in-process cache as the fallback path for local reads.

## Monitoring and Alerting

`CacheMetrics` provides counters for hits, misses, writes, evictions, and expirations. Export these counters to the service metrics backend and create dashboards for:

- hit ratio (`hit_ratio_bps`) by namespace and critical path;
- eviction rate, indicating undersized in-memory capacity;
- expiration rate, indicating TTL churn;
- cache operation latency P50/P95/P99 in the service adapter.

Suggested alerts:

- P99 cache operation latency over `operation_budget_ms` for 5 minutes;
- hit ratio below 80% for critical paths for 10 minutes;
- Redis connection errors above 1% of cache operations for 5 minutes.

## Blue-Green and Canary Rollout

1. Deploy the code with `redis = None` to validate in-memory behavior.
2. Enable Redis for a green/canary slice with the same TTL values.
3. Compare hit ratio, P99 latency, and application error rate between blue and green.
4. Expand only when P99 remains under 100ms and error rate does not regress.
5. Keep rollback simple by setting `redis = None` and relying on the in-memory fallback.

## Runbook

- **High miss rate:** verify TTL settings, namespace consistency, and Redis key cardinality.
- **High eviction rate:** increase `max_entries` for in-memory cache or reduce hot-key cardinality.
- **Redis timeout/error spike:** fail closed to local cache, verify network/TLS credentials, and roll back canary traffic if P99 exceeds budget.
- **Stale data report:** confirm callers pass monotonic `now_ms`, inspect per-entry TTL overrides, and invalidate the affected namespace.
