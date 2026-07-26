#![cfg(test)]

use sorosusu_contracts::rate_limit::{
    RateLimitConfig, RateLimitDecision, TenantRateLimiter, AVAILABILITY_TARGET_BPS,
    CRITICAL_PATH_P99_BUDGET_MS, DEFAULT_BURST_CAPACITY, DEFAULT_REFILL_RATE_PER_SECOND,
};

#[test]
fn token_bucket_enforces_per_tenant_burst_capacity() {
    let config = RateLimitConfig::new(3, 1).unwrap();
    let mut limiter = TenantRateLimiter::new(config);

    assert_eq!(
        limiter.check(42, 1_000, 1),
        RateLimitDecision::Allowed {
            remaining_tokens: 2
        }
    );
    assert_eq!(
        limiter.check(42, 1_000, 2),
        RateLimitDecision::Allowed {
            remaining_tokens: 0
        }
    );
    assert_eq!(
        limiter.check(42, 1_000, 1),
        RateLimitDecision::Denied {
            retry_after_seconds: 1
        }
    );
}

#[test]
fn tenants_have_independent_buckets() {
    let config = RateLimitConfig::new(2, 1).unwrap();
    let mut limiter = TenantRateLimiter::new(config);

    assert!(matches!(
        limiter.check(1, 10, 2),
        RateLimitDecision::Allowed {
            remaining_tokens: 0
        }
    ));
    assert!(matches!(
        limiter.check(1, 10, 1),
        RateLimitDecision::Denied { .. }
    ));

    assert_eq!(
        limiter.check(2, 10, 1),
        RateLimitDecision::Allowed {
            remaining_tokens: 1
        },
        "tenant 2 must not inherit tenant 1 throttling state"
    );
}

#[test]
fn refill_is_capped_at_burst_capacity() {
    let config = RateLimitConfig::new(5, 2).unwrap();
    let mut limiter = TenantRateLimiter::new(config);

    assert_eq!(
        limiter.check(7, 100, 5),
        RateLimitDecision::Allowed {
            remaining_tokens: 0
        }
    );
    assert_eq!(
        limiter.check(7, 101, 1),
        RateLimitDecision::Allowed {
            remaining_tokens: 1
        }
    );
    assert_eq!(
        limiter.check(7, 200, 5),
        RateLimitDecision::Allowed {
            remaining_tokens: 0
        },
        "long idle periods refill only to burst capacity"
    );
}

#[test]
fn retry_after_rounds_up_missing_tokens() {
    let config = RateLimitConfig::new(10, 3).unwrap();
    let mut limiter = TenantRateLimiter::new(config);

    assert!(matches!(
        limiter.check(9, 50, 10),
        RateLimitDecision::Allowed {
            remaining_tokens: 0
        }
    ));
    assert_eq!(
        limiter.check(9, 50, 7),
        RateLimitDecision::Denied {
            retry_after_seconds: 3
        },
        "7 missing tokens at 3 tokens/sec needs ceil(7/3) seconds"
    );
}

#[test]
fn saturating_time_math_handles_clock_regression() {
    let config = RateLimitConfig::new(2, 1).unwrap();
    let mut limiter = TenantRateLimiter::new(config);

    assert!(matches!(
        limiter.check(11, 200, 2),
        RateLimitDecision::Allowed {
            remaining_tokens: 0
        }
    ));
    assert_eq!(
        limiter.check(11, 100, 1),
        RateLimitDecision::Denied {
            retry_after_seconds: 1
        },
        "older timestamps must not underflow and grant unexpected refill"
    );
}

#[test]
fn metrics_and_snapshots_support_monitoring_dashboards() {
    let config = RateLimitConfig::new(2, 1).unwrap();
    let mut limiter = TenantRateLimiter::new(config);

    limiter.check(1, 10, 1);
    limiter.check(1, 10, 2);
    limiter.check(2, 10, 1);

    let tenant_one = limiter.snapshot(1).unwrap();
    assert_eq!(tenant_one.tenant_id, 1);
    assert_eq!(tenant_one.available_tokens, 1);
    assert_eq!(tenant_one.accepted_requests, 1);
    assert_eq!(tenant_one.rejected_requests, 1);

    let metrics = limiter.metrics();
    assert_eq!(metrics.tenants_tracked, 2);
    assert_eq!(metrics.accepted_requests, 2);
    assert_eq!(metrics.rejected_requests, 1);
}

#[test]
fn rejects_invalid_configuration() {
    assert_eq!(RateLimitConfig::new(0, 1), None);
    assert_eq!(RateLimitConfig::new(1, 0), None);
}

#[test]
fn issue_73_operational_constants_are_documented() {
    assert_eq!(DEFAULT_REFILL_RATE_PER_SECOND, 100);
    assert_eq!(DEFAULT_BURST_CAPACITY, 1_000);
    assert_eq!(CRITICAL_PATH_P99_BUDGET_MS, 100);
    assert_eq!(AVAILABILITY_TARGET_BPS, 9_999);
}
