//! Integration tests for cross-chain light-client committee synchronization
//! across heterogeneous finality gadgets (issue #136).
//!
//! The headline scenario simulates two chains with very different block times —
//! a 2-second chain and a 15-second chain — sharing one light client, with
//! 800 ms of relay latency injected on every header, and verifies that the
//! `chain_finality_lag_ms` gauge stays below the 10-second target on both.

use sorosusu_contracts::cross_chain::{
    ChainConfig, CommitteeSyncState, ConnectedChain, CrossChainError, FinalityDecision,
    FinalityVerifier, HeaderCache, LightClientRegistry, RecentHeader, SyncOutcome,
    GRACE_PERIOD_MULTIPLIER_BPS, HEADER_CACHE_CAPACITY, MAX_ACCEPTABLE_FINALITY_LAG_MS,
    MAX_CLOCK_DRIFT_MS_PER_HOP, MIN_SYNC_TIMEOUT_MS, SYNC_BACKOFF_BASE_MS, SYNC_BACKOFF_CAP_MS,
    SYNC_INTERVAL_DIVISOR, SYNC_TIMEOUT_MULTIPLIER,
};

// ---------------------------------------------------------------------------
// Simulation parameters
// ---------------------------------------------------------------------------

/// Relay latency injected on every header: block timestamp → local observation.
const INJECTED_LATENCY_MS: u64 = 800;
/// Total committee voting weight used throughout the simulation.
const COMMITTEE_WEIGHT: u64 = 100;
/// Attesting weight per header — comfortably above the 2/3+1 = 67 threshold.
const ATTESTING_WEIGHT: u64 = 70;
/// Both chains are two relay hops away → 1_000 ms clock-drift budget, above the
/// 800 ms injected latency, so a healthy run never trips drift detection.
const FINALITY_HOPS: u32 = 2;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn chain_config(id: &str, block_time_ms: u64) -> ChainConfig {
    ChainConfig::new(id.into(), block_time_ms, 128, FINALITY_HOPS)
}

/// Smallest committee-sync tick (a multiple of `interval`) at or after
/// `observed_at` — when the light client next processes finalization.
fn next_sync_tick(interval: u64, observed_at: u64) -> u64 {
    observed_at.div_ceil(interval) * interval
}

/// Drives one chain through `blocks` blocks inside `registry`, injecting relay
/// latency and keeping the committee freshly synced, and returns the maximum
/// `chain_finality_lag_ms` gauge value observed across the run.
fn simulate_chain(
    registry: &mut LightClientRegistry,
    chain_id: &str,
    block_time_ms: u64,
    blocks: u64,
) -> u64 {
    let interval = block_time_ms / SYNC_INTERVAL_DIVISOR;
    let mut max_lag = 0;

    for height in 1..=blocks {
        let produced_at = height * block_time_ms;
        let observed_at = produced_at + INJECTED_LATENCY_MS;

        // The committee is re-sampled when the header arrives, keeping the
        // light client's view fresh so no staleness drift accrues.
        registry
            .chain_mut(chain_id)
            .unwrap()
            .record_sync(SyncOutcome::Success, observed_at);
        registry
            .observe_header(
                chain_id,
                RecentHeader::new(
                    height,
                    produced_at,
                    COMMITTEE_WEIGHT,
                    ATTESTING_WEIGHT,
                    observed_at,
                ),
            )
            .unwrap();

        // Finalization is attempted on the next committee-sync tick.
        let finalized_at = next_sync_tick(interval, observed_at);
        let decision = registry.try_finalize(chain_id, finalized_at).unwrap();
        assert_eq!(
            decision,
            FinalityDecision::Finalized,
            "chain {chain_id} height {height} should finalize without drift"
        );

        let lag = registry
            .chain(chain_id)
            .unwrap()
            .finality_lag_ms(finalized_at);
        assert_eq!(
            lag,
            finalized_at - produced_at,
            "gauge must equal finalized_at - block_timestamp"
        );
        max_lag = max_lag.max(lag);
    }

    max_lag
}

// ---------------------------------------------------------------------------
// Headline acceptance scenario (issue #136)
// ---------------------------------------------------------------------------

#[test]
fn two_heterogeneous_chains_keep_finality_lag_under_target() {
    let mut registry = LightClientRegistry::new();
    registry.connect(chain_config("fast-2s", 2_000), 0).unwrap();
    registry
        .connect(chain_config("slow-15s", 15_000), 0)
        .unwrap();

    let fast_max_lag = simulate_chain(&mut registry, "fast-2s", 2_000, 30);
    let slow_max_lag = simulate_chain(&mut registry, "slow-15s", 15_000, 30);

    // Both chains finalize well within the 10 s target despite a 7.5x
    // difference in block time and 800 ms of injected relay latency.
    assert!(
        fast_max_lag < MAX_ACCEPTABLE_FINALITY_LAG_MS,
        "fast chain max finality lag {fast_max_lag} ms must be < {MAX_ACCEPTABLE_FINALITY_LAG_MS} ms"
    );
    assert!(
        slow_max_lag < MAX_ACCEPTABLE_FINALITY_LAG_MS,
        "slow chain max finality lag {slow_max_lag} ms must be < {MAX_ACCEPTABLE_FINALITY_LAG_MS} ms"
    );

    // Concretely: fast ≈ latency + a fraction of a 500 ms interval; slow ≈
    // latency + a fraction of a 3_750 ms interval.
    assert_eq!(fast_max_lag, 1_000);
    assert_eq!(slow_max_lag, 3_750);
}

#[test]
fn finality_lag_gauges_report_both_chains_within_target() {
    let mut registry = LightClientRegistry::new();
    registry.connect(chain_config("fast-2s", 2_000), 0).unwrap();
    registry
        .connect(chain_config("slow-15s", 15_000), 0)
        .unwrap();

    // Both chains observe and finalize a header whose block was produced at the
    // same wall-clock instant (100_000 ms) and observed after the 800 ms relay
    // delay, so a shared sample time gives each an identical, small lag.
    for id in ["fast-2s", "slow-15s"] {
        registry
            .chain_mut(id)
            .unwrap()
            .record_sync(SyncOutcome::Success, 100_800);
        registry
            .observe_header(
                id,
                RecentHeader::new(1, 100_000, COMMITTEE_WEIGHT, ATTESTING_WEIGHT, 100_800),
            )
            .unwrap();
        assert_eq!(
            registry.try_finalize(id, 101_000).unwrap(),
            FinalityDecision::Finalized
        );
    }

    let now = 101_000;
    let gauges = registry.finality_lag_gauges(now);
    assert_eq!(gauges.len(), 2);
    // BTreeMap ordering: "fast-2s" < "slow-15s".
    assert_eq!(gauges[0].chain_id, "fast-2s");
    assert_eq!(gauges[1].chain_id, "slow-15s");
    for gauge in &gauges {
        assert_eq!(gauge.finalized_height, Some(1));
        assert_eq!(gauge.finality_lag_ms, 1_000); // 101_000 - 100_000
        assert!(
            gauge.within_target,
            "{} lag {} ms exceeded target",
            gauge.chain_id, gauge.finality_lag_ms
        );
    }
    assert_eq!(registry.max_finality_lag_ms(now), 1_000);
    assert!(registry.all_within_target(now));
}

// ---------------------------------------------------------------------------
// Sync-drift grace period (issue #136 requirement 3), end-to-end
// ---------------------------------------------------------------------------

#[test]
fn stalled_sync_triggers_drift_and_grace_period_withholds_finality() {
    let mut registry = LightClientRegistry::new();
    registry.connect(chain_config("fast-2s", 2_000), 0).unwrap();

    // A header arrives, but the committee sync then stalls: no successful sync
    // is recorded, so staleness climbs past the 60 s sync timeout and drift is
    // declared. sync_timeout = max(3 * 2_000, 60_000) = 60_000 ms.
    registry
        .observe_header(
            "fast-2s",
            RecentHeader::new(1, 2_000, COMMITTEE_WEIGHT, ATTESTING_WEIGHT, 2_800),
        )
        .unwrap();

    let chain = registry.chain("fast-2s").unwrap();
    assert!(
        !chain.drift_detected(60_000),
        "no drift exactly at the timeout"
    );
    assert!(
        chain.drift_detected(60_001),
        "drift once staleness passes the timeout"
    );

    // Under drift the header is withheld until the grace period elapses:
    // grace = 1.5 * 60_000 = 90_000 ms, measured from observation (2_800).
    assert_eq!(
        registry.try_finalize("fast-2s", 92_799).unwrap(),
        FinalityDecision::AwaitingGracePeriod
    );
    assert_eq!(
        registry.try_finalize("fast-2s", 92_800).unwrap(),
        FinalityDecision::Finalized
    );
}

#[test]
fn clock_skew_beyond_hop_budget_triggers_drift() {
    let mut registry = LightClientRegistry::new();
    registry.connect(chain_config("fast-2s", 2_000), 0).unwrap();
    // Budget = 500 ms * 2 hops = 1_000 ms.
    let chain = registry.chain_mut("fast-2s").unwrap();
    chain.sync.observe_skew(1_000);
    assert!(!chain.drift_detected(0));
    chain.sync.observe_skew(1_001);
    assert!(chain.drift_detected(0));
}

// ---------------------------------------------------------------------------
// Exponential retry backoff (issue #136 invariant), end-to-end
// ---------------------------------------------------------------------------

#[test]
fn repeated_sync_failures_back_off_exponentially_and_cap() {
    let mut state = CommitteeSyncState::new("fast-2s".into(), 0);
    let expected = [
        SYNC_BACKOFF_BASE_MS,      // 1 s
        SYNC_BACKOFF_BASE_MS * 2,  // 2 s
        SYNC_BACKOFF_BASE_MS * 4,  // 4 s
        SYNC_BACKOFF_BASE_MS * 8,  // 8 s
        SYNC_BACKOFF_BASE_MS * 16, // 16 s
        SYNC_BACKOFF_CAP_MS,       // capped at 30 s
        SYNC_BACKOFF_CAP_MS,       // stays capped
    ];
    for exp in expected {
        state.record_outcome(SyncOutcome::Failure, 0);
        assert_eq!(state.backoff_delay_ms(), exp);
    }
    // A success resets the backoff to zero.
    state.record_outcome(SyncOutcome::Success, 10_000);
    assert_eq!(state.backoff_delay_ms(), 0);
}

// ---------------------------------------------------------------------------
// Bounded header cache (issue #136 invariant)
// ---------------------------------------------------------------------------

#[test]
fn header_cache_retains_only_the_most_recent_headers() {
    let mut cache = HeaderCache::new();
    for height in 0..(HEADER_CACHE_CAPACITY as u64 * 2) {
        cache.insert(RecentHeader::new(
            height,
            height * 2_000,
            COMMITTEE_WEIGHT,
            ATTESTING_WEIGHT,
            height * 2_000 + 800,
        ));
    }
    assert_eq!(cache.len(), HEADER_CACHE_CAPACITY);
    assert_eq!(cache.capacity(), HEADER_CACHE_CAPACITY);
    // The newest header is retained; the oldest half was evicted.
    assert_eq!(
        cache.latest().unwrap().height,
        HEADER_CACHE_CAPACITY as u64 * 2 - 1
    );
    assert!(cache.get(0).is_none());
}

// ---------------------------------------------------------------------------
// Direct verifier / registry unit-level integration checks
// ---------------------------------------------------------------------------

#[test]
fn finality_threshold_is_two_thirds_plus_one_of_committee_weight() {
    assert_eq!(
        FinalityVerifier::finality_threshold_weight(COMMITTEE_WEIGHT),
        67
    );
    assert!(!FinalityVerifier::meets_finality_threshold(
        66,
        COMMITTEE_WEIGHT
    ));
    assert!(FinalityVerifier::meets_finality_threshold(
        67,
        COMMITTEE_WEIGHT
    ));
}

#[test]
fn connected_chain_can_be_built_and_finalized_directly() {
    let mut chain = ConnectedChain::new(chain_config("solo", 2_000), 0);
    chain.record_sync(SyncOutcome::Success, 2_800);
    chain.observe_header(RecentHeader::new(
        1,
        2_000,
        COMMITTEE_WEIGHT,
        ATTESTING_WEIGHT,
        2_800,
    ));
    assert_eq!(
        chain.try_finalize_latest(3_000),
        FinalityDecision::Finalized
    );
    assert_eq!(chain.finalized_height(), Some(1));
    assert_eq!(chain.finality_lag_ms(3_000), 1_000);
}

#[test]
fn registry_rejects_duplicate_and_invalid_chains() {
    let mut registry = LightClientRegistry::new();
    registry.connect(chain_config("eth", 2_000), 0).unwrap();
    assert_eq!(
        registry.connect(chain_config("eth", 2_000), 0),
        Err(CrossChainError::ChainAlreadyConnected)
    );
    assert_eq!(
        registry.connect(ChainConfig::new(String::new(), 2_000, 32, 1), 0),
        Err(CrossChainError::EmptyChainId)
    );
    assert_eq!(registry.connected_count(), 1);
}

// ---------------------------------------------------------------------------
// Issue #136 operational constants
// ---------------------------------------------------------------------------

#[test]
fn issue_136_constants_match_technical_bounds() {
    assert_eq!(MAX_CLOCK_DRIFT_MS_PER_HOP, 500);
    assert_eq!(SYNC_TIMEOUT_MULTIPLIER, 3);
    assert_eq!(MIN_SYNC_TIMEOUT_MS, 60_000);
    assert_eq!(SYNC_INTERVAL_DIVISOR, 4);
    assert_eq!(HEADER_CACHE_CAPACITY, 256);
    assert_eq!(SYNC_BACKOFF_BASE_MS, 1_000);
    assert_eq!(SYNC_BACKOFF_CAP_MS, 30_000);
    assert_eq!(GRACE_PERIOD_MULTIPLIER_BPS, 15_000); // 1.5x
    assert_eq!(MAX_ACCEPTABLE_FINALITY_LAG_MS, 10_000);
}
