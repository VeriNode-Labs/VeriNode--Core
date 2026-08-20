//! Per-chain committee synchronization scheduling, retry backoff, and sync-drift
//! detection (issue #136).
//!
//! Each connected chain owns a [`CommitteeSyncState`] that decides *when* to
//! re-sample the sync committee and detects when the light client's view of
//! that committee has drifted — either because sampling has stalled past the
//! chain's [sync timeout](super::ChainConfig::sync_timeout_ms) or because the
//! observed clock skew exceeds the chain's per-hop
//! [drift budget](super::ChainConfig::max_clock_drift_ms).
//!
//! The sync cadence is derived per chain as `block_time_ms / 4`, so a 2 s chain
//! syncs every 500 ms and a 15 s chain every 3750 ms. Failed syncs back off
//! exponentially (1 s → 2 s → 4 s → … capped at 30 s) so a struggling upstream
//! is not hammered.

extern crate alloc;

use super::types::{ChainConfig, ChainId, SYNC_BACKOFF_BASE_MS, SYNC_BACKOFF_CAP_MS};

/// Outcome of a single committee-sync attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncOutcome {
    /// The committee was sampled successfully.
    Success,
    /// The sync attempt exceeded the chain's sync timeout.
    Timeout,
    /// The sync attempt failed for another reason (e.g. transport error).
    Failure,
}

/// Mutable synchronization state for one connected chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitteeSyncState {
    /// Identifier of the chain this state tracks.
    pub chain_id: ChainId,
    /// Local time of the last *successful* committee sync, in milliseconds.
    pub last_sync_ms: u64,
    /// Consecutive failed sync attempts since the last success.
    pub consecutive_failures: u32,
    /// Most recent observed clock skew between the chain and the light client,
    /// in milliseconds.
    pub last_observed_skew_ms: u64,
}

impl CommitteeSyncState {
    /// Creates fresh sync state for a chain, as of `now_ms`.
    pub fn new(chain_id: ChainId, now_ms: u64) -> Self {
        Self {
            chain_id,
            last_sync_ms: now_ms,
            consecutive_failures: 0,
            last_observed_skew_ms: 0,
        }
    }

    /// Local time at which the next committee sync is due.
    ///
    /// The base cadence is `block_time_ms / 4`; while sync attempts are failing
    /// the exponential [backoff](Self::backoff_delay_ms) is added so a
    /// struggling upstream is retried progressively less often.
    pub fn next_sync_due_ms(&self, config: &ChainConfig) -> u64 {
        self.last_sync_ms
            .saturating_add(config.sync_interval_ms())
            .saturating_add(self.backoff_delay_ms())
    }

    /// Returns `true` when `now_ms` has reached the next scheduled sync.
    pub fn due_for_sync(&self, config: &ChainConfig, now_ms: u64) -> bool {
        now_ms >= self.next_sync_due_ms(config)
    }

    /// Exponential retry backoff for the current failure streak, in
    /// milliseconds: `1 s, 2 s, 4 s, … capped at 30 s`. Zero when healthy.
    pub fn backoff_delay_ms(&self) -> u64 {
        if self.consecutive_failures == 0 {
            return 0;
        }
        // `checked_pow` guards the doubling itself; `checked_shl` would not
        // detect value overflow. Saturate to the cap either way.
        let factor = 2u64
            .checked_pow(self.consecutive_failures - 1)
            .unwrap_or(u64::MAX);
        SYNC_BACKOFF_BASE_MS
            .saturating_mul(factor)
            .min(SYNC_BACKOFF_CAP_MS)
    }

    /// Records the result of a sync attempt at `now_ms`.
    ///
    /// A success clears the failure streak and advances `last_sync_ms`; a
    /// timeout or failure increments the streak (and thus the backoff) but does
    /// not advance `last_sync_ms`, so staleness continues to accrue.
    pub fn record_outcome(&mut self, outcome: SyncOutcome, now_ms: u64) {
        match outcome {
            SyncOutcome::Success => {
                self.last_sync_ms = now_ms;
                self.consecutive_failures = 0;
            }
            SyncOutcome::Timeout | SyncOutcome::Failure => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            }
        }
    }

    /// Updates the most recently observed clock skew, in milliseconds.
    pub fn observe_skew(&mut self, skew_ms: u64) {
        self.last_observed_skew_ms = skew_ms;
    }

    /// Milliseconds elapsed since the last successful sync as of `now_ms`.
    pub fn staleness_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.last_sync_ms)
    }

    /// Returns `true` when the light client's committee view has drifted.
    ///
    /// Drift is declared when either the time since the last successful sync
    /// exceeds the chain's sync timeout, or the observed clock skew exceeds the
    /// chain's per-hop drift budget.
    pub fn drift_detected(&self, config: &ChainConfig, now_ms: u64) -> bool {
        self.staleness_ms(now_ms) > config.sync_timeout_ms()
            || self.last_observed_skew_ms > config.max_clock_drift_ms()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(block_time_ms: u64, hops: u32) -> ChainConfig {
        ChainConfig::new("chain".into(), block_time_ms, 32, hops)
    }

    fn state() -> CommitteeSyncState {
        CommitteeSyncState::new("chain".into(), 0)
    }

    #[test]
    fn healthy_backoff_is_zero() {
        assert_eq!(state().backoff_delay_ms(), 0);
    }

    #[test]
    fn backoff_grows_exponentially_then_caps() {
        let mut s = state();
        let expected = [1_000u64, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000];
        for exp in expected {
            s.record_outcome(SyncOutcome::Failure, 0);
            assert_eq!(s.backoff_delay_ms(), exp);
        }
    }

    #[test]
    fn backoff_saturates_for_pathological_failure_counts() {
        let mut s = state();
        s.consecutive_failures = u32::MAX;
        // Must not panic on overflow; caps at the ceiling.
        assert_eq!(s.backoff_delay_ms(), SYNC_BACKOFF_CAP_MS);
    }

    #[test]
    fn success_clears_failure_streak_and_advances_last_sync() {
        let mut s = state();
        s.record_outcome(SyncOutcome::Failure, 100);
        s.record_outcome(SyncOutcome::Timeout, 200);
        assert_eq!(s.consecutive_failures, 2);
        s.record_outcome(SyncOutcome::Success, 500);
        assert_eq!(s.consecutive_failures, 0);
        assert_eq!(s.last_sync_ms, 500);
        assert_eq!(s.backoff_delay_ms(), 0);
    }

    #[test]
    fn due_for_sync_follows_the_quarter_block_cadence() {
        let config = cfg(2_000, 1); // interval = 500 ms
        let s = state();
        assert!(!s.due_for_sync(&config, 499));
        assert!(s.due_for_sync(&config, 500));
    }

    #[test]
    fn backoff_defers_the_next_sync_while_failing() {
        let config = cfg(2_000, 1); // interval = 500 ms
        let mut s = state();
        s.record_outcome(SyncOutcome::Failure, 0); // backoff = 1_000 ms
        // Next sync is interval (500) + backoff (1_000) after last success (0).
        assert_eq!(s.next_sync_due_ms(&config), 1_500);
        assert!(!s.due_for_sync(&config, 1_499));
        assert!(s.due_for_sync(&config, 1_500));
    }

    #[test]
    fn drift_detected_when_staleness_exceeds_sync_timeout() {
        let config = cfg(2_000, 1); // sync_timeout floored at 60_000 ms
        let s = state();
        assert!(!s.drift_detected(&config, 60_000));
        assert!(s.drift_detected(&config, 60_001));
    }

    #[test]
    fn drift_detected_when_clock_skew_exceeds_budget() {
        let config = cfg(2_000, 2); // drift budget = 1_000 ms
        let mut s = state();
        s.observe_skew(1_000);
        assert!(!s.drift_detected(&config, 0));
        s.observe_skew(1_001);
        assert!(s.drift_detected(&config, 0));
    }
}

