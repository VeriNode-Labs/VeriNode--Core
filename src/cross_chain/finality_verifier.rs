//! Finality verification with sync-drift-aware grace period (issue #136).
//!
//! A header is finalized once at least `2/3 + 1` of the committee weight has
//! attested to it. When the committee sync has [drifted](super::CommitteeSyncState::drift_detected)
//! the verifier additionally withholds finalization until a grace period —
//! `1.5x` the chain's sync timeout, measured from when the header was first
//! observed — has elapsed. This prevents a temporarily skewed committee view
//! from finalizing a header prematurely while sampling catches back up.

extern crate alloc;

use super::types::{
    ChainConfig, BPS_DENOMINATOR, FINALITY_THRESHOLD_DENOMINATOR, FINALITY_THRESHOLD_NUMERATOR,
    GRACE_PERIOD_MULTIPLIER_BPS,
};

/// The result of evaluating whether a header can be finalized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalityDecision {
    /// The header is finalized.
    Finalized,
    /// The attesting committee weight is below the `2/3 + 1` threshold.
    InsufficientWeight,
    /// The weight threshold is met but sync drift was detected and the grace
    /// period has not yet elapsed.
    AwaitingGracePeriod,
}

/// Stateless finality verifier.
pub struct FinalityVerifier;

impl FinalityVerifier {
    /// Minimum attesting weight required to finalize, given the total committee
    /// weight: `floor(2/3 * total) + 1`.
    pub fn finality_threshold_weight(total_committee_weight: u64) -> u64 {
        total_committee_weight.saturating_mul(FINALITY_THRESHOLD_NUMERATOR)
            / FINALITY_THRESHOLD_DENOMINATOR
            + 1
    }

    /// Returns `true` when `attesting_weight` meets the `2/3 + 1` threshold.
    pub fn meets_finality_threshold(attesting_weight: u64, total_committee_weight: u64) -> bool {
        attesting_weight >= Self::finality_threshold_weight(total_committee_weight)
    }

    /// Grace period applied before finalizing under detected drift:
    /// `1.5x` the chain's sync timeout, in milliseconds.
    pub fn grace_period_ms(config: &ChainConfig) -> u64 {
        config
            .sync_timeout_ms()
            .saturating_mul(GRACE_PERIOD_MULTIPLIER_BPS)
            / BPS_DENOMINATOR
    }

    /// Evaluates whether a header can be finalized.
    ///
    /// Decision rules (in order):
    /// 1. Attesting weight below `2/3 + 1` → [`InsufficientWeight`](FinalityDecision::InsufficientWeight).
    /// 2. Threshold met **and** sync drift detected **and** the grace period has
    ///    not elapsed since the header was observed →
    ///    [`AwaitingGracePeriod`](FinalityDecision::AwaitingGracePeriod).
    /// 3. Otherwise → [`Finalized`](FinalityDecision::Finalized).
    pub fn evaluate_finality(
        config: &ChainConfig,
        attesting_weight: u64,
        total_committee_weight: u64,
        header_observed_ms: u64,
        now_ms: u64,
        sync_drift_detected: bool,
    ) -> FinalityDecision {
        if !Self::meets_finality_threshold(attesting_weight, total_committee_weight) {
            return FinalityDecision::InsufficientWeight;
        }

        if sync_drift_detected {
            let grace_deadline = header_observed_ms.saturating_add(Self::grace_period_ms(config));
            if now_ms < grace_deadline {
                return FinalityDecision::AwaitingGracePeriod;
            }
        }

        FinalityDecision::Finalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(block_time_ms: u64) -> ChainConfig {
        ChainConfig::new("chain".into(), block_time_ms, 32, 2)
    }

    #[test]
    fn threshold_is_two_thirds_plus_one() {
        // total = 99 → floor(2/3 * 99) + 1 = 66 + 1 = 67.
        assert_eq!(FinalityVerifier::finality_threshold_weight(99), 67);
        assert!(!FinalityVerifier::meets_finality_threshold(66, 99));
        assert!(FinalityVerifier::meets_finality_threshold(67, 99));
    }

    #[test]
    fn threshold_handles_zero_total_weight() {
        // floor(2/3 * 0) + 1 = 1, so any positive weight finalizes an empty set.
        assert_eq!(FinalityVerifier::finality_threshold_weight(0), 1);
        assert!(!FinalityVerifier::meets_finality_threshold(0, 0));
    }

    #[test]
    fn threshold_saturates_for_huge_committee_weight() {
        // Must not panic when 2 * total overflows u64.
        let _ = FinalityVerifier::finality_threshold_weight(u64::MAX);
    }

    #[test]
    fn grace_period_is_one_and_a_half_sync_timeouts() {
        // sync_timeout floored at 60_000 ms → grace = 90_000 ms.
        assert_eq!(FinalityVerifier::grace_period_ms(&cfg(2_000)), 90_000);
        // 25 s block → sync_timeout 75_000 ms → grace = 112_500 ms.
        assert_eq!(FinalityVerifier::grace_period_ms(&cfg(25_000)), 112_500);
    }

    #[test]
    fn insufficient_weight_is_never_finalized() {
        assert_eq!(
            FinalityVerifier::evaluate_finality(&cfg(2_000), 66, 99, 0, 1_000_000, false),
            FinalityDecision::InsufficientWeight
        );
    }

    #[test]
    fn finalizes_immediately_without_drift() {
        assert_eq!(
            FinalityVerifier::evaluate_finality(&cfg(2_000), 67, 99, 1_000, 1_050, false),
            FinalityDecision::Finalized
        );
    }

    #[test]
    fn withholds_finalization_during_grace_period_under_drift() {
        // Header observed at t=1_000; grace = 90_000 → deadline 91_000.
        let config = cfg(2_000);
        assert_eq!(
            FinalityVerifier::evaluate_finality(&config, 67, 99, 1_000, 90_999, true),
            FinalityDecision::AwaitingGracePeriod
        );
        assert_eq!(
            FinalityVerifier::evaluate_finality(&config, 67, 99, 1_000, 91_000, true),
            FinalityDecision::Finalized
        );
    }

    #[test]
    fn drift_without_weight_still_reports_insufficient_weight() {
        // Weight rule takes priority over the grace-period rule.
        assert_eq!(
            FinalityVerifier::evaluate_finality(&cfg(2_000), 10, 99, 0, 0, true),
            FinalityDecision::InsufficientWeight
        );
    }
}
