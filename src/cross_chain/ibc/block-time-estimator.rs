//! Per-chain block-time estimation for IBC packet timeouts (issue #138).
//!
//! # Why three statistics, and not one
//!
//! Issue #138's blueprint asks for "an EMA with `alpha = 0.3` over 100 blocks",
//! which conflates two objects that cannot be the same thing:
//!
//! * A **p95 is an order statistic**. It cannot be recovered from an EMA, which
//!   is a first-moment recursion carrying no distributional information. A
//!   retained sample window is therefore mandatory regardless.
//! * An **`alpha = 0.3` EMA has a mean lag of `(1 - a) / a = 2.33` samples** and
//!   settles to within 1% of a step in `ln(0.01) / ln(0.7) = 12.9` samples. It
//!   has forgotten everything older than ~13 blocks, so "over 100 blocks" is
//!   incoherent as a description of it — the window is ~8x longer than the
//!   EMA's entire memory.
//!
//! This estimator therefore keeps a 100-sample sliding window *and* an EMA, and
//! gives each of the three derived statistics one job it is actually suited to:
//!
//! | Statistic | Job |
//! | --- | --- |
//! | [`window_mean_block_time_ms`](BlockTimeEstimator::window_mean_block_time_ms) | the divisor in the timeout formula |
//! | [`p95_block_time_ms`](BlockTimeEstimator::p95_block_time_ms) | tail / dispersion signal and diagnostics |
//! | [`ema_block_time_ms`](BlockTimeEstimator::ema_block_time_ms) | fast regime tracker; re-seeds the window on recalibration |
//!
//! ## The divisor is the mean, not the p95
//!
//! The wall-clock time to advance `N` blocks is the **sum** of `N` block times,
//! so by the law of large numbers it concentrates on `N * mean` — never on
//! `N * p95`. Dividing the timeout delta by a p95 does not buy safety; it
//! systematically under-counts blocks. On issue #138's own scenario (2 s
//! baseline, every tenth block spiking to 30 s, so `mean = 4.8 s` and
//! `p95 = 30 s`), a 60 s delta yields `ceil(60/30) = 2` blocks that elapse in
//! ~9.6 s — an 84% under-shoot — against `ceil(60/4.8) = 13` blocks elapsing in
//! ~62.4 s, a 4% over-shoot. See [`super::packet_timeout`] for the full
//! derivation. The p95 is still computed and load-bearing, just not as the
//! divisor.
//!
//! ## Slowness and variance are orthogonal, and read from orthogonal statistics
//!
//! A uniformly slow chain (25 s blocks, no spread) and a spiky chain (2 s with
//! 30 s spikes) share the same p95, so a p95 alone cannot tell them apart. The
//! *level* is [`window_mean_block_time_ms`](BlockTimeEstimator::window_mean_block_time_ms)
//! and the *shape* is [`dispersion_bps`](BlockTimeEstimator::dispersion_bps)
//! (`p95 / mean`): ~10_400 bps for the uniformly slow chain against ~62_500 bps
//! for the spiky one. A consistently slow chain converges to an accurate — not
//! perpetually inflated — block time and is never treated as variable.
//!
//! All arithmetic is integer-only and saturating so the module compiles under
//! `no_std` (WASM), matching the rest of [`crate::cross_chain`].

extern crate alloc;

use alloc::vec::Vec;

use crate::cross_chain::types::{ChainConfig, ChainId, BPS_DENOMINATOR};

// ---------------------------------------------------------------------------
// Operational constants (issue #138 technical invariants)
// ---------------------------------------------------------------------------

/// Number of block-time samples retained per chain in the sliding window.
///
/// This is the "100 blocks" of the issue #138 blueprint, realized as a genuine
/// sliding sample window — the only structure from which a percentile can be
/// computed at all.
pub const BLOCK_TIME_WINDOW_SAMPLES: usize = 100;

/// EMA smoothing factor in basis points: `3_000 bps = alpha 0.3`.
///
/// Expressed in basis points against [`BPS_DENOMINATOR`] to keep the update
/// integer-only, matching [`crate::cross_chain::types::GRACE_PERIOD_MULTIPLIER_BPS`].
pub const BLOCK_TIME_EMA_ALPHA_BPS: u64 = 3_000;

/// Percentile used as the tail / dispersion statistic (the blueprint's p95).
pub const BLOCK_TIME_TAIL_PERCENTILE: u64 = 95;

// ---------------------------------------------------------------------------
// Nearest-rank percentiles
// ---------------------------------------------------------------------------

/// Nearest-rank percentile index into an ascending-sorted slice of length `n`
/// (`n > 0`). `p` is a whole-number percentile (e.g. `50`, `95`).
///
/// This is deliberately the same nearest-rank formula as
/// `crate::mempool::priority_queue`'s percentile helper: `ceil(p/100 * n) - 1`
/// in integer arithmetic, clamped into `[0, n - 1]`. Percentile definitions
/// diverge at small `n`, so pinning one matters. Nearest rank is chosen because
/// it is exact rather than approximate, needs no interpolation (and therefore
/// no floats, which this module cannot use), is well-defined for every `n >= 1`,
/// and always returns a value the chain actually produced — never an
/// interpolated block time that never occurred.
///
/// Small-`n` behaviour is consequently well-defined throughout: `n = 1` yields
/// the single sample, `n = 10` yields the maximum (`ceil(9.5) = 10`), `n = 20`
/// yields the 19th of 20, and `n = 100` yields the 95th.
fn nearest_rank_index(p: u64, n: usize) -> usize {
    let rank = (p * n as u64).div_ceil(100).max(1);
    (rank as usize - 1).min(n - 1)
}

// ---------------------------------------------------------------------------
// Estimator
// ---------------------------------------------------------------------------

/// Sliding-window block-time estimator for one chain.
///
/// Samples arrive from the header pipeline via
/// [`observe_header`](Self::observe_header); see that method for the
/// consecutive-heights sampling rule and why gaps are deliberately not
/// interpolated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockTimeEstimator {
    /// Identifier of the chain this estimator tracks.
    chain_id: ChainId,
    /// Ring buffer of the most recent block-time samples, in milliseconds.
    /// Every stored sample is strictly positive.
    samples: Vec<u64>,
    /// Next slot to write in `samples` once the ring is full.
    write_ptr: usize,
    /// Total samples ever recorded (saturating), used to distinguish a
    /// partially-filled ring from a wrapped one.
    samples_written: u64,
    /// Exponential moving average of the block time, in milliseconds. `None`
    /// until the first sample seeds it.
    ema_ms: Option<u64>,
    /// `(height, timestamp_ms)` of the last header that anchored a sample.
    anchor: Option<(u64, u64)>,
    /// Number of packet timeouts issued against this chain, driving the
    /// cold-start safety margin in [`super::packet_timeout`].
    packets_issued: u32,
}

impl BlockTimeEstimator {
    /// Creates an estimator with no samples for `chain_id`.
    pub fn new(chain_id: ChainId) -> Self {
        Self {
            chain_id,
            samples: Vec::new(),
            write_ptr: 0,
            samples_written: 0,
            ema_ms: None,
            anchor: None,
            packets_issued: 0,
        }
    }

    /// Identifier of the chain this estimator tracks.
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    // -----------------------------------------------------------------------
    // Ingest
    // -----------------------------------------------------------------------

    /// Records a raw block-time sample in milliseconds.
    ///
    /// Returns `false` (and records nothing) for a zero sample: a zero block
    /// time is malformed, and admitting one would let the window mean reach
    /// zero and become a divisor in the timeout formula.
    pub fn record_block_time_ms(&mut self, block_time_ms: u64) -> bool {
        if block_time_ms == 0 {
            return false;
        }

        // Seed the EMA from the first sample rather than from zero. Seeding
        // from zero would bias the estimate low for ~13 samples, and a low
        // block-time estimate inflates the block count, i.e. late timeouts.
        self.ema_ms = Some(match self.ema_ms {
            None => block_time_ms,
            Some(prev) => ema_step(prev, block_time_ms),
        });

        if self.samples.len() < BLOCK_TIME_WINDOW_SAMPLES {
            self.samples.push(block_time_ms);
        } else {
            self.samples[self.write_ptr] = block_time_ms;
        }
        self.write_ptr = (self.write_ptr + 1) % BLOCK_TIME_WINDOW_SAMPLES;
        self.samples_written = self.samples_written.saturating_add(1);
        true
    }

    /// Feeds a header observation from the header-sync pipeline, deriving a
    /// block-time sample from the gap to the previously anchored header.
    ///
    /// Returns `true` when a sample was recorded.
    ///
    /// # Sampling rule: consecutive heights only
    ///
    /// A sample is taken only when `height == anchor_height + 1` and the
    /// timestamp strictly increases. Any other case re-anchors without
    /// sampling:
    ///
    /// * **Height gaps are not interpolated.** Dividing a multi-block gap by the
    ///   number of blocks it spans would be arithmetically valid for the *mean*
    ///   but would smooth away exactly the per-block dispersion that
    ///   [`p95_block_time_ms`](Self::p95_block_time_ms) and
    ///   [`dispersion_bps`](Self::dispersion_bps) exist to measure — a burst of
    ///   30 s blocks would be laundered into a run of average ones, and the
    ///   spiky chain would become indistinguishable from the uniformly slow one.
    /// * **Non-increasing timestamps are dropped.** A stalled or backwards
    ///   header clock is malformed or adversarial; it would otherwise inject a
    ///   zero-or-negative interval.
    /// * **Non-advancing heights are dropped.** Re-observing a cached height
    ///   (attestations accumulate on a header over time, so the same height is
    ///   observed repeatedly) must not manufacture a second sample.
    pub fn observe_header(&mut self, height: u64, timestamp_ms: u64) -> bool {
        let sampled = match self.anchor {
            Some((anchor_height, anchor_ts))
                if height == anchor_height + 1 && timestamp_ms > anchor_ts =>
            {
                self.record_block_time_ms(timestamp_ms - anchor_ts)
            }
            _ => false,
        };

        // Re-anchor on any forward progress, so a gap costs exactly one sample
        // rather than stalling sampling permanently.
        match self.anchor {
            Some((anchor_height, _)) if height <= anchor_height => {}
            _ => self.anchor = Some((height, timestamp_ms)),
        }
        sampled
    }

    // -----------------------------------------------------------------------
    // Derived statistics
    // -----------------------------------------------------------------------

    /// Number of samples currently in the window (capped at
    /// [`BLOCK_TIME_WINDOW_SAMPLES`]).
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Returns `true` once the window holds a full [`BLOCK_TIME_WINDOW_SAMPLES`]
    /// samples.
    pub fn is_warm(&self) -> bool {
        self.samples.len() >= BLOCK_TIME_WINDOW_SAMPLES
    }

    /// Arithmetic mean of the samples in the window, in milliseconds, or `None`
    /// when the window is empty.
    ///
    /// This is the estimator the timeout formula divides by: elapsed wall-clock
    /// time over `N` blocks is a *sum* of `N` block times, which concentrates on
    /// `N * mean`.
    pub fn window_mean_block_time_ms(&self) -> Option<u64> {
        if self.samples.is_empty() {
            return None;
        }
        let total: u128 = self.samples.iter().map(|&s| s as u128).sum();
        Some((total / self.samples.len() as u128) as u64)
    }

    /// Block-time estimate used by the timeout formula, in milliseconds.
    ///
    /// Three tiers, each with its own justification:
    ///
    /// 1. **Window mean** when any sample exists — the lowest-variance estimator
    ///    of the long-run mean, and the right divisor for a sum of block times.
    /// 2. **EMA** when the window is empty but the EMA is seeded. This happens
    ///    only immediately after a recalibration clears the window, where the
    ///    EMA is the sole surviving memory of the current regime.
    /// 3. **`config.block_time_ms`** when neither exists — the chain's nominal
    ///    configured block time, already carried by [`ChainConfig`]. The
    ///    cold-start safety margin is precisely the hedge against this being
    ///    wrong.
    ///
    /// The result is floored at `1` so it is never a zero divisor even if a
    /// chain is configured with a zero block time (which
    /// [`ChainConfig::validate`] rejects, but this type does not depend on that
    /// having been called).
    pub fn mean_block_time_ms(&self, config: &ChainConfig) -> u64 {
        self.window_mean_block_time_ms()
            .or(self.ema_ms)
            .unwrap_or(config.block_time_ms)
            .max(1)
    }

    /// Nearest-rank percentile over the window, in milliseconds, or `None` when
    /// the window is empty. See [`nearest_rank_index`] for the definition.
    pub fn percentile_block_time_ms(&self, percentile: u64) -> Option<u64> {
        if self.samples.is_empty() {
            return None;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        Some(sorted[nearest_rank_index(percentile, sorted.len())])
    }

    /// The blueprint's p95 block time over the window, in milliseconds.
    ///
    /// Retained as the tail-risk and dispersion signal — *not* as the timeout
    /// divisor; see the module docs for why that distinction is load-bearing.
    pub fn p95_block_time_ms(&self) -> Option<u64> {
        self.percentile_block_time_ms(BLOCK_TIME_TAIL_PERCENTILE)
    }

    /// Current EMA of the block time in milliseconds (`alpha = 0.3`), or `None`
    /// before the first sample seeds it.
    pub fn ema_block_time_ms(&self) -> Option<u64> {
        self.ema_ms
    }

    /// Dispersion of the block-time distribution in basis points: `p95 / mean`.
    ///
    /// `10_000 bps` is a perfectly uniform chain. This is the statistic that
    /// separates "uniformly slow" from "variable": a 25 s chain with a second of
    /// jitter reads ~`10_400 bps`, while a 2 s chain spiking to 30 s reads
    /// ~`62_500 bps`, even though both have the same p95. Returns
    /// [`BPS_DENOMINATOR`] when no samples exist.
    pub fn dispersion_bps(&self, config: &ChainConfig) -> u64 {
        let Some(p95) = self.p95_block_time_ms() else {
            return BPS_DENOMINATOR;
        };
        let mean = self.mean_block_time_ms(config) as u128;
        ((p95 as u128 * BPS_DENOMINATOR as u128) / mean) as u64
    }

    // -----------------------------------------------------------------------
    // Cold-start accounting and recalibration
    // -----------------------------------------------------------------------

    /// Number of packet timeouts issued against this chain since the last
    /// cold-start reset.
    pub fn packets_issued(&self) -> u32 {
        self.packets_issued
    }

    /// Records that a packet timeout was issued against this chain.
    ///
    /// Called only on a successfully computed timeout, so rejected requests do
    /// not consume the cold-start allowance.
    pub fn note_packet_issued(&mut self) {
        self.packets_issued = self.packets_issued.saturating_add(1);
    }

    /// Returns the estimator to cold start, so the next packets receive the
    /// safety margin again.
    ///
    /// Driven by packet count, never by elapsed time: a time-based reset would
    /// let a well-calibrated chain slide back into a permanently inflated
    /// timeout simply by going idle.
    pub fn reset_cold_start(&mut self) {
        self.packets_issued = 0;
    }

    /// Recalibration action: clears the sample window and re-seeds it from the
    /// EMA.
    ///
    /// Misestimation under this design means the window mean is stale — the
    /// chain has moved to a new block-time regime and the window still holds
    /// the old one. The `alpha = 0.3` EMA has a ~13-sample memory, so it has
    /// already tracked the new regime and is the only surviving estimate of it.
    /// Re-seeding from it is direction-agnostic: it corrects the estimate
    /// whichever way the regime moved, unlike the cold-start margin, which can
    /// only push timeouts later.
    ///
    /// Returns the value the window was re-seeded with, if any.
    pub fn reseed_from_ema(&mut self) -> Option<u64> {
        let seed = self.ema_ms?;
        self.samples.clear();
        self.write_ptr = 0;
        self.samples.push(seed);
        self.write_ptr = 1;
        Some(seed)
    }
}

/// One integer EMA step: `alpha * sample + (1 - alpha) * prev`, rounded to
/// nearest.
///
/// Computed in `u128` so the basis-point products cannot overflow, matching the
/// widening used in [`crate::slo`]. Rounding to nearest (rather than truncating)
/// makes a constant input an exact fixed point: with `prev == sample`, the
/// numerator is exactly `BPS_DENOMINATOR * sample + BPS_DENOMINATOR / 2`, which
/// divides back to `sample`.
///
/// Approaching a *changed* constant leaves a fixed-point residue of at most
/// 1 ms — inherent to truncating a ratio at every step, and immaterial against
/// block times measured in thousands of milliseconds.
fn ema_step(prev: u64, sample: u64) -> u64 {
    let alpha = BLOCK_TIME_EMA_ALPHA_BPS as u128;
    let denom = BPS_DENOMINATOR as u128;
    let weighted = alpha * sample as u128 + (denom - alpha) * prev as u128 + denom / 2;
    (weighted / denom) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn estimator() -> BlockTimeEstimator {
        BlockTimeEstimator::new("dest".into())
    }

    fn config(block_time_ms: u64) -> ChainConfig {
        ChainConfig::new("dest".into(), block_time_ms, 32, 1)
    }

    fn feed(est: &mut BlockTimeEstimator, sample_ms: u64, times: usize) {
        for _ in 0..times {
            assert!(est.record_block_time_ms(sample_ms));
        }
    }

    /// The spiky chain of issue #138's own scenario: a 2 s baseline where every
    /// tenth block takes 30 s. Window mean 4_800 ms, p95 30_000 ms.
    fn spiky_window() -> BlockTimeEstimator {
        let mut est = estimator();
        for i in 0..BLOCK_TIME_WINDOW_SAMPLES {
            est.record_block_time_ms(if i % 10 == 9 { 30_000 } else { 2_000 });
        }
        est
    }

    /// A uniformly slow chain: 25 s blocks with 1 s of jitter, no spikes.
    fn uniformly_slow_window() -> BlockTimeEstimator {
        let mut est = estimator();
        for i in 0..BLOCK_TIME_WINDOW_SAMPLES {
            est.record_block_time_ms(24_000 + (i as u64 % 3) * 1_000);
        }
        est
    }

    // -----------------------------------------------------------------------
    // EMA
    // -----------------------------------------------------------------------

    #[test]
    fn ema_is_unseeded_until_the_first_sample() {
        let mut est = estimator();
        assert_eq!(est.ema_block_time_ms(), None);
        est.record_block_time_ms(2_000);
        // Seeded from the first sample, not from zero.
        assert_eq!(est.ema_block_time_ms(), Some(2_000));
    }

    #[test]
    fn ema_is_an_exact_fixed_point_on_constant_input() {
        let mut est = estimator();
        feed(&mut est, 2_000, 50);
        // alpha * x + (1 - alpha) * x == x for any alpha, and round-to-nearest
        // preserves that exactly: (10_000 * 2_000 + 5_000) / 10_000 == 2_000.
        assert_eq!(est.ema_block_time_ms(), Some(2_000));
    }

    #[test]
    fn ema_steps_match_hand_computed_arithmetic() {
        let mut est = estimator();
        est.record_block_time_ms(2_000);
        // (3_000 * 5_000 + 7_000 * 2_000 + 5_000) / 10_000
        //   = (15_000_000 + 14_000_000 + 5_000) / 10_000 = 2_900
        est.record_block_time_ms(5_000);
        assert_eq!(est.ema_block_time_ms(), Some(2_900));
        // (15_000_000 + 7_000 * 2_900 + 5_000) / 10_000
        //   = (15_000_000 + 20_300_000 + 5_000) / 10_000 = 3_530
        est.record_block_time_ms(5_000);
        assert_eq!(est.ema_block_time_ms(), Some(3_530));
    }

    #[test]
    fn ema_settles_to_within_one_percent_in_thirteen_samples() {
        // ln(0.01) / ln(1 - 0.3) = 12.9 samples, per the module docs.
        let mut est = estimator();
        est.record_block_time_ms(2_000);
        feed(&mut est, 5_000, 13);
        let ema = est.ema_block_time_ms().unwrap();
        assert!(
            ema >= 4_950,
            "EMA {ema} should be within 1% of 5_000 after 13 samples"
        );
    }

    #[test]
    fn ema_converges_to_a_changed_constant_within_one_millisecond() {
        let mut est = estimator();
        est.record_block_time_ms(2_000);
        feed(&mut est, 5_000, 200);
        let ema = est.ema_block_time_ms().unwrap();
        // Truncating the ratio each step leaves a residue of at most 1 ms.
        assert!(
            ema.abs_diff(5_000) <= 1,
            "EMA {ema} should converge to within 1 ms of 5_000"
        );
    }

    // -----------------------------------------------------------------------
    // Percentiles
    // -----------------------------------------------------------------------

    #[test]
    fn p95_of_one_to_one_hundred_is_exactly_ninety_five() {
        let mut est = estimator();
        for ms in 1..=100u64 {
            est.record_block_time_ms(ms);
        }
        // Nearest rank: ceil(95/100 * 100) = 95 -> the 95th ascending value.
        assert_eq!(est.p95_block_time_ms(), Some(95));
        // The same helper at other percentiles, on the same known distribution.
        assert_eq!(est.percentile_block_time_ms(50), Some(50));
        assert_eq!(est.percentile_block_time_ms(99), Some(99));
        assert_eq!(est.percentile_block_time_ms(100), Some(100));
        assert_eq!(est.percentile_block_time_ms(1), Some(1));
    }

    #[test]
    fn percentiles_are_well_defined_at_small_sample_counts() {
        // n = 1: ceil(0.95 * 1) = 1 -> the only sample.
        let mut one = estimator();
        one.record_block_time_ms(7_000);
        assert_eq!(one.p95_block_time_ms(), Some(7_000));
        assert_eq!(one.sample_count(), 1);

        // n = 10: ceil(9.5) = 10 -> the maximum.
        let mut ten = estimator();
        for ms in 1..=10u64 {
            ten.record_block_time_ms(ms);
        }
        assert_eq!(ten.p95_block_time_ms(), Some(10));

        // n = 20: ceil(19.0) = 19 -> the 19th of 20, not the maximum.
        let mut twenty = estimator();
        for ms in 1..=20u64 {
            twenty.record_block_time_ms(ms);
        }
        assert_eq!(twenty.p95_block_time_ms(), Some(19));
    }

    #[test]
    fn percentile_is_none_on_an_empty_window() {
        let est = estimator();
        assert_eq!(est.p95_block_time_ms(), None);
        assert_eq!(est.window_mean_block_time_ms(), None);
        assert_eq!(est.sample_count(), 0);
        assert!(!est.is_warm());
    }

    // -----------------------------------------------------------------------
    // Mean, dispersion, and the two failure modes it separates
    // -----------------------------------------------------------------------

    #[test]
    fn spiky_chain_mean_and_p95_match_hand_computed_values() {
        let est = spiky_window();
        // (90 * 2_000 + 10 * 30_000) / 100 = (180_000 + 300_000) / 100 = 4_800
        assert_eq!(est.window_mean_block_time_ms(), Some(4_800));
        // Sorted: ninety 2_000s then ten 30_000s; rank 95 lands in the spikes.
        assert_eq!(est.p95_block_time_ms(), Some(30_000));
        assert!(est.is_warm());
    }

    #[test]
    fn dispersion_separates_a_variable_chain_from_a_uniformly_slow_one() {
        let spiky = spiky_window();
        let slow = uniformly_slow_window();

        // Both chains have a high p95; only one of them is actually variable.
        assert_eq!(spiky.p95_block_time_ms(), Some(30_000));
        assert_eq!(slow.p95_block_time_ms(), Some(26_000));

        // 30_000 * 10_000 / 4_800 = 62_500 bps (6.25x).
        assert_eq!(spiky.dispersion_bps(&config(2_000)), 62_500);
        // (34 * 24_000 + 33 * 25_000 + 33 * 26_000) / 100 = 24_990 ms mean;
        // 26_000 * 10_000 / 24_990 = 10_404 bps (1.04x).
        assert_eq!(slow.window_mean_block_time_ms(), Some(24_990));
        assert_eq!(slow.dispersion_bps(&config(25_000)), 10_404);

        // The separation is what the design reads, and it is ~6x.
        assert!(spiky.dispersion_bps(&config(2_000)) > 60_000);
        assert!(slow.dispersion_bps(&config(25_000)) < 11_000);
    }

    #[test]
    fn dispersion_of_an_empty_window_is_unity() {
        assert_eq!(estimator().dispersion_bps(&config(2_000)), BPS_DENOMINATOR);
    }

    #[test]
    fn a_single_outlier_moves_the_mean_by_a_bounded_one_over_n_share() {
        // 99 blocks at 2 s and one 60 s stall.
        let mut est = estimator();
        feed(&mut est, 2_000, 99);
        est.record_block_time_ms(60_000);
        // (99 * 2_000 + 60_000) / 100 = 258_000 / 100 = 2_580 ms: a single
        // outlier shifts the mean by (outlier - mean) / N and no more.
        assert_eq!(est.window_mean_block_time_ms(), Some(2_580));
        // One sample in a hundred cannot reach the 95th percentile, so the
        // tail statistic correctly reports this chain as still a 2 s chain.
        assert_eq!(est.p95_block_time_ms(), Some(2_000));
    }

    // -----------------------------------------------------------------------
    // Window behaviour below and above capacity
    // -----------------------------------------------------------------------

    #[test]
    fn behaviour_below_a_full_window_is_defined_at_every_count() {
        let mut est = estimator();
        for n in 1..BLOCK_TIME_WINDOW_SAMPLES {
            est.record_block_time_ms(2_000);
            assert_eq!(est.sample_count(), n);
            assert!(!est.is_warm(), "{n} samples must not report warm");
            assert_eq!(est.window_mean_block_time_ms(), Some(2_000));
            assert_eq!(est.p95_block_time_ms(), Some(2_000));
        }
        est.record_block_time_ms(2_000);
        assert_eq!(est.sample_count(), BLOCK_TIME_WINDOW_SAMPLES);
        assert!(est.is_warm());
    }

    #[test]
    fn window_slides_and_forgets_samples_beyond_capacity() {
        let mut est = estimator();
        for ms in 1..=150u64 {
            est.record_block_time_ms(ms);
        }
        assert_eq!(est.sample_count(), BLOCK_TIME_WINDOW_SAMPLES);
        // The window now holds 51..=150: mean = (51 + 150) / 2 = 100.5 -> 100
        // by integer division of the exact sum 10_050 / 100.
        assert_eq!(est.window_mean_block_time_ms(), Some(100));
        // Rank 95 of 51..=150 is 51 + 94 = 145.
        assert_eq!(est.p95_block_time_ms(), Some(145));
    }

    // -----------------------------------------------------------------------
    // Degenerate ingest
    // -----------------------------------------------------------------------

    #[test]
    fn a_zero_block_time_sample_is_rejected() {
        let mut est = estimator();
        assert!(!est.record_block_time_ms(0));
        assert_eq!(est.sample_count(), 0);
        assert_eq!(est.ema_block_time_ms(), None);
    }

    #[test]
    fn mean_never_returns_a_zero_divisor() {
        // Even with a (validation-rejected) zero-block-time config and no
        // samples, the estimate is floored at 1 ms.
        assert_eq!(estimator().mean_block_time_ms(&config(0)), 1);
    }

    // -----------------------------------------------------------------------
    // Header-sync ingest
    // -----------------------------------------------------------------------

    #[test]
    fn consecutive_headers_produce_one_sample_each() {
        let mut est = estimator();
        // The first header only anchors; it cannot yield an interval.
        assert!(!est.observe_header(10, 1_000));
        assert_eq!(est.sample_count(), 0);
        assert!(est.observe_header(11, 3_000));
        assert!(est.observe_header(12, 5_500));
        assert_eq!(est.sample_count(), 2);
        // Intervals 2_000 and 2_500 -> mean 2_250.
        assert_eq!(est.window_mean_block_time_ms(), Some(2_250));
    }

    #[test]
    fn a_height_gap_costs_one_sample_and_re_anchors_without_interpolating() {
        let mut est = estimator();
        est.observe_header(10, 1_000);
        // Heights 11 and 12 were missed; the 10 -> 13 interval spans three
        // blocks and is deliberately NOT divided down into three samples,
        // because averaging it would launder away the per-block dispersion.
        assert!(!est.observe_header(13, 61_000));
        assert_eq!(est.sample_count(), 0);
        // Sampling resumes immediately from the new anchor.
        assert!(est.observe_header(14, 63_000));
        assert_eq!(est.sample_count(), 1);
        assert_eq!(est.window_mean_block_time_ms(), Some(2_000));
    }

    #[test]
    fn non_increasing_timestamps_and_repeated_heights_produce_no_sample() {
        let mut est = estimator();
        est.observe_header(10, 5_000);
        // Same height re-observed (attestations accumulate on a cached header).
        assert!(!est.observe_header(10, 5_000));
        // Consecutive height but a stalled clock.
        assert!(!est.observe_header(11, 5_000));
        // Consecutive height but a backwards clock.
        assert!(!est.observe_header(12, 4_000));
        assert_eq!(est.sample_count(), 0);
        // The anchor advanced to height 12 despite recording nothing, so a
        // well-formed successor samples correctly.
        assert!(est.observe_header(13, 6_000));
        assert_eq!(est.window_mean_block_time_ms(), Some(2_000));
    }

    // -----------------------------------------------------------------------
    // Fallback tiers, cold start, and recalibration
    // -----------------------------------------------------------------------

    #[test]
    fn mean_falls_back_through_the_ema_to_the_configured_block_time() {
        let cfg = config(7_777);
        let mut est = estimator();
        // Tier 3: no samples, no EMA -> the chain's nominal configured time.
        assert_eq!(est.mean_block_time_ms(&cfg), 7_777);

        // Tier 1: any sample at all wins over the config.
        est.record_block_time_ms(2_000);
        assert_eq!(est.mean_block_time_ms(&cfg), 2_000);

        // Tier 2: window cleared but the EMA survives (post-recalibration).
        est.samples.clear();
        est.write_ptr = 0;
        assert_eq!(est.ema_block_time_ms(), Some(2_000));
        assert_eq!(est.mean_block_time_ms(&cfg), 2_000);
    }

    #[test]
    fn cold_start_counter_increments_and_resets() {
        let mut est = estimator();
        assert_eq!(est.packets_issued(), 0);
        est.note_packet_issued();
        est.note_packet_issued();
        assert_eq!(est.packets_issued(), 2);
        est.reset_cold_start();
        assert_eq!(est.packets_issued(), 0);
    }

    #[test]
    fn cold_start_counter_saturates_instead_of_overflowing() {
        let mut est = estimator();
        est.packets_issued = u32::MAX;
        est.note_packet_issued();
        assert_eq!(est.packets_issued(), u32::MAX);
    }

    #[test]
    fn reseed_from_ema_replaces_the_window_with_the_current_regime() {
        let mut est = estimator();
        // A stale 2 s regime fills the window, then the chain moves to 30 s.
        feed(&mut est, 2_000, BLOCK_TIME_WINDOW_SAMPLES);
        feed(&mut est, 30_000, 20);
        let ema = est.ema_block_time_ms().unwrap();
        // The window still mostly holds the old regime; the EMA does not.
        let stale_mean = est.window_mean_block_time_ms().unwrap();
        assert!(
            stale_mean < 10_000,
            "window mean {stale_mean} should still be dominated by the old regime"
        );
        assert!(
            ema > 29_000,
            "EMA {ema} should already track the new regime"
        );

        assert_eq!(est.reseed_from_ema(), Some(ema));
        assert_eq!(est.sample_count(), 1);
        assert_eq!(est.window_mean_block_time_ms(), Some(ema));
    }

    #[test]
    fn reseed_from_ema_is_a_no_op_when_the_ema_is_unseeded() {
        let mut est = estimator();
        assert_eq!(est.reseed_from_ema(), None);
        assert_eq!(est.sample_count(), 0);
    }
}
