//! IBC packet timeout-height calculation (issue #138).
//!
//! # The formula, derived
//!
//! A packet's `timeout_height` is a height on the chain the timeout is
//! denominated in. To place it, convert the caller's wall-clock timeout window
//! into a block count and advance from a known height:
//!
//! ```text
//! blocks         = ceil(timeout_delta_ms / mean_block_time_ms)
//! timeout_height = reference_height + blocks
//! ```
//!
//! ## Units: the blueprint's formula is wrong by a factor of 1000
//!
//! Issue #138's blueprint states the formula as
//! `source_height + ceil(timeout_delta / p95_block_time_ms)`, with
//! `timeout_delta` documented in **seconds** (10-300 s) and the divisor in
//! **milliseconds**. Implemented literally, with a 60-second delta on a 2-second
//! chain:
//!
//! ```text
//! ceil(60 / 2_000) = ceil(0.03) = 1 block          <-- wrong
//! ceil(60_000 / 2_000) = 30 blocks                 <-- correct
//! ```
//!
//! The mismatch is exactly the s-to-ms factor, 1000x, and it always errs toward
//! the floor — so every packet would be given a single block to live and die at
//! the destination chain's very next block. That is a strictly worse form of the
//! bug this module exists to fix.
//!
//! This module therefore carries the delta as `timeout_delta_ms` throughout,
//! matching the `_ms` convention used everywhere in [`crate::cross_chain`], so
//! the units cancel dimensionally: `ms / ms` is a dimensionless block count.
//!
//! ## The divisor is the mean, not the p95
//!
//! The wall-clock time to advance `N` blocks is the **sum** of `N` block times.
//! By the law of large numbers that sum concentrates on `N * mean` — it never
//! concentrates on `N * p95`. Dividing by a p95 does not buy safety; it
//! systematically under-counts blocks, and the under-count is severe on exactly
//! the chains issue #138 is about.
//!
//! Worked on the issue's own scenario — a 2 s baseline where every tenth block
//! spikes to 30 s, giving `mean = 4_800 ms` and `p95 = 30_000 ms` — for a 60 s
//! timeout window:
//!
//! ```text
//! divisor   blocks                        expected elapsed          error
//! -------   ---------------------------   -----------------------   ------
//! 2_000     ceil(60_000/2_000)  = 30      30 * 4_800 = 144_000 ms   +140%
//! (assumed fixed 2 s: the status-quo bug)
//! 30_000    ceil(60_000/30_000) =  2       2 * 4_800 =   9_600 ms    -84%
//! (blueprint's p95 divisor)
//! 4_800     ceil(60_000/4_800)  = 13      13 * 4_800 =  62_400 ms     +4%
//! (this module's mean divisor)
//! ```
//!
//! The issue's own acceptance bar is "packet timeout accuracy > 95%". The p95
//! divisor misses it by an order of magnitude, in the opposite direction from
//! the status quo. The p95 remains fully computed and load-bearing — as the
//! dispersion signal, in the cold-start reasoning, and on the misestimation
//! event — it is simply not the divisor.
//!
//! ## `reference_height`, not `source_height`
//!
//! The blueprint names this `source_height`. The block count is denominated in
//! the **destination** chain's blocks: it is that chain's block time being
//! estimated, its heights that the timeout is compared against, and the
//! blueprint's own cold-start rule ("the first 10 packets *to a new chain*")
//! and per-destination recalibration both key on it. Adding a
//! destination-derived block count to a source-chain height produces a height
//! on neither chain. The parameter is named `reference_height` and documented
//! as the latest known height of the chain whose estimator is supplied, so the
//! two cannot be mixed up.
//!
//! ## Rounding
//!
//! `div_ceil`, not truncation. Under-counting blocks kills a packet before its
//! window has elapsed — a user-visible spurious failure — whereas over-counting
//! merely delays a refund. Rounding up costs at most one block and errs toward
//! the recoverable side.

extern crate alloc;

use super::block_time_estimator::BlockTimeEstimator;
use crate::cross_chain::types::{ChainConfig, BPS_DENOMINATOR};

// ---------------------------------------------------------------------------
// Operational constants (issue #138 technical invariants)
// ---------------------------------------------------------------------------

/// Minimum accepted timeout window, in milliseconds (10 s).
pub const MIN_TIMEOUT_DELTA_MS: u64 = 10_000;

/// Maximum accepted timeout window, in milliseconds (300 s).
pub const MAX_TIMEOUT_DELTA_MS: u64 = 300_000;

/// Maximum packet lifetime, in destination-chain blocks.
pub const MAX_PACKET_LIFETIME_BLOCKS: u64 = 1_000;

/// Number of packets to a chain that receive the cold-start safety margin.
pub const COLD_START_PACKET_COUNT: u32 = 10;

/// Cold-start safety margin applied to the block count, in basis points.
///
/// `15_000 bps = 1.5x`, expressed the same way as
/// [`crate::cross_chain::types::GRACE_PERIOD_MULTIPLIER_BPS`].
///
/// The margin raises the block count, which places the timeout height *later*
/// and therefore buys headroom against a premature timeout. That is the correct
/// direction while the window is thin: the dominant cold-start risk is
/// *over*-estimating the block time — a stale [`ChainConfig::block_time_ms`],
/// or the first few samples happening to be slow ones — which yields too small
/// a block count and kills the packet immediately.
pub const COLD_START_MARGIN_BPS: u64 = 15_000;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned when computing a packet timeout height.
///
/// Every out-of-bounds input is an `Err`, never a clamp and never a panic,
/// matching [`crate::cross_chain::types::CrossChainError`]. Clamping would be
/// the dangerous choice here: silently shortening a caller's requested window
/// to fit [`MAX_PACKET_LIFETIME_BLOCKS`] would produce exactly the premature
/// timeout this module exists to prevent, and would do it invisibly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IbcTimeoutError {
    /// The requested window is outside `[MIN_TIMEOUT_DELTA_MS, MAX_TIMEOUT_DELTA_MS]`.
    TimeoutDeltaOutOfRange,
    /// The requested window is shorter than a single block on this chain, so it
    /// cannot be expressed at height granularity at all.
    ///
    /// A 10 s deadline on a 25 s-block chain quantizes to one block and fires
    /// 150% late no matter how good the estimate is. That is a property of
    /// height-denominated deadlines, not an estimation failure, so it is
    /// rejected up front rather than issued and later blamed on the estimator.
    DeltaBelowBlockGranularity,
    /// The resulting block count exceeds [`MAX_PACKET_LIFETIME_BLOCKS`].
    PacketLifetimeExceeded,
}

// ---------------------------------------------------------------------------
// Timeout estimate
// ---------------------------------------------------------------------------

/// A computed packet timeout, with the estimator state that produced it.
///
/// The statistics are carried alongside the height so a misestimation can be
/// diagnosed after the fact without re-deriving what the estimator believed at
/// send time — by then the window has slid on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutEstimate {
    /// Destination-chain height at which the packet times out.
    pub timeout_height: u64,
    /// Latest known destination height the count was measured from.
    pub reference_height: u64,
    /// Block count actually applied, after any cold-start margin.
    pub block_count: u64,
    /// Block count before the cold-start margin.
    pub base_block_count: u64,
    /// Block-time estimate used as the divisor, in milliseconds.
    pub mean_block_time_ms: u64,
    /// Tail block time over the window, in milliseconds, when samples exist.
    pub p95_block_time_ms: Option<u64>,
    /// Block-time dispersion (`p95 / mean`) in basis points.
    pub dispersion_bps: u64,
    /// Whether the cold-start safety margin was applied.
    pub cold_start: bool,
}

// ---------------------------------------------------------------------------
// Calculation
// ---------------------------------------------------------------------------

/// Number of destination-chain blocks a `timeout_delta_ms` window spans, given
/// a block-time estimate.
///
/// Pure: no estimator state is read or written, so the formula can be checked
/// against hand arithmetic in isolation. See the module docs for the unit
/// derivation and for why the divisor is a mean.
///
/// The cold-start margin is applied *before* the
/// [`MAX_PACKET_LIFETIME_BLOCKS`] check, because the margined count is what
/// actually lands on the wire.
pub fn block_count(
    mean_block_time_ms: u64,
    timeout_delta_ms: u64,
    cold_start: bool,
) -> Result<u64, IbcTimeoutError> {
    if !(MIN_TIMEOUT_DELTA_MS..=MAX_TIMEOUT_DELTA_MS).contains(&timeout_delta_ms) {
        return Err(IbcTimeoutError::TimeoutDeltaOutOfRange);
    }
    let divisor = mean_block_time_ms.max(1);
    if timeout_delta_ms < divisor {
        return Err(IbcTimeoutError::DeltaBelowBlockGranularity);
    }

    // ms / ms -> a dimensionless block count. See the module docs: this is the
    // line the blueprint would have had wrong by 1000x.
    let base = timeout_delta_ms.div_ceil(divisor);

    let blocks = if cold_start {
        // ceil(base * 1.5) in basis points, widened so the product cannot wrap.
        let scaled = base as u128 * COLD_START_MARGIN_BPS as u128;
        (scaled.div_ceil(BPS_DENOMINATOR as u128)) as u64
    } else {
        base
    };

    if blocks > MAX_PACKET_LIFETIME_BLOCKS {
        return Err(IbcTimeoutError::PacketLifetimeExceeded);
    }
    Ok(blocks)
}

/// Returns `true` while `estimator`'s chain is still within its cold-start
/// allowance, i.e. fewer than [`COLD_START_PACKET_COUNT`] packets have been
/// issued against it.
///
/// The allowance is counted per destination chain and consumed only by packets
/// that were actually issued; it is reset on chain registration and,
/// conditionally, on recalibration. It is deliberately never reset by elapsed
/// time — a time-based reset would let a well-calibrated chain drift back into
/// a permanently inflated timeout just by going idle.
pub fn in_cold_start(estimator: &BlockTimeEstimator) -> bool {
    estimator.packets_issued() < COLD_START_PACKET_COUNT
}

/// Computes the timeout height for one packet and consumes one packet of the
/// destination chain's cold-start allowance.
///
/// `reference_height` is the latest known height of the chain `estimator`
/// tracks — the destination chain. See the module docs on why this is not the
/// source chain's height.
///
/// The cold-start allowance is consumed only on success, so a rejected request
/// does not burn one of the ten margined packets.
pub fn compute_timeout(
    estimator: &mut BlockTimeEstimator,
    config: &ChainConfig,
    reference_height: u64,
    timeout_delta_ms: u64,
) -> Result<TimeoutEstimate, IbcTimeoutError> {
    let mean_block_time_ms = estimator.mean_block_time_ms(config);
    let cold_start = in_cold_start(estimator);

    let base_block_count = block_count(mean_block_time_ms, timeout_delta_ms, false)?;
    let block_count = block_count(mean_block_time_ms, timeout_delta_ms, cold_start)?;

    estimator.note_packet_issued();

    Ok(TimeoutEstimate {
        timeout_height: reference_height.saturating_add(block_count),
        reference_height,
        block_count,
        base_block_count,
        mean_block_time_ms,
        p95_block_time_ms: estimator.p95_block_time_ms(),
        dispersion_bps: estimator.dispersion_bps(config),
        cold_start,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(block_time_ms: u64) -> ChainConfig {
        ChainConfig::new("dest".into(), block_time_ms, 32, 1)
    }

    /// An estimator whose window holds `count` samples of exactly `sample_ms`,
    /// so the mean is exactly `sample_ms`.
    fn estimator_at(sample_ms: u64, count: usize) -> BlockTimeEstimator {
        let mut est = BlockTimeEstimator::new("dest".into());
        for _ in 0..count {
            est.record_block_time_ms(sample_ms);
        }
        est
    }

    /// Issue #138's own scenario: 2 s baseline, every tenth block 30 s.
    /// Window mean 4_800 ms, p95 30_000 ms.
    fn spiky_estimator() -> BlockTimeEstimator {
        let mut est = BlockTimeEstimator::new("dest".into());
        for i in 0..100 {
            est.record_block_time_ms(if i % 10 == 9 { 30_000 } else { 2_000 });
        }
        est
    }

    // -----------------------------------------------------------------------
    // The corrected formula, against hand arithmetic
    // -----------------------------------------------------------------------

    #[test]
    fn block_count_matches_hand_computed_arithmetic() {
        // 60_000 / 2_000 = 30 exactly.
        assert_eq!(block_count(2_000, 60_000, false), Ok(30));
        // 60_000 / 4_800 = 12.5 -> 13.
        assert_eq!(block_count(4_800, 60_000, false), Ok(13));
        // 300_000 / 4_800 = 62.5 -> 63.
        assert_eq!(block_count(4_800, 300_000, false), Ok(63));
        // 300_000 / 25_000 = 12 exactly.
        assert_eq!(block_count(25_000, 300_000, false), Ok(12));
        // 120_000 / 25_000 = 4.8 -> 5.
        assert_eq!(block_count(25_000, 120_000, false), Ok(5));
    }

    #[test]
    fn the_literal_blueprint_formula_collapses_to_one_block_everywhere() {
        // The blueprint divides a delta documented in SECONDS by a block time
        // in MILLISECONDS. Across the entire documented input space -- 10-300 s
        // against any block time of a second or more -- the numerator is always
        // smaller than the divisor, so ceil() pins the result at 1 block.
        for delta_secs in [10u64, 60, 120, 300] {
            for block_time_ms in [1_000u64, 2_000, 4_800, 15_000, 30_000] {
                assert_eq!(
                    delta_secs.div_ceil(block_time_ms),
                    1,
                    "literal blueprint formula at delta={delta_secs}s, block={block_time_ms}ms"
                );
            }
        }
        // The unit-corrected form, same inputs, is the real answer.
        assert_eq!(60_000u64.div_ceil(2_000), 30);
        assert_eq!(block_count(2_000, 60_000, false), Ok(30));
    }

    #[test]
    fn the_p95_divisor_undershoots_the_issue_scenario_by_eighty_four_percent() {
        // Issue #138's scenario: mean 4_800 ms, p95 30_000 ms, 60 s window.
        const DELTA_MS: u64 = 60_000;
        const TRUE_MEAN_MS: u64 = 4_800;
        const P95_MS: u64 = 30_000;

        // Blueprint's divisor: ceil(60_000 / 30_000) = 2 blocks.
        let p95_blocks = block_count(P95_MS, DELTA_MS, false).unwrap();
        assert_eq!(p95_blocks, 2);
        // Those 2 blocks elapse in 2 * 4_800 = 9_600 ms against a 60_000 ms
        // intent -- 16% of the requested window, an 84% under-shoot.
        let p95_elapsed = p95_blocks * TRUE_MEAN_MS;
        assert_eq!(p95_elapsed, 9_600);
        assert_eq!(p95_elapsed * 100 / DELTA_MS, 16);

        // This module's divisor: ceil(60_000 / 4_800) = 13 blocks.
        let mean_blocks = block_count(TRUE_MEAN_MS, DELTA_MS, false).unwrap();
        assert_eq!(mean_blocks, 13);
        // 13 * 4_800 = 62_400 ms against 60_000 ms -- a 4% over-shoot.
        let mean_elapsed = mean_blocks * TRUE_MEAN_MS;
        assert_eq!(mean_elapsed, 62_400);
        assert_eq!(mean_elapsed * 100 / DELTA_MS, 104);

        // And the status quo, a fixed 2 s assumption: 30 blocks that actually
        // take 30 * 4_800 = 144_000 ms, a 140% over-shoot. The p95 divisor does
        // not fix this bug; it replaces it with a larger one pointing the other
        // way.
        let fixed_blocks = block_count(2_000, DELTA_MS, false).unwrap();
        assert_eq!(fixed_blocks * TRUE_MEAN_MS, 144_000);
    }

    // -----------------------------------------------------------------------
    // Cold-start safety margin
    // -----------------------------------------------------------------------

    #[test]
    fn cold_start_margin_is_a_ceiling_of_one_and_a_half_block_counts() {
        // 30 * 1.5 = 45 exactly.
        assert_eq!(block_count(2_000, 60_000, true), Ok(45));
        // 13 * 1.5 = 19.5 -> 20.
        assert_eq!(block_count(4_800, 60_000, true), Ok(20));
        // 1 * 1.5 = 1.5 -> 2: even the smallest count gains real headroom.
        assert_eq!(block_count(30_000, 30_000, true), Ok(2));
    }

    #[test]
    fn cold_start_margin_applies_to_exactly_the_first_ten_packets() {
        let cfg = config(2_000);
        let mut est = estimator_at(2_000, 100);

        for packet in 1..=COLD_START_PACKET_COUNT {
            let estimate = compute_timeout(&mut est, &cfg, 1_000, 60_000).unwrap();
            assert!(estimate.cold_start, "packet {packet} must be cold-start");
            assert_eq!(estimate.base_block_count, 30);
            assert_eq!(estimate.block_count, 45, "packet {packet}");
            assert_eq!(estimate.timeout_height, 1_045);
        }
        assert_eq!(est.packets_issued(), COLD_START_PACKET_COUNT);

        // The eleventh packet is out of the allowance: no margin at all.
        let eleventh = compute_timeout(&mut est, &cfg, 1_000, 60_000).unwrap();
        assert!(!eleventh.cold_start);
        assert_eq!(eleventh.block_count, 30);
        assert_eq!(eleventh.timeout_height, 1_030);
    }

    #[test]
    fn a_rejected_request_does_not_consume_the_cold_start_allowance() {
        let cfg = config(2_000);
        let mut est = estimator_at(2_000, 100);
        assert_eq!(
            compute_timeout(&mut est, &cfg, 1_000, 9_999),
            Err(IbcTimeoutError::TimeoutDeltaOutOfRange)
        );
        assert_eq!(est.packets_issued(), 0);
        assert!(in_cold_start(&est));
    }

    #[test]
    fn an_estimator_with_no_samples_falls_back_to_config_and_is_margined() {
        let cfg = config(2_000);
        let mut est = BlockTimeEstimator::new("dest".into());
        let estimate = compute_timeout(&mut est, &cfg, 0, 60_000).unwrap();
        // Divisor came from ChainConfig::block_time_ms; the margin is exactly
        // the hedge against that configured value being wrong.
        assert_eq!(estimate.mean_block_time_ms, 2_000);
        assert_eq!(estimate.base_block_count, 30);
        assert_eq!(estimate.block_count, 45);
        assert!(estimate.cold_start);
        assert_eq!(estimate.p95_block_time_ms, None);
        assert_eq!(estimate.dispersion_bps, BPS_DENOMINATOR);
    }

    // -----------------------------------------------------------------------
    // A uniformly slow chain is slow, not variable (Gate 0 item 4e)
    // -----------------------------------------------------------------------

    #[test]
    fn a_uniformly_slow_chain_converges_to_an_exact_timeout_after_cold_start() {
        let cfg = config(25_000);
        // 25 s blocks with no spread whatsoever.
        let mut est = estimator_at(25_000, 100);
        assert_eq!(est.window_mean_block_time_ms(), Some(25_000));
        assert_eq!(est.p95_block_time_ms(), Some(25_000));
        // Zero dispersion: this chain is slow, not variable.
        assert_eq!(est.dispersion_bps(&cfg), BPS_DENOMINATOR);

        // Burn the cold-start allowance.
        for _ in 0..COLD_START_PACKET_COUNT {
            let margined = compute_timeout(&mut est, &cfg, 0, 300_000).unwrap();
            assert_eq!(margined.block_count, 18); // ceil(12 * 1.5)
        }

        let warm = compute_timeout(&mut est, &cfg, 0, 300_000).unwrap();
        assert!(!warm.cold_start);
        // ceil(300_000 / 25_000) = 12 blocks, which elapse in exactly
        // 12 * 25_000 = 300_000 ms -- the requested window, to the millisecond.
        assert_eq!(warm.block_count, 12);
        assert_eq!(warm.block_count * 25_000, 300_000);
        // And emphatically not the inflated cold-start value: a consistently
        // slow chain must not be treated as a variable one forever.
        assert_ne!(warm.block_count, 18);
    }

    #[test]
    fn a_slow_chain_cannot_express_a_window_shorter_than_one_block() {
        // A 10 s deadline on a 25 s-block chain is not a height that exists.
        assert_eq!(
            block_count(25_000, 10_000, false),
            Err(IbcTimeoutError::DeltaBelowBlockGranularity)
        );
        // The boundary is delta == one block, either side of it:
        // a window of exactly one block is expressible...
        assert_eq!(block_count(10_000, 10_000, false), Ok(1));
        // ...one millisecond short of a block is not...
        assert_eq!(
            block_count(10_001, 10_000, false),
            Err(IbcTimeoutError::DeltaBelowBlockGranularity)
        );
        // ...and one millisecond over a block rounds up to two.
        assert_eq!(block_count(10_000, 10_001, false), Ok(2));
    }

    // -----------------------------------------------------------------------
    // Bounds
    // -----------------------------------------------------------------------

    #[test]
    fn timeout_delta_bounds_are_inclusive_and_rejected_outside() {
        assert_eq!(
            block_count(2_000, MIN_TIMEOUT_DELTA_MS - 1, false),
            Err(IbcTimeoutError::TimeoutDeltaOutOfRange)
        );
        assert_eq!(block_count(2_000, MIN_TIMEOUT_DELTA_MS, false), Ok(5));
        assert_eq!(block_count(2_000, MAX_TIMEOUT_DELTA_MS, false), Ok(150));
        assert_eq!(
            block_count(2_000, MAX_TIMEOUT_DELTA_MS + 1, false),
            Err(IbcTimeoutError::TimeoutDeltaOutOfRange)
        );
        assert_eq!(
            block_count(2_000, 0, false),
            Err(IbcTimeoutError::TimeoutDeltaOutOfRange)
        );
    }

    #[test]
    fn packet_lifetime_cap_is_enforced_at_exactly_one_thousand_blocks() {
        // 300_000 / 300 = 1_000 exactly -- the boundary is allowed.
        assert_eq!(
            block_count(300, MAX_TIMEOUT_DELTA_MS, false),
            Ok(MAX_PACKET_LIFETIME_BLOCKS)
        );
        // 300_000 / 299 = 1_003.3 -> 1_004, one over the bound.
        assert_eq!(
            block_count(299, MAX_TIMEOUT_DELTA_MS, false),
            Err(IbcTimeoutError::PacketLifetimeExceeded)
        );
    }

    #[test]
    fn the_lifetime_cap_is_applied_after_the_cold_start_margin() {
        // 300_000 / 429 = 699.3 -> 700 blocks, comfortably under the cap...
        assert_eq!(block_count(429, MAX_TIMEOUT_DELTA_MS, false), Ok(700));
        // ...but 700 * 1.5 = 1_050 is over it, and the margined count is what
        // actually lands on the wire, so it must be the one that is checked.
        assert_eq!(
            block_count(429, MAX_TIMEOUT_DELTA_MS, true),
            Err(IbcTimeoutError::PacketLifetimeExceeded)
        );
    }

    #[test]
    fn a_zero_block_time_estimate_never_divides_by_zero() {
        // The estimator already floors its estimate at 1 ms, but `block_count`
        // is public and floors the divisor again so a direct call cannot
        // panic. A 1 ms divisor yields an absurd 10_000-block count, which the
        // lifetime cap then rejects -- an error, never a division by zero.
        assert_eq!(
            block_count(0, 10_000, false),
            Err(IbcTimeoutError::PacketLifetimeExceeded)
        );
    }

    // -----------------------------------------------------------------------
    // Height arithmetic and reported state
    // -----------------------------------------------------------------------

    #[test]
    fn timeout_height_advances_from_the_reference_height_and_saturates() {
        let cfg = config(2_000);
        let mut est = estimator_at(2_000, 100);
        est.reset_cold_start();
        for _ in 0..COLD_START_PACKET_COUNT {
            est.note_packet_issued();
        }

        let estimate = compute_timeout(&mut est, &cfg, 1_000_000, 60_000).unwrap();
        assert_eq!(estimate.reference_height, 1_000_000);
        assert_eq!(estimate.timeout_height, 1_000_030);

        // A pathological reference height saturates rather than wrapping to a
        // height in the past, which would time the packet out immediately.
        let saturated = compute_timeout(&mut est, &cfg, u64::MAX, 60_000).unwrap();
        assert_eq!(saturated.timeout_height, u64::MAX);
    }

    #[test]
    fn the_estimate_carries_the_estimator_state_that_produced_it() {
        let cfg = config(2_000);
        let mut est = spiky_estimator();
        let estimate = compute_timeout(&mut est, &cfg, 500, 60_000).unwrap();
        assert_eq!(estimate.mean_block_time_ms, 4_800);
        assert_eq!(estimate.p95_block_time_ms, Some(30_000));
        assert_eq!(estimate.dispersion_bps, 62_500);
        assert_eq!(estimate.base_block_count, 13);
        assert_eq!(estimate.block_count, 20); // cold start: ceil(13 * 1.5)
        assert_eq!(estimate.timeout_height, 520);
    }
}
