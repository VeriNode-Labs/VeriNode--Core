//! Integration simulations for IBC packet commitment timeouts across variable
//! block-time chains (issue #138).
//!
//! Unit-level coverage of each component lives beside it in `src`. This file
//! holds the two end-to-end simulations the issue calls for, both driven
//! through the real header pipeline ([`ConnectedChain::observe_header`]) and
//! the real relayer:
//!
//! 1. [`variable_block_time_chain_meets_the_accuracy_bar`] — a 2 s chain with
//!    periodic 30 s spikes, which also scores the blueprint's original
//!    `÷ p95` formula on the *identical* trace so the two can be compared
//!    directly.
//! 2. [`uniformly_slow_chain_is_not_treated_as_a_variable_one`] — a 25 s chain
//!    with no spikes, proving the fix does not simply move the problem: a chain
//!    that is merely slow must converge to an accurate timeout, not a
//!    perpetually inflated one.
//!
//! # What "accuracy" means here
//!
//! A packet's timeout is a height; the caller's intent is a duration. A packet
//! is counted **accurate** when the wall-clock instant at which its height
//! deadline resolved lands within [`TIMEOUT_ACCURACY_TOLERANCE_BPS`] (+/-50%)
//! of `sent_at_ms + timeout_delta_ms`:
//!
//! ```text
//! accurate  <=>  |resolved_at_ms - (sent_at_ms + timeout_delta_ms)|
//!                    <= timeout_delta_ms * 5_000 / 10_000
//! ```
//!
//! Accuracy is `accurate / resolved`, over packets whose block count came from
//! a full 100-sample window and carried no cold-start margin — the steady state
//! the issue's ">95%" bar is about. The cold-start packets are reported
//! separately rather than dropped, so nothing is hidden.

use sorosusu_contracts::cross_chain::{
    BlockTimeEstimator, ChainConfig, ConnectedChain, PacketId, PacketRelayer, RecentHeader,
    TimeoutMiss, BLOCK_TIME_WINDOW_SAMPLES, BPS_DENOMINATOR, COLD_START_MARGIN_BPS,
    COLD_START_PACKET_COUNT, MAX_MISESTIMATION_RATE_BPS, TIMEOUT_ACCURACY_TOLERANCE_BPS,
};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Block-time models
//
// Both are closed-form so a reviewer can check any timestamp by hand without
// replaying the simulation.
// ---------------------------------------------------------------------------

/// Baseline block time of the variable chain, in milliseconds.
const BASE_BLOCK_MS: u64 = 2_000;
/// Spike block time of the variable chain, in milliseconds.
const SPIKE_BLOCK_MS: u64 = 30_000;
/// Every tenth block of the variable chain is a spike.
const SPIKE_PERIOD: u64 = 10;
/// Wall-clock duration of one full spike period: `9 * 2_000 + 30_000`.
const SPIKE_CYCLE_MS: u64 = (SPIKE_PERIOD - 1) * BASE_BLOCK_MS + SPIKE_BLOCK_MS;

/// Timestamp of block `height` on the variable chain, with block 0 at `t = 0`.
///
/// Mean block time over a whole number of periods is
/// `48_000 / 10 = 4_800 ms`; the p95 is `30_000 ms`, since exactly 10% of
/// blocks are spikes.
fn variable_timestamp_ms(height: u64) -> u64 {
    (height / SPIKE_PERIOD) * SPIKE_CYCLE_MS + (height % SPIKE_PERIOD) * BASE_BLOCK_MS
}

/// Timestamp of block `height` on the uniformly slow chain: 25 s blocks with
/// 1 s of deterministic jitter (25_000, 26_000, 24_000, repeating), so the mean
/// is exactly 25_000 ms and the p95 is 26_000 ms — a 1.04x dispersion against
/// the variable chain's 6.25x.
fn slow_timestamp_ms(height: u64) -> u64 {
    let extra = match height % 3 {
        0 => 0,
        1 => 25_000,
        _ => 51_000,
    };
    (height / 3) * 75_000 + extra
}

// ---------------------------------------------------------------------------
// Simulation harness
// ---------------------------------------------------------------------------

/// Timeout windows cycled across sent packets, in milliseconds, spanning the
/// issue's documented 10-300 s range.
const DELTAS_MS: [u64; 5] = [60_000, 120_000, 180_000, 240_000, 300_000];

/// What the simulation records about each packet at send time, so a resolution
/// can be attributed back to the estimator state that produced it.
#[derive(Clone, Copy)]
struct SentPacket {
    sent_at_ms: u64,
    delta_ms: u64,
    cold_start: bool,
    warm_window: bool,
}

/// Tally of one simulation run.
#[derive(Default)]
struct SimTally {
    resolved: usize,
    accurate: usize,
    steady_resolved: usize,
    steady_accurate: usize,
    cold_start_resolved: usize,
    cold_start_accurate: usize,
    early: usize,
    late: usize,
    recalibrations: usize,
    /// Largest steady-state per-packet error, as a fraction of the requested
    /// window, in basis points. Reported so a 100% pass rate cannot hide a
    /// band that is merely loose.
    worst_steady_error_bps: u64,
    /// Accuracy tally for the blueprint's `÷ p95` formula, scored on the same
    /// packets with the same accuracy band.
    p95_steady_resolved: usize,
    p95_steady_accurate: usize,
    /// Largest steady-state per-packet error under the `÷ p95` formula.
    worst_p95_error_bps: u64,
}

impl SimTally {
    fn steady_accuracy_bps(&self) -> u64 {
        ratio_bps(self.steady_accurate, self.steady_resolved)
    }
    fn overall_accuracy_bps(&self) -> u64 {
        ratio_bps(self.accurate, self.resolved)
    }
    fn p95_steady_accuracy_bps(&self) -> u64 {
        ratio_bps(self.p95_steady_accurate, self.p95_steady_resolved)
    }
    fn steady_misestimation_bps(&self) -> u64 {
        BPS_DENOMINATOR - self.steady_accuracy_bps()
    }
}

fn ratio_bps(numerator: usize, denominator: usize) -> u64 {
    if denominator == 0 {
        return 0;
    }
    (numerator as u64 * BPS_DENOMINATOR) / denominator as u64
}

fn bps_as_percent(bps: u64) -> f64 {
    bps as f64 / 100.0
}

/// Per-packet error as a fraction of the requested window, in basis points:
/// `|resolved_at - (sent_at + delta)| / delta`.
fn error_bps(sent_at_ms: u64, delta_ms: u64, resolved_at_ms: u64) -> u64 {
    resolved_at_ms.abs_diff(sent_at_ms + delta_ms) * BPS_DENOMINATOR / delta_ms
}

/// Returns `true` when a deadline that resolved at `resolved_at_ms` lands
/// inside the accuracy band for a packet sent at `sent_at_ms` with `delta_ms`.
fn within_band(sent_at_ms: u64, delta_ms: u64, resolved_at_ms: u64) -> bool {
    error_bps(sent_at_ms, delta_ms, resolved_at_ms) <= TIMEOUT_ACCURACY_TOLERANCE_BPS
}

/// Drives one chain from genesis, producing `blocks` blocks and sending a
/// packet every `packet_every` blocks.
///
/// `packet_every` must be **coprime with the block-time model's period**, so
/// that send heights sweep every phase of the block-time pattern. A cadence
/// sharing a factor with the period aliases: sending every 5 blocks against a
/// 10-block spike period only ever samples two of the ten phases, and the
/// simulation would silently never place a packet across the window that
/// happens to contain two spikes -- the worst case it exists to measure.
///
/// Each block: the header is fed into the real pipeline, in-flight packets are
/// resolved against the new height, and a packet is sent when due. The
/// `÷ p95` shadow is computed at send time from the same estimator state and
/// scored against the same band, so the only difference between the two
/// formulas is the divisor.
fn run_simulation(
    chain_id: &str,
    nominal_block_ms: u64,
    timestamp_ms: fn(u64) -> u64,
    blocks: u64,
    packet_every: u64,
) -> (SimTally, ConnectedChain, PacketRelayer) {
    let mut chain = ConnectedChain::new(
        ChainConfig::new(chain_id.into(), nominal_block_ms, 128, 2),
        0,
    );
    let mut relayer = PacketRelayer::new();
    let mut sent: BTreeMap<PacketId, SentPacket> = BTreeMap::new();
    let mut tally = SimTally::default();
    let mut next_sequence = 0u64;

    for height in 1..=blocks {
        let now_ms = timestamp_ms(height);

        // 1. The header reaches the light client, which samples the block time.
        chain.observe_header(RecentHeader::new(height, now_ms, 128, 90, now_ms));

        // 2. Resolve every packet whose height deadline has fired or whose
        //    window has run out.
        for resolution in relayer.observe_destination_height(&mut chain, height, now_ms) {
            let record = sent[&resolution.packet_id];
            let accurate = resolution.miss.is_none();

            // Re-derive accuracy from first principles and confirm the module
            // agrees: the harness and the implementation must not be able to
            // drift apart on what "accurate" means.
            assert_eq!(
                resolution.intended_deadline_ms,
                record.sent_at_ms + record.delta_ms
            );
            assert_eq!(
                accurate,
                within_band(
                    record.sent_at_ms,
                    record.delta_ms,
                    resolution.observed_at_ms
                ),
                "classification disagreed for {:?}",
                resolution.packet_id
            );

            tally.resolved += 1;
            tally.accurate += usize::from(accurate);
            match resolution.miss {
                Some(TimeoutMiss::TooEarly) => tally.early += 1,
                Some(TimeoutMiss::TooLate) => tally.late += 1,
                None => {}
            }
            if record.cold_start {
                tally.cold_start_resolved += 1;
                tally.cold_start_accurate += usize::from(accurate);
            } else if record.warm_window {
                tally.steady_resolved += 1;
                tally.steady_accurate += usize::from(accurate);
                tally.worst_steady_error_bps = tally.worst_steady_error_bps.max(error_bps(
                    record.sent_at_ms,
                    record.delta_ms,
                    resolution.observed_at_ms,
                ));
            }
            if resolution.recalibrated {
                tally.recalibrations += 1;
            }
        }

        // 3. Send a packet when due.
        if height % packet_every == 0 {
            let delta_ms = DELTAS_MS[(next_sequence as usize) % DELTAS_MS.len()];
            let id = PacketId::new("channel-0".into(), next_sequence);
            next_sequence += 1;

            // Capture the estimator state before `send_packet` mutates it, so
            // the shadow sees exactly what the real formula saw.
            let cold_start = chain.block_time.packets_issued() < COLD_START_PACKET_COUNT;
            let warm_window = chain.block_time.sample_count() >= BLOCK_TIME_WINDOW_SAMPLES;
            let p95 = chain.block_time.p95_block_time_ms();

            if relayer
                .send_packet(&mut chain, id.clone(), height, now_ms, delta_ms)
                .is_err()
            {
                continue;
            }
            sent.insert(
                id,
                SentPacket {
                    sent_at_ms: now_ms,
                    delta_ms,
                    cold_start,
                    warm_window,
                },
            );

            // Shadow: the blueprint's divisor, everything else held equal
            // (same delta, same reference height, same cold-start margin, same
            // accuracy band). Scored only over steady-state packets, the same
            // population the headline accuracy is measured on.
            if warm_window && !cold_start {
                if let Some(p95_ms) = p95 {
                    let mut shadow_blocks = delta_ms.div_ceil(p95_ms.max(1));
                    if cold_start {
                        shadow_blocks =
                            (shadow_blocks * COLD_START_MARGIN_BPS).div_ceil(BPS_DENOMINATOR);
                    }
                    // The block-time model is closed-form, so the shadow's
                    // resolution instant needs no simulation.
                    let shadow_resolved_at = timestamp_ms(height + shadow_blocks);
                    tally.p95_steady_resolved += 1;
                    tally.p95_steady_accurate +=
                        usize::from(within_band(now_ms, delta_ms, shadow_resolved_at));
                    tally.worst_p95_error_bps = tally.worst_p95_error_bps.max(error_bps(
                        now_ms,
                        delta_ms,
                        shadow_resolved_at,
                    ));
                }
            }
        }
    }

    (tally, chain, relayer)
}

// ---------------------------------------------------------------------------
// Simulation 1: variable block times (the issue's required scenario)
// ---------------------------------------------------------------------------

#[test]
fn variable_block_time_chain_meets_the_accuracy_bar() {
    // 1_500 blocks at a 4_800 ms mean is ~2 hours of chain time. A packet every
    // 7 blocks is coprime with the 10-block spike period, so send heights sweep
    // all ten phases and the 13-block windows containing *two* spikes are
    // actually exercised.
    let (tally, chain, relayer) =
        run_simulation("spiky-2s", BASE_BLOCK_MS, variable_timestamp_ms, 1_500, 7);

    println!("--- variable chain (2 s baseline, every 10th block 30 s) ---");
    println!(
        "  window mean {:?} ms, p95 {:?} ms, dispersion {} bps",
        chain.block_time.window_mean_block_time_ms(),
        chain.block_time.p95_block_time_ms(),
        chain.block_time.dispersion_bps(&chain.config)
    );
    println!(
        "  resolved {} packets ({} steady-state, {} cold-start)",
        tally.resolved, tally.steady_resolved, tally.cold_start_resolved
    );
    println!(
        "  steady-state accuracy   {}/{} = {:.2}%",
        tally.steady_accurate,
        tally.steady_resolved,
        bps_as_percent(tally.steady_accuracy_bps())
    );
    println!(
        "  overall accuracy        {}/{} = {:.2}%",
        tally.accurate,
        tally.resolved,
        bps_as_percent(tally.overall_accuracy_bps())
    );
    println!(
        "  cold-start accuracy     {}/{} (deliberately margined 1.5x)",
        tally.cold_start_accurate, tally.cold_start_resolved
    );
    println!(
        "  misses: {} early, {} late; {} recalibrations",
        tally.early, tally.late, tally.recalibrations
    );
    println!(
        "  worst steady-state error {:.2}% of the requested window (band: 50%)",
        bps_as_percent(tally.worst_steady_error_bps)
    );
    println!(
        "  BLUEPRINT (÷ p95) on the same trace: {}/{} = {:.2}%, worst error {:.2}%",
        tally.p95_steady_accurate,
        tally.p95_steady_resolved,
        bps_as_percent(tally.p95_steady_accuracy_bps()),
        bps_as_percent(tally.worst_p95_error_bps)
    );

    // The chain really is the one the issue describes.
    assert_eq!(chain.block_time.window_mean_block_time_ms(), Some(4_800));
    assert_eq!(chain.block_time.p95_block_time_ms(), Some(30_000));
    assert_eq!(chain.block_time.dispersion_bps(&chain.config), 62_500);

    // A realistic packet volume, not a handful.
    assert!(
        tally.steady_resolved >= 150,
        "only {} steady-state packets resolved",
        tally.steady_resolved
    );

    // The issue's bar: > 95% timeout accuracy.
    assert!(
        tally.steady_accuracy_bps() > 9_500,
        "steady-state accuracy {:.2}% must exceed 95%",
        bps_as_percent(tally.steady_accuracy_bps())
    );

    // The blueprint's own suggested divisor, scored on the identical trace with
    // the identical band, cannot reach its own bar. This is the regression
    // guard for the correction: if anyone reinstates `÷ p95`, this fails.
    assert!(
        tally.p95_steady_accuracy_bps() < 9_500,
        "the ÷p95 formula scored {:.2}%, which would make the correction moot",
        bps_as_percent(tally.p95_steady_accuracy_bps())
    );
    assert!(
        tally.steady_accuracy_bps() > tally.p95_steady_accuracy_bps(),
        "the corrected formula must beat the blueprint's on the same trace"
    );

    // The band is not merely loose: the worst steady-state packet still used a
    // real fraction of it, so this is a measured pass, not a vacuous one.
    assert!(
        tally.worst_steady_error_bps > 1_000,
        "worst error {:.2}% is suspiciously small -- is the trace exercising the spikes?",
        bps_as_percent(tally.worst_steady_error_bps)
    );
    assert!(
        tally.worst_steady_error_bps <= TIMEOUT_ACCURACY_TOLERANCE_BPS,
        "worst error {:.2}% escaped the band despite a 100% pass rate",
        bps_as_percent(tally.worst_steady_error_bps)
    );

    // No packet is left unaccounted for.
    assert_eq!(
        tally.accurate + tally.early + tally.late,
        tally.resolved,
        "every resolution is either accurate, early, or late"
    );
    // Every event the relayer emitted corresponds to a real miss.
    assert!(!relayer.events().is_empty() || tally.early + tally.late == 0);
}

// ---------------------------------------------------------------------------
// Simulation 2: uniformly slow, not variable (Gate 0 item 4e)
// ---------------------------------------------------------------------------

#[test]
fn uniformly_slow_chain_is_not_treated_as_a_variable_one() {
    // 800 blocks at 25 s is ~5.5 hours of chain time. A packet every 4 blocks is
    // coprime with the 3-block jitter cycle, so send heights sweep all three
    // phases of the jitter pattern.
    let (tally, chain, relayer) = run_simulation("slow-25s", 25_000, slow_timestamp_ms, 800, 4);

    let dispersion = chain.block_time.dispersion_bps(&chain.config);
    println!("--- uniformly slow chain (25 s blocks, 1 s jitter, no spikes) ---");
    println!(
        "  window mean {:?} ms, p95 {:?} ms, dispersion {} bps ({:.2}x)",
        chain.block_time.window_mean_block_time_ms(),
        chain.block_time.p95_block_time_ms(),
        dispersion,
        dispersion as f64 / BPS_DENOMINATOR as f64
    );
    println!(
        "  resolved {} packets ({} steady-state, {} cold-start)",
        tally.resolved, tally.steady_resolved, tally.cold_start_resolved
    );
    println!(
        "  steady-state accuracy      {}/{} = {:.2}%",
        tally.steady_accurate,
        tally.steady_resolved,
        bps_as_percent(tally.steady_accuracy_bps())
    );
    println!(
        "  steady-state misestimation {:.2}% (bar: <= 5%)",
        bps_as_percent(tally.steady_misestimation_bps())
    );
    println!(
        "  worst steady-state error   {:.2}% of the requested window",
        bps_as_percent(tally.worst_steady_error_bps)
    );
    println!(
        "  misses: {} early, {} late; {} recalibrations",
        tally.early, tally.late, tally.recalibrations
    );

    // This chain is slow, not variable, and the design reads that from the
    // dispersion rather than from the p95 level -- which is 26_000 ms here and
    // 30_000 ms on the spiky chain, i.e. almost the same.
    assert_eq!(chain.block_time.p95_block_time_ms(), Some(26_000));
    assert!(
        dispersion < 11_000,
        "dispersion {dispersion} bps must read as uniform (~10_000 bps)"
    );

    assert!(
        tally.steady_resolved >= 150,
        "only {} steady-state packets resolved",
        tally.steady_resolved
    );

    // The requirement: past cold start, a consistently slow chain must NOT show
    // a >5% misestimation rate. Its block time is high, not variable, so the
    // estimator converges on it and the timeout is accurate.
    assert!(
        tally.steady_misestimation_bps() <= MAX_MISESTIMATION_RATE_BPS,
        "steady-state misestimation {:.2}% must not exceed 5%",
        bps_as_percent(tally.steady_misestimation_bps())
    );

    // And the timeout is not perpetually inflated: the relayer's own window
    // agrees the estimator is healthy, so nothing recalibrates.
    assert_eq!(
        tally.recalibrations, 0,
        "a merely-slow chain must not trip the recalibration trigger"
    );
    assert!(
        relayer
            .misestimation_rate_bps("slow-25s")
            .is_none_or(|rate| rate <= MAX_MISESTIMATION_RATE_BPS),
        "relayer-reported rate must stay within the bar"
    );
}

// ---------------------------------------------------------------------------
// The two chains, side by side
// ---------------------------------------------------------------------------

#[test]
fn dispersion_separates_the_two_failure_modes_end_to_end() {
    // Both chains, driven through the real header pipeline, have a p95 within
    // 15% of each other -- so a p95 alone genuinely cannot tell them apart.
    let mut spiky = BlockTimeEstimator::new("spiky".into());
    let mut slow = BlockTimeEstimator::new("slow".into());
    for height in 1..=BLOCK_TIME_WINDOW_SAMPLES as u64 + 1 {
        spiky.observe_header(height, variable_timestamp_ms(height));
        slow.observe_header(height, slow_timestamp_ms(height));
    }

    let spiky_cfg = ChainConfig::new("spiky".into(), BASE_BLOCK_MS, 128, 2);
    let slow_cfg = ChainConfig::new("slow".into(), 25_000, 128, 2);

    assert_eq!(spiky.p95_block_time_ms(), Some(30_000));
    assert_eq!(slow.p95_block_time_ms(), Some(26_000));

    // The means, however, differ by 5.2x, and the dispersion by 6x.
    //
    // The 100 samples here are the intervals between heights 1..=101, i.e. the
    // durations of blocks 2..=101: 34 at 26_000 ms, 33 at 25_000 ms and 33 at
    // 24_000 ms, so the mean is 2_501_000 / 100 = 25_010 ms -- the 3-cycle
    // lands one 26_000 ms block heavy at this phase.
    assert_eq!(spiky.window_mean_block_time_ms(), Some(4_800));
    assert_eq!(slow.window_mean_block_time_ms(), Some(25_010));
    assert_eq!(spiky.dispersion_bps(&spiky_cfg), 62_500);
    // 26_000 * 10_000 / 25_010 = 10_395 bps.
    assert_eq!(slow.dispersion_bps(&slow_cfg), 10_395);

    println!("--- dispersion separation ---");
    println!(
        "  spiky: p95 30_000 ms, mean 4_800 ms  -> {} bps",
        spiky.dispersion_bps(&spiky_cfg)
    );
    println!(
        "  slow:  p95 26_000 ms, mean 25_010 ms -> {} bps",
        slow.dispersion_bps(&slow_cfg)
    );
}
