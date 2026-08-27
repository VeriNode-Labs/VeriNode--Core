//! In-flight IBC packet tracking, timeout misestimation detection, and
//! estimator recalibration (issue #138).
//!
//! # What "misestimation" means here
//!
//! A packet's timeout is a *height*, but the caller's intent is a *duration*.
//! The estimate is good exactly to the extent that the destination chain
//! reaches [`TimeoutEstimate::timeout_height`] at the wall-clock moment the
//! caller meant. So for each resolved packet this module compares:
//!
//! ```text
//! observed_at_ms                 -- when the height deadline actually resolved
//! sent_at_ms + timeout_delta_ms  -- when the caller meant it to
//! ```
//!
//! and calls the packet misestimated when they differ by more than
//! [`TIMEOUT_ACCURACY_TOLERANCE_BPS`] of the requested window, in either
//! direction: [`TimeoutMiss::TooEarly`] if the chain burned through the block
//! count before the window elapsed, [`TimeoutMiss::TooLate`] if the window
//! elapsed with the chain still at or below the timeout height.
//!
//! ## On the +/-50% tolerance
//!
//! The tolerance is a *calibrated* choice, not a derived one, and is documented
//! as such. What *is* derivable is its floor. A height-denominated deadline
//! quantizes to whole blocks, so the intrinsic per-packet spread is roughly one
//! tail block's excess over the mean, `(p95 - mean) / delta`. On issue #138's
//! own scenario (`p95 - mean = 25_200 ms`) that floor is 8.4% at a 300 s
//! window, 42% at 60 s, and 252% at 10 s. `50%` is a round number sitting above
//! that floor across the upper part of the issue's documented 10-300 s range.
//!
//! It is deliberately **fixed** rather than scaled from the chain's own
//! dispersion. An adaptive band would widen for precisely the chains behaving
//! worst, letting a chain grade its own homework and suppressing the signal the
//! band exists to raise.
//!
//! # The recalibration trigger
//!
//! A rate needs a denominator and a window, or it means nothing. Both are
//! defined concretely:
//!
//! * **Denominator** — the last [`MISESTIMATION_WINDOW_PACKETS`] *resolved*
//!   packets for that destination chain, acknowledged ones included. Excluding
//!   acknowledgements would make a chain with three timeouts and ten thousand
//!   clean deliveries read as 100% misestimated.
//! * **Cold-start packets are excluded from the window entirely** — from both
//!   numerator and denominator. The rate measures *estimator* quality, and a
//!   packet whose block count was deliberately inflated by 1.5x is not evidence
//!   about the estimator: it is evidence about the margin, which was applied on
//!   purpose. Counting them makes the trigger self-inflicted — the ten margined
//!   packets alone are 10% of a 100-packet window, enough to fire the trigger
//!   on their own and destroy a perfectly good sample window. Their
//!   misestimation events are still emitted, so nothing is hidden from
//!   operators; they simply do not vote on whether the estimator needs
//!   recalibrating.
//! * **Armed only when full.** The trigger is suppressed until the window holds
//!   a full 100 resolutions. Without that, one bad packet out of three reads as
//!   33% and fires on every newly connected chain.
//! * **Fires on `> 500 bps` strictly.** On a 100-packet window, 5 misses is
//!   exactly 500 bps and does *not* fire; 6 is 600 bps and does.
//!
//! ## What recalibration does
//!
//! 1. **Re-seeds the sample window from the EMA**
//!    ([`reseed_from_ema`](super::block_time_estimator::BlockTimeEstimator::reseed_from_ema)). Misestimation under this design
//!    means the window mean is stale — the chain moved to a new block-time
//!    regime and the window still holds the old one. The `alpha = 0.3` EMA has
//!    a ~13-sample memory and has already tracked the new regime. This step is
//!    direction-agnostic: it corrects the estimate whichever way the regime
//!    moved.
//! 2. **Clears the misestimation window**, so the trigger does not re-fire on
//!    the same stale evidence for the next 95 packets.
//! 3. **Re-enters cold start only when the misses were predominantly
//!    [`TimeoutMiss::TooEarly`]** — a strict majority of the window's misses.
//!    The 1.5x cold-start margin can only push timeouts *later*, so it is the
//!    right correction for early misses and actively makes late ones worse.
//!    Applying it unconditionally would be a bug. Ties do not re-enter cold
//!    start: the no-margin path is the conservative default, and resolving the
//!    tie with a second arbitrary threshold would only move the arbitrariness
//!    around.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::packet_timeout::{compute_timeout, IbcTimeoutError, TimeoutEstimate};
use crate::cross_chain::light_client::ConnectedChain;
use crate::cross_chain::types::{ChainId, BPS_DENOMINATOR};

// ---------------------------------------------------------------------------
// Operational constants (issue #138 technical invariants)
// ---------------------------------------------------------------------------

/// Number of resolved packets per destination chain over which the
/// misestimation rate is measured.
pub const MISESTIMATION_WINDOW_PACKETS: usize = 100;

/// Misestimation rate above which the estimator is recalibrated, in basis
/// points. `500 bps = 5%`, and the comparison is strictly greater-than.
pub const MAX_MISESTIMATION_RATE_BPS: u64 = 500;

/// Half-width of the accuracy band, as a fraction of the requested timeout
/// window, in basis points. `5_000 bps = +/-50%`.
///
/// See the module docs: calibrated against issue #138's own scenario, not
/// derived, and deliberately fixed rather than adaptive.
pub const TIMEOUT_ACCURACY_TOLERANCE_BPS: u64 = 5_000;

// ---------------------------------------------------------------------------
// Packet identity
// ---------------------------------------------------------------------------

/// Stable identifier for an IBC channel.
pub type ChannelId = String;

/// Identifies one packet on one channel.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PacketId {
    /// Channel the packet was sent on.
    pub channel: ChannelId,
    /// Monotonic sequence number within the channel.
    pub sequence: u64,
}

impl PacketId {
    /// Creates a packet identifier.
    pub fn new(channel: ChannelId, sequence: u64) -> Self {
        Self { channel, sequence }
    }
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

/// Direction in which a packet's height deadline missed the caller's intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeoutMiss {
    /// The destination reached the timeout height before the intended window
    /// had elapsed: the packet was killed early.
    TooEarly,
    /// The intended window elapsed while the destination was still at or below
    /// the timeout height: the packet outlived its window.
    TooLate,
}

/// How an in-flight packet was resolved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketOutcome {
    /// Acknowledged by the destination before either deadline.
    Acknowledged,
    /// The destination chain reached the packet's timeout height.
    TimedOutOnHeight,
    /// The intended window elapsed past tolerance with the destination still at
    /// or below the timeout height.
    TimedOutBeyondWindow,
}

/// The result of resolving one in-flight packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketResolution {
    /// The packet that resolved.
    pub packet_id: PacketId,
    /// How it resolved.
    pub outcome: PacketOutcome,
    /// The misestimation direction, when the deadline fell outside the accuracy
    /// band. `None` means the estimate was accurate.
    pub miss: Option<TimeoutMiss>,
    /// Destination height observed at resolution.
    pub observed_height: u64,
    /// Wall-clock time of the resolution, in milliseconds.
    pub observed_at_ms: u64,
    /// Wall-clock time the caller intended the packet to time out.
    pub intended_deadline_ms: u64,
    /// Whether this resolution tripped the recalibration trigger.
    pub recalibrated: bool,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by relayer packet operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IbcRelayerError {
    /// A packet with this identifier is already in flight.
    DuplicatePacket,
    /// No packet with this identifier is in flight.
    PacketNotFound,
    /// The timeout height could not be computed.
    Timeout(IbcTimeoutError),
}

impl From<IbcTimeoutError> for IbcRelayerError {
    fn from(err: IbcTimeoutError) -> Self {
        Self::Timeout(err)
    }
}

// ---------------------------------------------------------------------------
// Observability events
// ---------------------------------------------------------------------------

/// Observability events emitted by the relayer.
///
/// This crate has no metrics or event-bus dependency, and
/// [`crate::cross_chain`] takes no Soroban `Env`, so events accumulate in a
/// drainable buffer exactly as [`crate::consensus::engine::consensus_engine::ConsensusEngineEvent`]
/// does for the consensus loop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IbcRelayerEvent {
    /// A packet's height deadline missed the caller's intended window.
    ///
    /// The payload carries both sides of the comparison and the estimator state
    /// that produced the height, because by the time this is read the sample
    /// window has slid on and cannot be re-derived.
    PacketTimeoutMisestimation {
        /// The packet that was misestimated.
        packet_id: PacketId,
        /// Destination chain the timeout was denominated in.
        dest_chain: ChainId,
        /// Which way the deadline missed.
        direction: TimeoutMiss,
        /// Height the packet was estimated to time out at.
        timeout_height: u64,
        /// Destination height the estimate was measured from.
        reference_height: u64,
        /// Destination height actually observed at resolution.
        observed_height: u64,
        /// When the packet was sent, in milliseconds.
        sent_at_ms: u64,
        /// The caller's requested timeout window, in milliseconds.
        timeout_delta_ms: u64,
        /// When the caller intended the packet to time out.
        intended_deadline_ms: u64,
        /// When the height deadline actually resolved.
        observed_at_ms: u64,
        /// Block-time estimate used as the divisor, in milliseconds.
        mean_block_time_ms: u64,
        /// Tail block time at send time, in milliseconds.
        p95_block_time_ms: Option<u64>,
        /// Block-time dispersion (`p95 / mean`) at send time, in basis points.
        /// A high value says the chain is variable; a value near
        /// [`BPS_DENOMINATOR`] says it is merely slow.
        dispersion_bps: u64,
        /// Whether the cold-start margin had been applied to this packet.
        cold_start: bool,
    },
    /// The misestimation rate for a chain crossed the trigger and its estimator
    /// was recalibrated.
    EstimatorRecalibrated {
        /// Chain whose estimator was recalibrated.
        dest_chain: ChainId,
        /// Measured rate that tripped the trigger, in basis points.
        misestimation_rate_bps: u64,
        /// Early misses in the window that tripped it.
        early_count: u32,
        /// Late misses in the window that tripped it.
        late_count: u32,
        /// Block time the sample window was re-seeded to, in milliseconds.
        reseeded_block_time_ms: Option<u64>,
        /// Whether the cold-start margin was re-armed (early misses in strict
        /// majority).
        cold_start_reentered: bool,
    },
}

// ---------------------------------------------------------------------------
// Misestimation window
// ---------------------------------------------------------------------------

/// Sliding window of the last [`MISESTIMATION_WINDOW_PACKETS`] resolutions for
/// one destination chain.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct MisestimationWindow {
    /// `None` for an accurate resolution, `Some(direction)` for a miss.
    outcomes: Vec<Option<TimeoutMiss>>,
    write_ptr: usize,
}

impl MisestimationWindow {
    fn record(&mut self, miss: Option<TimeoutMiss>) {
        if self.outcomes.len() < MISESTIMATION_WINDOW_PACKETS {
            self.outcomes.push(miss);
        } else {
            self.outcomes[self.write_ptr] = miss;
        }
        self.write_ptr = (self.write_ptr + 1) % MISESTIMATION_WINDOW_PACKETS;
    }

    fn is_full(&self) -> bool {
        self.outcomes.len() >= MISESTIMATION_WINDOW_PACKETS
    }

    fn counts(&self) -> (u32, u32) {
        let mut early = 0;
        let mut late = 0;
        for outcome in &self.outcomes {
            match outcome {
                Some(TimeoutMiss::TooEarly) => early += 1,
                Some(TimeoutMiss::TooLate) => late += 1,
                None => {}
            }
        }
        (early, late)
    }

    /// Misestimation rate over the window, in basis points, or `None` when the
    /// window is empty.
    fn rate_bps(&self) -> Option<u64> {
        if self.outcomes.is_empty() {
            return None;
        }
        let (early, late) = self.counts();
        let missed = (early + late) as u64;
        Some(missed * BPS_DENOMINATOR / self.outcomes.len() as u64)
    }

    fn clear(&mut self) {
        self.outcomes.clear();
        self.write_ptr = 0;
    }
}

// ---------------------------------------------------------------------------
// In-flight packets
// ---------------------------------------------------------------------------

/// A packet awaiting acknowledgement or timeout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InFlightPacket {
    /// The packet's identifier.
    pub id: PacketId,
    /// Destination chain the timeout is denominated in.
    pub dest_chain: ChainId,
    /// When the packet was sent, in milliseconds.
    pub sent_at_ms: u64,
    /// The caller's requested timeout window, in milliseconds.
    pub timeout_delta_ms: u64,
    /// The timeout height and the estimator state that produced it.
    pub estimate: TimeoutEstimate,
}

impl InFlightPacket {
    /// Wall-clock time the caller intended the packet to time out.
    pub fn intended_deadline_ms(&self) -> u64 {
        self.sent_at_ms.saturating_add(self.timeout_delta_ms)
    }

    /// Half-width of the accuracy band for this packet, in milliseconds:
    /// [`TIMEOUT_ACCURACY_TOLERANCE_BPS`] of the requested window.
    pub fn tolerance_ms(&self) -> u64 {
        self.timeout_delta_ms * TIMEOUT_ACCURACY_TOLERANCE_BPS / BPS_DENOMINATOR
    }

    /// Earliest wall-clock time at which the height deadline may resolve
    /// without counting as [`TimeoutMiss::TooEarly`].
    pub fn earliest_acceptable_ms(&self) -> u64 {
        self.intended_deadline_ms()
            .saturating_sub(self.tolerance_ms())
    }

    /// Latest wall-clock time at which the height deadline may resolve without
    /// counting as [`TimeoutMiss::TooLate`].
    pub fn latest_acceptable_ms(&self) -> u64 {
        self.intended_deadline_ms()
            .saturating_add(self.tolerance_ms())
    }
}

// ---------------------------------------------------------------------------
// Relayer
// ---------------------------------------------------------------------------

/// Tracks in-flight packets, classifies their timeouts, and recalibrates
/// per-chain block-time estimators when they drift.
///
/// The relayer holds no chain registry of its own: block-time estimators live
/// on [`ConnectedChain`], fed by the header pipeline the light client already
/// runs, and are borrowed here at call time. There is exactly one header path
/// and exactly one estimator per chain.
#[derive(Clone, Debug, Default)]
pub struct PacketRelayer {
    in_flight: BTreeMap<PacketId, InFlightPacket>,
    windows: BTreeMap<ChainId, MisestimationWindow>,
    events: Vec<IbcRelayerEvent>,
}

impl PacketRelayer {
    /// Creates an empty relayer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Computes a packet's timeout height against `chain`'s block-time
    /// estimator and records it as in flight.
    ///
    /// `reference_height` is the latest known height of `chain` — the
    /// destination chain, whose blocks the timeout is denominated in.
    pub fn send_packet(
        &mut self,
        chain: &mut ConnectedChain,
        id: PacketId,
        reference_height: u64,
        sent_at_ms: u64,
        timeout_delta_ms: u64,
    ) -> Result<TimeoutEstimate, IbcRelayerError> {
        if self.in_flight.contains_key(&id) {
            return Err(IbcRelayerError::DuplicatePacket);
        }
        let estimate = compute_timeout(
            &mut chain.block_time,
            &chain.config,
            reference_height,
            timeout_delta_ms,
        )?;

        self.in_flight.insert(
            id.clone(),
            InFlightPacket {
                id,
                dest_chain: chain.config.chain_id.clone(),
                sent_at_ms,
                timeout_delta_ms,
                estimate,
            },
        );
        Ok(estimate)
    }

    /// Records that a packet was acknowledged by the destination before either
    /// deadline.
    ///
    /// Acknowledgements count toward the misestimation *denominator* — the rate
    /// is over resolved packets, not over timeouts — but never as a miss.
    pub fn acknowledge_packet(
        &mut self,
        chain: &mut ConnectedChain,
        id: &PacketId,
        observed_height: u64,
        now_ms: u64,
    ) -> Result<PacketResolution, IbcRelayerError> {
        let packet = self
            .in_flight
            .remove(id)
            .ok_or(IbcRelayerError::PacketNotFound)?;
        Ok(self.resolve(
            chain,
            packet,
            PacketOutcome::Acknowledged,
            None,
            observed_height,
            now_ms,
        ))
    }

    /// Resolves every in-flight packet for `chain` that either has reached its
    /// timeout height or has outlived its intended window.
    ///
    /// Two resolution conditions, checked in this order:
    ///
    /// 1. `observed_height >= timeout_height` — the height deadline has fired.
    ///    It is a misestimation if it fired outside the packet's accuracy band
    ///    in either direction.
    /// 2. `now_ms` past the band with the destination still **at or below** the
    ///    timeout height — the packet outlived its window because the chain ran
    ///    slower than estimated. This is [`TimeoutMiss::TooLate`].
    ///
    /// Returns the resolutions in packet-identifier order.
    pub fn observe_destination_height(
        &mut self,
        chain: &mut ConnectedChain,
        observed_height: u64,
        now_ms: u64,
    ) -> Vec<PacketResolution> {
        let chain_id = &chain.config.chain_id;
        let due: Vec<PacketId> = self
            .in_flight
            .values()
            .filter(|p| {
                &p.dest_chain == chain_id
                    && (observed_height >= p.estimate.timeout_height
                        || now_ms > p.latest_acceptable_ms())
            })
            .map(|p| p.id.clone())
            .collect();

        let mut resolutions = Vec::with_capacity(due.len());
        for id in due {
            let packet = self
                .in_flight
                .remove(&id)
                .expect("packet id was just collected from in_flight");

            let (outcome, miss) = if observed_height >= packet.estimate.timeout_height {
                let miss = if now_ms < packet.earliest_acceptable_ms() {
                    Some(TimeoutMiss::TooEarly)
                } else if now_ms > packet.latest_acceptable_ms() {
                    Some(TimeoutMiss::TooLate)
                } else {
                    None
                };
                (PacketOutcome::TimedOutOnHeight, miss)
            } else {
                // The window elapsed past tolerance and the destination is
                // still at or below the timeout height.
                (
                    PacketOutcome::TimedOutBeyondWindow,
                    Some(TimeoutMiss::TooLate),
                )
            };

            resolutions.push(self.resolve(chain, packet, outcome, miss, observed_height, now_ms));
        }
        resolutions
    }

    /// Records one resolution, emits a misestimation event if it missed, and
    /// evaluates the recalibration trigger.
    fn resolve(
        &mut self,
        chain: &mut ConnectedChain,
        packet: InFlightPacket,
        outcome: PacketOutcome,
        miss: Option<TimeoutMiss>,
        observed_height: u64,
        now_ms: u64,
    ) -> PacketResolution {
        let chain_id = chain.config.chain_id.clone();
        let intended_deadline_ms = packet.intended_deadline_ms();

        if let Some(direction) = miss {
            self.events
                .push(IbcRelayerEvent::PacketTimeoutMisestimation {
                    packet_id: packet.id.clone(),
                    dest_chain: chain_id.clone(),
                    direction,
                    timeout_height: packet.estimate.timeout_height,
                    reference_height: packet.estimate.reference_height,
                    observed_height,
                    sent_at_ms: packet.sent_at_ms,
                    timeout_delta_ms: packet.timeout_delta_ms,
                    intended_deadline_ms,
                    observed_at_ms: now_ms,
                    mean_block_time_ms: packet.estimate.mean_block_time_ms,
                    p95_block_time_ms: packet.estimate.p95_block_time_ms,
                    dispersion_bps: packet.estimate.dispersion_bps,
                    cold_start: packet.estimate.cold_start,
                });
        }

        // Cold-start packets are deliberately margined, so their misses say
        // nothing about the estimator; see the module docs.
        let recalibrated = if packet.estimate.cold_start {
            false
        } else {
            let window = self.windows.entry(chain_id.clone()).or_default();
            window.record(miss);
            self.maybe_recalibrate(chain, &chain_id)
        };

        PacketResolution {
            packet_id: packet.id,
            outcome,
            miss,
            observed_height,
            observed_at_ms: now_ms,
            intended_deadline_ms,
            recalibrated,
        }
    }

    /// Evaluates the recalibration trigger for `chain_id` and applies it if it
    /// fires. See the module docs for the trigger definition and the three
    /// recalibration actions.
    fn maybe_recalibrate(&mut self, chain: &mut ConnectedChain, chain_id: &str) -> bool {
        let Some(window) = self.windows.get_mut(chain_id) else {
            return false;
        };
        // Armed only on a full window: a rate over three packets is noise.
        if !window.is_full() {
            return false;
        }
        let Some(rate_bps) = window.rate_bps() else {
            return false;
        };
        if rate_bps <= MAX_MISESTIMATION_RATE_BPS {
            return false;
        }

        let (early_count, late_count) = window.counts();
        window.clear();

        let reseeded_block_time_ms = chain.block_time.reseed_from_ema();
        // The 1.5x margin only pushes timeouts later, so it corrects early
        // misses and worsens late ones. Ties keep the no-margin default.
        let cold_start_reentered = early_count > late_count;
        if cold_start_reentered {
            chain.block_time.reset_cold_start();
        }

        self.events.push(IbcRelayerEvent::EstimatorRecalibrated {
            dest_chain: chain_id.into(),
            misestimation_rate_bps: rate_bps,
            early_count,
            late_count,
            reseeded_block_time_ms,
            cold_start_reentered,
        });
        true
    }

    // -----------------------------------------------------------------------
    // Inspection
    // -----------------------------------------------------------------------

    /// Misestimation rate for a chain over its current window, in basis points.
    pub fn misestimation_rate_bps(&self, chain_id: &str) -> Option<u64> {
        self.windows.get(chain_id).and_then(|w| w.rate_bps())
    }

    /// Number of resolutions currently in a chain's misestimation window.
    pub fn resolved_in_window(&self, chain_id: &str) -> usize {
        self.windows.get(chain_id).map_or(0, |w| w.outcomes.len())
    }

    /// Number of packets currently in flight.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Returns an in-flight packet, if tracked.
    pub fn in_flight(&self, id: &PacketId) -> Option<&InFlightPacket> {
        self.in_flight.get(id)
    }

    /// Accumulated observability events.
    pub fn events(&self) -> &[IbcRelayerEvent] {
        &self.events
    }

    /// Takes the accumulated events, leaving the buffer empty.
    pub fn drain_events(&mut self) -> Vec<IbcRelayerEvent> {
        core::mem::take(&mut self.events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_chain::ibc::packet_timeout::COLD_START_PACKET_COUNT;
    use crate::cross_chain::types::ChainConfig;

    /// Every packet in these tests asks for a 60 s window on a 2 s chain, which
    /// is `ceil(60_000 / 2_000) = 30` blocks from a reference height of 0:
    ///
    /// ```text
    /// timeout_height       = 30
    /// intended deadline    = sent_at (0) + 60_000 = 60_000 ms
    /// tolerance            = 60_000 * 5_000 / 10_000 = 30_000 ms
    /// accuracy band        = [30_000, 90_000] ms, inclusive both ends
    /// ```
    const DELTA_MS: u64 = 60_000;
    const TIMEOUT_HEIGHT: u64 = 30;
    const BAND_START_MS: u64 = 30_000;
    const BAND_END_MS: u64 = 90_000;

    /// A 2 s chain whose estimator is warm (100 samples) and past cold start,
    /// so every packet gets the un-margined 30-block count above.
    fn warm_chain() -> ConnectedChain {
        let mut chain = ConnectedChain::new(ChainConfig::new("dest".into(), 2_000, 32, 1), 0);
        for _ in 0..100 {
            chain.block_time.record_block_time_ms(2_000);
        }
        for _ in 0..COLD_START_PACKET_COUNT {
            chain.block_time.note_packet_issued();
        }
        chain
    }

    fn packet(sequence: u64) -> PacketId {
        PacketId::new("channel-0".into(), sequence)
    }

    /// Sends packet `sequence` at t=0 and resolves it at `resolve_at_ms` with
    /// the destination chain at `observed_height`.
    fn cycle(
        relayer: &mut PacketRelayer,
        chain: &mut ConnectedChain,
        sequence: u64,
        observed_height: u64,
        resolve_at_ms: u64,
    ) -> PacketResolution {
        let estimate = relayer
            .send_packet(chain, packet(sequence), 0, 0, DELTA_MS)
            .unwrap();
        assert_eq!(estimate.timeout_height, TIMEOUT_HEIGHT);
        let mut resolutions =
            relayer.observe_destination_height(chain, observed_height, resolve_at_ms);
        assert_eq!(
            resolutions.len(),
            1,
            "packet {sequence} should have resolved"
        );
        resolutions.remove(0)
    }

    /// Resolves `count` packets, starting at sequence `from`, each landing
    /// inside the accuracy band.
    fn accurate_run(
        relayer: &mut PacketRelayer,
        chain: &mut ConnectedChain,
        from: u64,
        count: u64,
    ) {
        for sequence in from..from + count {
            let res = cycle(relayer, chain, sequence, TIMEOUT_HEIGHT, DELTA_MS);
            assert_eq!(res.miss, None);
            assert!(!res.recalibrated);
        }
    }

    /// Resolves `count` packets that miss in `direction`.
    fn miss_run(
        relayer: &mut PacketRelayer,
        chain: &mut ConnectedChain,
        from: u64,
        count: u64,
        direction: TimeoutMiss,
    ) -> Vec<PacketResolution> {
        let at_ms = match direction {
            TimeoutMiss::TooEarly => BAND_START_MS - 1,
            TimeoutMiss::TooLate => BAND_END_MS + 1,
        };
        (from..from + count)
            .map(|sequence| {
                let res = cycle(relayer, chain, sequence, TIMEOUT_HEIGHT, at_ms);
                assert_eq!(res.miss, Some(direction));
                res
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Classification and its exact boundaries
    // -----------------------------------------------------------------------

    #[test]
    fn a_deadline_inside_the_band_is_accurate() {
        let (mut relayer, mut chain) = (PacketRelayer::new(), warm_chain());
        let res = cycle(&mut relayer, &mut chain, 1, TIMEOUT_HEIGHT, DELTA_MS);
        assert_eq!(res.outcome, PacketOutcome::TimedOutOnHeight);
        assert_eq!(res.miss, None);
        assert_eq!(res.intended_deadline_ms, 60_000);
        assert!(
            relayer.events().is_empty(),
            "an accurate packet emits nothing"
        );
    }

    #[test]
    fn the_accuracy_band_is_inclusive_at_both_ends() {
        // Exactly at the early edge: accurate. One millisecond earlier: early.
        let (mut relayer, mut chain) = (PacketRelayer::new(), warm_chain());
        assert_eq!(
            cycle(&mut relayer, &mut chain, 1, TIMEOUT_HEIGHT, BAND_START_MS).miss,
            None
        );
        assert_eq!(
            cycle(
                &mut relayer,
                &mut chain,
                2,
                TIMEOUT_HEIGHT,
                BAND_START_MS - 1
            )
            .miss,
            Some(TimeoutMiss::TooEarly)
        );
        // Exactly at the late edge: accurate. One millisecond later: late.
        assert_eq!(
            cycle(&mut relayer, &mut chain, 3, TIMEOUT_HEIGHT, BAND_END_MS).miss,
            None
        );
        assert_eq!(
            cycle(&mut relayer, &mut chain, 4, TIMEOUT_HEIGHT, BAND_END_MS + 1).miss,
            Some(TimeoutMiss::TooLate)
        );
    }

    #[test]
    fn a_packet_outliving_its_window_below_the_timeout_height_is_a_late_miss() {
        // Issue #138 Phase 3 requirement: the destination is still *below* the
        // estimated timeout height when the intended window has run out, so the
        // chain ran slower than the estimate predicted.
        let (mut relayer, mut chain) = (PacketRelayer::new(), warm_chain());
        let res = cycle(
            &mut relayer,
            &mut chain,
            1,
            TIMEOUT_HEIGHT - 1,
            BAND_END_MS + 1,
        );
        assert_eq!(res.outcome, PacketOutcome::TimedOutBeyondWindow);
        assert_eq!(res.miss, Some(TimeoutMiss::TooLate));
        assert_eq!(res.observed_height, 29);
    }

    #[test]
    fn a_packet_below_its_timeout_height_and_inside_its_window_stays_in_flight() {
        let (mut relayer, mut chain) = (PacketRelayer::new(), warm_chain());
        relayer
            .send_packet(&mut chain, packet(1), 0, 0, DELTA_MS)
            .unwrap();
        assert!(relayer
            .observe_destination_height(&mut chain, 29, BAND_END_MS)
            .is_empty());
        assert_eq!(relayer.in_flight_count(), 1);
    }

    #[test]
    fn an_acknowledged_packet_counts_in_the_denominator_but_never_as_a_miss() {
        let (mut relayer, mut chain) = (PacketRelayer::new(), warm_chain());
        relayer
            .send_packet(&mut chain, packet(1), 0, 0, DELTA_MS)
            .unwrap();
        let res = relayer
            .acknowledge_packet(&mut chain, &packet(1), 12, 20_000)
            .unwrap();
        assert_eq!(res.outcome, PacketOutcome::Acknowledged);
        assert_eq!(res.miss, None);
        assert_eq!(relayer.resolved_in_window("dest"), 1);
        assert_eq!(relayer.misestimation_rate_bps("dest"), Some(0));
    }

    // -----------------------------------------------------------------------
    // The misestimation event's diagnostic payload
    // -----------------------------------------------------------------------

    #[test]
    fn the_misestimation_event_carries_both_sides_of_the_comparison() {
        let mut relayer = PacketRelayer::new();
        // A chain whose window says 2 s but whose estimator has seen spikes, so
        // the event's dispersion field is meaningful.
        let mut chain = ConnectedChain::new(ChainConfig::new("dest".into(), 2_000, 32, 1), 0);
        for i in 0..100 {
            chain
                .block_time
                .record_block_time_ms(if i % 10 == 9 { 30_000 } else { 2_000 });
        }
        for _ in 0..COLD_START_PACKET_COUNT {
            chain.block_time.note_packet_issued();
        }

        // mean 4_800 -> ceil(60_000 / 4_800) = 13 blocks from height 500.
        let estimate = relayer
            .send_packet(&mut chain, packet(7), 500, 1_000, DELTA_MS)
            .unwrap();
        assert_eq!(estimate.timeout_height, 513);
        // Resolved far past the band: deadline 61_000, tolerance 30_000.
        relayer.observe_destination_height(&mut chain, 520, 200_000);

        let events = relayer.drain_events();
        assert_eq!(events.len(), 1);
        let IbcRelayerEvent::PacketTimeoutMisestimation {
            packet_id,
            dest_chain,
            direction,
            timeout_height,
            reference_height,
            observed_height,
            sent_at_ms,
            timeout_delta_ms,
            intended_deadline_ms,
            observed_at_ms,
            mean_block_time_ms,
            p95_block_time_ms,
            dispersion_bps,
            cold_start,
        } = events[0].clone()
        else {
            panic!("expected a misestimation event, got {:?}", events[0]);
        };

        // Which packet, on which chain, and which way it missed.
        assert_eq!(packet_id, packet(7));
        assert_eq!(dest_chain, "dest");
        assert_eq!(direction, TimeoutMiss::TooLate);
        // Estimated versus actual height.
        assert_eq!(reference_height, 500);
        assert_eq!(timeout_height, 513);
        assert_eq!(observed_height, 520);
        // Estimated versus actual time.
        assert_eq!(sent_at_ms, 1_000);
        assert_eq!(timeout_delta_ms, 60_000);
        assert_eq!(intended_deadline_ms, 61_000);
        assert_eq!(observed_at_ms, 200_000);
        // The estimator state that produced the height, which cannot be
        // recovered later because the sample window has slid on.
        assert_eq!(mean_block_time_ms, 4_800);
        assert_eq!(p95_block_time_ms, Some(30_000));
        assert_eq!(dispersion_bps, 62_500);
        assert!(!cold_start);
        // 62_500 bps says "variable", not "uniformly slow" -- the operator can
        // tell the two failure modes apart from the event alone.
        assert!(dispersion_bps > 60_000);
    }

    // -----------------------------------------------------------------------
    // The recalibration trigger and its 5% boundary
    // -----------------------------------------------------------------------

    #[test]
    fn the_trigger_is_disarmed_until_the_window_is_full() {
        let (mut relayer, mut chain) = (PacketRelayer::new(), warm_chain());
        // 1 miss in 3 resolutions is a 33% rate, and must not fire: a rate over
        // three packets is noise, not evidence.
        accurate_run(&mut relayer, &mut chain, 1, 2);
        let res = miss_run(&mut relayer, &mut chain, 3, 1, TimeoutMiss::TooEarly);
        assert!(!res[0].recalibrated);
        assert_eq!(relayer.misestimation_rate_bps("dest"), Some(3_333));
        assert_eq!(relayer.resolved_in_window("dest"), 3);
    }

    #[test]
    fn the_trigger_does_not_fire_at_exactly_five_percent() {
        let (mut relayer, mut chain) = (PacketRelayer::new(), warm_chain());
        accurate_run(&mut relayer, &mut chain, 1, 95);
        let misses = miss_run(&mut relayer, &mut chain, 96, 5, TimeoutMiss::TooEarly);
        assert!(misses.iter().all(|r| !r.recalibrated));
        // 5 * 10_000 / 100 = 500 bps, exactly the bound, which is not above it.
        assert_eq!(relayer.misestimation_rate_bps("dest"), Some(500));
        assert_eq!(
            relayer.misestimation_rate_bps("dest"),
            Some(MAX_MISESTIMATION_RATE_BPS)
        );
        assert_eq!(relayer.resolved_in_window("dest"), 100);
        // Only the five per-packet misestimation events; no recalibration.
        assert_eq!(relayer.events().len(), 5);
    }

    #[test]
    fn the_trigger_fires_at_six_percent() {
        let (mut relayer, mut chain) = (PacketRelayer::new(), warm_chain());
        accurate_run(&mut relayer, &mut chain, 1, 95);
        miss_run(&mut relayer, &mut chain, 96, 5, TimeoutMiss::TooEarly);
        // The 101st resolution overwrites the oldest (accurate) slot with a
        // sixth miss: 6 * 10_000 / 100 = 600 bps, which is above the bound.
        let sixth = miss_run(&mut relayer, &mut chain, 101, 1, TimeoutMiss::TooEarly);
        assert!(sixth[0].recalibrated);

        let recal = relayer
            .events()
            .iter()
            .find_map(|e| match e {
                IbcRelayerEvent::EstimatorRecalibrated {
                    misestimation_rate_bps,
                    early_count,
                    late_count,
                    reseeded_block_time_ms,
                    cold_start_reentered,
                    ..
                } => Some((
                    *misestimation_rate_bps,
                    *early_count,
                    *late_count,
                    *reseeded_block_time_ms,
                    *cold_start_reentered,
                )),
                _ => None,
            })
            .expect("a recalibration event");
        assert_eq!(recal.0, 600);
        assert_eq!(recal.1, 6); // early
        assert_eq!(recal.2, 0); // late
        assert_eq!(recal.3, Some(2_000)); // re-seeded from the EMA
        assert!(recal.4); // early misses in strict majority -> cold start

        // The window was cleared, so the trigger cannot re-fire on the same
        // evidence for the next 95 packets.
        assert_eq!(relayer.resolved_in_window("dest"), 0);
        assert_eq!(relayer.misestimation_rate_bps("dest"), None);
        // And the estimator was re-seeded from the EMA rather than emptied.
        assert_eq!(chain.block_time.sample_count(), 1);
        assert_eq!(chain.block_time.window_mean_block_time_ms(), Some(2_000));
    }

    // -----------------------------------------------------------------------
    // The dominant-direction gate on re-entering cold start
    // -----------------------------------------------------------------------

    /// Drives one full window of `early` early misses and `late` late misses
    /// (padded to 101 resolutions with accurate ones) and returns whether cold
    /// start was re-entered.
    fn recalibrate_with(early: u64, late: u64) -> (bool, u32, u32) {
        let (mut relayer, mut chain) = (PacketRelayer::new(), warm_chain());
        let misses = early + late;
        accurate_run(&mut relayer, &mut chain, 1, 101 - misses);
        miss_run(&mut relayer, &mut chain, 200, early, TimeoutMiss::TooEarly);
        miss_run(&mut relayer, &mut chain, 300, late, TimeoutMiss::TooLate);

        relayer
            .events()
            .iter()
            .find_map(|e| match e {
                IbcRelayerEvent::EstimatorRecalibrated {
                    cold_start_reentered,
                    early_count,
                    late_count,
                    ..
                } => Some((*cold_start_reentered, *early_count, *late_count)),
                _ => None,
            })
            .expect("a recalibration event")
    }

    #[test]
    fn cold_start_is_re_entered_only_when_early_misses_are_in_strict_majority() {
        // Early misses dominate: the 1.5x margin pushes timeouts later, which
        // is exactly the correction they need.
        assert_eq!(recalibrate_with(6, 0), (true, 6, 0));
        assert_eq!(recalibrate_with(4, 2), (true, 4, 2));

        // Boundary: a dead tie does NOT re-enter cold start. The no-margin path
        // is the conservative default, and breaking the tie would require a
        // second arbitrary threshold.
        assert_eq!(recalibrate_with(3, 3), (false, 3, 3));

        // Late misses dominate: the margin would only push timeouts later
        // still, making accuracy worse. Re-seeding from the EMA is the whole
        // correction here.
        assert_eq!(recalibrate_with(2, 4), (false, 2, 4));
        assert_eq!(recalibrate_with(0, 6), (false, 0, 6));
    }

    // -----------------------------------------------------------------------
    // Packet bookkeeping
    // -----------------------------------------------------------------------

    #[test]
    fn a_duplicate_packet_identifier_is_rejected() {
        let (mut relayer, mut chain) = (PacketRelayer::new(), warm_chain());
        relayer
            .send_packet(&mut chain, packet(1), 0, 0, DELTA_MS)
            .unwrap();
        assert_eq!(
            relayer.send_packet(&mut chain, packet(1), 0, 0, DELTA_MS),
            Err(IbcRelayerError::DuplicatePacket)
        );
        assert_eq!(relayer.in_flight_count(), 1);
    }

    #[test]
    fn acknowledging_an_untracked_packet_reports_packet_not_found() {
        let (mut relayer, mut chain) = (PacketRelayer::new(), warm_chain());
        assert_eq!(
            relayer.acknowledge_packet(&mut chain, &packet(9), 0, 0),
            Err(IbcRelayerError::PacketNotFound)
        );
    }

    #[test]
    fn a_rejected_timeout_computation_propagates_and_tracks_nothing() {
        let (mut relayer, mut chain) = (PacketRelayer::new(), warm_chain());
        assert_eq!(
            relayer.send_packet(&mut chain, packet(1), 0, 0, 1_000),
            Err(IbcRelayerError::Timeout(
                IbcTimeoutError::TimeoutDeltaOutOfRange
            ))
        );
        assert_eq!(relayer.in_flight_count(), 0);
    }

    #[test]
    fn resolutions_are_scoped_to_the_chain_being_observed() {
        let mut relayer = PacketRelayer::new();
        let mut dest = warm_chain();
        let mut other = ConnectedChain::new(ChainConfig::new("other".into(), 2_000, 32, 1), 0);

        relayer
            .send_packet(&mut dest, packet(1), 0, 0, DELTA_MS)
            .unwrap();
        // Observing a different chain's height must not resolve this packet.
        assert!(relayer
            .observe_destination_height(&mut other, 10_000, 500_000)
            .is_empty());
        assert_eq!(relayer.in_flight_count(), 1);
        assert_eq!(
            relayer
                .observe_destination_height(&mut dest, TIMEOUT_HEIGHT, DELTA_MS)
                .len(),
            1
        );
    }

    #[test]
    fn cold_start_packets_are_excluded_from_the_misestimation_window() {
        let mut relayer = PacketRelayer::new();
        // A fresh chain: the estimator is warm (100 samples) but no packet has
        // been issued, so the first ten are margined.
        let mut chain = ConnectedChain::new(ChainConfig::new("dest".into(), 2_000, 32, 1), 0);
        for _ in 0..100 {
            chain.block_time.record_block_time_ms(2_000);
        }

        // All ten cold-start packets miss badly (margined to 45 blocks, then
        // resolved far outside the band).
        for sequence in 1..=COLD_START_PACKET_COUNT as u64 {
            let estimate = relayer
                .send_packet(&mut chain, packet(sequence), 0, 0, DELTA_MS)
                .unwrap();
            assert!(estimate.cold_start);
            assert_eq!(estimate.timeout_height, 45); // ceil(30 * 1.5)
            let res = relayer.observe_destination_height(&mut chain, 45, BAND_END_MS + 1);
            assert_eq!(res[0].miss, Some(TimeoutMiss::TooLate));
            assert!(!res[0].recalibrated);
        }

        // Ten misses, and yet the window that drives the trigger is empty:
        // the margin caused them, not the estimator.
        assert_eq!(relayer.events().len(), COLD_START_PACKET_COUNT as usize);
        assert_eq!(relayer.resolved_in_window("dest"), 0);
        assert_eq!(relayer.misestimation_rate_bps("dest"), None);

        // The eleventh packet is un-margined and does count.
        let res = cycle(&mut relayer, &mut chain, 11, TIMEOUT_HEIGHT, DELTA_MS);
        assert_eq!(res.miss, None);
        assert_eq!(relayer.resolved_in_window("dest"), 1);
    }

    #[test]
    fn drain_events_empties_the_buffer() {
        let (mut relayer, mut chain) = (PacketRelayer::new(), warm_chain());
        miss_run(&mut relayer, &mut chain, 1, 2, TimeoutMiss::TooEarly);
        assert_eq!(relayer.drain_events().len(), 2);
        assert!(relayer.events().is_empty());
    }
}
