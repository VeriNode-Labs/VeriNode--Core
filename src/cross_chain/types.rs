//! Core types and operational constants for cross-chain light-client
//! committee synchronization (issue #136).
//!
//! Every finality gadget a light client tracks advertises a different block
//! time. A 2-second chain and a 15-second chain cannot share a single fixed
//! sync cadence without one of them drifting out of committee sync, so all of
//! the timing bounds below are derived *per chain* from its
//! [`ChainConfig::block_time_ms`]:
//!
//! * **Sync timeout** — `max(3 * block_time_ms, 60_000)` (three block times,
//!   floored at one minute so very fast chains do not thrash).
//! * **Sync interval** — `block_time_ms / 4` (poll the committee four times per
//!   block so a single missed sample never starves finality).
//! * **Clock-drift budget** — `500 ms * finality_hops` (500 ms per relay hop).
//!
//! All arithmetic is integer-only and saturating so the module compiles under
//! `no_std` (WASM) and is shared verbatim by off-chain relayers.

extern crate alloc;

use alloc::string::String;

// ---------------------------------------------------------------------------
// Operational constants (issue #136 technical invariants)
// ---------------------------------------------------------------------------

/// Maximum tolerated clock drift per relay hop, in milliseconds.
pub const MAX_CLOCK_DRIFT_MS_PER_HOP: u64 = 500;

/// Committee sync timeout is this multiple of the chain block time.
pub const SYNC_TIMEOUT_MULTIPLIER: u64 = 3;

/// Floor for the committee sync timeout, in milliseconds (one minute).
///
/// Fast chains (e.g. 2 s blocks) would otherwise derive a 6 s timeout that is
/// too aggressive under transient network latency; the floor keeps the timeout
/// stable across heterogeneous finality gadgets.
pub const MIN_SYNC_TIMEOUT_MS: u64 = 60_000;

/// The committee is polled `block_time_ms / SYNC_INTERVAL_DIVISOR` apart, i.e.
/// four samples per block.
pub const SYNC_INTERVAL_DIVISOR: u64 = 4;

/// Number of recent headers retained per chain in the bounded header cache.
pub const HEADER_CACHE_CAPACITY: usize = 256;

/// Base delay for exponential sync-retry backoff, in milliseconds.
pub const SYNC_BACKOFF_BASE_MS: u64 = 1_000;

/// Ceiling for exponential sync-retry backoff, in milliseconds.
pub const SYNC_BACKOFF_CAP_MS: u64 = 30_000;

/// Grace-period multiplier applied to the sync timeout, in basis points.
///
/// `15_000 bps = 1.5x`. When sync drift is detected the finality verifier waits
/// `1.5 * sync_timeout_ms` after a header is observed before finalizing it, so
/// a temporarily skewed committee view cannot finalize a header prematurely.
pub const GRACE_PERIOD_MULTIPLIER_BPS: u64 = 15_000;

/// Denominator for basis-point arithmetic (`10_000 bps = 100%`).
pub const BPS_DENOMINATOR: u64 = 10_000;

/// Numerator of the Byzantine finality threshold fraction (2/3).
pub const FINALITY_THRESHOLD_NUMERATOR: u64 = 2;

/// Denominator of the Byzantine finality threshold fraction (2/3).
pub const FINALITY_THRESHOLD_DENOMINATOR: u64 = 3;

/// Maximum acceptable end-to-end finality lag exported to dashboards, in
/// milliseconds. A connected chain whose finality lag exceeds this bound is
/// flagged out-of-target by [`crate::cross_chain::ChainFinalityMetrics`].
pub const MAX_ACCEPTABLE_FINALITY_LAG_MS: u64 = 10_000;

/// Maximum number of chains a single light-client registry tracks.
pub const MAX_CONNECTED_CHAINS: usize = 64;

// ---------------------------------------------------------------------------
// Chain identity
// ---------------------------------------------------------------------------

/// Stable identifier for a connected chain / finality gadget.
pub type ChainId = String;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by cross-chain light-client operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrossChainError {
    /// The chain identifier was empty.
    EmptyChainId,
    /// The configured block time was zero.
    InvalidBlockTime,
    /// The configured committee size was zero.
    InvalidCommitteeSize,
    /// The registry is already tracking the maximum number of chains.
    TooManyChains,
    /// A chain with the same identifier is already connected.
    ChainAlreadyConnected,
    /// No chain with the requested identifier is connected.
    ChainNotFound,
}

// ---------------------------------------------------------------------------
// Chain configuration
// ---------------------------------------------------------------------------

/// Per-chain configuration describing a connected finality gadget.
///
/// All synchronization timing is derived from [`block_time_ms`](Self::block_time_ms)
/// so heterogeneous chains stay in committee sync without a shared global clock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainConfig {
    /// Stable identifier for the chain.
    pub chain_id: ChainId,
    /// Nominal block production time in milliseconds.
    pub block_time_ms: u64,
    /// Number of validators in the sync committee.
    pub committee_size: u32,
    /// Number of relay hops between this chain and the light client.
    pub finality_hops: u32,
}

impl ChainConfig {
    /// Creates a new chain configuration.
    pub fn new(
        chain_id: ChainId,
        block_time_ms: u64,
        committee_size: u32,
        finality_hops: u32,
    ) -> Self {
        Self {
            chain_id,
            block_time_ms,
            committee_size,
            finality_hops,
        }
    }

    /// Validates the configuration before it is admitted to a registry.
    pub fn validate(&self) -> Result<(), CrossChainError> {
        if self.chain_id.is_empty() {
            return Err(CrossChainError::EmptyChainId);
        }
        if self.block_time_ms == 0 {
            return Err(CrossChainError::InvalidBlockTime);
        }
        if self.committee_size == 0 {
            return Err(CrossChainError::InvalidCommitteeSize);
        }
        Ok(())
    }

    /// Committee sync timeout for this chain: `max(3 * block_time_ms, 60_000)`.
    ///
    /// This is the per-chain realization of the issue #136 invariant
    /// "committee sync timeout 3x max block time", floored at
    /// [`MIN_SYNC_TIMEOUT_MS`] so fast chains do not derive an over-aggressive
    /// timeout.
    pub fn sync_timeout_ms(&self) -> u64 {
        self.block_time_ms
            .saturating_mul(SYNC_TIMEOUT_MULTIPLIER)
            .max(MIN_SYNC_TIMEOUT_MS)
    }

    /// Committee sync interval for this chain: `block_time_ms / 4`.
    ///
    /// Polling four times per block means a single dropped sample still leaves
    /// three within one block time. The interval is floored at 1 ms so the
    /// scheduler never busy-loops on a (misconfigured) sub-4-ms block time.
    pub fn sync_interval_ms(&self) -> u64 {
        (self.block_time_ms / SYNC_INTERVAL_DIVISOR).max(1)
    }

    /// Clock-drift budget for this chain: `500 ms * finality_hops`.
    pub fn max_clock_drift_ms(&self) -> u64 {
        MAX_CLOCK_DRIFT_MS_PER_HOP.saturating_mul(self.finality_hops as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(block_time_ms: u64, hops: u32) -> ChainConfig {
        ChainConfig::new("chain".into(), block_time_ms, 32, hops)
    }

    #[test]
    fn sync_timeout_uses_three_block_times_when_above_floor() {
        // 25 s block → 3 * 25_000 = 75_000 ms, above the 60_000 floor.
        assert_eq!(cfg(25_000, 1).sync_timeout_ms(), 75_000);
    }

    #[test]
    fn sync_timeout_is_floored_at_minimum_for_fast_chains() {
        // 2 s block → 3 * 2_000 = 6_000 ms, floored to 60_000 ms.
        assert_eq!(cfg(2_000, 1).sync_timeout_ms(), MIN_SYNC_TIMEOUT_MS);
        // 15 s block → 3 * 15_000 = 45_000 ms, still floored to 60_000 ms.
        assert_eq!(cfg(15_000, 1).sync_timeout_ms(), MIN_SYNC_TIMEOUT_MS);
    }

    #[test]
    fn sync_timeout_saturates_instead_of_overflowing() {
        assert_eq!(cfg(u64::MAX, 1).sync_timeout_ms(), u64::MAX);
    }

    #[test]
    fn sync_interval_is_a_quarter_of_the_block_time() {
        assert_eq!(cfg(2_000, 1).sync_interval_ms(), 500);
        assert_eq!(cfg(15_000, 1).sync_interval_ms(), 3_750);
    }

    #[test]
    fn sync_interval_is_floored_at_one_ms() {
        assert_eq!(cfg(1, 1).sync_interval_ms(), 1);
    }

    #[test]
    fn clock_drift_budget_scales_with_hops() {
        assert_eq!(cfg(2_000, 0).max_clock_drift_ms(), 0);
        assert_eq!(cfg(2_000, 1).max_clock_drift_ms(), 500);
        assert_eq!(cfg(2_000, 2).max_clock_drift_ms(), 1_000);
    }

    #[test]
    fn validate_rejects_degenerate_configs() {
        assert_eq!(
            ChainConfig::new(String::new(), 2_000, 32, 1).validate(),
            Err(CrossChainError::EmptyChainId)
        );
        assert_eq!(
            ChainConfig::new("c".into(), 0, 32, 1).validate(),
            Err(CrossChainError::InvalidBlockTime)
        );
        assert_eq!(
            ChainConfig::new("c".into(), 2_000, 0, 1).validate(),
            Err(CrossChainError::InvalidCommitteeSize)
        );
    }

    #[test]
    fn validate_accepts_a_well_formed_config() {
        assert!(cfg(2_000, 2).validate().is_ok());
    }
}
