//! Cross-chain light-client committee synchronization across heterogeneous
//! finality gadgets (issue #136).
//!
//! Different chains finalize at different speeds. A light client that tracks
//! several of them with a single fixed sync cadence lets the slow chains fall
//! behind and the fast chains thrash, producing *committee synchronization
//! skew* — the light client's cached view of a chain's sync committee drifts
//! out of date and finality stalls or, worse, finalizes on a stale committee.
//!
//! This module keeps every connected chain in sync by deriving all timing from
//! that chain's own block time:
//!
//! * [`types`] — [`ChainConfig`] and the derived per-chain sync timeout
//!   (`max(3 * block_time_ms, 60_000)`), sync interval (`block_time_ms / 4`),
//!   and clock-drift budget (`500 ms * finality_hops`).
//! * [`header_cache`] — a bounded [`HeaderCache`] of the 256 most recent
//!   headers per chain.
//! * [`committee_sync`] — [`CommitteeSyncState`] scheduling, exponential retry
//!   backoff (1 s → 2 s → 4 s → … capped at 30 s), and sync-drift detection.
//! * [`finality_verifier`] — the `2/3 + 1` committee-weight
//!   [`FinalityVerifier`] with a `1.5x` sync-timeout grace period applied when
//!   sync drift is detected.
//! * [`light_client`] — the [`LightClientRegistry`] that ties the above
//!   together and exports the `chain_finality_lag_ms` gauge
//!   ([`ChainFinalityMetrics`]) for every connected chain.
//!
//! All logic is deterministic, integer-only, and dependency-free so it compiles
//! to WASM (`no_std`) and is shared verbatim by off-chain relayers and
//! monitoring agents.

pub mod committee_sync;
pub mod finality_verifier;
pub mod header_cache;
pub mod light_client;
pub mod types;

pub use committee_sync::{CommitteeSyncState, SyncOutcome};
pub use finality_verifier::{FinalityDecision, FinalityVerifier};
pub use header_cache::{HeaderCache, RecentHeader};
pub use light_client::{ChainFinalityMetrics, ConnectedChain, LightClientRegistry};
pub use types::{
    ChainConfig, ChainId, CrossChainError, BPS_DENOMINATOR, FINALITY_THRESHOLD_DENOMINATOR,
    FINALITY_THRESHOLD_NUMERATOR, GRACE_PERIOD_MULTIPLIER_BPS, HEADER_CACHE_CAPACITY,
    MAX_ACCEPTABLE_FINALITY_LAG_MS, MAX_CLOCK_DRIFT_MS_PER_HOP, MAX_CONNECTED_CHAINS,
    MIN_SYNC_TIMEOUT_MS, SYNC_BACKOFF_BASE_MS, SYNC_BACKOFF_CAP_MS, SYNC_INTERVAL_DIVISOR,
    SYNC_TIMEOUT_MULTIPLIER,
};
