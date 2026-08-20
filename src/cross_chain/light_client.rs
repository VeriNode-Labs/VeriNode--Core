//! Light-client registry that ties per-chain config, header cache, committee
//! sync, and finality verification together and exports the
//! `chain_finality_lag_ms` gauge for every connected chain (issue #136).
//!
//! A [`ConnectedChain`] owns one chain's [`ChainConfig`], [`HeaderCache`], and
//! [`CommitteeSyncState`]; the [`LightClientRegistry`] holds all connected
//! chains and produces the per-chain finality-lag gauges consumed by
//! dashboards and alerting.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::committee_sync::{CommitteeSyncState, SyncOutcome};
use super::finality_verifier::{FinalityDecision, FinalityVerifier};
use super::header_cache::{HeaderCache, RecentHeader};
use super::types::{
    ChainConfig, ChainId, CrossChainError, MAX_ACCEPTABLE_FINALITY_LAG_MS, MAX_CONNECTED_CHAINS,
};

/// Per-chain finality metrics exported to dashboards and alerting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainFinalityMetrics {
    /// Identifier of the chain.
    pub chain_id: ChainId,
    /// Age of the latest finalized header as of the sample time, in
    /// milliseconds — the `chain_finality_lag_ms` gauge.
    pub finality_lag_ms: u64,
    /// Height of the latest finalized header, if any.
    pub finalized_height: Option<u64>,
    /// Whether the finality lag is within [`MAX_ACCEPTABLE_FINALITY_LAG_MS`].
    pub within_target: bool,
}

/// One chain tracked by the light client.
#[derive(Clone, Debug)]
pub struct ConnectedChain {
    /// Timing configuration for this chain.
    pub config: ChainConfig,
    /// Bounded cache of recently observed headers.
    pub cache: HeaderCache,
    /// Committee synchronization state.
    pub sync: CommitteeSyncState,
    last_finalized_height: Option<u64>,
}

impl ConnectedChain {
    /// Connects a chain as of `now_ms`.
    pub fn new(config: ChainConfig, now_ms: u64) -> Self {
        let sync = CommitteeSyncState::new(config.chain_id.clone(), now_ms);
        Self {
            config,
            cache: HeaderCache::new(),
            sync,
            last_finalized_height: None,
        }
    }

    /// Records a header observed from the chain (after relay latency).
    pub fn observe_header(&mut self, header: RecentHeader) {
        self.cache.insert(header);
    }

    /// Records the outcome of a committee-sync attempt at `now_ms`.
    pub fn record_sync(&mut self, outcome: SyncOutcome, now_ms: u64) {
        self.sync.record_outcome(outcome, now_ms);
    }

    /// Returns `true` when this chain's committee view has drifted as of
    /// `now_ms`.
    pub fn drift_detected(&self, now_ms: u64) -> bool {
        self.sync.drift_detected(&self.config, now_ms)
    }

    /// Attempts to finalize the latest observed header as of `now_ms`.
    ///
    /// Honors the sync-drift grace period via [`FinalityVerifier`]. On a
    /// [`Finalized`](FinalityDecision::Finalized) decision the header is marked
    /// finalized in the cache and becomes the chain's finalized tip.
    pub fn try_finalize_latest(&mut self, now_ms: u64) -> FinalityDecision {
        let drift = self.drift_detected(now_ms);
        let Some(header) = self.cache.latest().copied() else {
            return FinalityDecision::InsufficientWeight;
        };

        let decision = FinalityVerifier::evaluate_finality(
            &self.config,
            header.attesting_weight,
            header.committee_weight,
            header.observed_at_ms,
            now_ms,
            drift,
        );

        if decision == FinalityDecision::Finalized {
            self.cache.mark_finalized(header.height);
            self.last_finalized_height = Some(header.height);
        }
        decision
    }

    /// Height of the latest finalized header, if any.
    pub fn finalized_height(&self) -> Option<u64> {
        self.last_finalized_height
    }

    /// `chain_finality_lag_ms` gauge: age of the latest finalized header as of
    /// `now_ms`. Returns `0` when no header has been finalized yet.
    pub fn finality_lag_ms(&self, now_ms: u64) -> u64 {
        match self.cache.latest_finalized() {
            Some(h) => now_ms.saturating_sub(h.timestamp_ms),
            None => 0,
        }
    }

    /// Builds the exported finality metrics for this chain as of `now_ms`.
    pub fn metrics(&self, now_ms: u64) -> ChainFinalityMetrics {
        let finality_lag_ms = self.finality_lag_ms(now_ms);
        ChainFinalityMetrics {
            chain_id: self.config.chain_id.clone(),
            finality_lag_ms,
            finalized_height: self.last_finalized_height,
            within_target: finality_lag_ms <= MAX_ACCEPTABLE_FINALITY_LAG_MS,
        }
    }
}

/// Registry of all chains a light client tracks.
#[derive(Clone, Debug, Default)]
pub struct LightClientRegistry {
    chains: BTreeMap<ChainId, ConnectedChain>,
}

impl LightClientRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            chains: BTreeMap::new(),
        }
    }

    /// Connects a chain as of `now_ms`.
    ///
    /// Returns an error if the configuration is invalid, the registry is at
    /// capacity, or the chain is already connected.
    pub fn connect(&mut self, config: ChainConfig, now_ms: u64) -> Result<(), CrossChainError> {
        config.validate()?;
        if self.chains.contains_key(&config.chain_id) {
            return Err(CrossChainError::ChainAlreadyConnected);
        }
        if self.chains.len() >= MAX_CONNECTED_CHAINS {
            return Err(CrossChainError::TooManyChains);
        }
        let chain_id = config.chain_id.clone();
        self.chains
            .insert(chain_id, ConnectedChain::new(config, now_ms));
        Ok(())
    }

    /// Returns a reference to a connected chain.
    pub fn chain(&self, chain_id: &str) -> Option<&ConnectedChain> {
        self.chains.get(chain_id)
    }

    /// Returns a mutable reference to a connected chain.
    pub fn chain_mut(&mut self, chain_id: &str) -> Option<&mut ConnectedChain> {
        self.chains.get_mut(chain_id)
    }

    /// Records a header observation for a connected chain.
    pub fn observe_header(
        &mut self,
        chain_id: &str,
        header: RecentHeader,
    ) -> Result<(), CrossChainError> {
        let chain = self
            .chains
            .get_mut(chain_id)
            .ok_or(CrossChainError::ChainNotFound)?;
        chain.observe_header(header);
        Ok(())
    }

    /// Attempts to finalize the latest observed header for a connected chain.
    pub fn try_finalize(
        &mut self,
        chain_id: &str,
        now_ms: u64,
    ) -> Result<FinalityDecision, CrossChainError> {
        let chain = self
            .chains
            .get_mut(chain_id)
            .ok_or(CrossChainError::ChainNotFound)?;
        Ok(chain.try_finalize_latest(now_ms))
    }

    /// Number of connected chains.
    pub fn connected_count(&self) -> usize {
        self.chains.len()
    }

    /// Per-chain `chain_finality_lag_ms` gauges as of `now_ms`, ordered by
    /// chain identifier.
    pub fn finality_lag_gauges(&self, now_ms: u64) -> Vec<ChainFinalityMetrics> {
        self.chains.values().map(|c| c.metrics(now_ms)).collect()
    }

    /// Largest finality lag across all connected chains as of `now_ms`.
    pub fn max_finality_lag_ms(&self, now_ms: u64) -> u64 {
        self.chains
            .values()
            .map(|c| c.finality_lag_ms(now_ms))
            .max()
            .unwrap_or(0)
    }

    /// Returns `true` when every connected chain's finality lag is within
    /// [`MAX_ACCEPTABLE_FINALITY_LAG_MS`] as of `now_ms`.
    pub fn all_within_target(&self, now_ms: u64) -> bool {
        self.chains
            .values()
            .all(|c| c.finality_lag_ms(now_ms) <= MAX_ACCEPTABLE_FINALITY_LAG_MS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(id: &str, block_time_ms: u64) -> ChainConfig {
        // 2 hops → 1_000 ms drift budget.
        ChainConfig::new(id.into(), block_time_ms, 99, 2)
    }

    /// A header with `attesting_weight` above the 2/3+1 threshold of 99.
    fn finalizable_header(height: u64, timestamp_ms: u64, observed_at_ms: u64) -> RecentHeader {
        RecentHeader::new(height, timestamp_ms, 99, 67, observed_at_ms)
    }

    #[test]
    fn connect_validates_and_rejects_duplicates() {
        let mut reg = LightClientRegistry::new();
        assert_eq!(
            reg.connect(ChainConfig::new(String::new(), 2_000, 32, 1), 0),
            Err(CrossChainError::EmptyChainId)
        );
        reg.connect(config("eth", 2_000), 0).unwrap();
        assert_eq!(
            reg.connect(config("eth", 2_000), 0),
            Err(CrossChainError::ChainAlreadyConnected)
        );
        assert_eq!(reg.connected_count(), 1);
    }

    #[test]
    fn observe_and_finalize_updates_the_finalized_tip() {
        let mut reg = LightClientRegistry::new();
        reg.connect(config("eth", 2_000), 0).unwrap();
        reg.observe_header("eth", finalizable_header(10, 1_000, 1_800))
            .unwrap();

        // No drift → finalizes immediately.
        assert_eq!(
            reg.try_finalize("eth", 2_000).unwrap(),
            FinalityDecision::Finalized
        );
        let chain = reg.chain("eth").unwrap();
        assert_eq!(chain.finalized_height(), Some(10));
        // Lag = now (2_000) - block timestamp (1_000) = 1_000 ms.
        assert_eq!(chain.finality_lag_ms(2_000), 1_000);
    }

    #[test]
    fn finalization_withheld_under_drift_until_grace_elapses() {
        let mut reg = LightClientRegistry::new();
        reg.connect(config("eth", 2_000), 0).unwrap();
        // Force drift via excessive observed clock skew (budget = 1_000 ms).
        reg.chain_mut("eth").unwrap().sync.observe_skew(2_000);
        reg.observe_header("eth", finalizable_header(10, 1_000, 1_800))
            .unwrap();

        // grace = 1.5 * 60_000 = 90_000 ms; deadline = observed (1_800) + 90_000.
        assert_eq!(
            reg.try_finalize("eth", 50_000).unwrap(),
            FinalityDecision::AwaitingGracePeriod
        );
        assert_eq!(
            reg.try_finalize("eth", 91_800).unwrap(),
            FinalityDecision::Finalized
        );
    }

    #[test]
    fn insufficient_weight_is_not_finalized() {
        let mut reg = LightClientRegistry::new();
        reg.connect(config("eth", 2_000), 0).unwrap();
        // 66 < 67 threshold.
        reg.observe_header("eth", RecentHeader::new(10, 1_000, 99, 66, 1_800))
            .unwrap();
        assert_eq!(
            reg.try_finalize("eth", 2_000).unwrap(),
            FinalityDecision::InsufficientWeight
        );
        assert_eq!(reg.chain("eth").unwrap().finalized_height(), None);
    }

    #[test]
    fn gauges_report_one_entry_per_chain_sorted_by_id() {
        let mut reg = LightClientRegistry::new();
        reg.connect(config("zeta", 2_000), 0).unwrap();
        reg.connect(config("alpha", 15_000), 0).unwrap();

        let gauges = reg.finality_lag_gauges(0);
        assert_eq!(gauges.len(), 2);
        assert_eq!(gauges[0].chain_id, "alpha");
        assert_eq!(gauges[1].chain_id, "zeta");
    }

    #[test]
    fn lag_is_zero_and_within_target_before_any_finalization() {
        let mut reg = LightClientRegistry::new();
        reg.connect(config("eth", 2_000), 0).unwrap();
        let m = reg.chain("eth").unwrap().metrics(5_000);
        assert_eq!(m.finality_lag_ms, 0);
        assert_eq!(m.finalized_height, None);
        assert!(m.within_target);
    }

    #[test]
    fn unknown_chain_operations_report_chain_not_found() {
        let mut reg = LightClientRegistry::new();
        assert_eq!(
            reg.observe_header("ghost", finalizable_header(1, 0, 0)),
            Err(CrossChainError::ChainNotFound)
        );
        assert_eq!(
            reg.try_finalize("ghost", 0),
            Err(CrossChainError::ChainNotFound)
        );
    }

    #[test]
    fn max_finality_lag_and_all_within_target_aggregate_across_chains() {
        let mut reg = LightClientRegistry::new();
        reg.connect(config("eth", 2_000), 0).unwrap();
        reg.connect(config("sol", 15_000), 0).unwrap();
        reg.observe_header("eth", finalizable_header(1, 1_000, 1_800))
            .unwrap();
        reg.observe_header("sol", finalizable_header(1, 1_000, 1_800))
            .unwrap();
        reg.try_finalize("eth", 2_000).unwrap();
        reg.try_finalize("sol", 5_000).unwrap();

        // eth lag @5_000 = 4_000; sol lag @5_000 = 4_000.
        assert_eq!(reg.max_finality_lag_ms(5_000), 4_000);
        assert!(reg.all_within_target(5_000));
        // Far in the future both exceed the 10 s target.
        assert!(!reg.all_within_target(100_000));
    }
}
