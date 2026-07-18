//! Greedy priority-fee block builder (issue #63).

extern crate alloc;
use alloc::vec::Vec;

use super::priority_queue::{Gas, PriorityMempool, Transaction};

/// Maximum total gas a built block may consume. Chosen to match the
/// issue's stated bound; a hard invariant, never exceeded.
pub const BLOCK_GAS_LIMIT: Gas = 30_000_000;

/// A block assembled from the mempool.
#[derive(Clone, Debug, PartialEq)]
pub struct BuiltBlock {
    pub transactions: Vec<Transaction>,
    pub gas_used: Gas,
}

impl BuiltBlock {
    /// Fraction of [`BLOCK_GAS_LIMIT`] consumed by this block, in `[0.0, 1.0]`.
    pub fn gas_utilization(&self) -> f64 {
        self.gas_used as f64 / BLOCK_GAS_LIMIT as f64
    }
}

pub struct BlockBuilder;

impl BlockBuilder {
    /// Greedily select transactions from `mempool` by descending priority
    /// (highest effective fee-per-gas first), packing as many as fit under
    /// [`BLOCK_GAS_LIMIT`].
    ///
    /// # Misfit policy: skip-and-continue
    ///
    /// A transaction whose `gas_limit` does not fit in the remaining budget
    /// is *skipped*, not discarded and not treated as a stopping point — it
    /// stays in the mempool untouched, and the builder keeps walking to the
    /// next (lower-priority) transaction to see if it fits the remaining
    /// gas. This maximizes gas utilization: a single large, high-priority
    /// transaction that doesn't fit should not prevent smaller,
    /// lower-priority ones from filling the rest of the block.
    ///
    /// This is also the correct reading of the issue's "top transactions by
    /// fee-per-gas that fit in 30M gas" requirement: once transactions have
    /// varying gas sizes, "the top N by fee" and "the set that fits and
    /// maximizes included priority" are not the same set whenever the
    /// highest-fee transaction is also oversized relative to the remaining
    /// budget. A naive "top 10% by count" selection (the issue's informal
    /// framing) would not respect the gas limit at all; this implementation
    /// takes the gas-limit-constrained reading as authoritative.
    ///
    /// # Removal timing
    ///
    /// Selection is computed read-only in a first pass over
    /// [`PriorityMempool::iter_by_priority_desc`]; transactions are removed
    /// from the mempool only after the final included set is decided, so a
    /// transaction that doesn't fit is never touched, and a partially-built
    /// selection can never leave the mempool in an inconsistent state.
    pub fn build_block(mempool: &mut PriorityMempool) -> BuiltBlock {
        let mut gas_used: Gas = 0;
        let mut selected: Vec<Transaction> = Vec::new();

        for tx in mempool.iter_by_priority_desc() {
            let fits = match gas_used.checked_add(tx.gas_limit()) {
                Some(candidate) if candidate <= BLOCK_GAS_LIMIT => Some(candidate),
                _ => None,
            };
            let Some(candidate_gas) = fits else {
                continue;
            };
            gas_used = candidate_gas;
            selected.push(tx.clone());
        }

        let transactions = selected
            .iter()
            .map(|tx| {
                mempool
                    .remove(tx)
                    .expect("selected transaction must still be present")
            })
            .collect();

        BuiltBlock {
            transactions,
            gas_used,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::priority_queue::TxHash;
    use super::*;

    fn hash(id: u32) -> TxHash {
        let mut h = [0u8; 32];
        h[28..32].copy_from_slice(&id.to_be_bytes());
        h
    }

    fn tx(id: u32, fee: u64, gas_limit: Gas) -> Transaction {
        Transaction::new(hash(id), fee, 0, gas_limit).unwrap()
    }

    #[test]
    fn empty_mempool_builds_empty_block() {
        let mut mempool = PriorityMempool::new();
        let block = BlockBuilder::build_block(&mut mempool);
        assert!(block.transactions.is_empty());
        assert_eq!(block.gas_used, 0);
    }

    #[test]
    fn top_fee_transactions_are_selected_first() {
        let mut mempool = PriorityMempool::new();
        mempool.insert(tx(1, 10, 1)).unwrap();
        mempool.insert(tx(2, 30, 1)).unwrap();
        mempool.insert(tx(3, 20, 1)).unwrap();

        let block = BlockBuilder::build_block(&mut mempool);
        let order: Vec<u32> = block
            .transactions
            .iter()
            .map(|t| u32::from_be_bytes(t.tx_hash()[28..32].try_into().unwrap()))
            .collect();
        assert_eq!(order, alloc::vec![2, 3, 1]);
        assert!(mempool.is_empty());
    }

    #[test]
    fn exact_gas_boundary_is_accepted() {
        let mut mempool = PriorityMempool::new();
        mempool.insert(tx(1, 10, BLOCK_GAS_LIMIT)).unwrap();

        let block = BlockBuilder::build_block(&mut mempool);
        assert_eq!(block.gas_used, BLOCK_GAS_LIMIT);
        assert_eq!(block.transactions.len(), 1);
    }

    #[test]
    fn one_gas_over_boundary_is_rejected() {
        let mut mempool = PriorityMempool::new();
        mempool.insert(tx(1, 10, BLOCK_GAS_LIMIT + 1)).unwrap();

        let block = BlockBuilder::build_block(&mut mempool);
        assert!(block.transactions.is_empty());
        assert_eq!(block.gas_used, 0);
        // Never discarded: it remains in the mempool.
        assert!(mempool.contains(&hash(1)));
    }

    #[test]
    fn never_exceeds_gas_limit_with_mixed_sizes() {
        let mut mempool = PriorityMempool::new();
        // tx 1: effective price 200_000_000 / 29_999_990 ~= 6.67/gas, higher
        // priority than tx 2's 90/20 = 4.5/gas, and consumes nearly the
        // whole block, leaving only 10 gas of headroom.
        mempool
            .insert(tx(1, 200_000_000, BLOCK_GAS_LIMIT - 10))
            .unwrap();
        mempool.insert(tx(2, 90, 20)).unwrap();

        let block = BlockBuilder::build_block(&mut mempool);
        assert!(block.gas_used <= BLOCK_GAS_LIMIT);
        // Only tx 1 fits; tx 2 (20 gas) cannot fit in the remaining 10.
        assert_eq!(block.transactions.len(), 1);
        assert!(mempool.contains(&hash(2)));
    }

    #[test]
    fn skip_and_continue_lets_smaller_lower_priority_tx_fill_remaining_gas() {
        let mut mempool = PriorityMempool::new();
        // tx 1: highest priority, but too big to fit at all.
        mempool.insert(tx(1, 1000, BLOCK_GAS_LIMIT + 1)).unwrap();
        // tx 2: lower priority, but fits exactly.
        mempool.insert(tx(2, 10, BLOCK_GAS_LIMIT)).unwrap();

        let block = BlockBuilder::build_block(&mut mempool);
        assert_eq!(block.gas_used, BLOCK_GAS_LIMIT);
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.transactions[0].tx_hash(), hash(2));
        // The oversized, higher-priority tx is skipped, not discarded.
        assert!(mempool.contains(&hash(1)));
    }

    #[test]
    fn single_oversized_tx_in_otherwise_empty_mempool_is_skipped_not_discarded() {
        let mut mempool = PriorityMempool::new();
        mempool.insert(tx(1, 5, BLOCK_GAS_LIMIT + 1)).unwrap();

        let block = BlockBuilder::build_block(&mut mempool);
        assert!(block.transactions.is_empty());
        assert_eq!(mempool.len(), 1);
        assert!(mempool.contains(&hash(1)));
    }

    #[test]
    fn selected_txs_removed_only_on_successful_build_skipped_txs_retained() {
        let mut mempool = PriorityMempool::new();
        mempool.insert(tx(1, 50, 10)).unwrap();
        mempool.insert(tx(2, 40, BLOCK_GAS_LIMIT)).unwrap(); // will be skipped

        let block = BlockBuilder::build_block(&mut mempool);
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.transactions[0].tx_hash(), hash(1));
        assert!(!mempool.contains(&hash(1)));
        assert!(mempool.contains(&hash(2)));
    }
}
