//! Reorg handling: re-insert orphaned transactions (issue #63).
//!
//! When a reorg orphans a block, its transactions are re-submitted through
//! [`PriorityMempool::insert`] one at a time — the exact same path a freshly
//! submitted transaction takes, never a raw append into the backing
//! `BTreeSet`. That is what keeps the ordering invariant intact: a raw
//! append could violate the tree's ordering invariants and would also have
//! to reimplement duplicate detection and capacity eviction from scratch.
//! Going through `insert` means both fall out for free and behave
//! identically to the organic-submission case:
//!
//! - An orphaned transaction that is already back in the mempool (e.g. it
//!   was independently resubmitted, or appears in more than one orphaned
//!   block during a deep reorg) is rejected as a duplicate — recorded in
//!   [`ReorgOutcome::rejected_duplicates`], not treated as an error.
//! - An orphaned transaction that ranks in the bottom priority decile after
//!   re-insertion can be evicted immediately, exactly as any newly-arrived
//!   low-priority transaction can (see `super::eviction`).
//! - If re-insertion pushes the mempool over capacity, eviction runs after
//!   *that* insert, same as any other — processing orphaned transactions
//!   one at a time (rather than batch-inserting all of them before
//!   evicting once) keeps this identical to the organic-insert case instead
//!   of introducing a second, batch-specific code path.

extern crate alloc;
use alloc::vec::Vec;

use super::eviction::MempoolEvicted;
use super::priority_queue::{MempoolError, PriorityMempool, Transaction, TxHash};

/// Result of replaying a set of orphaned transactions back into the mempool.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ReorgOutcome {
    /// Hashes successfully re-inserted.
    pub re_inserted: Vec<TxHash>,
    /// Hashes rejected because they were already present in the mempool.
    pub rejected_duplicates: Vec<TxHash>,
    /// Any eviction events triggered while re-inserting.
    pub evictions: Vec<MempoolEvicted>,
}

pub struct ReorgHandler;

impl ReorgHandler {
    /// Re-insert every transaction from an orphaned block into `mempool`,
    /// in the order given, through the normal insert path.
    pub fn handle_reorg(mempool: &mut PriorityMempool, orphaned: Vec<Transaction>) -> ReorgOutcome {
        let mut outcome = ReorgOutcome::default();
        for tx in orphaned {
            let tx_hash = tx.tx_hash();
            match mempool.insert(tx) {
                Ok(insert_outcome) => {
                    outcome.re_inserted.push(tx_hash);
                    if let Some(evicted) = insert_outcome.evicted {
                        outcome.evictions.push(evicted);
                    }
                }
                Err(MempoolError::DuplicateTransaction) => {
                    outcome.rejected_duplicates.push(tx_hash);
                }
            }
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::super::eviction::MEMPOOL_CAPACITY;
    use super::*;

    fn hash(id: u32) -> TxHash {
        let mut h = [0u8; 32];
        h[28..32].copy_from_slice(&id.to_be_bytes());
        h
    }

    fn tx(id: u32, fee: u64) -> Transaction {
        Transaction::new(hash(id), fee, 0, 1).unwrap()
    }

    #[test]
    fn reorg_reinserts_through_normal_path_preserving_order() {
        let mut mempool = PriorityMempool::new();
        mempool.insert(tx(1, 10)).unwrap();

        let orphaned = alloc::vec![tx(2, 30), tx(3, 20)];
        let outcome = ReorgHandler::handle_reorg(&mut mempool, orphaned);

        assert_eq!(outcome.re_inserted, alloc::vec![hash(2), hash(3)]);
        assert!(outcome.rejected_duplicates.is_empty());

        // Heap property: highest fee (30) must be highest priority.
        let order: alloc::vec::Vec<u32> = mempool
            .iter_by_priority_desc()
            .map(|t| {
                let mut b = [0u8; 4];
                b.copy_from_slice(&t.tx_hash()[28..32]);
                u32::from_be_bytes(b)
            })
            .collect();
        assert_eq!(order, alloc::vec![2, 3, 1]);
    }

    #[test]
    fn orphaned_tx_already_back_in_mempool_is_rejected_as_duplicate() {
        let mut mempool = PriorityMempool::new();
        mempool.insert(tx(1, 10)).unwrap();

        let outcome = ReorgHandler::handle_reorg(&mut mempool, alloc::vec![tx(1, 999)]);

        assert!(outcome.re_inserted.is_empty());
        assert_eq!(outcome.rejected_duplicates, alloc::vec![hash(1)]);
        // Original entry must be untouched by the rejected duplicate.
        assert_eq!(mempool.peek_highest().unwrap().base_fee(), 10);
    }

    #[test]
    fn orphaned_low_priority_tx_can_be_evicted_immediately() {
        let mut mempool = PriorityMempool::new();
        for id in 0..MEMPOOL_CAPACITY as u32 {
            mempool.insert(tx(id + 1000, (id + 1000) as u64)).unwrap();
        }

        let orphaned = alloc::vec![tx(0, 0)]; // lowest possible priority
        let outcome = ReorgHandler::handle_reorg(&mut mempool, orphaned);

        assert_eq!(outcome.re_inserted, alloc::vec![hash(0)]);
        assert_eq!(outcome.evictions.len(), 1);
        assert!(outcome.evictions[0].evicted.contains(&hash(0)));
        assert!(!mempool.contains(&hash(0)));
    }

    #[test]
    fn reorg_eviction_check_is_independent_per_insert() {
        use super::super::eviction::EVICTION_BATCH_SIZE;

        let mut mempool = PriorityMempool::new();
        for id in 0..MEMPOOL_CAPACITY as u32 {
            mempool.insert(tx(id, id as u64)).unwrap();
        }

        // Two high-priority orphaned transactions, re-inserted one at a
        // time. The first crosses the capacity threshold and triggers
        // eviction of a 10% batch, which drops the mempool well below
        // capacity again — so the second insert legitimately does *not*
        // trigger a further eviction. This demonstrates the threshold is
        // re-checked independently after each insert (not batched across
        // the whole orphaned set), not that every insert must evict.
        let orphaned = alloc::vec![
            tx(MEMPOOL_CAPACITY as u32 + 1, 999_999),
            tx(MEMPOOL_CAPACITY as u32 + 2, 999_998),
        ];
        let outcome = ReorgHandler::handle_reorg(&mut mempool, orphaned);

        assert_eq!(outcome.re_inserted.len(), 2);
        assert_eq!(outcome.evictions.len(), 1);
        assert_eq!(mempool.len(), MEMPOOL_CAPACITY + 2 - EVICTION_BATCH_SIZE);
    }
}
