//! Mempool capacity control (issue #63).
//!
//! Once the mempool holds more than [`MEMPOOL_CAPACITY`] transactions, the
//! lowest-priority [`EVICTION_BATCH_SIZE`] (10% of capacity) are drained.
//!
//! Trigger point: checked immediately after every successful
//! [`crate::mempool::priority_queue::PriorityMempool::insert`], not on a
//! timer or a separate maintenance pass. `EVICTION_BATCH_SIZE` is a fixed
//! count (`MEMPOOL_CAPACITY / 10` = 10_000), not a live 10% of whatever the
//! length happens to be at trigger time — the issue names it as a fixed
//! batch ("10_000 txs").
//!
//! The just-inserted transaction is not protected from its own eviction
//! trigger: eviction runs against the full post-insert ordering, so if the
//! newest arrival ranks in the bottom decile it is drained right back out.
//! There is no separate "grace period" for new arrivals — priority is the
//! only criterion, which keeps the policy simple and unexploitable (a
//! transaction can't buy itself protection just by being new).

extern crate alloc;
use alloc::vec::Vec;

use super::priority_queue::{PriorityMempool, TxHash};

/// Maximum mempool size before eviction is triggered.
pub const MEMPOOL_CAPACITY: usize = 100_000;

/// Number of lowest-priority transactions drained per eviction, fixed at
/// 10% of [`MEMPOOL_CAPACITY`].
pub const EVICTION_BATCH_SIZE: usize = MEMPOOL_CAPACITY / 10;

/// Emitted when eviction runs.
///
/// This repo has no Soroban-event usage (`env.events().publish` appears
/// nowhere in the codebase) and no event-bus abstraction to hook into, so
/// this is a plain returned value rather than a published event — the
/// caller (e.g. a node's own event/metrics forwarding) decides what to do
/// with it. See [`InsertOutcome`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolEvicted {
    /// Hashes of the evicted transactions, in eviction order (lowest
    /// priority first).
    pub evicted: Vec<TxHash>,
    /// Mempool length that triggered this eviction (i.e. `MEMPOOL_CAPACITY + 1`,
    /// the length immediately after the insert that crossed the threshold).
    pub trigger_len: usize,
}

/// Result of [`PriorityMempool::insert`]: whether that insert triggered an
/// eviction.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct InsertOutcome {
    pub evicted: Option<MempoolEvicted>,
}

/// Evict the lowest-priority batch if `mempool` is over capacity. Called
/// from inside `PriorityMempool::insert` after every successful insert.
pub(crate) fn maybe_evict(mempool: &mut PriorityMempool) -> Option<MempoolEvicted> {
    if mempool.len() <= MEMPOOL_CAPACITY {
        return None;
    }
    let trigger_len = mempool.len();
    let mut evicted = Vec::with_capacity(EVICTION_BATCH_SIZE);
    for _ in 0..EVICTION_BATCH_SIZE {
        match mempool.pop_lowest() {
            Some(tx) => evicted.push(tx.tx_hash()),
            None => break,
        }
    }
    Some(MempoolEvicted {
        evicted,
        trigger_len,
    })
}

#[cfg(test)]
mod tests {
    use super::super::priority_queue::Transaction;
    use super::*;

    fn hash(id: u32) -> TxHash {
        let mut h = [0u8; 32];
        h[28..32].copy_from_slice(&id.to_be_bytes());
        h
    }

    /// Insert `n` transactions with strictly increasing priority
    /// (priority_fee == id, gas_limit == 1), so insertion order and
    /// priority order coincide: id 0 is always lowest priority.
    fn fill(mempool: &mut PriorityMempool, n: u32) {
        for id in 0..n {
            let tx = Transaction::new(hash(id), id as u64, 0, 1).unwrap();
            mempool.insert(tx).unwrap();
        }
    }

    #[test]
    fn no_eviction_below_capacity() {
        let mut mempool = PriorityMempool::new();
        fill(&mut mempool, MEMPOOL_CAPACITY as u32);
        assert_eq!(mempool.len(), MEMPOOL_CAPACITY);
    }

    #[test]
    fn eviction_at_exactly_capacity_plus_one() {
        let mut mempool = PriorityMempool::new();
        fill(&mut mempool, MEMPOOL_CAPACITY as u32);
        assert_eq!(mempool.len(), MEMPOOL_CAPACITY);

        // The capacity+1-th insert must trigger eviction.
        let last_tx =
            Transaction::new(hash(MEMPOOL_CAPACITY as u32), MEMPOOL_CAPACITY as u64, 0, 1).unwrap();
        let outcome = mempool.insert(last_tx).unwrap();

        let evicted = outcome
            .evicted
            .expect("eviction must trigger at capacity+1");
        assert_eq!(evicted.evicted.len(), EVICTION_BATCH_SIZE);
        assert_eq!(evicted.trigger_len, MEMPOOL_CAPACITY + 1);
        assert_eq!(mempool.len(), MEMPOOL_CAPACITY + 1 - EVICTION_BATCH_SIZE);
    }

    #[test]
    fn evicts_exactly_the_lowest_priority_decile() {
        let mut mempool = PriorityMempool::new();
        // ids 0..=100_000 -> id 0 is lowest priority (priority_fee=0),
        // id 100_000 is highest.
        fill(&mut mempool, MEMPOOL_CAPACITY as u32 + 1);

        // The lowest EVICTION_BATCH_SIZE ids (0..EVICTION_BATCH_SIZE) must
        // all be gone; everything else must remain.
        for id in 0..EVICTION_BATCH_SIZE as u32 {
            assert!(
                !mempool.contains(&hash(id)),
                "id {id} should have been evicted"
            );
        }
        for id in EVICTION_BATCH_SIZE as u32..(MEMPOOL_CAPACITY as u32 + 1) {
            assert!(mempool.contains(&hash(id)), "id {id} should remain");
        }
    }

    #[test]
    fn newly_inserted_lowest_priority_tx_is_evicted_immediately() {
        let mut mempool = PriorityMempool::new();
        // Fill to exactly capacity with high priorities (ids offset so all
        // outrank the incoming low-priority transaction).
        for id in 0..MEMPOOL_CAPACITY as u32 {
            let tx = Transaction::new(hash(id + 1000), (id + 1000) as u64, 0, 1).unwrap();
            mempool.insert(tx).unwrap();
        }

        // Insert a transaction with the lowest possible priority (fee 0).
        let low_priority_hash = hash(0);
        let tx = Transaction::new(low_priority_hash, 0, 0, 1).unwrap();
        let outcome = mempool.insert(tx).unwrap();

        let evicted = outcome.evicted.expect("must trigger eviction");
        assert!(evicted.evicted.contains(&low_priority_hash));
        assert!(!mempool.contains(&low_priority_hash));
    }
}
