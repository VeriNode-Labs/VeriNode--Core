//! Property-based ordering invariant tests for the priority mempool (#63).

use proptest::prelude::*;
use sorosusu_contracts::mempool::{PriorityMempool, Transaction, TxHash};

fn hash_of(seed: u32) -> TxHash {
    let mut h = [0u8; 32];
    h[28..32].copy_from_slice(&seed.to_be_bytes());
    h
}

proptest! {
    /// After inserting an arbitrary set of distinct transactions, the
    /// transaction returned by `peek_highest` must have an effective
    /// fee-per-gas at least as large as every other transaction in the
    /// mempool, compared via the same overflow-safe cross-multiplication
    /// the mempool itself uses internally (never integer division).
    #[test]
    fn prop_peek_highest_has_maximal_effective_price(
        fees in prop::collection::vec((1u64..1_000_000, 0u64..1_000_000, 1u64..1_000_000), 1..200)
    ) {
        let mut mempool = PriorityMempool::new();
        let mut txs = Vec::new();
        for (i, (base_fee, tip, gas_limit)) in fees.into_iter().enumerate() {
            let tx = Transaction::new(hash_of(i as u32), base_fee, tip, gas_limit).unwrap();
            txs.push(tx.clone());
            mempool.insert(tx).unwrap();
        }

        let top = mempool.peek_highest().unwrap();
        for tx in &txs {
            let top_price = top.priority_fee() as u128 * tx.gas_limit() as u128;
            let other_price = tx.priority_fee() as u128 * top.gas_limit() as u128;
            prop_assert!(top_price >= other_price);
        }
    }
}
