//! Property-based conservation tests for the fee burn/tip split (#63).

use proptest::prelude::*;
use sorosusu_contracts::consensus::fee::split_fee;
use sorosusu_contracts::mempool::{Transaction, TxHash};

fn hash_of(seed: u8) -> TxHash {
    let mut h = [0u8; 32];
    h[31] = seed;
    h
}

proptest! {
    /// For any valid transaction, `burned + tipped == priority_fee` exactly:
    /// no value is created or destroyed by the split, and there is no
    /// rounding remainder because `base_fee`/`tip` are stored pre-split
    /// (see `crate::consensus::fee::burn` docs).
    #[test]
    fn prop_fee_split_conserves_value(base_fee in 0u64..u64::MAX / 2, tip in 0u64..u64::MAX / 2) {
        let tx = Transaction::new(hash_of(1), base_fee, tip, 1).unwrap();
        let split = split_fee(&tx);
        prop_assert_eq!(split.burned + split.tipped, tx.priority_fee());
        prop_assert_eq!(split.burned, base_fee);
        prop_assert_eq!(split.tipped, tip);
    }
}
