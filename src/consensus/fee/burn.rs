//! EIP-1559-style fee burn / tip split for finalized blocks (issue #63).
//!
//! On block finalization, each transaction's `base_fee` is burned and its
//! `tip` is paid to the block proposer. This subsystem is self-contained
//! (see `crate::mempool` module docs) and has no existing account/balance
//! ledger or finalization hook to plug into — none exists anywhere in this
//! repository to reuse, so [`finalize_block_fees`] stops at computing the
//! aggregate totals rather than inventing a settlement path (crediting a
//! balance, decrementing a token supply) that has no real counterpart here.
//! This is called out explicitly in the issue #63 design-assumptions list.

extern crate alloc;

use crate::mempool::{BuiltBlock, FeeAmount, Transaction};

/// Opaque block-proposer / fee-recipient identifier.
///
/// No account or address type exists to reuse: the SoroSusu contract's
/// `soroban_sdk::Address` is tied to a Soroban `Env` and unusable outside
/// contract execution, and the beacon-chain-style consensus modules
/// identify validators by `ValidatorIndex` (`u64`), not by a settlement
/// account. `AccountId` reuses that same `u64` shape as a neutral
/// placeholder — documented as an assumption to be corrected once a real
/// account model exists.
pub type AccountId = u64;

/// The burn/tip split for a single transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeSplit {
    pub burned: FeeAmount,
    pub tipped: FeeAmount,
}

/// Split a transaction's fee: `base_fee` is burned (EIP-1559 semantics),
/// `tip` is paid to the block proposer.
///
/// No division occurs in this split, and so there is no rounding remainder
/// to account for: [`Transaction`] stores `base_fee` and `tip` as
/// already-separated amounts (see `crate::mempool::priority_queue` docs),
/// not a combined total later divided by a burn percentage. `burned +
/// tipped == tx.priority_fee()` holds exactly, by construction, for every
/// transaction.
pub fn split_fee(tx: &Transaction) -> FeeSplit {
    FeeSplit {
        burned: tx.base_fee(),
        tipped: tx.tip(),
    }
}

/// Errors aggregating fees across a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeBurnError {
    /// Summing burned or tipped amounts across the block overflowed [`FeeAmount`].
    TotalOverflow,
}

/// Aggregate burn/tip totals for a finalized block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedBlockFees {
    pub proposer: AccountId,
    pub total_burned: FeeAmount,
    pub total_tipped: FeeAmount,
}

/// Compute the aggregate burn/tip totals for every transaction in `block`.
pub fn finalize_block_fees(
    block: &BuiltBlock,
    proposer: AccountId,
) -> Result<FinalizedBlockFees, FeeBurnError> {
    let mut total_burned: FeeAmount = 0;
    let mut total_tipped: FeeAmount = 0;
    for tx in &block.transactions {
        let split = split_fee(tx);
        total_burned = total_burned
            .checked_add(split.burned)
            .ok_or(FeeBurnError::TotalOverflow)?;
        total_tipped = total_tipped
            .checked_add(split.tipped)
            .ok_or(FeeBurnError::TotalOverflow)?;
    }
    Ok(FinalizedBlockFees {
        proposer,
        total_burned,
        total_tipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::TxHash;

    fn hash(id: u8) -> TxHash {
        let mut h = [0u8; 32];
        h[31] = id;
        h
    }

    fn tx(id: u8, base_fee: u64, tip: u64) -> Transaction {
        Transaction::new(hash(id), base_fee, tip, 1).unwrap()
    }

    #[test]
    fn split_conserves_value_for_simple_values() {
        let t = tx(1, 100, 50);
        let split = split_fee(&t);
        assert_eq!(split.burned, 100);
        assert_eq!(split.tipped, 50);
        assert_eq!(split.burned + split.tipped, t.priority_fee());
    }

    #[test]
    fn split_conserves_value_for_adversarial_values() {
        // fee = 1 (minimum nonzero), odd tip, and near-max values.
        for (base_fee, tip) in [
            (1u64, 0u64),
            (0, 1),
            (1, 1),
            (3, 7),
            (u64::MAX / 2, u64::MAX / 2),
            (u64::MAX - 1, 1),
        ] {
            let t = tx(1, base_fee, tip);
            let split = split_fee(&t);
            assert_eq!(
                split.burned + split.tipped,
                t.priority_fee(),
                "conservation violated for base_fee={base_fee}, tip={tip}"
            );
            assert_eq!(split.burned, base_fee);
            assert_eq!(split.tipped, tip);
        }
    }

    #[test]
    fn finalize_block_fees_sums_and_conserves_across_block() {
        let block = BuiltBlock {
            transactions: alloc::vec![tx(1, 100, 10), tx(2, 200, 20), tx(3, 1, 0)],
            gas_used: 3,
        };
        let fees = finalize_block_fees(&block, 42).unwrap();
        assert_eq!(fees.proposer, 42);
        assert_eq!(fees.total_burned, 301);
        assert_eq!(fees.total_tipped, 30);
        assert_eq!(
            fees.total_burned + fees.total_tipped,
            block
                .transactions
                .iter()
                .map(|t| t.priority_fee())
                .sum::<u64>()
        );
    }

    #[test]
    fn finalize_block_fees_empty_block_is_zero() {
        let block = BuiltBlock {
            transactions: alloc::vec![],
            gas_used: 0,
        };
        let fees = finalize_block_fees(&block, 1).unwrap();
        assert_eq!(fees.total_burned, 0);
        assert_eq!(fees.total_tipped, 0);
    }

    #[test]
    fn finalize_block_fees_detects_total_overflow() {
        let block = BuiltBlock {
            transactions: alloc::vec![tx(1, u64::MAX, 0), tx(2, u64::MAX, 0)],
            gas_used: 2,
        };
        assert_eq!(
            finalize_block_fees(&block, 1),
            Err(FeeBurnError::TotalOverflow)
        );
    }
}
