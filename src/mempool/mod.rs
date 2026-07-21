//! Mempool transaction ordering with priority-fee auction (issue #63).
//!
//! Self-contained subsystem: it does not depend on, and is not depended on
//! by, the SoroSusu contract (`crate` root) or the beacon-chain-style
//! consensus modules (`crate::attestation`, `crate::validator`,
//! `crate::state`, `crate::slashing`, `crate::crypto`). Those modules model
//! a different domain (a Soroban ROSCA contract and a PoS attestation
//! layer, respectively) with no transaction/gas/fee-market concept to
//! extend; this subsystem defines its own minimal `Transaction` and fee
//! model instead of retrofitting one of theirs. See
//! `crate::consensus::fee::burn` for the paired fee-burn module.

pub mod block_builder;
pub mod eviction;
pub mod priority_queue;
pub mod reorg_handler;

pub use block_builder::{BlockBuilder, BuiltBlock, BLOCK_GAS_LIMIT};
pub use eviction::{InsertOutcome, MempoolEvicted, EVICTION_BATCH_SIZE, MEMPOOL_CAPACITY};
pub use priority_queue::{
    FeeAmount, Gas, MempoolError, MempoolMetrics, PriorityMempool, Transaction, TransactionError,
    TxHash,
};
pub use reorg_handler::{ReorgHandler, ReorgOutcome};
