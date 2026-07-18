//! Priority-fee-ordered transaction queue (issue #63).
//!
//! Transactions are ranked by *effective fee-per-gas*, `priority_fee /
//! gas_limit` descending, where `priority_fee = base_fee + tip`. The ranking
//! must never compare that ratio via integer division: `3/2` and `1/1` both
//! truncate to `1`, which would treat a 3-gas-price transaction as tied with
//! a 1-gas-price one and corrupt the auction. Instead every comparison
//! cross-multiplies in a wider integer type: `a.priority_fee * b.gas_limit`
//! vs `b.priority_fee * a.gas_limit`. `FeeAmount` and `Gas` are both `u64`,
//! so their product fits in `u128` with headroom to spare
//! (`u64::MAX * u64::MAX < u128::MAX`).
//!
//! # Backing structure
//!
//! The issue asks for O(log n) insert / O(1) peek, which a `std::BinaryHeap`
//! gives for a *single* end of the order. This subsystem needs efficient
//! access to **both** ends: [`PriorityMempool::peek_highest`] for block
//! building and lowest-priority eviction (see `super::eviction`) for
//! capacity control. A binary heap has no efficient way to reach its lowest
//! elements short of draining it. `BTreeSet` gives O(log n) insert/remove
//! and O(log n) access to both `first()` (lowest) and `last()` (highest) —
//! at n <= 100_000 that's a tree depth of ~17, effectively O(1) in practice,
//! and it mirrors the `BTreeSet`-backed ordering already used by
//! [`crate::validator::activation_queue::ActivationQueue`] and
//! [`crate::validator::exit_queue::ExitQueue`]. Peek is therefore O(log n),
//! not literally O(1); this is a disclosed, deliberate deviation from the
//! issue's literal wording in favor of a structure that actually supports
//! every required operation.

extern crate alloc;
use alloc::collections::{BTreeMap, BTreeSet};
use core::cmp::Ordering;

use super::eviction::{self, InsertOutcome};

/// Total fee amount, in the smallest unit of the fee-paying asset.
///
/// `u64` is used (rather than `u128`) specifically so that cross-multiplying
/// two fee/gas pairs during ordering comparisons (`fee * gas`) is guaranteed
/// to fit in `u128` without overflow: `u64::MAX * u64::MAX` is just under
/// `2^128`, comfortably inside `u128::MAX`.
pub type FeeAmount = u64;

/// Gas units. `u64` for the same cross-multiplication-safety reason as
/// [`FeeAmount`]; the 30M block gas limit fits with enormous headroom.
pub type Gas = u64;

/// Transaction hash: a 32-byte digest, matching this codebase's other
/// 32-byte hash conventions (see `crate::crypto::sha256`). This subsystem
/// does not depend on `crate::crypto` (self-contained per issue #63 scope)
/// so the alias is defined locally rather than imported.
pub type TxHash = [u8; 32];

/// Errors constructing a [`Transaction`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionError {
    /// `gas_limit` was zero. A zero-gas transaction has an undefined
    /// fee-per-gas ratio and would need division-by-zero handling in every
    /// ordering comparison; rejecting it at construction keeps the ordering
    /// total function total.
    ZeroGasLimit,
    /// `base_fee + tip` overflowed `FeeAmount`. Rejected at construction so
    /// every later read of `priority_fee()` can add the two fields directly
    /// without re-checking.
    FeeOverflow,
}

/// A mempool transaction.
///
/// Fields are private and only reachable through [`Transaction::new`] and
/// its getters: `gas_limit == 0` and `base_fee + tip` overflow are both
/// invariants the priority queue's ordering depends on, so construction is
/// the single choke point that enforces them (no `Transaction` can exist in
/// a state that would make `Ord` panic or misbehave).
///
/// `base_fee` and `tip` are already-separated amounts (not a combined total
/// later split by a division), matching real EIP-1559 semantics where the
/// base fee is burned and the tip is paid to the block proposer. See
/// `crate::consensus::fee::burn` for the burn/tip split, which is exact by
/// construction because of this choice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    tx_hash: TxHash,
    base_fee: FeeAmount,
    tip: FeeAmount,
    gas_limit: Gas,
}

impl Transaction {
    /// Construct a transaction, validating the invariants the priority
    /// queue's ordering relies on.
    pub fn new(
        tx_hash: TxHash,
        base_fee: FeeAmount,
        tip: FeeAmount,
        gas_limit: Gas,
    ) -> Result<Self, TransactionError> {
        if gas_limit == 0 {
            return Err(TransactionError::ZeroGasLimit);
        }
        base_fee
            .checked_add(tip)
            .ok_or(TransactionError::FeeOverflow)?;
        Ok(Self {
            tx_hash,
            base_fee,
            tip,
            gas_limit,
        })
    }

    pub fn tx_hash(&self) -> TxHash {
        self.tx_hash
    }

    pub fn base_fee(&self) -> FeeAmount {
        self.base_fee
    }

    pub fn tip(&self) -> FeeAmount {
        self.tip
    }

    pub fn gas_limit(&self) -> Gas {
        self.gas_limit
    }

    /// `base_fee + tip`. Never overflows: validated in [`Transaction::new`].
    pub fn priority_fee(&self) -> FeeAmount {
        self.base_fee + self.tip
    }
}

/// Errors returned by [`PriorityMempool::insert`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MempoolError {
    /// A transaction with this `tx_hash` is already queued. Rejected rather
    /// than replaced, matching the precedent set by
    /// [`crate::validator::activation_queue::ActivationQueue`] and
    /// [`crate::validator::exit_queue::ExitQueue`], which both reject
    /// duplicate keys instead of silently overwriting.
    DuplicateTransaction,
}

/// Internal heap entry: a transaction plus its insertion-order tiebreaker.
///
/// `arrival_seq` is assigned by [`PriorityMempool`] at insertion time from a
/// monotonically increasing counter — never user-supplied, so a transaction
/// cannot game its own tiebreak position. Because `arrival_seq` is unique
/// per entry, `Ord::cmp` never returns `Equal` for two distinct entries
/// (even before the final `tx_hash` tiebreak is consulted), which keeps
/// `Eq` and `Ord` consistent as `BTreeSet` requires: `Eq` for two entries
/// holds iff they are the exact same transaction (same `tx_hash`), and
/// `Ord` can only agree once `arrival_seq` and `tx_hash` also match, which
/// only happens for the same entry.
#[derive(Clone, Debug)]
struct QueuedTx {
    tx: Transaction,
    arrival_seq: u64,
}

impl PartialEq for QueuedTx {
    fn eq(&self, other: &Self) -> bool {
        self.tx.tx_hash == other.tx.tx_hash
    }
}

impl Eq for QueuedTx {}

impl Ord for QueuedTx {
    fn cmp(&self, other: &Self) -> Ordering {
        // Effective fee-per-gas descending, compared via cross-multiplication
        // to avoid the integer-division trap (e.g. 3/2 truncating to 1 and
        // tying with 1/1). Widen to u128 before multiplying.
        let lhs = self.tx.priority_fee() as u128 * other.tx.gas_limit() as u128;
        let rhs = other.tx.priority_fee() as u128 * self.tx.gas_limit() as u128;
        lhs.cmp(&rhs)
            // Tie: earlier arrival is higher priority. Smaller arrival_seq
            // must sort as Greater (BTreeSet::last() = highest priority),
            // hence the reversed comparison.
            .then_with(|| other.arrival_seq.cmp(&self.arrival_seq))
            // Final deterministic tiebreak (unreachable in practice since
            // arrival_seq is unique, but keeps the order total on paper).
            .then_with(|| self.tx.tx_hash.cmp(&other.tx.tx_hash))
    }
}

impl PartialOrd for QueuedTx {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Snapshot of mempool-observability figures.
///
/// This repo has no metrics crate (no `prometheus`/`metrics` dependency
/// exists anywhere in `Cargo.toml`), and issue #63's constraints direct us
/// not to add one. `MempoolMetrics` is a plain, on-demand snapshot instead
/// of a push-based exporter integration; wiring it to a real metrics
/// backend is out of scope for this subsystem.
///
/// Percentiles use the nearest-rank method over a fresh sort of the current
/// entries' `priority_fee()` values (O(n log n)). This is the "on-demand
/// from a snapshot" strategy rather than a streaming estimator (e.g.
/// t-digest): simpler, exact (not approximate), and cheap enough given the
/// mempool is capacity-bounded at 100_000 entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolMetrics {
    pub depth: usize,
    pub priority_fee_p50: FeeAmount,
    pub priority_fee_p95: FeeAmount,
    pub priority_fee_p99: FeeAmount,
}

/// Nearest-rank percentile index into an ascending-sorted slice of length
/// `n` (n > 0). `p` is a whole-number percentile (e.g. 50, 95, 99).
fn nearest_rank_index(p: u64, n: usize) -> usize {
    // ceil(p/100 * n) - 1, computed in integer arithmetic to avoid float
    // rounding, clamped into [0, n - 1].
    let rank = (p * n as u64).div_ceil(100).max(1);
    (rank as usize - 1).min(n - 1)
}

/// A priority-fee-ordered mempool. See the module docs for the ordering and
/// backing-structure rationale.
///
/// `hashes` maps each queued `tx_hash` to its `arrival_seq` rather than just
/// tracking membership. `BTreeSet<QueuedTx>` is ordered by effective
/// fee-per-gas, not by `tx_hash`, so removing an entry by hash alone would
/// otherwise require an O(n) scan to find it (there's no way to navigate a
/// tree ordered by price using only a hash). Keeping `arrival_seq` alongside
/// each hash lets [`PriorityMempool::remove`] reconstruct the exact sort key
/// (`priority_fee`, `gas_limit`, `arrival_seq`, `tx_hash` — everything
/// `QueuedTx::cmp` reads) from a `&Transaction` the caller already has, and
/// remove it in true O(log n).
#[derive(Clone, Debug, Default)]
pub struct PriorityMempool {
    entries: BTreeSet<QueuedTx>,
    hashes: BTreeMap<TxHash, u64>,
    next_seq: u64,
}

impl PriorityMempool {
    pub fn new() -> Self {
        Self {
            entries: BTreeSet::new(),
            hashes: BTreeMap::new(),
            next_seq: 0,
        }
    }

    /// Number of queued transactions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a transaction with this hash is currently queued.
    pub fn contains(&self, tx_hash: &TxHash) -> bool {
        self.hashes.contains_key(tx_hash)
    }

    /// Insert a transaction. Rejects duplicates (see [`MempoolError`]).
    ///
    /// Eviction trigger point: checked immediately after this insert
    /// succeeds. If the resulting length exceeds the capacity, the lowest
    /// 10% (by this same ordering) is drained — see `super::eviction`. The
    /// just-inserted transaction is not special-cased: if it ranks in the
    /// evicted decile, it is removed again immediately. There is no
    /// "protect the newest arrival" rule; priority alone decides.
    pub fn insert(&mut self, tx: Transaction) -> Result<InsertOutcome, MempoolError> {
        if self.hashes.contains_key(&tx.tx_hash) {
            return Err(MempoolError::DuplicateTransaction);
        }
        let arrival_seq = self.next_seq;
        self.next_seq += 1;
        self.hashes.insert(tx.tx_hash, arrival_seq);
        self.entries.insert(QueuedTx { tx, arrival_seq });

        let evicted = eviction::maybe_evict(self);
        Ok(InsertOutcome { evicted })
    }

    /// Inspect the highest-priority transaction without removing it.
    pub fn peek_highest(&self) -> Option<&Transaction> {
        self.entries.last().map(|q| &q.tx)
    }

    /// Iterate transactions from highest to lowest priority, without
    /// removing them. Used by the block builder's read-only selection pass.
    pub(crate) fn iter_by_priority_desc(&self) -> impl Iterator<Item = &Transaction> {
        self.entries.iter().rev().map(|q| &q.tx)
    }

    /// Remove and return the lowest-priority transaction, if any. Used by
    /// the eviction policy.
    pub(crate) fn pop_lowest(&mut self) -> Option<Transaction> {
        let queued = self.entries.pop_first()?;
        self.hashes.remove(&queued.tx.tx_hash);
        Some(queued.tx)
    }

    /// Remove a specific transaction, if present. Used by the block builder
    /// to remove exactly the selected set after a successful build.
    ///
    /// O(log n): `entries` is ordered by price, not by hash, so removing by
    /// hash alone would require an O(n) scan to locate the node. Instead
    /// this looks up the transaction's `arrival_seq` from `hashes` (O(log
    /// n)) and reconstructs the exact `QueuedTx` sort key from the caller's
    /// `&Transaction` plus that `arrival_seq`, which lets `BTreeSet::remove`
    /// navigate straight to the node (O(log n)) instead of scanning.
    pub(crate) fn remove(&mut self, tx: &Transaction) -> Option<Transaction> {
        let arrival_seq = self.hashes.remove(&tx.tx_hash)?;
        let key = QueuedTx {
            tx: tx.clone(),
            arrival_seq,
        };
        self.entries.remove(&key);
        Some(key.tx)
    }

    /// Snapshot current depth and fee percentiles. See [`MempoolMetrics`]
    /// docs for the computation strategy.
    pub fn metrics_snapshot(&self) -> MempoolMetrics {
        let depth = self.entries.len();
        if depth == 0 {
            return MempoolMetrics {
                depth: 0,
                priority_fee_p50: 0,
                priority_fee_p95: 0,
                priority_fee_p99: 0,
            };
        }
        let mut fees: alloc::vec::Vec<FeeAmount> =
            self.entries.iter().map(|q| q.tx.priority_fee()).collect();
        fees.sort_unstable();

        MempoolMetrics {
            depth,
            priority_fee_p50: fees[nearest_rank_index(50, depth)],
            priority_fee_p95: fees[nearest_rank_index(95, depth)],
            priority_fee_p99: fees[nearest_rank_index(99, depth)],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> TxHash {
        let mut h = [0u8; 32];
        h[31] = byte;
        h
    }

    fn tx(id: u8, base_fee: FeeAmount, tip: FeeAmount, gas_limit: Gas) -> Transaction {
        Transaction::new(hash(id), base_fee, tip, gas_limit).unwrap()
    }

    #[test]
    fn rejects_zero_gas_limit() {
        assert_eq!(
            Transaction::new(hash(1), 1, 0, 0),
            Err(TransactionError::ZeroGasLimit)
        );
    }

    #[test]
    fn rejects_fee_overflow() {
        assert_eq!(
            Transaction::new(hash(1), FeeAmount::MAX, 1, 1),
            Err(TransactionError::FeeOverflow)
        );
    }

    #[test]
    fn integer_division_trap_is_avoided() {
        // fee=3,gas=2 -> effective price 1.5; fee=1,gas=1 -> effective price 1.0.
        // Naive integer division (3/2=1, 1/1=1) would tie these. The
        // cross-multiplication comparison must strictly rank 3/2 above 1/1.
        let mut mempool = PriorityMempool::new();
        mempool.insert(tx(1, 1, 0, 1)).unwrap(); // 1/1
        mempool.insert(tx(2, 3, 0, 2)).unwrap(); // 3/2

        assert_eq!(mempool.peek_highest().unwrap().tx_hash(), hash(2));
    }

    #[test]
    fn strict_descending_order_across_crafted_cases() {
        let mut mempool = PriorityMempool::new();
        // Effective prices: 5, 4, 3, 2, 1 in shuffled insertion order.
        mempool.insert(tx(3, 3, 0, 1)).unwrap();
        mempool.insert(tx(1, 5, 0, 1)).unwrap();
        mempool.insert(tx(5, 1, 0, 1)).unwrap();
        mempool.insert(tx(2, 4, 0, 1)).unwrap();
        mempool.insert(tx(4, 2, 0, 1)).unwrap();

        let order: alloc::vec::Vec<u8> = mempool
            .iter_by_priority_desc()
            .map(|t| t.tx_hash()[31])
            .collect();
        assert_eq!(order, alloc::vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn ties_break_by_earlier_arrival_then_by_hash() {
        let mut mempool = PriorityMempool::new();
        // Identical effective price (2/1), inserted in this order.
        mempool.insert(tx(9, 2, 0, 1)).unwrap();
        mempool.insert(tx(1, 2, 0, 1)).unwrap();

        // Earlier arrival (hash(9), inserted first) must win the tie despite
        // having a numerically larger hash.
        assert_eq!(mempool.peek_highest().unwrap().tx_hash(), hash(9));
    }

    #[test]
    fn duplicate_tx_hash_is_rejected() {
        let mut mempool = PriorityMempool::new();
        mempool.insert(tx(1, 5, 0, 1)).unwrap();
        assert_eq!(
            mempool.insert(tx(1, 100, 0, 1)),
            Err(MempoolError::DuplicateTransaction)
        );
        assert_eq!(mempool.len(), 1);
        // The original entry must be unchanged (rejected, not replaced).
        assert_eq!(mempool.peek_highest().unwrap().base_fee(), 5);
    }

    #[test]
    fn peek_does_not_mutate() {
        let mut mempool = PriorityMempool::new();
        mempool.insert(tx(1, 5, 0, 1)).unwrap();
        mempool.peek_highest();
        mempool.peek_highest();
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn metrics_snapshot_on_empty_mempool() {
        let mempool = PriorityMempool::new();
        let m = mempool.metrics_snapshot();
        assert_eq!(
            m,
            MempoolMetrics {
                depth: 0,
                priority_fee_p50: 0,
                priority_fee_p95: 0,
                priority_fee_p99: 0,
            }
        );
    }

    #[test]
    fn metrics_snapshot_percentiles_nearest_rank() {
        let mut mempool = PriorityMempool::new();
        // priority_fee values 1..=10, distinct gas so ordering is well-defined.
        for i in 1u8..=10 {
            mempool.insert(tx(i, i as FeeAmount, 0, 1)).unwrap();
        }
        let m = mempool.metrics_snapshot();
        assert_eq!(m.depth, 10);
        // Nearest-rank over [1..=10]: p50 -> rank 5 -> value 5.
        assert_eq!(m.priority_fee_p50, 5);
        // p95 -> ceil(0.95*10)=10 -> value 10.
        assert_eq!(m.priority_fee_p95, 10);
        assert_eq!(m.priority_fee_p99, 10);
    }
}
