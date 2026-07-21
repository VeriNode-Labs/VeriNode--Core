//! Chaos test for issue #63: submit 50_000 transactions with varying fees
//! (deterministic seeded generation), build the next block, and verify the
//! included set is exactly the top transactions by fee-per-gas that fit in
//! the 30M gas limit.
//!
//! Uses a minimal inline splitmix64 PRNG instead of adding a `rand`
//! dependency: this repo has no `rand` crate anywhere in `Cargo.toml`, and
//! issue #63 is scoped to stay self-contained. splitmix64 is a well-known,
//! trivially deterministic generator (same seed -> same sequence on every
//! run and every machine), which is all this test needs.

use sorosusu_contracts::mempool::{
    BlockBuilder, PriorityMempool, Transaction, TxHash, BLOCK_GAS_LIMIT,
};

struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[lo, hi)`.
    fn next_range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next_u64() % (hi - lo)
    }
}

fn hash_for(id: u32) -> TxHash {
    let mut h = [0u8; 32];
    h[28..32].copy_from_slice(&id.to_be_bytes());
    h
}

const CHAOS_TX_COUNT: u32 = 50_000;
// Fixed seed referencing the issue number, chosen once and never varied, so
// the test is exactly reproducible across every run and every machine.
const CHAOS_SEED: u64 = 0x0000_0000_0000_0063;

#[test]
fn chaos_50k_transactions_block_matches_top_fee_per_gas_subject_to_gas_limit() {
    let start = std::time::Instant::now();

    let mut rng = SplitMix64::new(CHAOS_SEED);
    let mut mempool = PriorityMempool::new();
    // (arrival index, transaction) — arrival index mirrors the mempool's
    // own arrival_seq tiebreak, since transactions are inserted in this
    // same order below.
    let mut all_txs: Vec<(u32, Transaction)> = Vec::with_capacity(CHAOS_TX_COUNT as usize);

    for id in 0..CHAOS_TX_COUNT {
        let base_fee = rng.next_range(1, 1_000_000);
        let tip = rng.next_range(0, 500_000);
        let gas_limit = rng.next_range(21_000, 2_000_000);
        let tx = Transaction::new(hash_for(id), base_fee, tip, gas_limit).unwrap();
        all_txs.push((id, tx.clone()));
        mempool.insert(tx).unwrap();
    }
    assert_eq!(mempool.len(), CHAOS_TX_COUNT as usize);

    let block = BlockBuilder::build_block(&mut mempool);

    // Independent cross-check: sort every submitted transaction by the same
    // rule the mempool's `Ord` uses (effective fee-per-gas descending via
    // cross-multiplication, tie-break by earlier arrival then by tx_hash),
    // then greedily pack by gas limit with skip-and-continue on misfit. This
    // recomputes the expected selection via a completely separate code path
    // (sort + linear scan, not the BTreeSet) as a cross-check on the
    // mempool's actual algorithm.
    let mut by_priority = all_txs.clone();
    by_priority.sort_by(|(a_seq, a), (b_seq, b)| {
        let lhs = a.priority_fee() as u128 * b.gas_limit() as u128;
        let rhs = b.priority_fee() as u128 * a.gas_limit() as u128;
        rhs.cmp(&lhs) // descending effective price
            .then_with(|| a_seq.cmp(b_seq)) // earlier arrival first on tie
            .then_with(|| a.tx_hash().cmp(&b.tx_hash()))
    });

    let mut expected_gas: u64 = 0;
    let mut expected_included: Vec<TxHash> = Vec::new();
    for (_, tx) in &by_priority {
        if let Some(candidate) = expected_gas.checked_add(tx.gas_limit()) {
            if candidate <= BLOCK_GAS_LIMIT {
                expected_gas = candidate;
                expected_included.push(tx.tx_hash());
            }
        }
    }

    let actual_included: Vec<TxHash> = block.transactions.iter().map(|t| t.tx_hash()).collect();

    assert_eq!(block.gas_used, expected_gas);
    assert!(block.gas_used <= BLOCK_GAS_LIMIT);
    assert_eq!(actual_included.len(), expected_included.len());
    assert_eq!(
        actual_included, expected_included,
        "block builder's selection must exactly match the independently \
         computed top-by-fee-per-gas-subject-to-gas-limit set"
    );

    // Relationship to the issue's informal "top 10% by fee are included"
    // framing: with varying gas sizes, "top 10% by count" and "top by
    // fee-per-gas subject to the 30M gas limit" are not the same set
    // whenever gas-limit packing causes a high-fee transaction to be
    // skipped so several lower-fee transactions can fill the remaining
    // budget instead (see `BlockBuilder::build_block` docs for the
    // skip-and-continue policy this depends on). The gas-limit-constrained
    // version implemented here is the correct reading: it is the only one
    // that can never violate the hard 30M gas invariant. A literal "top 10%
    // by count" selection has no such guarantee — it could exceed the gas
    // limit (if those transactions are large) or leave gas unused (if they
    // are small), neither of which is an acceptable block-building policy.
    let naive_top_10_pct_by_count = (CHAOS_TX_COUNT as usize) / 10;
    println!(
        "chaos: gas-limit-constrained selection included {} txs (gas_used={}/{} = {:.4} utilization); \
         naive top-10%-by-count would have selected {} txs without regard to the gas limit",
        block.transactions.len(),
        block.gas_used,
        BLOCK_GAS_LIMIT,
        block.gas_utilization(),
        naive_top_10_pct_by_count,
    );

    let elapsed = start.elapsed();
    println!("chaos_50k_transactions test duration: {elapsed:?}");
}
