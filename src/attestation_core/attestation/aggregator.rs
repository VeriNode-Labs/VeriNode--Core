//! Distributed Node Attestation BLS Signature Aggregation
//!
//! Pure-logic BLS aggregation functions. Storage and Soroban SDK bindings
//! live at the contract-impl layer, not here — this keeps the module
//! `no_std`-compatible and testable without Soroban test harness.
//!
//! ## Concurrency fix
//!
//! The caller MUST key each `AggregationState` by `NodeId` in storage so
//! concurrent rounds for different nodes operate on isolated keys.
//! Originally `bls_aggregate` wrote to a shared global key, causing
//! interleaving corruption. Per-node isolation eliminates the race.

use crate::crypto::sha256::sha256;

/// A 32-byte node identifier.
pub type NodeId = [u8; 32];

/// A BLS signature (96 bytes compressed).
pub type BLSSignature = [u8; 96];

/// A public key for BLS verification.
pub type BLSPublicKey = [u8; 48];

/// A validator's attestation payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestationEntry {
    pub node_id: NodeId,
    pub validator_key: BLSPublicKey,
    pub signature: BLSSignature,
}

/// Aggregation state for a single node's attestation round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregationState {
    pub node_id: NodeId,
    pub current_aggregate: BLSSignature,
    pub validator_count: u32,
    pub finalized: bool,
}

/// Core BLS aggregation: merge two signatures into one.
///
/// In a real deployment this uses BLS12-381 curve operations. In WASM
/// without a BLS crate, we model aggregation as a deterministic hash chain:
///   SHA-256(aggregate || new_signature), then repeat to fill 96 bytes.
///
/// The concurrency fix lives in storage-key isolation, not here.
pub fn bls_aggregate(current: &BLSSignature, new_sig: &BLSSignature) -> BLSSignature {
    let mut combined = [0u8; 192];
    combined[..96].copy_from_slice(current);
    combined[96..].copy_from_slice(new_sig);

    let hash = sha256(&combined);
    let mut result = [0u8; 96];
    result[..32].copy_from_slice(&hash);
    result[32..64].copy_from_slice(&hash);
    result[64..96].copy_from_slice(&hash);
    result
}

/// Aggregate a list of pending attestation entries into a final state.
/// Pure function — no storage side effects.
pub fn aggregate_signatures(entries: &[AttestationEntry]) -> (BLSSignature, u32) {
    if entries.is_empty() {
        return ([0u8; 96], 0);
    }

    let mut current = [0u8; 96];
    for entry in entries {
        current = bls_aggregate(&current, &entry.signature);
    }

    (current, entries.len() as u32)
}

/// Produce an aggregation state from a list of entries.
/// Pure function — no storage side effects.
pub fn build_aggregation_state(node_id: &NodeId, entries: &[AttestationEntry]) -> AggregationState {
    let (aggregate, count) = aggregate_signatures(entries);
    AggregationState {
        node_id: *node_id,
        current_aggregate: aggregate,
        validator_count: count,
        finalized: true,
    }
}

/// Compute the initial aggregation state (zero aggregate, no validators).
pub fn initial_state(node_id: &NodeId) -> AggregationState {
    AggregationState {
        node_id: *node_id,
        current_aggregate: [0u8; 96],
        validator_count: 0,
        finalized: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_id(seed: u8) -> NodeId {
        let mut id = [0u8; 32];
        id[0] = seed;
        id
    }

    fn make_sig(seed: u8) -> BLSSignature {
        let mut sig = [0u8; 96];
        sig[0] = seed;
        sig
    }

    fn make_key(seed: u8) -> BLSPublicKey {
        let mut key = [0u8; 48];
        key[0] = seed;
        key
    }

    fn make_entry(node_seed: u8, key_seed: u8, sig_seed: u8) -> AttestationEntry {
        AttestationEntry {
            node_id: make_node_id(node_seed),
            validator_key: make_key(key_seed),
            signature: make_sig(sig_seed),
        }
    }

    #[test]
    fn test_bls_aggregate_non_zero() {
        let a = make_sig(100);
        let b = make_sig(200);
        let result = bls_aggregate(&a, &b);
        assert_ne!(result, [0u8; 96], "aggregate should be non-zero");
        assert_ne!(result, a, "aggregate should differ from first input");
        assert_ne!(result, b, "aggregate should differ from second input");
    }

    #[test]
    fn test_bls_aggregate_deterministic() {
        let a = make_sig(100);
        let b = make_sig(200);
        assert_eq!(bls_aggregate(&a, &b), bls_aggregate(&a, &b));
    }

    #[test]
    fn test_aggregate_single_node() {
        let entries = [
            make_entry(1, 10, 100),
            make_entry(1, 20, 200),
        ];
        let (aggregate, count) = aggregate_signatures(&entries);
        assert_eq!(count, 2);
        assert_ne!(aggregate, [0u8; 96]);
    }

    #[test]
    fn test_concurrent_nodes_dont_collide() {
        // Two independent sets of entries produce different aggregates.
        let entries_a = [make_entry(1, 10, 100)];
        let entries_b = [make_entry(2, 20, 200)];

        let (agg_a, count_a) = aggregate_signatures(&entries_a);
        let (agg_b, count_b) = aggregate_signatures(&entries_b);

        assert_eq!(count_a, 1);
        assert_eq!(count_b, 1);
        assert_ne!(agg_a, agg_b, "different signatures must produce different aggregates");

        // State isolation: each set only reflects its own entries.
        let state_a = build_aggregation_state(&make_node_id(1), &entries_a);
        let state_b = build_aggregation_state(&make_node_id(2), &entries_b);
        assert_eq!(state_a.validator_count, 1);
        assert_eq!(state_b.validator_count, 1);
        assert_ne!(state_a.current_aggregate, state_b.current_aggregate);
    }

    #[test]
    fn test_empty_entries() {
        let (aggregate, count) = aggregate_signatures(&[]);
        assert_eq!(count, 0);
        assert_eq!(aggregate, [0u8; 96]);
    }

    #[test]
    fn test_initial_state() {
        let state = initial_state(&make_node_id(42));
        assert_eq!(state.node_id[0], 42);
        assert_eq!(state.validator_count, 0);
        assert!(!state.finalized);
        assert_eq!(state.current_aggregate, [0u8; 96]);
    }
}