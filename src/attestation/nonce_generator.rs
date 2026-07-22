//! Epoch-scoped nonce generation for the proof-of-connectivity protocol.
//!
//! ## Security property (issue #54)
//!
//! Each nonce is derived as:
//!
//! ```text
//! nonce = BLAKE2b-256(epoch_id_le || random_seed || node_id)
//! ```
//!
//! Binding the epoch identifier into the hash input ensures that two
//! challenges in different epochs — even if they share the same random seed
//! and node id — produce distinct 256-bit nonces.  A replayed nonce from
//! epoch `e` is therefore invalid in epoch `e+1` regardless of the nonce
//! cache state, because the derived value differs.
//!
//! Nonce length: 256 bits (BLAKE2b-256 output).

use crate::attestation::types::{EpochId, NodeId, Nonce, RandomSeed};
use crate::crypto::blake2b::blake2b_256;

/// Derive a 256-bit, epoch-scoped nonce.
///
/// The preimage is the concatenation (total 68 bytes):
///
/// | Field       | Bytes | Encoding         |
/// |-------------|-------|------------------|
/// | `epoch_id`  | 4     | little-endian u32 |
/// | `seed`      | 32    | raw bytes        |
/// | `node_id`   | 32    | raw bytes        |
///
/// # Arguments
///
/// * `epoch_id` – current epoch counter.
/// * `seed`     – 32-byte random seed (sourced from CSPRNG in production).
/// * `node_id`  – 32-byte identifier of the challenged node.
pub fn derive_nonce(epoch_id: EpochId, seed: &RandomSeed, node_id: &NodeId) -> Nonce {
    // Build the 68-byte preimage on the stack.
    let mut preimage = [0u8; 68];
    preimage[..4].copy_from_slice(&epoch_id.to_le_bytes());
    preimage[4..36].copy_from_slice(&seed.0);
    preimage[36..68].copy_from_slice(node_id);
    blake2b_256(&preimage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::types::RandomSeed;

    fn node(seed: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = seed;
        n
    }

    #[test]
    fn test_derive_nonce_deterministic() {
        let seed = RandomSeed::from_counter(1);
        let nid = node(1);
        assert_eq!(derive_nonce(7, &seed, &nid), derive_nonce(7, &seed, &nid));
    }

    #[test]
    fn test_different_epochs_produce_different_nonces() {
        let seed = RandomSeed::from_counter(42);
        let nid = node(5);
        let n0 = derive_nonce(0, &seed, &nid);
        let n1 = derive_nonce(1, &seed, &nid);
        assert_ne!(n0, n1, "same seed/node but different epochs must differ");
    }

    #[test]
    fn test_different_seeds_produce_different_nonces() {
        let epoch: EpochId = 3;
        let nid = node(7);
        let n_a = derive_nonce(epoch, &RandomSeed::from_counter(10), &nid);
        let n_b = derive_nonce(epoch, &RandomSeed::from_counter(11), &nid);
        assert_ne!(n_a, n_b);
    }

    #[test]
    fn test_different_nodes_produce_different_nonces() {
        let epoch: EpochId = 5;
        let seed = RandomSeed::from_counter(99);
        let n_a = derive_nonce(epoch, &seed, &node(1));
        let n_b = derive_nonce(epoch, &seed, &node(2));
        assert_ne!(n_a, n_b);
    }

    #[test]
    fn test_nonce_is_256_bits() {
        let nonce = derive_nonce(0, &RandomSeed::from_counter(0), &node(0));
        assert_eq!(nonce.len(), 32, "nonce must be 256 bits (32 bytes)");
    }
}
