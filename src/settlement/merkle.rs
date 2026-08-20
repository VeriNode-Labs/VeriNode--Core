//! Domain-separated Merkle inclusion-proof verification.
//!
//! # Second-preimage resistance
//!
//! Leaf hashes and internal-node hashes are computed under distinct
//! single-byte domain prefixes (`LEAF_DOMAIN` / `NODE_DOMAIN`), following the
//! same domain-separation principle `crate::crypto::domain` uses for
//! attestation signatures: without it, an attacker who knows two leaves `A`
//! and `B` hash to some value `H` could submit `H` itself as a *third* leaf
//! and pass verification against a proof that never actually included it —
//! the classic second-preimage attack on unprefixed Merkle trees (RFC 6962
//! exists specifically to close this). Prefixing makes a leaf hash and an
//! internal-node hash land in disjoint ranges, so an internal node can never
//! also verify as a leaf.
//!
//! # Hashing engine: host-native, not `crate::crypto::sha256`
//!
//! `crate::crypto::sha256` is a hand-rolled, `Env`-free SHA-256 built for
//! the off-chain/light-client-style attestation layer (see its module
//! docs). Everything in this module runs inside contract storage context
//! and calls `env.crypto().sha256`, the Soroban host's native
//! implementation — real CPU-instruction cost for the hand-rolled version
//! scales with the *Rust* instruction count of a 64-round compression
//! function per call; the host-native version is a single host function
//! invocation metered directly by the network. For a proof verified up to
//! [`super::MAX_BATCH_SIZE`] times per reveal, at up to [`MAX_PROOF_DEPTH`]
//! (20) levels each, that difference is the dominant cost driver, so the
//! host primitive is used throughout instead of reusing the existing
//! hand-rolled hasher. See [`super::MAX_BATCH_SIZE`]'s own docs for the
//! measured cost that sized it.

use soroban_sdk::{Bytes, BytesN, Env, Vec};

pub use super::MAX_PROOF_DEPTH;

const LEAF_DOMAIN: u8 = 0x00;
const NODE_DOMAIN: u8 = 0x01;

/// Hash arbitrary leaf content under the leaf domain prefix.
pub fn hash_leaf(env: &Env, data: &Bytes) -> BytesN<32> {
    let mut buf = Bytes::from_array(env, &[LEAF_DOMAIN]);
    buf.append(data);
    env.crypto().sha256(&buf).to_bytes()
}

/// Hash two child node hashes under the internal-node domain prefix.
/// `pub(crate)` (rather than private) so test scaffolding elsewhere in this
/// module tree can build reference trees without duplicating this logic.
pub(crate) fn hash_node(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
    let mut buf = Bytes::from_array(env, &[NODE_DOMAIN]);
    buf.append(&Bytes::from(left.clone()));
    buf.append(&Bytes::from(right.clone()));
    env.crypto().sha256(&buf).to_bytes()
}

/// Verify that `leaf` is included in the tree committed to by `root`, at
/// position `index`, via the sibling path `proof`.
///
/// `index`'s bits select, level by level, whether `proof[level]` is the
/// left or right sibling: even -> the running hash is the left child,
/// odd -> it's the right child. This ordering is positional (derived from
/// `index`), not a commutative sort of the pair — a proof only verifies at
/// the exact position it was generated for.
///
/// `proof.len() > MAX_PROOF_DEPTH` (20, i.e. a tree taller than
/// 1,048,576 leaves) is rejected outright rather than walked, bounding
/// worst-case verification cost per leaf and preventing a caller from
/// forcing an unbounded-length traversal.
pub fn verify_proof(
    env: &Env,
    leaf: &BytesN<32>,
    proof: &Vec<BytesN<32>>,
    index: u32,
    root: &BytesN<32>,
) -> bool {
    if proof.len() > MAX_PROOF_DEPTH {
        return false;
    }

    let mut computed = leaf.clone();
    let mut idx = index;
    for sibling in proof.iter() {
        computed = if idx % 2 == 0 {
            hash_node(env, &computed, &sibling)
        } else {
            hash_node(env, &sibling, &computed)
        };
        idx /= 2;
    }

    computed == *root
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;

    fn leaf_hash(env: &Env, tag: u8) -> BytesN<32> {
        let data = Bytes::from_array(env, &[tag]);
        hash_leaf(env, &data)
    }

    /// Build a tree over `leaves` (power-of-two length) and return
    /// `(root, proof_for(target))`.
    fn build_tree(
        env: &Env,
        leaves: &alloc::vec::Vec<BytesN<32>>,
        target: usize,
    ) -> (BytesN<32>, Vec<BytesN<32>>) {
        let mut proof = Vec::new(env);
        let mut level = leaves.clone();
        let mut idx = target;

        while level.len() > 1 {
            let sibling_idx = idx ^ 1;
            proof.push_back(level[sibling_idx].clone());

            let mut next = alloc::vec::Vec::new();
            let mut i = 0;
            while i < level.len() {
                next.push(hash_node(env, &level[i], &level[i + 1]));
                i += 2;
            }
            level = next;
            idx /= 2;
        }

        (level[0].clone(), proof)
    }

    #[test]
    fn verifies_a_valid_proof_at_every_position() {
        let env = Env::default();
        let leaves: alloc::vec::Vec<BytesN<32>> = (0u8..8).map(|i| leaf_hash(&env, i)).collect();

        for target in 0..leaves.len() {
            let (root, proof) = build_tree(&env, &leaves, target);
            assert!(verify_proof(
                &env,
                &leaves[target],
                &proof,
                target as u32,
                &root
            ));
        }
    }

    #[test]
    fn rejects_a_tampered_leaf() {
        let env = Env::default();
        let leaves: alloc::vec::Vec<BytesN<32>> = (0u8..8).map(|i| leaf_hash(&env, i)).collect();
        let (root, proof) = build_tree(&env, &leaves, 0);

        let wrong_leaf = leaf_hash(&env, 99);
        assert!(!verify_proof(&env, &wrong_leaf, &proof, 0, &root));
    }

    #[test]
    fn rejects_a_tampered_sibling() {
        let env = Env::default();
        let leaves: alloc::vec::Vec<BytesN<32>> = (0u8..8).map(|i| leaf_hash(&env, i)).collect();
        let (root, mut proof) = build_tree(&env, &leaves, 0);

        let tampered = leaf_hash(&env, 200);
        proof.set(0, tampered);
        assert!(!verify_proof(&env, &leaves[0], &proof, 0, &root));
    }

    #[test]
    fn rejects_wrong_index_for_a_valid_proof() {
        let env = Env::default();
        let leaves: alloc::vec::Vec<BytesN<32>> = (0u8..8).map(|i| leaf_hash(&env, i)).collect();
        let (root, proof) = build_tree(&env, &leaves, 0);

        // Proof for index 0 must not also verify at index 1 (different
        // left/right ordering at every level).
        assert!(!verify_proof(&env, &leaves[0], &proof, 1, &root));
    }

    /// The second-preimage attack this module's domain separation exists to
    /// stop: without a leaf/node prefix, `hash_node(a, b)` could be replayed
    /// as if it were a leaf whose own hash happens to equal that internal
    /// node's value, forging inclusion for data that was never actually a
    /// leaf. With domain separation, a raw internal-node hash never has the
    /// leaf-domain prefix, so `hash_leaf` can never coincide with it for the
    /// same preimage bytes.
    #[test]
    fn leaf_domain_and_node_domain_are_disjoint_for_the_same_bytes() {
        let env = Env::default();
        let a = leaf_hash(&env, 1);
        let b = leaf_hash(&env, 2);

        let node_hash = hash_node(&env, &a, &b);

        // Hashing the identical concatenated bytes under the leaf domain
        // instead of the node domain must differ from the real node hash.
        let mut raw = Bytes::from(a.clone());
        raw.append(&Bytes::from(b.clone()));
        let as_if_leaf = hash_leaf(&env, &raw);

        assert_ne!(node_hash, as_if_leaf);
    }

    #[test]
    fn depth_exactly_20_is_accepted_depth_21_is_rejected() {
        let env = Env::default();
        let leaf = leaf_hash(&env, 1);
        let sibling = leaf_hash(&env, 2);

        // A proof of 20 siblings must at least be attempted (not rejected
        // purely for length) — build one and confirm it verifies against
        // its own honestly-computed root.
        let mut proof_20 = Vec::new(&env);
        let mut computed = leaf.clone();
        for _ in 0..20 {
            proof_20.push_back(sibling.clone());
            computed = hash_node(&env, &computed, &sibling);
        }
        assert!(verify_proof(&env, &leaf, &proof_20, 0, &computed));

        // 21 siblings: rejected outright regardless of whether it would
        // otherwise hash correctly.
        let mut proof_21 = proof_20.clone();
        proof_21.push_back(sibling.clone());
        let computed_21 = hash_node(&env, &computed, &sibling);
        assert!(!verify_proof(&env, &leaf, &proof_21, 0, &computed_21));
    }
}
