//! Minimal SSZ-style merkleization used to compute `hash_tree_root`.

use crate::crypto::sha256::sha256;

/// A 32-byte hash / merkle node.
pub type Hash256 = [u8; 32];

/// Hash two 32-byte child nodes into their parent: `SHA-256(left || right)`.
pub fn hash_nodes(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha256(&buf)
}

/// Merkleize exactly 8 leaf chunks into a single root.
///
/// Containers with fewer than 8 fields pad the leaf array with zero chunks to
/// the next power of two before calling this, matching SSZ semantics for a
/// fixed-size container.
pub fn merkleize_8(leaves: &[Hash256; 8]) -> Hash256 {
    let mut level = *leaves;
    let mut width = 8usize;
    while width > 1 {
        let half = width / 2;
        let mut next = [[0u8; 32]; 8];
        for i in 0..half {
            next[i] = hash_nodes(&level[2 * i], &level[2 * i + 1]);
        }
        level = next;
        width = half;
    }
    level[0]
}
