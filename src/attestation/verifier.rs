//! Attestation signing-root computation and signature verification.
//!
//! The security-critical property here is **domain separation**:
//! [`compute_signing_root`] folds the 8-byte domain into the hash input, so a
//! signature produced for one domain (e.g. `DOMAIN_BEACON_ATTESTER`) can never
//! be replayed as valid in another (e.g. `DOMAIN_RANDAO` / `DOMAIN_DEPOSIT`).
//! Previously the root was `hash_tree_root(AttestationData)` alone, which is
//! identical across domains and therefore replayable.

use crate::crypto::domain::Domain;
use crate::crypto::merkle::{merkleize_8, Hash256};
use crate::crypto::sha256::sha256;

/// Simplified beacon-chain `AttestationData` container (7 fields).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestationData {
    pub slot: u64,
    pub index: u64,
    pub beacon_block_root: Hash256,
    pub source_epoch: u64,
    pub source_root: Hash256,
    pub target_epoch: u64,
    pub target_root: Hash256,
}

/// Encode a `u64` as a little-endian, right-padded 32-byte SSZ chunk.
fn u64_chunk(v: u64) -> Hash256 {
    let mut c = [0u8; 32];
    c[..8].copy_from_slice(&v.to_le_bytes());
    c
}

impl AttestationData {
    /// `hash_tree_root(AttestationData)` — merkleized over its 7 fields,
    /// padded to 8 leaves (the next power of two).
    pub fn hash_tree_root(&self) -> Hash256 {
        let leaves: [Hash256; 8] = [
            u64_chunk(self.slot),
            u64_chunk(self.index),
            self.beacon_block_root,
            u64_chunk(self.source_epoch),
            self.source_root,
            u64_chunk(self.target_epoch),
            self.target_root,
            [0u8; 32], // padding leaf
        ];
        merkleize_8(&leaves)
    }
}

/// Domain-separated signing root: `SHA-256(domain || hash_tree_root(data))`.
///
/// Prepending `domain` is what prevents cross-domain signature replay: with
/// distinct domains the signing root differs even for identical attestation
/// data, so a signature is bound to exactly one domain.
pub fn compute_signing_root(domain: &Domain, data: &AttestationData) -> Hash256 {
    let root = data.hash_tree_root();
    let mut buf = [0u8; 40]; // 8-byte domain || 32-byte attestation root
    buf[..8].copy_from_slice(domain);
    buf[8..].copy_from_slice(&root);
    sha256(&buf)
}

// --- Signature primitive ---
//
// Real beacon-chain deployments verify BLS12-381 signatures. To keep this
// crate self-contained and deterministic (no BLS dependency), we model a
// signature as a keyed MAC over the signing root:
//     sign(key, root) = SHA-256(key || signing_root)
// The domain-separation property under test is independent of the underlying
// signature primitive — it lives entirely in `compute_signing_root`. Swapping
// this MAC for BLS verification does not change the replay-protection behavior.

/// A signing key (stands in for a validator's BLS key material).
pub type SecretKey = [u8; 32];

/// A signature over a domain-separated signing root.
pub type Signature = [u8; 32];

/// Produce a signature over `data` under `domain`.
pub fn sign_attestation(key: &SecretKey, domain: &Domain, data: &AttestationData) -> Signature {
    let root = compute_signing_root(domain, data);
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(key);
    buf[32..].copy_from_slice(&root);
    sha256(&buf)
}

/// Verify a single attestation signature under `domain`.
///
/// Recomputes the domain-separated signing root for the supplied `domain`, so
/// a signature produced under a different domain will not validate.
pub fn verify_attestation_signature(
    key: &SecretKey,
    domain: &Domain,
    data: &AttestationData,
    signature: &Signature,
) -> bool {
    let expected = sign_attestation(key, domain, data);
    ct_eq(&expected, signature)
}

/// Verify an aggregate: every `(key, signature)` pair must validate over the
/// same `domain` and attestation `data`. Returns `false` if the inputs are
/// empty or length-mismatched.
pub fn verify_aggregate_signature(
    keys: &[SecretKey],
    domain: &Domain,
    data: &AttestationData,
    signatures: &[Signature],
) -> bool {
    if keys.is_empty() || keys.len() != signatures.len() {
        return false;
    }
    let mut ok = true;
    for (k, s) in keys.iter().zip(signatures.iter()) {
        ok &= verify_attestation_signature(k, domain, data, s);
    }
    ok
}

/// Constant-time comparison of two 32-byte values.
fn ct_eq(a: &Hash256, b: &Hash256) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
