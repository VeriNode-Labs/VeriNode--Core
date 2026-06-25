//! BLS single and aggregate signature verification with subgroup enforcement.
//!
//! Fixes #12: every untrusted public key is subgroup-checked before its
//! signature is trusted. The signature primitive itself is the same mock MAC
//! used elsewhere in this crate (a stand-in for BLS pairing verification); the
//! security-relevant gate under test is the subgroup check, not the MAC.

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::bls_keys::{subgroup_check_g2, G2Point};
use crate::crypto::sha256::sha256;

/// A signature (mock: a MAC keyed by the serialized public key).
pub type Signature = [u8; 32];

/// Verifier configuration toggle (#12, step 4).
///
/// Production networks require the subgroup check; only test networks may
/// disable it. Default is `require_subgroup_check = true`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureVerifierConfig {
    pub require_subgroup_check: bool,
}

impl Default for SignatureVerifierConfig {
    fn default() -> Self {
        Self {
            require_subgroup_check: true,
        }
    }
}

impl SignatureVerifierConfig {
    /// Production policy: subgroup checks enabled (the `RequireSubgroupCheck`
    /// toggle in its on position).
    pub const REQUIRE_SUBGROUP_CHECK: Self = Self {
        require_subgroup_check: true,
    };

    /// Test-network policy: subgroup checks disabled. Reproduces the
    /// pre-#12 (vulnerable) verification path.
    pub const TEST_NETWORK: Self = Self {
        require_subgroup_check: false,
    };
}

/// Mock signature: `SHA-256(pk_bytes || msg)`. Stands in for BLS pairing
/// verification — a holder of `pk` (or an attacker who supplies their own
/// `pk`) can produce a matching signature, which is exactly why the subgroup
/// check on `pk` is the load-bearing defense.
fn mac(public_key: &G2Point, msg: &[u8]) -> Signature {
    let mut buf = Vec::with_capacity(8 + msg.len());
    buf.extend_from_slice(&public_key.to_bytes());
    buf.extend_from_slice(msg);
    sha256(&buf)
}

/// Produce a signature over `msg` for `public_key`.
pub fn sign_message(public_key: &G2Point, msg: &[u8]) -> Signature {
    mac(public_key, msg)
}

/// Verify a single signature.
///
/// Defense-in-depth (#12, step 3): when enabled, the public key is rejected
/// unless it lies in the prime-order subgroup — even if ingress validation was
/// somehow bypassed.
pub fn verify_single_signature(
    config: SignatureVerifierConfig,
    public_key: &G2Point,
    msg: &[u8],
    signature: &Signature,
) -> bool {
    if config.require_subgroup_check && !subgroup_check_g2(public_key) {
        return false;
    }
    ct_eq(&mac(public_key, msg), signature)
}

/// Verify an aggregate over a common message: every `(public_key, signature)`
/// pair must validate (and every key must pass the subgroup check when
/// enabled). Returns `false` on empty or length-mismatched inputs.
pub fn verify_aggregate(
    config: SignatureVerifierConfig,
    public_keys: &[G2Point],
    msg: &[u8],
    signatures: &[Signature],
) -> bool {
    if public_keys.is_empty() || public_keys.len() != signatures.len() {
        return false;
    }
    public_keys
        .iter()
        .zip(signatures.iter())
        .all(|(pk, sig)| verify_single_signature(config, pk, msg, sig))
}

/// Constant-time comparison of two 32-byte values.
fn ct_eq(a: &Signature, b: &Signature) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
