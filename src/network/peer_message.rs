//! Inbound peer-message deserialization for attested public keys.
//!
//! Fixes #12 (step 2): subgroup validation happens on ingress, so a malformed
//! public key is rejected at the network boundary and never reaches the
//! verifier, aggregation, or persistent storage.

use crate::attestation::bls_aggregator::SignatureVerifierConfig;
use crate::crypto::bls_keys::{subgroup_check_g2, G2Point};

/// Errors produced while deserializing an inbound peer message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerMessageError {
    /// Fewer than the 8 bytes needed for a compressed public key.
    Truncated,
    /// The public key is not in the prime-order subgroup.
    SubgroupCheckFailed,
}

/// Deserialize an attested public key from inbound bytes, validating subgroup
/// membership on ingress when the policy requires it.
pub fn deserialize_public_key(
    config: SignatureVerifierConfig,
    bytes: &[u8],
) -> Result<G2Point, PeerMessageError> {
    if bytes.len() < 8 {
        return Err(PeerMessageError::Truncated);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    let public_key = G2Point::from_bytes(&buf);

    if config.require_subgroup_check && !subgroup_check_g2(&public_key) {
        return Err(PeerMessageError::SubgroupCheckFailed);
    }
    Ok(public_key)
}
