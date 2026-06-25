//! Domain separation for attestation signatures.
//!
//! Every consensus message is signed under a distinct *domain* so that a
//! signature produced for one domain (e.g. beacon attester) can never be
//! reinterpreted as a valid signature in another (e.g. RANDAO or deposit).
//! The domain is folded into the signing root in
//! [`crate::attestation::verifier::compute_signing_root`].

/// A 4-byte domain type tag.
pub type DomainType = [u8; 4];

/// A 4-byte fork version.
pub type ForkVersion = [u8; 4];

/// An 8-byte domain = `domain_type (4 bytes) || fork_version (4 bytes)`.
pub type Domain = [u8; 8];

// --- Domain type tags ---

pub const DOMAIN_BEACON_PROPOSER: DomainType = [0x00, 0x00, 0x00, 0x00];
pub const DOMAIN_BEACON_ATTESTER: DomainType = [0x01, 0x00, 0x00, 0x00];
pub const DOMAIN_RANDAO: DomainType = [0x02, 0x00, 0x00, 0x00];
pub const DOMAIN_DEPOSIT: DomainType = [0x03, 0x00, 0x00, 0x00];
pub const DOMAIN_VOLUNTARY_EXIT: DomainType = [0x04, 0x00, 0x00, 0x00];

/// All five domain types, used to assert mutual signing-root distinctness.
pub const ALL_DOMAIN_TYPES: [DomainType; 5] = [
    DOMAIN_BEACON_PROPOSER,
    DOMAIN_BEACON_ATTESTER,
    DOMAIN_RANDAO,
    DOMAIN_DEPOSIT,
    DOMAIN_VOLUNTARY_EXIT,
];

/// Genesis fork version (`0x00000000`).
pub const GENESIS_FORK_VERSION: ForkVersion = [0x00, 0x00, 0x00, 0x00];

/// Compute the 8-byte domain from a domain type and fork version.
///
/// Binding the fork version into the domain means signatures are also scoped
/// to a fork: a signature is only replayable until the fork version changes.
pub fn compute_domain(domain_type: DomainType, fork_version: ForkVersion) -> Domain {
    let mut domain = [0u8; 8];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fork_version);
    domain
}
