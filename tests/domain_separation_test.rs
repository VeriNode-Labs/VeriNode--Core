//! Domain-binding tests for attestation signatures.
//!
//! Cargo only auto-discovers test targets at the top level of `tests/`, so
//! this file lives here (rather than `tests/attestation/`) to ensure it runs.

use sorosusu_contracts::attestation::verifier::{
    compute_signing_root, sign_attestation, verify_aggregate_signature,
    verify_attestation_signature, AttestationData,
};
use sorosusu_contracts::crypto::domain::{
    compute_domain, ALL_DOMAIN_TYPES, DOMAIN_BEACON_ATTESTER, DOMAIN_RANDAO, GENESIS_FORK_VERSION,
};
use sorosusu_contracts::crypto::sha256::sha256;

use proptest::prelude::*;

fn sample_data() -> AttestationData {
    AttestationData {
        slot: 42,
        index: 3,
        beacon_block_root: [0x11; 32],
        source_epoch: 1,
        source_root: [0x22; 32],
        target_epoch: 2,
        target_root: [0x33; 32],
    }
}

/// Known-answer test pinning the SHA-256 implementation: SHA-256("abc").
#[test]
fn sha256_known_answer() {
    let digest = sha256(b"abc");
    let expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    assert_eq!(digest, expected);
}

/// Core regression for #22: a signature produced in the beacon attester
/// domain must NOT verify in the RANDAO domain.
#[test]
fn signature_does_not_replay_across_domains() {
    let key = [0xAB; 32];
    let data = sample_data();

    let attester_domain = compute_domain(DOMAIN_BEACON_ATTESTER, GENESIS_FORK_VERSION);
    let randao_domain = compute_domain(DOMAIN_RANDAO, GENESIS_FORK_VERSION);

    // Sign in the beacon attester domain.
    let sig = sign_attestation(&key, &attester_domain, &data);

    // Valid in its own domain...
    assert!(verify_attestation_signature(
        &key,
        &attester_domain,
        &data,
        &sig
    ));
    // ...but the SAME signature must fail in the RANDAO domain.
    assert!(!verify_attestation_signature(
        &key,
        &randao_domain,
        &data,
        &sig
    ));
}

/// Signing roots must be pairwise distinct across all five domain types for
/// fixed attestation data.
#[test]
fn signing_roots_distinct_across_all_domains() {
    let data = sample_data();
    let roots: Vec<_> = ALL_DOMAIN_TYPES
        .iter()
        .map(|dt| compute_signing_root(&compute_domain(*dt, GENESIS_FORK_VERSION), &data))
        .collect();

    for i in 0..roots.len() {
        for j in (i + 1)..roots.len() {
            assert_ne!(
                roots[i], roots[j],
                "domain types {i} and {j} produced an identical signing root"
            );
        }
    }
}

/// Aggregate verification must also be domain-bound.
#[test]
fn aggregate_verification_respects_domain() {
    let keys = [[0x01; 32], [0x02; 32], [0x03; 32]];
    let data = sample_data();
    let domain = compute_domain(DOMAIN_BEACON_ATTESTER, GENESIS_FORK_VERSION);

    let sigs: Vec<[u8; 32]> = keys
        .iter()
        .map(|k| sign_attestation(k, &domain, &data))
        .collect();

    assert!(verify_aggregate_signature(&keys, &domain, &data, &sigs));

    // Same aggregate, wrong domain → rejected.
    let wrong_domain = compute_domain(DOMAIN_RANDAO, GENESIS_FORK_VERSION);
    assert!(!verify_aggregate_signature(
        &keys,
        &wrong_domain,
        &data,
        &sigs
    ));
}

proptest! {
    /// Property: for arbitrary attestation data, signing roots are distinct
    /// across all five domain types.
    #[test]
    fn prop_signing_roots_distinct_across_domains(
        slot in any::<u64>(),
        index in any::<u64>(),
        beacon_block_root in any::<[u8; 32]>(),
        source_epoch in any::<u64>(),
        source_root in any::<[u8; 32]>(),
        target_epoch in any::<u64>(),
        target_root in any::<[u8; 32]>(),
    ) {
        let data = AttestationData {
            slot,
            index,
            beacon_block_root,
            source_epoch,
            source_root,
            target_epoch,
            target_root,
        };

        let roots: Vec<_> = ALL_DOMAIN_TYPES
            .iter()
            .map(|dt| compute_signing_root(&compute_domain(*dt, GENESIS_FORK_VERSION), &data))
            .collect();

        for i in 0..roots.len() {
            for j in (i + 1)..roots.len() {
                prop_assert_ne!(roots[i], roots[j]);
            }
        }
    }
}
