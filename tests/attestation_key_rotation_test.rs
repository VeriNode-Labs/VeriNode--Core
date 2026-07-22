//! Key-rotation cache-poisoning tests (#5).
//!
//! Cargo only auto-discovers test targets at the top level of `tests/`, so this
//! lives here rather than at `tests/attestation/`.

use sorosusu_contracts::attestation::key_registry::{
    verify_with_rotation, KeyRegistry, VerificationCache, ROTATION_WINDOW_LEDGERS,
};
use sorosusu_contracts::attestation::verifier::{
    sign_attestation, verify_attestation_signature, AttestationData,
};
use sorosusu_contracts::crypto::domain::{compute_domain, DOMAIN_BEACON_ATTESTER, GENESIS_FORK_VERSION};

use proptest::prelude::*;

const OLD_KEY: [u8; 32] = [0x11; 32];
const NEW_KEY: [u8; 32] = [0x22; 32];
const VALIDATOR: u32 = 1;

fn sample_data(slot: u64) -> AttestationData {
    AttestationData {
        slot,
        index: 0,
        beacon_block_root: [0xAA; 32],
        source_epoch: 1,
        source_root: [0xBB; 32],
        target_epoch: 2,
        target_root: [0xCC; 32],
    }
}

/// Core regression for #5: after a rotation, a NEW-key attestation that would
/// be rejected against the stale cached key is accepted because the versioned
/// cache reloads; and an in-flight OLD-key attestation still verifies within
/// the rotation window.
#[test]
fn rotation_window_accepts_old_and_new_keys() {
    let domain = compute_domain(DOMAIN_BEACON_ATTESTER, GENESIS_FORK_VERSION);
    let data = sample_data(42);

    let mut registry = KeyRegistry::new();
    let mut cache = VerificationCache::new();
    registry.register(VALIDATOR, OLD_KEY);

    let sig_old = sign_attestation(&OLD_KEY, &domain, &data);
    let sig_new = sign_attestation(&NEW_KEY, &domain, &data);

    // Before rotation: old key verifies and is cached at gen 0.
    assert!(verify_with_rotation(&mut cache, &registry, VALIDATOR, &domain, &data, &sig_old, 100));
    assert_eq!(cache.cached_key_gen(VALIDATOR), Some(0));

    // Rotate to the new key at ledger 100.
    assert_eq!(registry.rotate_key(VALIDATOR, NEW_KEY, 100), Some(1));

    // The poisoning failure mode: verifying the new attestation against the old
    // (stale) key fails.
    assert!(!verify_attestation_signature(&OLD_KEY, &domain, &data, &sig_new));

    // The fix: the versioned cache reloads (gen 0 -> 1) and the new attestation
    // verifies.
    assert!(verify_with_rotation(&mut cache, &registry, VALIDATOR, &domain, &data, &sig_new, 101));
    assert_eq!(cache.cached_key_gen(VALIDATOR), Some(1));

    // An in-flight old-key attestation still verifies within the window.
    assert!(verify_with_rotation(&mut cache, &registry, VALIDATOR, &domain, &data, &sig_old, 102));
}

/// Once the rotation window elapses, the old key is no longer accepted but the
/// new key still is.
#[test]
fn old_key_expires_after_window() {
    let domain = compute_domain(DOMAIN_BEACON_ATTESTER, GENESIS_FORK_VERSION);
    let data = sample_data(7);

    let mut registry = KeyRegistry::new();
    let mut cache = VerificationCache::new();
    registry.register(VALIDATOR, OLD_KEY);
    registry.rotate_key(VALIDATOR, NEW_KEY, 1_000);

    let sig_old = sign_attestation(&OLD_KEY, &domain, &data);
    let sig_new = sign_attestation(&NEW_KEY, &domain, &data);

    let after_window = 1_000 + ROTATION_WINDOW_LEDGERS;
    assert!(!verify_with_rotation(&mut cache, &registry, VALIDATOR, &domain, &data, &sig_old, after_window));
    assert!(verify_with_rotation(&mut cache, &registry, VALIDATOR, &domain, &data, &sig_new, after_window));
}

/// Blueprint step 5: a rotation lands while a batch of verifications is in
/// flight; old-key and new-key attestations alike all pass within the window.
#[test]
fn concurrent_rotation_and_verification_all_pass() {
    let domain = compute_domain(DOMAIN_BEACON_ATTESTER, GENESIS_FORK_VERSION);

    let mut registry = KeyRegistry::new();
    let mut cache = VerificationCache::new();
    registry.register(VALIDATOR, OLD_KEY);
    registry.rotate_key(VALIDATOR, NEW_KEY, 200);

    for i in 0..10u64 {
        let ledger = 201 + i; // 201..210, all inside the [200, 210) window
        let data = sample_data(i);
        // Even slots are in-flight old-key attestations, odd are new-key.
        let signer = if i % 2 == 0 { OLD_KEY } else { NEW_KEY };
        let sig = sign_attestation(&signer, &domain, &data);
        assert!(
            verify_with_rotation(&mut cache, &registry, VALIDATOR, &domain, &data, &sig, ledger),
            "verification {i} (ledger {ledger}) should pass"
        );
    }
}

/// Unknown validators never verify.
#[test]
fn unknown_validator_rejected() {
    let domain = compute_domain(DOMAIN_BEACON_ATTESTER, GENESIS_FORK_VERSION);
    let data = sample_data(1);
    let mut cache = VerificationCache::new();
    let registry = KeyRegistry::new();
    let sig = sign_attestation(&OLD_KEY, &domain, &data);
    assert!(!verify_with_rotation(&mut cache, &registry, 99, &domain, &data, &sig, 0));
}

proptest! {
    /// For any ledger offset after a rotation: the new key always verifies; the
    /// old key verifies iff still inside the rotation window.
    #[test]
    fn prop_window_acceptance(offset in 0_u64..30, use_new_key in any::<bool>()) {
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, GENESIS_FORK_VERSION);
        let data = sample_data(3);

        let mut registry = KeyRegistry::new();
        let mut cache = VerificationCache::new();
        registry.register(VALIDATOR, OLD_KEY);
        registry.rotate_key(VALIDATOR, NEW_KEY, 1_000);

        let signer = if use_new_key { NEW_KEY } else { OLD_KEY };
        let sig = sign_attestation(&signer, &domain, &data);
        let got = verify_with_rotation(&mut cache, &registry, VALIDATOR, &domain, &data, &sig, 1_000 + offset);

        let expected = use_new_key || offset < ROTATION_WINDOW_LEDGERS;
        prop_assert_eq!(got, expected);
    }
}
