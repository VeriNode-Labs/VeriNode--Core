//! BLS G2 subgroup-check tests (#12).
//!
//! Cargo only auto-discovers test targets at the top level of `tests/`, so this
//! lives here rather than at `tests/crypto/`.

use sorosusu_contracts::attestation::bls_aggregator::{
    sign_message, verify_aggregate, verify_single_signature, SignatureVerifierConfig,
};
use sorosusu_contracts::crypto::bls_keys::{
    add, low_order_point, subgroup_check_g2, subgroup_member, G2Point, LOW_ORDER_POINTS,
};
use sorosusu_contracts::network::peer_message::{deserialize_public_key, PeerMessageError};

use proptest::prelude::*;

const MSG: &[u8] = b"slashing-evidence";

/// Concrete regression: subgroup members are accepted, the identity is in the
/// subgroup, and each known low-order point is rejected.
#[test]
fn subgroup_check_accepts_members_rejects_low_order() {
    assert!(subgroup_check_g2(&subgroup_member(1)));
    assert!(subgroup_check_g2(&subgroup_member(42)));
    assert!(subgroup_check_g2(&G2Point::identity()));

    for i in 0..LOW_ORDER_POINTS.len() {
        assert!(
            !subgroup_check_g2(&low_order_point(i)),
            "low-order point {i} was not rejected"
        );
    }
}

/// The default config rejects a forged pair built from an attacker-supplied
/// low-order key; disabling the check (test-network policy) reproduces the
/// pre-#12 vulnerability where the forgery is accepted.
#[test]
fn forged_low_order_key_rejected_by_default() {
    let attacker_key = low_order_point(0);
    let forged_sig = sign_message(&attacker_key, MSG); // attacker self-signs

    // Fixed path: rejected on subgroup grounds.
    assert!(!verify_single_signature(
        SignatureVerifierConfig::default(),
        &attacker_key,
        MSG,
        &forged_sig
    ));

    // Vulnerable path (checks disabled): the forgery is wrongly accepted,
    // demonstrating exactly what #12 closes.
    assert!(verify_single_signature(
        SignatureVerifierConfig::TEST_NETWORK,
        &attacker_key,
        MSG,
        &forged_sig
    ));
}

/// A legitimate subgroup key with a valid signature verifies under the strict
/// default policy.
#[test]
fn honest_key_verifies_under_strict_policy() {
    let pk = subgroup_member(7);
    let sig = sign_message(&pk, MSG);
    assert!(verify_single_signature(
        SignatureVerifierConfig::REQUIRE_SUBGROUP_CHECK,
        &pk,
        MSG,
        &sig
    ));
}

/// Ingress validation rejects malformed keys at the network boundary and
/// accepts well-formed ones.
#[test]
fn ingress_rejects_low_order_keys() {
    let cfg = SignatureVerifierConfig::default();

    let bad = low_order_point(1);
    assert_eq!(
        deserialize_public_key(cfg, &bad.to_bytes()),
        Err(PeerMessageError::SubgroupCheckFailed)
    );

    let good = subgroup_member(3);
    assert_eq!(deserialize_public_key(cfg, &good.to_bytes()), Ok(good));

    assert_eq!(
        deserialize_public_key(cfg, &[0u8; 4]),
        Err(PeerMessageError::Truncated)
    );
}

/// Aggregate verification fails if any contributor key is off-subgroup.
#[test]
fn aggregate_rejects_any_low_order_member() {
    let cfg = SignatureVerifierConfig::default();

    let good_pks = [subgroup_member(1), subgroup_member(2)];
    let good_sigs = [sign_message(&good_pks[0], MSG), sign_message(&good_pks[1], MSG)];
    assert!(verify_aggregate(cfg, &good_pks, MSG, &good_sigs));

    let mixed_pks = [subgroup_member(1), low_order_point(2)];
    let mixed_sigs = [
        sign_message(&mixed_pks[0], MSG),
        sign_message(&mixed_pks[1], MSG),
    ];
    assert!(!verify_aggregate(cfg, &mixed_pks, MSG, &mixed_sigs));
}

proptest! {
    /// Any key constructed as `scalar * generator` is in the prime-order
    /// subgroup and is accepted.
    #[test]
    fn prop_subgroup_members_accepted(scalar in any::<u64>()) {
        prop_assert!(subgroup_check_g2(&subgroup_member(scalar)));
    }

    /// Any subgroup member perturbed by a low-order component leaves the
    /// subgroup and is rejected.
    #[test]
    fn prop_low_order_perturbation_rejected(scalar in any::<u64>(), i in 0usize..LOW_ORDER_POINTS.len()) {
        let off_subgroup = add(&subgroup_member(scalar), &low_order_point(i));
        prop_assert!(!subgroup_check_g2(&off_subgroup));
    }

    /// Under the strict policy, no off-subgroup key with a self-signed
    /// signature is ever accepted.
    #[test]
    fn prop_forged_low_order_always_rejected(scalar in any::<u64>(), i in 0usize..LOW_ORDER_POINTS.len()) {
        let key = add(&subgroup_member(scalar), &low_order_point(i));
        let sig = sign_message(&key, MSG);
        prop_assert!(!verify_single_signature(
            SignatureVerifierConfig::default(), &key, MSG, &sig
        ));
    }
}
