//! Comprehensive BLS subgroup security tests - additional edge cases
//!
//! This test file supplements bls_subgroup_test.rs with additional edge cases
//! and stress tests to ensure the subgroup check is bulletproof.

use sorosusu_contracts::attestation::bls_aggregator::{
    sign_message, verify_aggregate, verify_single_signature, SignatureVerifierConfig,
};
use sorosusu_contracts::crypto::bls_keys::{
    add, low_order_point, scalar_mul, subgroup_check_g2, subgroup_member, G2Point,
    LOW_ORDER_POINTS, MODEL_GROUP_ORDER, PRIME_SUBGROUP_ORDER,
};
use sorosusu_contracts::network::peer_message::{deserialize_public_key, PeerMessageError};

const MSG: &[u8] = b"test-message";

/// Test: Identity point must pass subgroup check (it's in every subgroup)
#[test]
fn identity_always_in_subgroup() {
    assert!(subgroup_check_g2(&G2Point::identity()));
}

/// Test: Multiple of group order is also identity
#[test]
fn group_order_multiples_are_identity() {
    let pt = G2Point::new(MODEL_GROUP_ORDER);
    assert!(pt.is_identity());
    assert!(subgroup_check_g2(&pt));

    let pt2 = G2Point::new(2 * MODEL_GROUP_ORDER);
    assert!(pt2.is_identity());
    assert!(subgroup_check_g2(&pt2));

    let pt3 = G2Point::new(100 * MODEL_GROUP_ORDER);
    assert!(pt3.is_identity());
    assert!(subgroup_check_g2(&pt3));
}

/// Test: Generator itself must be in the subgroup
#[test]
fn generator_in_subgroup() {
    let generator = G2Point { value: 6 }; // SUBGROUP_GENERATOR
    assert!(subgroup_check_g2(&generator));
}

/// Test: All low-order points have order dividing the cofactor
#[test]
fn low_order_points_have_small_order() {
    // Each low-order point should NOT be in the prime subgroup
    for &value in &LOW_ORDER_POINTS {
        let pt = G2Point { value };
        assert!(
            !subgroup_check_g2(&pt),
            "Low-order point {value} incorrectly passed subgroup check"
        );

        // But should be in the full group
        assert_eq!(pt.value, value % MODEL_GROUP_ORDER);
    }
}

/// Test: Scalar multiplication is consistent
#[test]
fn scalar_mul_consistency() {
    let gen = subgroup_member(1);

    // 0 * G = O
    let zero_mul = scalar_mul(0, &gen);
    assert!(zero_mul.is_identity());

    // 1 * G = G
    let one_mul = scalar_mul(1, &gen);
    assert_eq!(one_mul, gen);

    // r * G = O (for subgroup member)
    let r_mul = scalar_mul(PRIME_SUBGROUP_ORDER, &gen);
    assert!(r_mul.is_identity());
}

/// Test: Adding a subgroup member to itself stays in subgroup
#[test]
fn subgroup_closed_under_addition() {
    let pk1 = subgroup_member(5);
    let pk2 = subgroup_member(7);

    // Both in subgroup
    assert!(subgroup_check_g2(&pk1));
    assert!(subgroup_check_g2(&pk2));

    // Sum also in subgroup
    let sum = add(&pk1, &pk2);
    assert!(subgroup_check_g2(&sum));
}

/// Test: Large scalar multiples stay in subgroup
#[test]
fn large_scalar_multiples_in_subgroup() {
    for scalar in [100, 1000, 10000, u64::MAX / 2, u64::MAX - 1] {
        let pk = subgroup_member(scalar);
        assert!(
            subgroup_check_g2(&pk),
            "Large scalar {scalar} failed subgroup check"
        );
    }
}

/// Test: Boundary values
#[test]
fn boundary_value_testing() {
    // Test edge values around the prime subgroup order
    let near_r = [
        PRIME_SUBGROUP_ORDER - 1,
        PRIME_SUBGROUP_ORDER,
        PRIME_SUBGROUP_ORDER + 1,
    ];

    for scalar in near_r {
        let pk = subgroup_member(scalar);
        assert!(
            subgroup_check_g2(&pk),
            "Boundary scalar {scalar} failed subgroup check"
        );
    }
}

/// Test: Empty aggregate is rejected
#[test]
fn empty_aggregate_rejected() {
    let cfg = SignatureVerifierConfig::default();
    let empty_pks: Vec<G2Point> = vec![];
    let empty_sigs = vec![];

    assert!(!verify_aggregate(cfg, &empty_pks, MSG, &empty_sigs));
}

/// Test: Length mismatch between keys and signatures
#[test]
fn mismatched_lengths_rejected() {
    let cfg = SignatureVerifierConfig::default();

    let pks = vec![subgroup_member(1), subgroup_member(2)];
    let sigs = vec![sign_message(&pks[0], MSG)]; // Only 1 signature for 2 keys

    assert!(!verify_aggregate(cfg, &pks, MSG, &sigs));
}

/// Test: All keys valid but one signature wrong
#[test]
fn one_bad_signature_fails_aggregate() {
    let cfg = SignatureVerifierConfig::default();

    let pk1 = subgroup_member(1);
    let pk2 = subgroup_member(2);
    let pks = vec![pk1, pk2];

    let sig1 = sign_message(&pk1, MSG);
    let wrong_sig2 = sign_message(&pk2, b"wrong-message");
    let sigs = vec![sig1, wrong_sig2];

    assert!(!verify_aggregate(cfg, &pks, MSG, &sigs));
}

/// Test: Ingress validation with edge case inputs
#[test]
fn ingress_edge_cases() {
    let cfg = SignatureVerifierConfig::default();

    // Too short input
    assert_eq!(
        deserialize_public_key(cfg, &[0u8; 4]),
        Err(PeerMessageError::Truncated)
    );
    assert_eq!(
        deserialize_public_key(cfg, &[]),
        Err(PeerMessageError::Truncated)
    );

    // Exactly 8 bytes but invalid key
    let low_order_bytes = low_order_point(0).to_bytes();
    assert_eq!(
        deserialize_public_key(cfg, &low_order_bytes),
        Err(PeerMessageError::SubgroupCheckFailed)
    );

    // Valid key
    let valid_bytes = subgroup_member(42).to_bytes();
    assert!(deserialize_public_key(cfg, &valid_bytes).is_ok());

    // Extra bytes (should work, takes first 8)
    let extra_bytes = [
        valid_bytes[0], valid_bytes[1], valid_bytes[2], valid_bytes[3],
        valid_bytes[4], valid_bytes[5], valid_bytes[6], valid_bytes[7],
        99, 99, 99, 99, // Extra bytes ignored
    ];
    assert!(deserialize_public_key(cfg, &extra_bytes).is_ok());
}

/// Test: Serialization roundtrip
#[test]
fn serialization_roundtrip() {
    for scalar in [1, 7, 42, 100, 1000] {
        let original = subgroup_member(scalar);
        let bytes = original.to_bytes();
        let deserialized = G2Point::from_bytes(&bytes);

        assert_eq!(
            original, deserialized,
            "Roundtrip failed for scalar {scalar}"
        );
        assert!(subgroup_check_g2(&deserialized));
    }
}

/// Test: Low-order point + identity = still low-order
#[test]
fn low_order_plus_identity() {
    let low = low_order_point(0);
    let identity = G2Point::identity();

    let sum = add(&low, &identity);
    assert_eq!(sum, low);
    assert!(!subgroup_check_g2(&sum));
}

/// Test: Cofactor multiple of generator has specific order
#[test]
fn cofactor_structure() {
    // In the toy model: MODEL_COFACTOR = 6, PRIME_SUBGROUP_ORDER = 101
    // So MODEL_GROUP_ORDER = 606

    let gen = subgroup_member(1);

    // r * G = O (prime subgroup order)
    let r_mul = scalar_mul(PRIME_SUBGROUP_ORDER, &gen);
    assert!(r_mul.is_identity());

    // (r-1) * G ≠ O
    let r_minus_1_mul = scalar_mul(PRIME_SUBGROUP_ORDER - 1, &gen);
    assert!(!r_minus_1_mul.is_identity());
}

/// Test: Config toggle works correctly
#[test]
fn config_toggle_behavior() {
    let valid_pk = subgroup_member(10);
    let invalid_pk = low_order_point(0);
    let valid_sig = sign_message(&valid_pk, MSG);
    let invalid_sig = sign_message(&invalid_pk, MSG);

    // Strict config: valid passes, invalid fails
    let strict = SignatureVerifierConfig::REQUIRE_SUBGROUP_CHECK;
    assert!(verify_single_signature(strict, &valid_pk, MSG, &valid_sig));
    assert!(!verify_single_signature(strict, &invalid_pk, MSG, &invalid_sig));

    // Test network config: both pass (demonstrates vulnerability)
    let test = SignatureVerifierConfig::TEST_NETWORK;
    assert!(verify_single_signature(test, &valid_pk, MSG, &valid_sig));
    assert!(verify_single_signature(test, &invalid_pk, MSG, &invalid_sig)); // ⚠️ Vulnerable!

    // Default is strict
    let default = SignatureVerifierConfig::default();
    assert_eq!(default.require_subgroup_check, true);
}

/// Test: Multiple low-order points in aggregate
#[test]
fn multiple_rogue_keys_in_aggregate() {
    let cfg = SignatureVerifierConfig::default();

    let rogue1 = low_order_point(0);
    let rogue2 = low_order_point(1);
    let valid = subgroup_member(5);

    let pks = vec![rogue1, valid, rogue2];
    let sigs = vec![
        sign_message(&rogue1, MSG),
        sign_message(&valid, MSG),
        sign_message(&rogue2, MSG),
    ];

    // Should fail due to multiple rogue keys
    assert!(!verify_aggregate(cfg, &pks, MSG, &sigs));
}

/// Test: Stress test with maximum typical aggregate size
#[test]
fn large_aggregate_all_valid() {
    let cfg = SignatureVerifierConfig::default();
    let size = 256; // Typical committee size

    let pks: Vec<G2Point> = (0..size).map(|i| subgroup_member(i as u64 + 1)).collect();
    let sigs: Vec<_> = pks.iter().map(|pk| sign_message(pk, MSG)).collect();

    assert!(verify_aggregate(cfg, &pks, MSG, &sigs));
}

/// Test: Large aggregate with one rogue key at various positions
#[test]
fn large_aggregate_one_rogue_at_various_positions() {
    let cfg = SignatureVerifierConfig::default();
    let size = 100;

    for rogue_pos in [0, 25, 50, 75, 99] {
        let mut pks: Vec<G2Point> = (0..size).map(|i| subgroup_member(i as u64 + 1)).collect();
        pks[rogue_pos] = low_order_point(0); // Insert rogue key

        let sigs: Vec<_> = pks.iter().map(|pk| sign_message(pk, MSG)).collect();

        assert!(
            !verify_aggregate(cfg, &pks, MSG, &sigs),
            "Aggregate with rogue key at position {rogue_pos} should fail"
        );
    }
}

/// Test: Determinism - same inputs produce same outputs
#[test]
fn deterministic_behavior() {
    let pk = subgroup_member(42);

    // Subgroup check is deterministic
    for _ in 0..10 {
        assert!(subgroup_check_g2(&pk));
    }

    // Signature generation is deterministic (in this model)
    let sig1 = sign_message(&pk, MSG);
    let sig2 = sign_message(&pk, MSG);
    assert_eq!(sig1, sig2);

    // Verification is deterministic
    for _ in 0..10 {
        assert!(verify_single_signature(
            SignatureVerifierConfig::default(),
            &pk,
            MSG,
            &sig1
        ));
    }
}

/// Test: All arithmetic respects modular reduction
#[test]
fn modular_arithmetic_correctness() {
    let large_value = MODEL_GROUP_ORDER * 5 + 42;
    let pt = G2Point::new(large_value);

    // Should reduce to 42
    assert_eq!(pt.value, 42);

    // And the reduced value is the same as if we started with 42
    let pt2 = G2Point::new(42);
    assert_eq!(pt, pt2);
}

/// Test: Zero scalar produces identity
#[test]
fn zero_scalar_identity() {
    let base = subgroup_member(10);
    let zero_mul = scalar_mul(0, &base);

    assert!(zero_mul.is_identity());
    assert!(subgroup_check_g2(&zero_mul));
}

/// Test: Point addition is commutative
#[test]
fn addition_commutative() {
    let pk1 = subgroup_member(7);
    let pk2 = subgroup_member(13);

    let sum1 = add(&pk1, &pk2);
    let sum2 = add(&pk2, &pk1);

    assert_eq!(sum1, sum2);
    assert!(subgroup_check_g2(&sum1));
}

/// Test: Point addition is associative
#[test]
fn addition_associative() {
    let pk1 = subgroup_member(3);
    let pk2 = subgroup_member(5);
    let pk3 = subgroup_member(7);

    let sum1 = add(&add(&pk1, &pk2), &pk3);
    let sum2 = add(&pk1, &add(&pk2, &pk3));

    assert_eq!(sum1, sum2);
    assert!(subgroup_check_g2(&sum1));
}

/// Test: Subgroup check performance (should be fast)
#[test]
fn subgroup_check_performance() {
    let pk = subgroup_member(42);
    let iterations = 10000;

    let start = std::time::Instant::now();
    for _ in 0..iterations {
        assert!(subgroup_check_g2(&pk));
    }
    let duration = start.elapsed();

    // Should complete 10,000 checks in under 1 second
    assert!(
        duration.as_secs() < 1,
        "Subgroup checks too slow: {:?}",
        duration
    );
}
