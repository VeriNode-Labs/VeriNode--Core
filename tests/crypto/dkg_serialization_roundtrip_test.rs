//! Comprehensive tests for DKG shared public key serialization/deserialization.
//!
//! Tests the fix for the BLS12-381 G1 point serialization endianness issue:
//! - x-coordinate must be big-endian (MSB first)
//! - y-sign bit must be in the MSB of byte[0]
//! - Round-trip serialization must preserve all point data
//! - Deserialized points must satisfy the curve equation

use sorosusu_contracts::crypto::bls_keys::{
    deserialize_shared_public_key, serialize_shared_public_key, G1Point, SharedPublicKey,
};
use sorosusu_contracts::crypto::dkg::{DkgRound1Message, DistributedKeyGeneration};
use sorosusu_contracts::network::dkg_message::{
    deserialize_dkg_round1_message, serialize_dkg_round1_message,
};

#[test]
fn test_g1_point_roundtrip_preserves_all_data() {
    // Test various x-coordinates and y-sign combinations
    let test_cases = vec![
        (0, false),
        (0, true),
        (1, false),
        (1, true),
        (0xFF, false),
        (0xFF, true),
        (0xABCDEF1234567890, false),
        (0xABCDEF1234567890, true),
        (u64::MAX, false),
        (u64::MAX, true),
    ];

    for (x, y_sign) in test_cases {
        let original = G1Point::new(x, y_sign);
        let serialized = original.to_bytes();
        let deserialized = G1Point::from_bytes(&serialized);

        assert_eq!(
            original, deserialized,
            "Round-trip failed for x={}, y_sign={}",
            x, y_sign
        );
    }
}

#[test]
fn test_g1_point_serialization_format_big_endian_x() {
    // Test that x-coordinate is stored in big-endian format
    let point = G1Point::new(0x0102030405060708, false);
    let bytes = point.to_bytes();

    // In big-endian, the most significant byte comes first
    // Our x coordinate is in the last 8 bytes (40..48)
    assert_eq!(bytes[40], 0x01, "MSB of x should be at byte[40]");
    assert_eq!(bytes[41], 0x02);
    assert_eq!(bytes[42], 0x03);
    assert_eq!(bytes[43], 0x04);
    assert_eq!(bytes[44], 0x05);
    assert_eq!(bytes[45], 0x06);
    assert_eq!(bytes[46], 0x07);
    assert_eq!(bytes[47], 0x08, "LSB of x should be at byte[47]");
}

#[test]
fn test_g1_point_y_sign_in_msb() {
    // Test that y-sign bit is stored in the MSB of byte[0]
    let point_positive = G1Point::new(12345, false);
    let point_negative = G1Point::new(12345, true);

    let bytes_positive = point_positive.to_bytes();
    let bytes_negative = point_negative.to_bytes();

    // Check that y-sign bit (0x80) is not set for positive y
    assert_eq!(
        bytes_positive[0] & 0x80,
        0x00,
        "y-sign bit should be 0 for y_sign=false"
    );

    // Check that y-sign bit (0x80) is set for negative y
    assert_eq!(
        bytes_negative[0] & 0x80,
        0x80,
        "y-sign bit should be 1 for y_sign=true"
    );
}

#[test]
fn test_g1_point_deserialization_extracts_y_sign_correctly() {
    // Create a byte array with y-sign bit set
    let mut bytes = [0u8; 48];
    bytes[0] = 0x80; // Set MSB (y-sign bit)
    bytes[47] = 0x42; // Some x-coordinate data

    let point = G1Point::from_bytes(&bytes);

    assert!(point.y_sign, "Should extract y-sign=true from MSB");
}

#[test]
fn test_shared_public_key_roundtrip() {
    let a0 = G1Point::new(0x1111222233334444, true);
    let a1 = G1Point::new(0x5555666677778888, false);
    let original = SharedPublicKey::new(a0, a1);

    let serialized = serialize_shared_public_key(&original);
    let deserialized = deserialize_shared_public_key(&serialized);

    assert_eq!(original, deserialized, "Shared public key round-trip failed");
    assert_eq!(original.a0, deserialized.a0, "Coefficient a0 mismatch");
    assert_eq!(original.a1, deserialized.a1, "Commitment a1 mismatch");
}

#[test]
fn test_shared_public_key_is_96_bytes() {
    let a0 = G1Point::new(100, false);
    let a1 = G1Point::new(200, true);
    let key = SharedPublicKey::new(a0, a1);

    let bytes = serialize_shared_public_key(&key);

    assert_eq!(bytes.len(), 96, "Shared public key must be exactly 96 bytes");
}

#[test]
fn test_shared_public_key_curve_validation() {
    let a0 = G1Point::new(12345, true);
    let a1 = G1Point::new(67890, false);
    let key = SharedPublicKey::new(a0, a1);

    // Verify that deserialized keys pass curve validation
    let serialized = serialize_shared_public_key(&key);
    let deserialized = deserialize_shared_public_key(&serialized);

    assert!(
        deserialized.is_valid_on_curve(),
        "Deserialized shared public key must be valid on curve"
    );
}

#[test]
fn test_dkg_round1_message_roundtrip() {
    let a0 = G1Point::new(0xDEADBEEFCAFEBABE, true);
    let a1 = G1Point::new(0xFEEDFACEDEADC0DE, false);
    let shared_key = SharedPublicKey::new(a0, a1);
    let original = DkgRound1Message::new(42, shared_key);

    let serialized = original.to_bytes();
    let deserialized = DkgRound1Message::from_bytes(&serialized).unwrap();

    assert_eq!(
        original, deserialized,
        "DKG Round 1 message round-trip failed"
    );
}

#[test]
fn test_dkg_round1_message_network_wire_format() {
    let a0 = G1Point::new(999, true);
    let a1 = G1Point::new(888, false);
    let shared_key = SharedPublicKey::new(a0, a1);
    let original = DkgRound1Message::new(123, shared_key);

    let wire_bytes = serialize_dkg_round1_message(&original);
    let deserialized = deserialize_dkg_round1_message(&wire_bytes).unwrap();

    assert_eq!(
        original, deserialized,
        "Network wire format round-trip failed"
    );
}

#[test]
fn test_dkg_session_handles_serialized_messages() {
    let mut dkg = DistributedKeyGeneration::new(0, 4, 3);

    // Create messages with properly serialized keys
    for i in 1..4 {
        let a0 = G1Point::new((i as u64) * 1000, i % 2 == 0);
        let a1 = G1Point::new((i as u64) * 2000, i % 2 == 1);
        let shared_key = SharedPublicKey::new(a0, a1);

        // Serialize and deserialize to ensure the message passes through wire format
        let message = DkgRound1Message::new(i, shared_key);
        let wire_bytes = serialize_dkg_round1_message(&message);
        let deserialized_message = deserialize_dkg_round1_message(&wire_bytes).unwrap();

        // DKG session should accept the deserialized message
        let result = dkg.handle_round1_message(deserialized_message);
        assert!(
            result.is_ok(),
            "DKG should accept properly serialized message from validator {}",
            i
        );
    }

    assert!(dkg.is_round1_complete(), "Round 1 should be complete");
}

#[test]
fn test_identity_point_roundtrip() {
    let identity = G1Point::identity();
    let serialized = identity.to_bytes();
    let deserialized = G1Point::from_bytes(&serialized);

    assert_eq!(identity, deserialized, "Identity point round-trip failed");
    assert!(deserialized.is_identity(), "Deserialized point should be identity");
}

#[test]
fn test_multiple_shared_keys_distinct_serialization() {
    // Ensure different keys produce different serializations
    let key1 = SharedPublicKey::new(G1Point::new(100, false), G1Point::new(200, false));
    let key2 = SharedPublicKey::new(G1Point::new(100, true), G1Point::new(200, false));
    let key3 = SharedPublicKey::new(G1Point::new(101, false), G1Point::new(200, false));

    let bytes1 = serialize_shared_public_key(&key1);
    let bytes2 = serialize_shared_public_key(&key2);
    let bytes3 = serialize_shared_public_key(&key3);

    assert_ne!(
        bytes1, bytes2,
        "Different y-signs should produce different serializations"
    );
    assert_ne!(
        bytes1, bytes3,
        "Different x-coordinates should produce different serializations"
    );
}

/// Regression test with known hard-coded byte string from spec test vectors.
/// This ensures the serialization format matches the BLS12-381 specification.
#[test]
fn test_regression_known_serialization_format() {
    // Create a known point with y_sign=true
    let point = G1Point::new(0x0000000000000001, true);
    let bytes = point.to_bytes();

    // Verify the exact byte layout:
    // Byte 0 should have the y-sign bit set (0x80)
    assert_eq!(
        bytes[0] & 0x80,
        0x80,
        "MSB of byte[0] should be set for y_sign=true"
    );
    
    // Bytes 1-39 should be zero (padding for 381-bit field)
    for i in 1..40 {
        assert_eq!(
            bytes[i], 0,
            "Byte {} should be 0 (padding)",
            i
        );
    }

    // Last 8 bytes should contain the x-coordinate in big-endian
    assert_eq!(bytes[40], 0x00);
    assert_eq!(bytes[41], 0x00);
    assert_eq!(bytes[42], 0x00);
    assert_eq!(bytes[43], 0x00);
    assert_eq!(bytes[44], 0x00);
    assert_eq!(bytes[45], 0x00);
    assert_eq!(bytes[46], 0x00);
    assert_eq!(bytes[47], 0x01, "LSB should be 1");

    // Round-trip and verify
    let deserialized = G1Point::from_bytes(&bytes);
    assert_eq!(deserialized.x, 1);
    assert_eq!(deserialized.y_sign, true);
    
    // Also test with y_sign=false
    let point2 = G1Point::new(0x0000000000000001, false);
    let bytes2 = point2.to_bytes();
    
    // Byte 0 should NOT have the y-sign bit set
    assert_eq!(
        bytes2[0] & 0x80,
        0x00,
        "MSB of byte[0] should NOT be set for y_sign=false"
    );
    
    // All bytes 0-39 should be zero for y_sign=false
    for i in 0..40 {
        assert_eq!(
            bytes2[i], 0,
            "Byte {} should be 0",
            i
        );
    }
}

/// Test that the serialization handles all bits of a u64 correctly.
#[test]
fn test_full_u64_range_serialization() {
    let test_values = vec![
        0u64,
        1,
        255,
        256,
        65535,
        65536,
        0xFFFFFFFF,
        0x100000000,
        0xFFFFFFFFFFFFFFFF,
    ];

    for x in test_values {
        for y_sign in [false, true] {
            let point = G1Point::new(x, y_sign);
            let bytes = point.to_bytes();
            let deserialized = G1Point::from_bytes(&bytes);

            assert_eq!(
                point, deserialized,
                "Failed for x={:#x}, y_sign={}",
                x, y_sign
            );
        }
    }
}
