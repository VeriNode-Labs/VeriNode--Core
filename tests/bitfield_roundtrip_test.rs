//! SSZ attestation-bitfield ordering tests (#9).
//!
//! Cargo only auto-discovers test targets at the top level of `tests/`, so this
//! lives here rather than at `tests/attestation/`.

use sorosusu_contracts::attestation::bitfield::AttestationBitfield;
use sorosusu_contracts::attestation::verifier::{
    sign_attestation, verify_attestation, AttestationData,
};
use sorosusu_contracts::crypto::domain::{compute_domain, DOMAIN_BEACON_ATTESTER, GENESIS_FORK_VERSION};
use sorosusu_contracts::network::ssz_codec::{
    decode_attestation_data, encode_attestation_data, ATTESTATION_DATA_SSZ_LEN,
};

use proptest::prelude::*;

fn sample_data() -> AttestationData {
    AttestationData {
        slot: 7,
        index: 3,
        beacon_block_root: [0xAA; 32],
        source_epoch: 1,
        source_root: [0xBB; 32],
        target_epoch: 2,
        target_root: [0xCC; 32],
    }
}

/// Regression for #9: a hard-coded wire bitfield must attribute set bits to the
/// correct validators under SSZ LSB0 ordering. An MSB0-within-byte regression
/// would mis-map every non-byte-aligned index (e.g. attribute validator 9 to
/// validator 14), so this pins indices 8..15 specifically.
#[test]
fn known_bitfield_attributes_validators_lsb0() {
    // 16-validator committee, two bytes.
    //   byte0 = 0b0000_0001 -> bit 0  -> validator 0
    //   byte1 = 0b0000_0010 -> bit 9  -> validator 9
    let wire = [0b0000_0001u8, 0b0000_0010u8];
    let bf = AttestationBitfield::from_ssz_bytes(&wire, 16).unwrap();

    for i in 0..16 {
        let expected = i == 0 || i == 9;
        assert_eq!(
            bf.is_attesting(i).unwrap(),
            expected,
            "validator {i} attribution mismatch"
        );
    }
}

/// Round-trip via SSZ bytes preserves every bit and stays canonical length.
#[test]
fn bitfield_roundtrip_fixed() {
    let mut bf = AttestationBitfield::with_committee_size(20).unwrap();
    for i in [0usize, 8, 9, 15, 16, 19] {
        bf.set(i, true).unwrap();
    }
    let wire = bf.to_ssz_bytes();
    assert_eq!(wire.len(), (20 + 7) / 8);

    let decoded = AttestationBitfield::from_ssz_bytes(&wire, 20).unwrap();
    assert_eq!(decoded, bf);
}

/// `verify_attestation` attributes signatures to the right validators. If bit 9
/// were mis-mapped, it would check a non-attesting validator's (zero) signature
/// and fail.
#[test]
fn verify_attestation_attributes_signatures_correctly() {
    let committee = 16usize;
    let domain = compute_domain(DOMAIN_BEACON_ATTESTER, GENESIS_FORK_VERSION);
    let data = sample_data();

    let keys: Vec<[u8; 32]> = (0..committee).map(|i| [i as u8; 32]).collect();

    let mut bf = AttestationBitfield::with_committee_size(committee).unwrap();
    bf.set(0, true).unwrap();
    bf.set(9, true).unwrap();

    let mut sigs = vec![[0u8; 32]; committee];
    sigs[0] = sign_attestation(&keys[0], &domain, &data);
    sigs[9] = sign_attestation(&keys[9], &domain, &data);

    assert!(verify_attestation(&bf, &keys, &domain, &data, &sigs));

    // A wrong signature for an attesting validator must fail verification.
    let mut bad = sigs.clone();
    bad[9] = [0xFF; 32];
    assert!(!verify_attestation(&bf, &keys, &domain, &data, &bad));
}

/// SSZ codec round-trips `AttestationData`.
#[test]
fn attestation_data_ssz_roundtrip() {
    let data = sample_data();
    let encoded = encode_attestation_data(&data);
    assert_eq!(encoded.len(), ATTESTATION_DATA_SSZ_LEN);

    let decoded = decode_attestation_data(&encoded).unwrap();
    assert_eq!(decoded, data);

    assert_eq!(decode_attestation_data(&[0u8; 1]), Err(
        sorosusu_contracts::network::ssz_codec::SszError::InvalidLength
    ));
}

proptest! {
    /// Fuzz: a random bit assignment serialized via SSZ and deserialized must
    /// reproduce every bit exactly, for any committee size in 1..=512.
    #[test]
    fn prop_bitfield_ssz_roundtrip(bits in prop::collection::vec(any::<bool>(), 1..=512usize)) {
        let mut bf = AttestationBitfield::with_committee_size(bits.len()).unwrap();
        for (i, b) in bits.iter().enumerate() {
            bf.set(i, *b).unwrap();
        }

        let wire = bf.to_ssz_bytes();
        prop_assert_eq!(wire.len(), (bits.len() + 7) / 8);

        let decoded = AttestationBitfield::from_ssz_bytes(&wire, bits.len()).unwrap();
        for (i, b) in bits.iter().enumerate() {
            prop_assert_eq!(decoded.get(i).unwrap(), *b);
            prop_assert_eq!(decoded.is_attesting(i).unwrap(), *b);
        }
    }
}
