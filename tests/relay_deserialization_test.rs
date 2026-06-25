use sorosusu_contracts::network::message_codec::DeserializationError;
use sorosusu_contracts::slashing::cross_chain_relay::{deserialize_evidence, MAX_EVIDENCE_LENGTH};

fn message_with_payload(payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&1u32.to_be_bytes());
    message.extend_from_slice(&2u32.to_be_bytes());
    message.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    message.extend_from_slice(payload);
    message
}

#[test]
fn deserialize_evidence_rejects_oversized_declared_length_without_payload_allocation() {
    let mut message = Vec::new();
    message.extend_from_slice(&1u32.to_be_bytes());
    message.extend_from_slice(&2u32.to_be_bytes());
    message.extend_from_slice(&u32::MAX.to_be_bytes());

    let error = deserialize_evidence(&message).unwrap_err();
    assert_eq!(error, DeserializationError::OversizedPayload);
}

#[test]
fn deserialize_evidence_accepts_maximum_protocol_payload() {
    let payload = vec![7u8; MAX_EVIDENCE_LENGTH];
    let evidence = deserialize_evidence(&message_with_payload(&payload)).unwrap();

    assert_eq!(evidence.chain_id, 1);
    assert_eq!(evidence.msg_type, 2);
    assert_eq!(evidence.length, MAX_EVIDENCE_LENGTH as u32);
    assert_eq!(evidence.evidence, payload);
}

#[test]
fn deserialize_evidence_rejects_length_mismatch() {
    let mut message = message_with_payload(&[1, 2, 3]);
    message[11] = 4;

    let error = deserialize_evidence(&message).unwrap_err();
    assert_eq!(error, DeserializationError::LengthMismatch);
}

#[test]
fn fuzz_deserialize_evidence_never_panics_on_random_bytes() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;

    for _ in 0..10_000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let len = (state as usize) % 128;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            state = state
                .wrapping_mul(2862933555777941757)
                .wrapping_add(3037000493);
            bytes.push((state >> 32) as u8);
        }

        let _ = deserialize_evidence(&bytes);
    }
}
