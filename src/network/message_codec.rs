use alloc::vec::Vec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeserializationError {
    TruncatedEnvelope,
    TruncatedLengthPrefix,
    TruncatedPayload,
    OversizedPayload,
    LengthMismatch,
}

/// Read the 4-byte big-endian payload length that follows the 8-byte relay envelope.
pub fn read_varint_length(message: &[u8]) -> Result<u32, DeserializationError> {
    let length_bytes = message
        .get(8..12)
        .ok_or(DeserializationError::TruncatedLengthPrefix)?;

    Ok(u32::from_be_bytes([
        length_bytes[0],
        length_bytes[1],
        length_bytes[2],
        length_bytes[3],
    ]))
}

/// Copy a bounded payload from the relay message without allocating from an untrusted length.
pub fn read_payload(
    message: &[u8],
    declared_length: usize,
    max_length: usize,
) -> Result<Vec<u8>, DeserializationError> {
    if message.len() < 8 {
        return Err(DeserializationError::TruncatedEnvelope);
    }

    if declared_length > max_length {
        return Err(DeserializationError::OversizedPayload);
    }

    let payload = message
        .get(12..)
        .ok_or(DeserializationError::TruncatedPayload)?;
    if payload.len() != declared_length {
        return Err(DeserializationError::LengthMismatch);
    }

    let mut evidence = Vec::with_capacity(core::cmp::min(declared_length, max_length));
    evidence.extend_from_slice(payload);
    Ok(evidence)
}
