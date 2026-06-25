use crate::network::message_codec::{read_payload, read_varint_length, DeserializationError};
use crate::slashing::types::RelayedSlashingEvidence;

/// Protocol maximum for relayed slashing evidence payloads.
pub const MAX_EVIDENCE_LENGTH: usize = 4096;
const ENVELOPE_LENGTH: usize = 8;
const LENGTH_PREFIX_LENGTH: usize = 4;
const HEADER_LENGTH: usize = ENVELOPE_LENGTH + LENGTH_PREFIX_LENGTH;

pub fn deserialize_evidence(
    message: &[u8],
) -> Result<RelayedSlashingEvidence, DeserializationError> {
    if message.len() < ENVELOPE_LENGTH {
        return Err(DeserializationError::TruncatedEnvelope);
    }

    let chain_id = u32::from_be_bytes([message[0], message[1], message[2], message[3]]);
    let msg_type = u32::from_be_bytes([message[4], message[5], message[6], message[7]]);
    let declared_length = read_varint_length(message)?;
    let declared_length_usize =
        usize::try_from(declared_length).map_err(|_| DeserializationError::OversizedPayload)?;

    if declared_length_usize > MAX_EVIDENCE_LENGTH {
        return Err(DeserializationError::OversizedPayload);
    }

    if message.len() < HEADER_LENGTH {
        return Err(DeserializationError::TruncatedLengthPrefix);
    }

    let evidence = read_payload(message, declared_length_usize, MAX_EVIDENCE_LENGTH)?;
    if evidence.len() != declared_length_usize {
        return Err(DeserializationError::LengthMismatch);
    }

    Ok(RelayedSlashingEvidence {
        chain_id,
        msg_type,
        length: declared_length,
        evidence,
    })
}

pub fn process_relayed_slashing(
    message: &[u8],
) -> Result<RelayedSlashingEvidence, DeserializationError> {
    deserialize_evidence(message)
}
