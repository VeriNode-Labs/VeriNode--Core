//! Minimal SSZ codec for the fixed-size `AttestationData` container.
//!
//! All integers are little-endian per the SSZ spec; the 32-byte roots are
//! fixed-length vectors emitted verbatim. The container is fixed-size, so its
//! encoding is the concatenation of its field encodings with no offsets.

extern crate alloc;
use alloc::vec::Vec;

use crate::attestation::verifier::AttestationData;
use crate::crypto::merkle::Hash256;

/// Serialized length of `AttestationData`:
/// `slot(8) + index(8) + beacon_block_root(32) + source_epoch(8)
///  + source_root(32) + target_epoch(8) + target_root(32)`.
pub const ATTESTATION_DATA_SSZ_LEN: usize = 8 + 8 + 32 + 8 + 32 + 8 + 32;

/// Errors produced while decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SszError {
    /// Input length did not equal [`ATTESTATION_DATA_SSZ_LEN`].
    InvalidLength,
}

/// SSZ-encode `AttestationData` into [`ATTESTATION_DATA_SSZ_LEN`] bytes.
pub fn encode_attestation_data(data: &AttestationData) -> Vec<u8> {
    let mut out = Vec::with_capacity(ATTESTATION_DATA_SSZ_LEN);
    out.extend_from_slice(&data.slot.to_le_bytes());
    out.extend_from_slice(&data.index.to_le_bytes());
    out.extend_from_slice(&data.beacon_block_root);
    out.extend_from_slice(&data.source_epoch.to_le_bytes());
    out.extend_from_slice(&data.source_root);
    out.extend_from_slice(&data.target_epoch.to_le_bytes());
    out.extend_from_slice(&data.target_root);
    out
}

/// SSZ-decode `AttestationData` from exactly [`ATTESTATION_DATA_SSZ_LEN`] bytes.
pub fn decode_attestation_data(bytes: &[u8]) -> Result<AttestationData, SszError> {
    if bytes.len() != ATTESTATION_DATA_SSZ_LEN {
        return Err(SszError::InvalidLength);
    }
    let mut offset = 0usize;
    let slot = read_u64(bytes, &mut offset);
    let index = read_u64(bytes, &mut offset);
    let beacon_block_root = read_h256(bytes, &mut offset);
    let source_epoch = read_u64(bytes, &mut offset);
    let source_root = read_h256(bytes, &mut offset);
    let target_epoch = read_u64(bytes, &mut offset);
    let target_root = read_h256(bytes, &mut offset);
    Ok(AttestationData {
        slot,
        index,
        beacon_block_root,
        source_epoch,
        source_root,
        target_epoch,
        target_root,
    })
}

fn read_u64(bytes: &[u8], offset: &mut usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[*offset..*offset + 8]);
    *offset += 8;
    u64::from_le_bytes(buf)
}

fn read_h256(bytes: &[u8], offset: &mut usize) -> Hash256 {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes[*offset..*offset + 32]);
    *offset += 32;
    buf
}
