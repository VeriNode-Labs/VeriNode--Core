//! SSZ-compatible attestation bitfield with explicit LSB0 ordering.
//!
//! Fixes #9: the wire format (SSZ) stores bit `i` in byte `i / 8` at offset
//! `i % 8` — little-endian byte order, least-significant-bit-first within the
//! byte (LSB0). The committee-assignment mapping previously applied the
//! opposite (MSB0-within-byte) transform at the verifier call site, so every
//! validator whose index was not byte-aligned (`i % 8 != 0`, most visibly
//! indices 8..15) was attributed the wrong attestation bit — surfacing as
//! ~12.5% spurious signature-verification failures for honest validators.
//!
//! This type pins the LSB0 convention in `get`/`set`/`from_ssz_bytes`/
//! `to_ssz_bytes` and exposes a single mapping seam, [`committee_index`], that
//! the verifier must route through.
//!
//! [`committee_index`]: AttestationBitfield::committee_index

extern crate alloc;
use alloc::vec::Vec;

/// Maximum committee size (bits) supported by an attestation bitfield.
pub const MAX_COMMITTEE_SIZE: usize = 512;

/// Errors produced when constructing or indexing a bitfield.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitfieldError {
    /// `committee_size` exceeds [`MAX_COMMITTEE_SIZE`].
    CommitteeTooLarge,
    /// The byte slice length does not equal `(committee_size + 7) / 8`.
    LengthMismatch,
    /// A bit index is `>= committee_size`.
    IndexOutOfBounds,
}

/// Number of bytes required to hold `committee_size` bits.
#[inline]
fn byte_count(committee_size: usize) -> usize {
    (committee_size + 7) / 8
}

/// A fixed-size attestation bitfield (`Bitvector[committee_size]`), one bit per
/// validator in the committee, encoded in SSZ LSB0 order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationBitfield {
    bytes: Vec<u8>,
    len: usize,
}

impl AttestationBitfield {
    /// Create a zeroed bitfield for `committee_size` validators.
    pub fn with_committee_size(committee_size: usize) -> Result<Self, BitfieldError> {
        if committee_size > MAX_COMMITTEE_SIZE {
            return Err(BitfieldError::CommitteeTooLarge);
        }
        let mut bytes = Vec::new();
        bytes.resize(byte_count(committee_size), 0u8);
        Ok(Self {
            bytes,
            len: committee_size,
        })
    }

    /// Number of validators (bits) the bitfield covers.
    pub fn committee_size(&self) -> usize {
        self.len
    }

    /// Number of bytes in the SSZ encoding.
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    /// Map a logical validator position within the committee to its bit
    /// position in the bitfield.
    ///
    /// SSZ uses LSB0 ordering, under which the mapping is the identity:
    /// validator `i` occupies bit `i` (byte `i / 8`, offset `i % 8`). This is
    /// the *single seam* where the logical→wire mapping lives; the verifier
    /// must index through here rather than transforming indices itself.
    #[inline]
    pub fn committee_index(validator_index: usize) -> usize {
        validator_index
    }

    /// Read bit `i` using SSZ LSB0 ordering.
    pub fn get(&self, i: usize) -> Result<bool, BitfieldError> {
        if i >= self.len {
            return Err(BitfieldError::IndexOutOfBounds);
        }
        Ok((self.bytes[i / 8] >> (i % 8)) & 1 == 1)
    }

    /// Set bit `i` to `value` using SSZ LSB0 ordering.
    pub fn set(&mut self, i: usize, value: bool) -> Result<(), BitfieldError> {
        if i >= self.len {
            return Err(BitfieldError::IndexOutOfBounds);
        }
        let mask = 1u8 << (i % 8);
        if value {
            self.bytes[i / 8] |= mask;
        } else {
            self.bytes[i / 8] &= !mask;
        }
        Ok(())
    }

    /// Whether the validator at logical committee position `validator_index`
    /// attested. Routes through [`committee_index`](Self::committee_index) so
    /// the ordering always matches the SSZ wire format.
    pub fn is_attesting(&self, validator_index: usize) -> Result<bool, BitfieldError> {
        self.get(Self::committee_index(validator_index))
    }

    /// Deserialize from SSZ wire bytes for a committee of `committee_size`.
    ///
    /// The slice must be exactly `(committee_size + 7) / 8` bytes. Any padding
    /// bits above `committee_size` in the final byte are cleared so the
    /// in-memory representation is canonical.
    pub fn from_ssz_bytes(bytes: &[u8], committee_size: usize) -> Result<Self, BitfieldError> {
        if committee_size > MAX_COMMITTEE_SIZE {
            return Err(BitfieldError::CommitteeTooLarge);
        }
        if bytes.len() != byte_count(committee_size) {
            return Err(BitfieldError::LengthMismatch);
        }
        let mut v = Vec::new();
        v.extend_from_slice(bytes);
        let rem = committee_size % 8;
        if rem != 0 {
            let mask = (1u8 << rem) - 1;
            let last = v.len() - 1;
            v[last] &= mask;
        }
        Ok(Self {
            bytes: v,
            len: committee_size,
        })
    }

    /// Serialize to SSZ wire bytes (LSB0), `(committee_size + 7) / 8` bytes.
    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}
