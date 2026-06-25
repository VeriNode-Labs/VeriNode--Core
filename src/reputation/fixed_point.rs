//! Integer fixed-point primitives for reputation decay.
//!
//! Public reputation scores are integers in `[0, MAX_REPUTATION]`. Applying an
//! exponential decay `lambda` per epoch in Q16.16 (`score = (score * lambda)
//! >> 16`) truncates every epoch, and the public Q16.16 grid (1/65536) cannot
//! even represent `lambda = 0.9985` exactly — the nearest value is
//! `65431/65536 = 0.99848938`. Over thousands of epochs the representation gap
//! plus per-epoch truncation keep a long-idle score pinned above its true
//! value instead of decaying toward zero (#11).
//!
//! The fix compounds decay in Q32.32 (1/2^32 precision) and downsamples to the
//! public Q16.16 / integer representation only on read-out, so per-epoch
//! truncation is ~2^-32 score units and stays negligible across 10k+ epochs.

/// Fractional bits in the public Q16.16 representation.
pub const Q16_FRACTIONAL_BITS: u32 = 16;
/// Fractional bits in the internal Q32.32 accumulator.
pub const Q32_FRACTIONAL_BITS: u32 = 32;

const Q16_TO_Q32_SHIFT: u32 = Q32_FRACTIONAL_BITS - Q16_FRACTIONAL_BITS;

/// Q16.16 fixed-point value, `i64`-backed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Q16_16(pub i64);

/// Q32.32 fixed-point value, `i64`-backed — the decay accumulator domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Q32_32(pub i64);

impl Q16_16 {
    /// The value `1.0`.
    pub const ONE: Q16_16 = Q16_16(1 << Q16_FRACTIONAL_BITS);

    /// Wrap a raw Q16.16 fraction (e.g. `65431` represents `65431/65536`).
    pub const fn from_raw(raw: i64) -> Self {
        Q16_16(raw)
    }

    /// Promote an integer to Q16.16.
    pub const fn from_int(value: i64) -> Self {
        Q16_16(value << Q16_FRACTIONAL_BITS)
    }

    /// Promote to the Q32.32 accumulator domain (lossless).
    pub const fn to_q32_32(self) -> Q32_32 {
        Q32_32(self.0 << Q16_TO_Q32_SHIFT)
    }

    /// Round to the nearest integer.
    pub const fn round_to_int(self) -> i64 {
        let half = 1i64 << (Q16_FRACTIONAL_BITS - 1);
        (self.0 + half) >> Q16_FRACTIONAL_BITS
    }
}

impl Q32_32 {
    /// The value `1.0`.
    pub const ONE: Q32_32 = Q32_32(1 << Q32_FRACTIONAL_BITS);

    /// Promote an integer to Q32.32.
    pub const fn from_int(value: i64) -> Self {
        Q32_32(value << Q32_FRACTIONAL_BITS)
    }

    /// Multiply two Q32.32 values via `i128`, truncating the surplus fractional
    /// bits. Truncation here costs at most `2^-32` and does not compound into
    /// the integer read-out.
    pub fn mul(self, rhs: Q32_32) -> Q32_32 {
        let product = (self.0 as i128 * rhs.0 as i128) >> Q32_FRACTIONAL_BITS;
        Q32_32(product as i64)
    }

    /// Downsample to Q16.16 (truncating the extra fractional bits).
    pub const fn to_q16_16(self) -> Q16_16 {
        Q16_16(self.0 >> Q16_TO_Q32_SHIFT)
    }

    /// Round to the nearest integer.
    pub const fn round_to_int(self) -> i64 {
        let half = 1i64 << (Q32_FRACTIONAL_BITS - 1);
        (self.0 + half) >> Q32_FRACTIONAL_BITS
    }

    /// Truncate toward zero to an integer (floor for non-negative values).
    pub const fn trunc_to_int(self) -> i64 {
        self.0 >> Q32_FRACTIONAL_BITS
    }
}
