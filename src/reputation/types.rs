use super::fixed_point::{Q16_16, Q32_32};

/// Maximum reputation score accepted by validator selection.
pub const MAX_REPUTATION: u64 = 1_000_000;

/// Default decay factor as a raw Q16.16 fraction: `round(65536 * 0.9985)`.
/// Note `65431/65536 = 0.99848938`, i.e. Q16.16 cannot represent `0.9985`.
pub const DEFAULT_DECAY_Q16: i64 = 65431;

/// Default decay factor as a raw Q32.32 fraction: `round(0.9985 * 2^32)`.
/// `4_288_524_845 / 2^32 = 0.99849999998697`, i.e. `0.9985` to ~1e-11.
pub const DEFAULT_DECAY_Q32: i64 = 4_288_524_845;

/// Per-epoch exponential decay factor, held in Q32.32 for precise compounding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecayFactor(pub Q32_32);

impl DecayFactor {
    /// Build from a raw Q16.16 fraction (e.g. `65431`), promoted to Q32.32.
    /// This preserves the public-API precision and is the lossy legacy factor.
    pub const fn from_q16_raw(raw: i64) -> Self {
        DecayFactor(Q16_16::from_raw(raw).to_q32_32())
    }

    /// Build directly from a raw Q32.32 fraction (full precision).
    pub const fn from_q32_raw(raw: i64) -> Self {
        DecayFactor(Q32_32(raw))
    }
}

impl Default for DecayFactor {
    /// `lambda = 0.9985` to full Q32.32 precision.
    fn default() -> Self {
        DecayFactor::from_q32_raw(DEFAULT_DECAY_Q32)
    }
}

/// A reputation score carried at Q32.32 internal precision.
///
/// Construct from an integer score, apply per-epoch decay any number of times,
/// then downsample with [`to_int`](Self::to_int) / [`to_q16_16`](Self::to_q16_16)
/// only when an external value is required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReputationScore {
    accumulator: Q32_32,
}

impl ReputationScore {
    /// Promote an integer score into the Q32.32 accumulator (clamped to range).
    pub fn from_int(score: u64) -> Self {
        ReputationScore {
            accumulator: Q32_32::from_int(score.min(MAX_REPUTATION) as i64),
        }
    }

    /// Wrap an existing Q32.32 accumulator.
    pub const fn from_accumulator(accumulator: Q32_32) -> Self {
        ReputationScore { accumulator }
    }

    /// The raw Q32.32 accumulator.
    pub const fn accumulator(self) -> Q32_32 {
        self.accumulator
    }

    /// Downsample to the public integer score (rounded, clamped to range).
    pub fn to_int(self) -> u64 {
        let value = self.accumulator.round_to_int();
        if value < 0 {
            0
        } else {
            (value as u64).min(MAX_REPUTATION)
        }
    }

    /// Downsample to the public Q16.16 representation.
    pub const fn to_q16_16(self) -> Q16_16 {
        self.accumulator.to_q16_16()
    }
}

/// EMA window size, expressed in epochs.
pub type WindowSize = u64;

/// Epochs elapsed since the validator reputation was last updated.
pub type TimeSinceLastUpdate = u64;

/// Reputation EMA parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmaWeights {
    pub window_epochs: WindowSize,
}

impl EmaWeights {
    pub const fn new(window_epochs: WindowSize) -> Self {
        Self { window_epochs }
    }
}

impl Default for EmaWeights {
    fn default() -> Self {
        Self::new(2048)
    }
}
