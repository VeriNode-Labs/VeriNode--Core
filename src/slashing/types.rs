extern crate alloc;

use alloc::vec::Vec;
use core::ops::{Add, AddAssign, Deref, Sub, SubAssign};

/// Monotonically increasing epoch identifier.
pub type EpochIndex = u64;

/// Unique identifier for a consensus validator.
pub type ValidatorIndex = u64;

/// Default historical window size in epochs (4096 epochs ~ 18.2 days).
pub const DEFAULT_SLASHING_WINDOW: usize = 4096;

/// Alias for window size constant.
pub const WINDOW: usize = DEFAULT_SLASHING_WINDOW;

/// Alias for window size constant.
pub const WINDOW_SIZE: usize = DEFAULT_SLASHING_WINDOW;

/// Maximum value for a 16-bit window generation before wrapping.
pub const MAX_WINDOW_GENERATION: u16 = u16::MAX;

/// A validated offset within the historical slashing window.
/// Wraps a `u16` and guarantees safe, saturating arithmetic.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WindowOffset(pub u16);

impl WindowOffset {
    /// Create a new WindowOffset from a raw `u16`.
    #[inline]
    pub const fn new(offset: u16) -> Self {
        Self(offset)
    }

    /// Return the raw `u16` offset value.
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Return the offset as `usize` for array/slice indexing.
    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }

    /// Computes `self + rhs`, saturating at the numeric bounds instead of overflowing.
    #[inline]
    pub fn saturating_add(self, rhs: u16) -> Self {
        WindowOffset(self.0.saturating_add(rhs))
    }

    /// Computes `self - rhs`, saturating at the numeric bounds instead of overflowing.
    #[inline]
    pub fn saturating_sub(self, rhs: u16) -> Self {
        WindowOffset(self.0.saturating_sub(rhs))
    }

    /// Checked integer addition. Computes `self + rhs`, returning `None` if overflow occurred.
    #[inline]
    pub fn checked_add(self, rhs: u16) -> Option<Self> {
        self.0.checked_add(rhs).map(WindowOffset)
    }

    /// Checked integer subtraction. Computes `self - rhs`, returning `None` if overflow occurred.
    #[inline]
    pub fn checked_sub(self, rhs: u16) -> Option<Self> {
        self.0.checked_sub(rhs).map(WindowOffset)
    }

    /// Computes `(self + rhs) % modulus` safely without overflowing.
    #[inline]
    pub fn wrapping_add_mod(self, rhs: u16, modulus: u16) -> Self {
        if modulus == 0 {
            return self;
        }
        let wide = (self.0 as u32) + (rhs as u32);
        WindowOffset((wide % (modulus as u32)) as u16)
    }
}

impl Deref for WindowOffset {
    type Target = u16;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<u16> for WindowOffset {
    #[inline]
    fn from(val: u16) -> Self {
        WindowOffset(val)
    }
}

impl From<WindowOffset> for u16 {
    #[inline]
    fn from(offset: WindowOffset) -> Self {
        offset.0
    }
}

impl From<WindowOffset> for usize {
    #[inline]
    fn from(offset: WindowOffset) -> Self {
        offset.0 as usize
    }
}

impl Add<u16> for WindowOffset {
    type Output = Self;

    #[inline]
    fn add(self, rhs: u16) -> Self::Output {
        self.saturating_add(rhs)
    }
}

impl Sub<u16> for WindowOffset {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: u16) -> Self::Output {
        self.saturating_sub(rhs)
    }
}

impl AddAssign<u16> for WindowOffset {
    #[inline]
    fn add_assign(&mut self, rhs: u16) {
        self.0 = self.0.saturating_add(rhs);
    }
}

impl SubAssign<u16> for WindowOffset {
    #[inline]
    fn sub_assign(&mut self, rhs: u16) {
        self.0 = self.0.saturating_sub(rhs);
    }
}

/// Generational tracking tag for an accumulator window slot.
/// Prevents rollover collisions by pairing a 16-bit window generation
/// with a 16-bit window offset.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GenerationalTag {
    /// The generation of the historical window rollover.
    pub window_generation: u16,
    /// Offset within the current window.
    pub offset: WindowOffset,
}

impl GenerationalTag {
    /// Create a new GenerationalTag.
    #[inline]
    pub const fn new(window_generation: u16, offset: WindowOffset) -> Self {
        Self {
            window_generation,
            offset,
        }
    }

    /// Derive a generational tag from an absolute `EpochIndex` and window size.
    #[inline]
    pub fn from_epoch(epoch: EpochIndex, window_size: usize) -> Self {
        let win = window_size as u64;
        let offset = WindowOffset((epoch.wrapping_rem(win)) as u16);
        let window_generation = ((epoch / win).wrapping_rem(65536)) as u16;
        Self {
            window_generation,
            offset,
        }
    }

    /// Validate whether this tag matches the expected generation and offset for an epoch.
    #[inline]
    pub fn matches_epoch(&self, epoch: EpochIndex, window_size: usize) -> bool {
        let expected = Self::from_epoch(epoch, window_size);
        self.window_generation == expected.window_generation && self.offset == expected.offset
    }
}

/// A recorded slashing entry linking a validator, epoch, and generational coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingRecord {
    pub validator_index: ValidatorIndex,
    pub epoch: EpochIndex,
    pub window_generation: u16,
    pub offset: WindowOffset,
}

impl SlashingRecord {
    /// Create a new SlashingRecord.
    pub fn new(validator_index: ValidatorIndex, epoch: EpochIndex, window_size: usize) -> Self {
        let tag = GenerationalTag::from_epoch(epoch, window_size);
        Self {
            validator_index,
            epoch,
            window_generation: tag.window_generation,
            offset: tag.offset,
        }
    }

    /// Return the generational tag for this record.
    pub fn generational_tag(&self) -> GenerationalTag {
        GenerationalTag {
            window_generation: self.window_generation,
            offset: self.offset,
        }
    }
}

/// Snapshot summary of slashing accumulator state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingAccumulatorState {
    pub current_epoch: EpochIndex,
    pub window_generation: u16,
    pub window_size: u16,
    pub total_slashed_count: u64,
}

/// Error types encountered during slashing condition evaluation and accumulator operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlashingError {
    AlreadySlashed,
    InvalidEpoch,
    WindowExpired,
    AccumulatorCapacityReached,
    GenerationalMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayedSlashingEvidence {
    pub chain_id: u32,
    pub msg_type: u32,
    pub length: u32,
    pub evidence: Vec<u8>,
}
