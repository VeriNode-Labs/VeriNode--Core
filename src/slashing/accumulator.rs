//! Generational Slashing Accumulator.
//!
//! Fixes Issue #145: historical epoch limit integer overflow and wrap collision
//! during accumulator rollover.
//!
//! Naive rolling window accumulators indexed solely by `epoch % WINDOW` suffer from
//! false positive collisions when the epoch rolls over past `WINDOW` (e.g. epoch 0
//! colliding with epoch 4096 or epoch 65536). Furthermore, 16-bit epoch counters
//! overflow at 2^16 (65536).
//!
//! This module implements generational window tracking:
//! 1. `EpochIndex` is 64-bit (`u64`).
//! 2. Window offset is computed via `epoch.wrapping_rem(WINDOW as u64) as u16`.
//! 3. Generational tags (`window_generation: u16`) are validated on every lookup.
//! 4. `record_slashing()` clears any obsolete historical tag for the validator and
//!    updates the active generational tag and bit state.
//! 5. `check_slashed()` verifies both the bit state AND the generation tag.

extern crate alloc;

use crate::slashing::types::{
    EpochIndex, GenerationalTag, SlashingAccumulatorState, SlashingRecord, ValidatorIndex,
    WindowOffset, DEFAULT_SLASHING_WINDOW,
};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Internal validator state tracked within the accumulator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSlashingState {
    pub bit_state: bool,
    pub generation: u16,
    pub offset: WindowOffset,
    pub epoch: EpochIndex,
}

/// Generational accumulator preventing rollover wrap collisions across epochs.
#[derive(Clone, Debug)]
pub struct SlashingAccumulator {
    window_size: usize,
    /// Complete validator state map.
    validators: BTreeMap<ValidatorIndex, ValidatorSlashingState>,
    /// Map from window offset to (validator_index -> window_generation).
    offset_entries: BTreeMap<u16, BTreeMap<ValidatorIndex, u16>>,
    /// Slashed validator bit state.
    bit_states: BTreeMap<ValidatorIndex, bool>,
    /// Generational tags indexed by validator_index.
    generational_tags: BTreeMap<ValidatorIndex, GenerationalTag>,
    /// Latest observed epoch.
    current_epoch: EpochIndex,
    /// Latest window generation.
    window_generation: u16,
    /// Total slashing events recorded.
    total_slashed: u64,
}

impl SlashingAccumulator {
    /// Create a new SlashingAccumulator with the default window size (4096 epochs).
    pub fn new() -> Self {
        Self::with_window_size(DEFAULT_SLASHING_WINDOW)
    }

    /// Create a new SlashingAccumulator with a custom window size.
    pub fn with_window_size(window_size: usize) -> Self {
        let actual_size = if window_size == 0 {
            DEFAULT_SLASHING_WINDOW
        } else {
            window_size
        };
        Self {
            window_size: actual_size,
            validators: BTreeMap::new(),
            offset_entries: BTreeMap::new(),
            bit_states: BTreeMap::new(),
            generational_tags: BTreeMap::new(),
            current_epoch: 0,
            window_generation: 0,
            total_slashed: 0,
        }
    }

    /// Configured window size in epochs.
    #[inline]
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// Latest tracked epoch.
    #[inline]
    pub fn current_epoch(&self) -> EpochIndex {
        self.current_epoch
    }

    /// Latest tracked window generation.
    #[inline]
    pub fn current_generation(&self) -> u16 {
        self.window_generation
    }

    /// Compute the window offset for a given epoch.
    #[inline]
    pub fn compute_offset(&self, epoch: EpochIndex) -> WindowOffset {
        WindowOffset((epoch.wrapping_rem(self.window_size as u64)) as u16)
    }

    /// Compute the window generation for a given epoch.
    #[inline]
    pub fn compute_generation(&self, epoch: EpochIndex) -> u16 {
        ((epoch / (self.window_size as u64)).wrapping_rem(65536)) as u16
    }

    /// Derive the generational tag for a given epoch.
    #[inline]
    pub fn compute_tag(&self, epoch: EpochIndex) -> GenerationalTag {
        GenerationalTag {
            window_generation: self.compute_generation(epoch),
            offset: self.compute_offset(epoch),
        }
    }

    /// Record a slashing event for a validator at a specific epoch.
    /// Clears any previous generational tags/offset mappings for the validator and updates
    /// both the bit state and generational tag.
    pub fn record_slashing(
        &mut self,
        validator_index: ValidatorIndex,
        epoch: EpochIndex,
    ) -> SlashingRecord {
        let offset = self.compute_offset(epoch);
        let gen = self.compute_generation(epoch);
        let tag = GenerationalTag {
            window_generation: gen,
            offset,
        };

        // Clear previous generational tag and offset entry for this validator if previously recorded
        if let Some(old_state) = self.validators.get(&validator_index) {
            let old_offset = old_state.offset.0;
            if let Some(validators_at_offset) = self.offset_entries.get_mut(&old_offset) {
                validators_at_offset.remove(&validator_index);
            }
        }

        // Update generational tags and bit state for the validator
        self.generational_tags.insert(validator_index, tag);
        self.bit_states.insert(validator_index, true);
        self.validators.insert(
            validator_index,
            ValidatorSlashingState {
                bit_state: true,
                generation: gen,
                offset,
                epoch,
            },
        );

        self.offset_entries
            .entry(offset.0)
            .or_default()
            .insert(validator_index, gen);

        if epoch > self.current_epoch {
            self.current_epoch = epoch;
            self.window_generation = gen;
        }

        self.total_slashed = self.total_slashed.saturating_add(1);

        SlashingRecord {
            validator_index,
            epoch,
            window_generation: gen,
            offset,
        }
    }

    /// Check if a validator was slashed in a specific epoch.
    /// Compares BOTH bit state AND generational tag (window_generation + offset).
    pub fn check_slashed(&self, validator_index: ValidatorIndex, epoch: EpochIndex) -> bool {
        let expected_offset = self.compute_offset(epoch);
        let expected_gen = self.compute_generation(epoch);

        // 1. Compare bit state: must be marked slashed
        let bit = self
            .bit_states
            .get(&validator_index)
            .copied()
            .unwrap_or(false);
        if !bit {
            return false;
        }

        // 2. Compare generational tag: generation and offset must match
        if let Some(tag) = self.generational_tags.get(&validator_index) {
            if tag.window_generation == expected_gen && tag.offset == expected_offset {
                if let Some(state) = self.validators.get(&validator_index) {
                    return state.bit_state
                        && state.generation == expected_gen
                        && state.offset == expected_offset;
                }
                return true;
            }
        }

        false
    }

    /// Check if a validator is currently slashed within the active historical window
    /// relative to `current_epoch`.
    pub fn is_slashed_in_window(
        &self,
        validator_index: ValidatorIndex,
        current_epoch: EpochIndex,
    ) -> bool {
        let bit = self
            .bit_states
            .get(&validator_index)
            .copied()
            .unwrap_or(false);
        if !bit {
            return false;
        }

        if let Some(state) = self.validators.get(&validator_index) {
            if !state.bit_state {
                return false;
            }
            if current_epoch >= state.epoch
                && current_epoch.saturating_sub(state.epoch) < (self.window_size as u64)
            {
                return true;
            }
        }

        false
    }

    /// Retrieve the slashing record for a validator, if active.
    pub fn get_slashing_record(&self, validator_index: ValidatorIndex) -> Option<SlashingRecord> {
        self.validators.get(&validator_index).and_then(|state| {
            if state.bit_state {
                Some(SlashingRecord {
                    validator_index,
                    epoch: state.epoch,
                    window_generation: state.generation,
                    offset: state.offset,
                })
            } else {
                None
            }
        })
    }

    /// Retrieve the generational tag for a validator.
    pub fn get_generational_tag(&self, validator_index: ValidatorIndex) -> Option<GenerationalTag> {
        self.generational_tags.get(&validator_index).copied()
    }

    /// Retrieve the raw bit state for a validator.
    pub fn get_bit_state(&self, validator_index: ValidatorIndex) -> bool {
        self.bit_states
            .get(&validator_index)
            .copied()
            .unwrap_or(false)
    }

    /// Clear all slashing state for a validator.
    pub fn clear_validator(&mut self, validator_index: ValidatorIndex) {
        if let Some(old_state) = self.validators.remove(&validator_index) {
            if let Some(validators_at_offset) = self.offset_entries.get_mut(&old_state.offset.0) {
                validators_at_offset.remove(&validator_index);
            }
        }
        self.generational_tags.remove(&validator_index);
        self.bit_states.remove(&validator_index);
    }

    /// Clear all entries for a specific offset and window generation.
    pub fn clear_window_offset(&mut self, offset: WindowOffset, generation: u16) {
        if let Some(validators_at_offset) = self.offset_entries.get_mut(&offset.0) {
            let to_remove: Vec<ValidatorIndex> = validators_at_offset
                .iter()
                .filter(|(_, &gen)| gen == generation)
                .map(|(&val, _)| val)
                .collect();

            for val in to_remove {
                validators_at_offset.remove(&val);
                if let Some(tag) = self.generational_tags.get(&val) {
                    if tag.window_generation == generation && tag.offset == offset {
                        self.generational_tags.remove(&val);
                        self.bit_states.remove(&val);
                        self.validators.remove(&val);
                    }
                }
            }
        }
    }

    /// Advance accumulator current epoch.
    pub fn advance_to_epoch(&mut self, new_epoch: EpochIndex) {
        if new_epoch > self.current_epoch {
            self.current_epoch = new_epoch;
            self.window_generation = self.compute_generation(new_epoch);
        }
    }

    /// Total count of slashing events recorded over time.
    pub fn total_slashed(&self) -> u64 {
        self.total_slashed
    }

    /// Number of validators currently marked as slashed.
    pub fn active_slashed_count(&self) -> usize {
        self.bit_states.values().filter(|&&b| b).count()
    }

    /// Export accumulator state summary.
    pub fn state_summary(&self) -> SlashingAccumulatorState {
        SlashingAccumulatorState {
            current_epoch: self.current_epoch,
            window_generation: self.window_generation,
            window_size: self.window_size as u16,
            total_slashed_count: self.total_slashed,
        }
    }

    /// Returns an iterator over all active slashing records.
    pub fn iter_records(&self) -> impl Iterator<Item = SlashingRecord> + '_ {
        self.validators.iter().filter_map(|(&val, state)| {
            if state.bit_state {
                Some(SlashingRecord {
                    validator_index: val,
                    epoch: state.epoch,
                    window_generation: state.generation,
                    offset: state.offset,
                })
            } else {
                None
            }
        })
    }
}

impl Default for SlashingAccumulator {
    fn default() -> Self {
        Self::new()
    }
}
