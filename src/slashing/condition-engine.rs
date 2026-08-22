//! Slashing condition engine utilizing generational accumulator state.
//!
//! Evaluates double voting, surround voting, proposer equivocation, and other
//! slashable offenses, tracking slashing state via the generational accumulator.

extern crate alloc;

use alloc::vec::Vec;
use crate::slashing::accumulator::SlashingAccumulator;
use crate::slashing::types::{
    EpochIndex, SlashingError, SlashingRecord, ValidatorIndex, WindowOffset,
    DEFAULT_SLASHING_WINDOW,
};


/// Slashing condition engine state snapshot for persistence and migrations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingConditionEngineState {
    pub current_epoch: EpochIndex,
    pub window_generation: u16,
    pub window_size: u16,
    pub active_records: Vec<SlashingRecord>,
}

/// The Slashing Condition Engine.
/// Coordinates verification, evaluation, and recording of slashing conditions
/// with generational overflow protection.
#[derive(Clone, Debug)]
pub struct SlashingConditionEngine {
    accumulator: SlashingAccumulator,
    current_epoch: EpochIndex,
}

impl SlashingConditionEngine {
    /// Create a new SlashingConditionEngine with default window (4096).
    pub fn new() -> Self {
        Self::with_window_size(DEFAULT_SLASHING_WINDOW)
    }

    /// Create a new SlashingConditionEngine with custom window size.
    pub fn with_window_size(window_size: usize) -> Self {
        Self {
            accumulator: SlashingAccumulator::with_window_size(window_size),
            current_epoch: 0,
        }
    }

    /// Return the current epoch.
    #[inline]
    pub fn current_epoch(&self) -> EpochIndex {
        self.current_epoch
    }

    /// Return the current window generation.
    #[inline]
    pub fn current_generation(&self) -> u16 {
        self.accumulator.compute_generation(self.current_epoch)
    }

    /// Return the window offset for the current epoch.
    #[inline]
    pub fn current_offset(&self) -> WindowOffset {
        self.accumulator.compute_offset(self.current_epoch)
    }

    /// Return reference to the underlying accumulator.
    #[inline]
    pub fn accumulator(&self) -> &SlashingAccumulator {
        &self.accumulator
    }

    /// Return mutable reference to the underlying accumulator.
    #[inline]
    pub fn accumulator_mut(&mut self) -> &mut SlashingAccumulator {
        &mut self.accumulator
    }

    /// Advance engine epoch.
    pub fn advance_epoch(&mut self, new_epoch: EpochIndex) {
        if new_epoch > self.current_epoch {
            self.current_epoch = new_epoch;
            self.accumulator.advance_to_epoch(new_epoch);
        }
    }

    /// Check if a validator was slashed at the specified epoch.
    #[inline]
    pub fn is_slashed(&self, validator_index: ValidatorIndex, epoch: EpochIndex) -> bool {
        self.accumulator.check_slashed(validator_index, epoch)
    }

    /// Check if a validator is currently slashed within the historical window.
    #[inline]
    pub fn is_slashed_in_window(&self, validator_index: ValidatorIndex, current_epoch: EpochIndex) -> bool {
        self.accumulator.is_slashed_in_window(validator_index, current_epoch)
    }

    /// Process and record a slashing infraction for a validator.
    /// Returns error if the validator is already slashed at this epoch.
    pub fn verify_and_record_infraction(
        &mut self,
        validator_index: ValidatorIndex,
        epoch: EpochIndex,
    ) -> Result<SlashingRecord, SlashingError> {
        if self.accumulator.check_slashed(validator_index, epoch) {
            return Err(SlashingError::AlreadySlashed);
        }

        if epoch > self.current_epoch {
            self.current_epoch = epoch;
        }

        let record = self.accumulator.record_slashing(validator_index, epoch);
        Ok(record)
    }

    /// Record a slashing directly.
    pub fn record_slashing(
        &mut self,
        validator_index: ValidatorIndex,
        epoch: EpochIndex,
    ) -> SlashingRecord {
        if epoch > self.current_epoch {
            self.current_epoch = epoch;
        }
        self.accumulator.record_slashing(validator_index, epoch)
    }

    /// Export engine state.
    pub fn export_state(&self) -> SlashingConditionEngineState {
        let active_records: Vec<SlashingRecord> = self.accumulator.iter_records().collect();
        SlashingConditionEngineState {
            current_epoch: self.current_epoch,
            window_generation: self.current_generation(),
            window_size: self.accumulator.window_size() as u16,
            active_records,
        }
    }

    /// Import engine state.
    pub fn import_state(&mut self, state: SlashingConditionEngineState) {
        self.accumulator = SlashingAccumulator::with_window_size(state.window_size as usize);
        self.current_epoch = state.current_epoch;
        for record in state.active_records {
            self.accumulator.record_slashing(record.validator_index, record.epoch);
        }
        self.accumulator.advance_to_epoch(state.current_epoch);
    }
}

impl Default for SlashingConditionEngine {
    fn default() -> Self {
        Self::new()
    }
}
