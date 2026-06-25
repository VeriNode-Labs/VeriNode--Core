//! Validator set and exit-queue processing.

extern crate alloc;
use alloc::vec::Vec;

use crate::validator::exit_queue::{Epoch, ExitQueue, ExitQueueError, ValidatorIndex};

/// Lifecycle status of a validator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidatorStatus {
    Active,
    ExitQueued,
    Exited,
}

/// A single validator record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validator {
    pub index: ValidatorIndex,
    pub status: ValidatorStatus,
    pub exit_epoch: Option<Epoch>,
}

/// The active validator set plus its pending exit queue.
#[derive(Clone, Debug, Default)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    exit_queue: ExitQueue,
}

impl ValidatorSet {
    /// Create an empty validator set.
    pub fn new() -> Self {
        Self {
            validators: Vec::new(),
            exit_queue: ExitQueue::new(),
        }
    }

    /// Register a new active validator.
    pub fn add_validator(&mut self, index: ValidatorIndex) {
        self.validators.push(Validator {
            index,
            status: ValidatorStatus::Active,
            exit_epoch: None,
        });
    }

    /// Look up a validator by index.
    pub fn get(&self, index: ValidatorIndex) -> Option<&Validator> {
        self.validators.iter().find(|v| v.index == index)
    }

    /// Number of exits currently queued.
    pub fn queued_exits(&self) -> usize {
        self.exit_queue.len()
    }

    /// Queue a validator for exit at `exit_epoch`. The queue keeps exits in
    /// deterministic `(exit_epoch, validator_index)` order.
    pub fn exit_validator(
        &mut self,
        index: ValidatorIndex,
        exit_epoch: Epoch,
    ) -> Result<(), ExitQueueError> {
        self.exit_queue.push_exit(exit_epoch, index)?;
        if let Some(v) = self.validators.iter_mut().find(|v| v.index == index) {
            v.status = ValidatorStatus::ExitQueued;
            v.exit_epoch = Some(exit_epoch);
        }
        Ok(())
    }

    /// Process all exits eligible at or before `current_epoch`, marking each
    /// validator `Exited`. Returns the processed validator indices in the
    /// exact order they were applied — strictly ascending by
    /// `(exit_epoch, validator_index)`.
    pub fn process_exit_queue(&mut self, current_epoch: Epoch) -> Vec<ValidatorIndex> {
        let drained = self.exit_queue.drain_eligible(current_epoch);
        let mut processed = Vec::with_capacity(drained.len());
        for (_, index) in drained {
            if let Some(v) = self.validators.iter_mut().find(|v| v.index == index) {
                v.status = ValidatorStatus::Exited;
            }
            processed.push(index);
        }
        processed
    }
}
