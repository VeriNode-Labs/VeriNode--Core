//! Validator set and exit-queue processing.

extern crate alloc;
use alloc::vec::Vec;

use crate::validator::activation_queue::{ActivationQueue, ActivationQueueError};
use crate::validator::exit_queue::{Epoch, ExitQueue, ExitQueueError, ValidatorIndex};

/// Lifecycle status of a validator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidatorStatus {
    Pending,
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
    activation_queue: ActivationQueue,
    exit_queue: ExitQueue,
    /// Slot at which the last reorganization occurred
    last_reorg_slot: Option<u64>,
}

impl ValidatorSet {
    /// Create an empty validator set.
    pub fn new() -> Self {
        Self {
            validators: Vec::new(),
            activation_queue: ActivationQueue::new(),
            exit_queue: ExitQueue::new(),
            last_reorg_slot: None,
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

    /// Register a new pending validator and queue it for activation.
    pub fn add_pending_validator(
        &mut self,
        index: ValidatorIndex,
        activation_epoch: Epoch,
    ) -> Result<(), ActivationQueueError> {
        self.activation_queue
            .push_activation(activation_epoch, index)?;
        self.validators.push(Validator {
            index,
            status: ValidatorStatus::Pending,
            exit_epoch: None,
        });
        Ok(())
    }

    /// Number of activations currently queued.
    pub fn queued_activations(&self) -> usize {
        self.activation_queue.len()
    }

    /// Activate a pending validator by index.
    pub fn activate_validator(&mut self, index: ValidatorIndex) -> bool {
        if let Some(v) = self.validators.iter_mut().find(|v| v.index == index) {
            if v.status == ValidatorStatus::Pending {
                v.status = ValidatorStatus::Active;
                return true;
            }
        }
        false
    }

    /// Process all activations eligible at or before `current_epoch`.
    pub fn process_activation_queue(&mut self, current_epoch: Epoch) -> Vec<ValidatorIndex> {
        let drained = self.activation_queue.drain_eligible(current_epoch);
        let mut processed = Vec::with_capacity(drained.len());
        for (_, index) in drained {
            if self.activate_validator(index) {
                processed.push(index);
            }
        }
        processed
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

    /// Trigger a mid-epoch reorganization at the given slot.
    /// This should be called when a validator exits irregularly or
    /// activates late, causing the committee composition to change.
    pub fn reorg_validator_set(&mut self, slot: u64) {
        self.last_reorg_slot = Some(slot);
    }

    /// Get the slot of the last reorganization, if any.
    pub fn last_reorg_slot(&self) -> Option<u64> {
        self.last_reorg_slot
    }

    /// Get all active validator indices.
    pub fn active_validators(&self) -> Vec<ValidatorIndex> {
        self.validators
            .iter()
            .filter(|v| v.status == ValidatorStatus::Active)
            .map(|v| v.index)
            .collect()
    }
}
