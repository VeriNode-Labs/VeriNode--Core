//! Deterministic validator activation queue.
//!
//! Pending validators are released at epoch boundaries once their
//! `activation_epoch` is less than or equal to the current epoch. Boundary
//! equality is intentional: a validator scheduled for epoch `N` must activate
//! during the epoch-`N` transition, including after a mid-epoch reorg rebuilds
//! or updates the queue.

extern crate alloc;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::validator::exit_queue::{Epoch, ValidatorIndex};

/// Spec-mandated maximum number of queued validator activations.
pub const MAX_PENDING_VALIDATORS: usize = 8_192;

/// Epoch delay before a newly pending validator becomes eligible for activation.
pub const MIN_VALIDATOR_WITHDRAWABILITY_DELAY: Epoch = 4;

/// Errors returned when enqueuing an activation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationQueueError {
    /// The queue already holds [`MAX_PENDING_VALIDATORS`] entries.
    QueueFull,
    /// An identical `(activation_epoch, validator_index)` activation is already queued.
    DuplicateActivation,
}

/// A validator activation queue ordered by `(activation_epoch, validator_index)`.
#[derive(Clone, Debug, Default)]
pub struct ActivationQueue {
    entries: BTreeSet<(Epoch, ValidatorIndex)>,
}

impl ActivationQueue {
    /// Create an empty queue.
    pub fn new() -> Self {
        Self {
            entries: BTreeSet::new(),
        }
    }

    /// Number of queued activations.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute the epoch at which a validator pending at `current_epoch`
    /// becomes eligible for activation.
    pub fn compute_activation_epoch(current_epoch: Epoch) -> Epoch {
        current_epoch.saturating_add(MIN_VALIDATOR_WITHDRAWABILITY_DELAY)
    }

    /// Enqueue an activation request.
    pub fn push_activation(
        &mut self,
        activation_epoch: Epoch,
        validator_index: ValidatorIndex,
    ) -> Result<(), ActivationQueueError> {
        let entry = (activation_epoch, validator_index);
        if self.entries.contains(&entry) {
            return Err(ActivationQueueError::DuplicateActivation);
        }
        if self.entries.len() >= MAX_PENDING_VALIDATORS {
            return Err(ActivationQueueError::QueueFull);
        }
        self.entries.insert(entry);
        Ok(())
    }

    /// Inspect the next activation without removing it.
    pub fn peek_activation(&self) -> Option<(Epoch, ValidatorIndex)> {
        self.entries.first().copied()
    }

    /// Remove and return the next activation in canonical order.
    pub fn pop_activation(&mut self) -> Option<(Epoch, ValidatorIndex)> {
        self.entries.pop_first()
    }

    /// Drain every activation whose `activation_epoch <= current_epoch`.
    pub fn drain_eligible(&mut self, current_epoch: Epoch) -> Vec<(Epoch, ValidatorIndex)> {
        let mut drained = Vec::new();
        while let Some(&(activation_epoch, _)) = self.entries.first() {
            if activation_epoch > current_epoch {
                break;
            }
            // Safe: `first()` just confirmed an element exists.
            drained.push(self.entries.pop_first().unwrap());
        }
        drained
    }
}
