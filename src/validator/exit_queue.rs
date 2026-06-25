//! Deterministic validator exit queue.
//!
//! Fixes #18: the queue must process exits in strict
//! `(exit_epoch, validator_index)` ascending order. A `VecDeque` ordered the
//! queue by submission (FIFO) within an epoch, so a validator that submitted
//! later but has a lower index could be processed first — non-deterministic
//! across clients and a consensus (state-root) hazard.
//!
//! The fix backs the queue with a `BTreeSet<(Epoch, ValidatorIndex)>`, which
//! keeps entries in canonical order regardless of insertion order and
//! de-duplicates repeat requests.

extern crate alloc;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

/// Epoch number.
pub type Epoch = u64;
/// Validator index.
pub type ValidatorIndex = u64;

/// Spec-mandated maximum number of queued exits.
pub const MAX_EXIT_QUEUE_LENGTH: usize = 16_384;

/// Errors returned when enqueuing an exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitQueueError {
    /// The queue already holds [`MAX_EXIT_QUEUE_LENGTH`] entries.
    QueueFull,
    /// An identical `(exit_epoch, validator_index)` exit is already queued.
    DuplicateExit,
}

/// A validator exit queue ordered by `(exit_epoch, validator_index)` ascending.
#[derive(Clone, Debug, Default)]
pub struct ExitQueue {
    entries: BTreeSet<(Epoch, ValidatorIndex)>,
}

impl ExitQueue {
    /// Create an empty queue.
    pub fn new() -> Self {
        Self {
            entries: BTreeSet::new(),
        }
    }

    /// Number of queued exits.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Enqueue an exit request. Insertion position is determined solely by
    /// `(exit_epoch, validator_index)`, never by submission order.
    pub fn push_exit(
        &mut self,
        exit_epoch: Epoch,
        validator_index: ValidatorIndex,
    ) -> Result<(), ExitQueueError> {
        let entry = (exit_epoch, validator_index);
        if self.entries.contains(&entry) {
            return Err(ExitQueueError::DuplicateExit);
        }
        if self.entries.len() >= MAX_EXIT_QUEUE_LENGTH {
            return Err(ExitQueueError::QueueFull);
        }
        self.entries.insert(entry);
        Ok(())
    }

    /// Remove and return the next exit in ascending
    /// `(exit_epoch, validator_index)` order.
    pub fn pop_exit(&mut self) -> Option<(Epoch, ValidatorIndex)> {
        self.entries.pop_first()
    }

    /// Inspect the next exit without removing it.
    pub fn peek_exit(&self) -> Option<(Epoch, ValidatorIndex)> {
        self.entries.first().copied()
    }

    /// Drain every exit whose `exit_epoch <= current_epoch`, returned in
    /// canonical ascending order.
    pub fn drain_eligible(&mut self, current_epoch: Epoch) -> Vec<(Epoch, ValidatorIndex)> {
        let mut drained = Vec::new();
        while let Some(&(epoch, _)) = self.entries.first() {
            if epoch > current_epoch {
                break;
            }
            // Safe: `first()` just confirmed an element exists.
            drained.push(self.entries.pop_first().unwrap());
        }
        drained
    }
}
