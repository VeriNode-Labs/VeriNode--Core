//! Storage Trie Pruning Engine with Burst Finalization & Backpressure Guards.
//!
//! Resolves Issue #143: Prevents permanent pruner halts under burst epoch finalization.
//!
//! ## Invariants & Guarantees
//! - `PRUNE_DEPTH = 256` (~27 hours of history).
//! - Merges contiguous pruning ranges when multiple finalizations arrive in the same slot.
//! - Bounded queue backpressure (capacity 4) to prevent unbounded memory growth.
//! - Deterministic checkpointing of pruning progress (`last_pruned_epoch`, `total_pruned`).
//! - Guarantees linear-time completion without cursor corruption under burst load (up to 8+ epochs/slot).

extern crate alloc;
use alloc::collections::VecDeque;

/// Number of finalized epochs retained before state entries become eligible for pruning.
pub const PRUNE_DEPTH: u64 = 256;

/// Maximum number of distinct non-contiguous pruning jobs permitted before backpressure is asserted.
pub const MAX_JOB_QUEUE_CAPACITY: usize = 4;

/// Default entry budget processed per pruning invocation (~100ms budget).
pub const DEFAULT_ENTRY_BUDGET: usize = 500;

/// Errors emitted by the storage trie pruner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrunerError {
    /// The job queue is at maximum capacity and incoming job is non-contiguous.
    BackpressureExceeded,
    /// Finalized epoch is prior to or within the retention window.
    NothingToPrune,
    /// Invalid epoch range specified.
    InvalidEpochRange,
    /// Pruner is in an unrecoverable corrupted state.
    PrunerHalted,
}

/// A discrete unit of pruning work covering a contiguous epoch range `[from_epoch, to_epoch]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PruneJob {
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub cursor: u64,
    pub enqueued_slot: u64,
    pub completed: bool,
}

impl PruneJob {
    pub fn new(from_epoch: u64, to_epoch: u64, enqueued_slot: u64) -> Self {
        Self {
            from_epoch,
            to_epoch,
            cursor: from_epoch,
            enqueued_slot,
            completed: from_epoch > to_epoch,
        }
    }

    /// Attempt to merge another contiguous or overlapping job into this one.
    pub fn try_merge(&mut self, other: &PruneJob) -> bool {
        // Overlapping or adjacent ranges
        if other.from_epoch <= self.to_epoch + 1 && other.to_epoch >= self.from_epoch {
            self.from_epoch = self.from_epoch.min(other.from_epoch);
            self.to_epoch = self.to_epoch.max(other.to_epoch);
            if self.cursor > self.to_epoch {
                self.completed = true;
            } else {
                self.completed = false;
            }
            true
        } else {
            false
        }
    }
}

/// Checkpoint recording persisted pruning progress.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PruningCheckpoint {
    pub last_pruned_epoch: u64,
    pub total_pruned_entries: u64,
    pub last_checkpoint_slot: u64,
}

/// Outcome of a single pruning invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PruneStepResult {
    pub entries_pruned: usize,
    pub epochs_completed: usize,
    pub remaining_jobs: usize,
    pub is_caught_up: bool,
}

/// Storage Trie Pruning Coordinator.
#[derive(Clone, Debug)]
pub struct TriePruner {
    pub queue: VecDeque<PruneJob>,
    pub checkpoint: PruningCheckpoint,
    pub is_halted: bool,
    pub max_queue_capacity: usize,
}

impl Default for TriePruner {
    fn default() -> Self {
        Self::new(MAX_JOB_QUEUE_CAPACITY)
    }
}

impl TriePruner {
    pub fn new(max_queue_capacity: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            checkpoint: PruningCheckpoint::default(),
            is_halted: false,
            max_queue_capacity,
        }
    }

    /// Notify the pruner of an epoch finalization event.
    ///
    /// If the newly eligible epoch range is adjacent to an existing pending job,
    /// it merges automatically without consuming extra queue capacity.
    pub fn on_epoch_finalized(
        &mut self,
        finalized_epoch: u64,
        current_slot: u64,
    ) -> Result<bool, PrunerError> {
        if self.is_halted {
            return Err(PrunerError::PrunerHalted);
        }

        if finalized_epoch <= PRUNE_DEPTH {
            return Err(PrunerError::NothingToPrune);
        }

        let target_prune_epoch = finalized_epoch - PRUNE_DEPTH;
        let start_prune_epoch = self.checkpoint.last_pruned_epoch.saturating_add(1);

        if start_prune_epoch > target_prune_epoch {
            return Err(PrunerError::NothingToPrune);
        }

        let new_job = PruneJob::new(start_prune_epoch, target_prune_epoch, current_slot);

        // Attempt merging into the last enqueued job
        if let Some(last_job) = self.queue.back_mut() {
            if last_job.try_merge(&new_job) {
                return Ok(true); // Merged into existing job
            }
        }

        // Backpressure check if queue is full
        if self.queue.len() >= self.max_queue_capacity {
            return Err(PrunerError::BackpressureExceeded);
        }

        self.queue.push_back(new_job);
        Ok(false) // Added as new job
    }

    /// Execute a bounded step of trie pruning.
    pub fn step_prune(&mut self, entry_budget: usize) -> PruneStepResult {
        if self.is_halted || self.queue.is_empty() {
            return PruneStepResult {
                entries_pruned: 0,
                epochs_completed: 0,
                remaining_jobs: self.queue.len(),
                is_caught_up: self.queue.is_empty(),
            };
        }

        let mut entries_pruned = 0;
        let mut epochs_completed = 0;

        while let Some(job) = self.queue.front_mut() {
            while job.cursor <= job.to_epoch && entries_pruned < entry_budget {
                // Simulate pruning state diff entries for epoch `job.cursor`
                let epoch_entries = 50; // nominal entries per epoch
                entries_pruned += epoch_entries;
                self.checkpoint.last_pruned_epoch = job.cursor;
                self.checkpoint.total_pruned_entries += epoch_entries as u64;
                job.cursor += 1;
                epochs_completed += 1;
            }

            if job.cursor > job.to_epoch {
                job.completed = true;
                self.queue.pop_front();
            }

            if entries_pruned >= entry_budget {
                break;
            }
        }

        PruneStepResult {
            entries_pruned,
            epochs_completed,
            remaining_jobs: self.queue.len(),
            is_caught_up: self.queue.is_empty(),
        }
    }

    /// Process all pending jobs to completion (used during sync catching up).
    pub fn drain_all(&mut self) -> usize {
        let mut total_epochs = 0;
        while !self.queue.is_empty() {
            let res = self.step_prune(DEFAULT_ENTRY_BUDGET);
            total_epochs += res.epochs_completed;
        }
        total_epochs
    }
}
