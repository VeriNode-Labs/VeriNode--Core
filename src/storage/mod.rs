//! Storage and Trie Pruning Module.

pub mod trie_pruner;

pub use trie_pruner::{
    PruneJob, PruneStepResult, PrunerError, PruningCheckpoint, TriePruner,
    DEFAULT_ENTRY_BUDGET, MAX_JOB_QUEUE_CAPACITY, PRUNE_DEPTH,
};
