//! Ordering tests for the deterministic validator exit queue (#18).
//!
//! Cargo only auto-discovers test targets at the top level of `tests/`, so
//! this lives here rather than at `tests/validator/`.

use sorosusu_contracts::state::epoch_transition::{epoch_transition, exit_queue_root};
use sorosusu_contracts::validator::exit_queue::{ExitQueue, ExitQueueError, MAX_EXIT_QUEUE_LENGTH};
use sorosusu_contracts::validator::validator_set::{ValidatorSet, ValidatorStatus};

/// Core regression for #18: three exits submitted in the SAME epoch but out of
/// index order must pop in ascending validator-index order, not submission
/// (FIFO) order.
#[test]
fn same_epoch_pops_in_ascending_index_order() {
    let mut q = ExitQueue::new();
    // Submit out of order: index 7, then 2, then 5 — all in epoch 10.
    q.push_exit(10, 7).unwrap();
    q.push_exit(10, 2).unwrap();
    q.push_exit(10, 5).unwrap();

    assert_eq!(q.pop_exit(), Some((10, 2)));
    assert_eq!(q.pop_exit(), Some((10, 5)));
    assert_eq!(q.pop_exit(), Some((10, 7)));
    assert_eq!(q.pop_exit(), None);
}

/// Across epochs, ordering is by epoch first, then index.
#[test]
fn orders_by_epoch_then_index() {
    let mut q = ExitQueue::new();
    q.push_exit(11, 1).unwrap();
    q.push_exit(10, 9).unwrap();
    q.push_exit(10, 3).unwrap();
    q.push_exit(11, 0).unwrap();

    assert_eq!(q.pop_exit(), Some((10, 3)));
    assert_eq!(q.pop_exit(), Some((10, 9)));
    assert_eq!(q.pop_exit(), Some((11, 0)));
    assert_eq!(q.pop_exit(), Some((11, 1)));
}

/// Duplicate exits are rejected; capacity is bounded.
#[test]
fn rejects_duplicates_and_respects_capacity() {
    let mut q = ExitQueue::new();
    q.push_exit(10, 1).unwrap();
    assert_eq!(q.push_exit(10, 1), Err(ExitQueueError::DuplicateExit));
    assert_eq!(q.len(), 1);
    assert!(MAX_EXIT_QUEUE_LENGTH == 16_384);
}

/// `drain_eligible` only releases exits at or before the current epoch, in order.
#[test]
fn drains_only_eligible_epochs_in_order() {
    let mut q = ExitQueue::new();
    q.push_exit(12, 4).unwrap();
    q.push_exit(10, 8).unwrap();
    q.push_exit(10, 1).unwrap();

    let drained = q.drain_eligible(10);
    assert_eq!(drained, vec![(10, 1), (10, 8)]);
    // The epoch-12 exit remains queued.
    assert_eq!(q.peek_exit(), Some((12, 4)));
}

/// The epoch transition marks validators exited in canonical order, and the
/// resulting state root is independent of submission order (the #18 invariant
/// for cross-client consensus).
#[test]
fn state_root_is_independent_of_submission_order() {
    let order_a = [(10u64, 7u64), (10, 2), (10, 5)];
    let order_b = [(10u64, 5u64), (10, 7), (10, 2)];

    let build = |submissions: &[(u64, u64)]| {
        let mut set = ValidatorSet::new();
        for &(_, idx) in submissions {
            set.add_validator(idx);
        }
        for &(epoch, idx) in submissions {
            set.exit_validator(idx, epoch).unwrap();
        }
        let processed = epoch_transition(&mut set, 10);
        (processed.clone(), exit_queue_root(&processed), set)
    };

    let (processed_a, root_a, set_a) = build(&order_a);
    let (processed_b, root_b, _set_b) = build(&order_b);

    // Same canonical processing order regardless of submission order.
    assert_eq!(processed_a, vec![2, 5, 7]);
    assert_eq!(processed_a, processed_b);
    // Same state root.
    assert_eq!(root_a, root_b);

    // Processed validators are marked Exited.
    for idx in [2u64, 5, 7] {
        assert_eq!(set_a.get(idx).unwrap().status, ValidatorStatus::Exited);
    }
}
