//! Regression tests for validator activation queue boundary handling (#16).

use sorosusu_contracts::validator::activation_queue::{
    ActivationQueue, ActivationQueueError, MAX_PENDING_VALIDATORS,
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
};
use sorosusu_contracts::validator::validator_set::{ValidatorSet, ValidatorStatus};

#[test]
fn boundary_epoch_activation_is_drained() {
    let mut q = ActivationQueue::new();
    q.push_activation(10, 42).unwrap();

    assert_eq!(q.drain_eligible(10), vec![(10, 42)]);
    assert!(q.is_empty());
}

#[test]
fn validator_at_current_epoch_is_activated() {
    let mut set = ValidatorSet::new();
    set.add_pending_validator(7, 10).unwrap();

    let activated = set.process_activation_queue(10);

    assert_eq!(activated, vec![7]);
    assert_eq!(set.get(7).unwrap().status, ValidatorStatus::Active);
    assert_eq!(set.queued_activations(), 0);
}

#[test]
fn multiple_validators_at_boundary_activate_once_in_order() {
    let mut set = ValidatorSet::new();
    set.add_pending_validator(9, 10).unwrap();
    set.add_pending_validator(3, 10).unwrap();
    set.add_pending_validator(5, 10).unwrap();

    assert_eq!(set.process_activation_queue(10), vec![3, 5, 9]);
    assert_eq!(set.process_activation_queue(10), Vec::<u64>::new());

    for idx in [3u64, 5, 9] {
        assert_eq!(set.get(idx).unwrap().status, ValidatorStatus::Active);
    }
}

#[test]
fn future_epoch_remains_pending_and_activation_epoch_uses_delay() {
    let mut set = ValidatorSet::new();
    let activation_epoch = ActivationQueue::compute_activation_epoch(10);
    assert_eq!(activation_epoch, 10 + MIN_VALIDATOR_WITHDRAWABILITY_DELAY);
    set.add_pending_validator(1, activation_epoch).unwrap();

    assert_eq!(set.process_activation_queue(13), Vec::<u64>::new());
    assert_eq!(set.get(1).unwrap().status, ValidatorStatus::Pending);
    assert_eq!(set.process_activation_queue(14), vec![1]);
}

#[test]
fn rejects_duplicates_and_respects_capacity_constant() {
    let mut q = ActivationQueue::new();
    q.push_activation(10, 1).unwrap();
    assert_eq!(
        q.push_activation(10, 1),
        Err(ActivationQueueError::DuplicateActivation)
    );
    assert_eq!(MAX_PENDING_VALIDATORS, 8_192);
}
