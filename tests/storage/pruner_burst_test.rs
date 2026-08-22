#![cfg(test)]

use sorosusu_contracts::storage::{
    PrunerError, TriePruner, DEFAULT_ENTRY_BUDGET,
};

#[test]
fn test_prune_depth_threshold_respected() {
    let mut pruner = TriePruner::default();

    // Finalizing epoch <= PRUNE_DEPTH (256) yields NothingToPrune
    assert_eq!(
        pruner.on_epoch_finalized(250, 100),
        Err(PrunerError::NothingToPrune)
    );
    assert_eq!(
        pruner.on_epoch_finalized(256, 101),
        Err(PrunerError::NothingToPrune)
    );
    assert_eq!(pruner.queue.len(), 0);
}

#[test]
fn test_single_epoch_finalization_enqueues_correct_range() {
    let mut pruner = TriePruner::default();

    // Finalizing epoch 257 should enqueue pruning for epoch 1 (257 - 256 = 1)
    let res = pruner.on_epoch_finalized(257, 1000);
    assert_eq!(res, Ok(false));
    assert_eq!(pruner.queue.len(), 1);

    let job = &pruner.queue[0];
    assert_eq!(job.from_epoch, 1);
    assert_eq!(job.to_epoch, 1);
    assert_eq!(job.cursor, 1);

    // Step prune processes epoch 1
    let step = pruner.step_prune(DEFAULT_ENTRY_BUDGET);
    assert_eq!(step.epochs_completed, 1);
    assert_eq!(step.is_caught_up, true);
    assert_eq!(pruner.checkpoint.last_pruned_epoch, 1);
}

#[test]
fn test_burst_finalization_merges_contiguous_ranges_without_queue_exhaustion() {
    let mut pruner = TriePruner::default();

    // Simulate 8 sequential burst finalizations in a SINGLE slot (epochs 260 to 267)
    // Targets: epochs 4, 5, 6, 7, 8, 9, 10, 11
    let slot = 5000;
    for epoch in 260..=267 {
        let merged = pruner.on_epoch_finalized(epoch, slot).expect("Must succeed");
        if epoch > 260 {
            assert!(merged, "Subsequent contiguous epochs in burst must merge");
        }
    }

    // Crucial invariant: Queue length remains 1 because all 8 contiguous epochs were merged!
    assert_eq!(
        pruner.queue.len(),
        1,
        "Burst finalizations must merge into a single contiguous job"
    );

    let job = &pruner.queue[0];
    assert_eq!(job.from_epoch, 1);
    assert_eq!(job.to_epoch, 11);

    // Prune all 11 epochs
    let epochs_pruned = pruner.drain_all();
    assert_eq!(epochs_pruned, 11);
    assert_eq!(pruner.checkpoint.last_pruned_epoch, 11);
    assert!(pruner.queue.is_empty());
}

#[test]
fn test_backpressure_enforcement_on_non_contiguous_overflow() {
    let mut pruner = TriePruner::new(2); // Small capacity of 2 for testing

    // First contiguous job (epochs 1 to 5)
    pruner.on_epoch_finalized(261, 100).unwrap();
    assert_eq!(pruner.queue.len(), 1);

    // Manually advance checkpoint to simulate a non-contiguous gap
    pruner.checkpoint.last_pruned_epoch = 10;

    // Second job (epochs 11 to 15)
    pruner.on_epoch_finalized(271, 200).unwrap();
    assert_eq!(pruner.queue.len(), 2);

    // Again simulate non-contiguous gap
    pruner.checkpoint.last_pruned_epoch = 20;

    // Third job exceeds capacity 2 and cannot merge -> BackpressureExceeded
    let err = pruner.on_epoch_finalized(281, 300);
    assert_eq!(err, Err(PrunerError::BackpressureExceeded));
}

#[test]
fn test_incremental_step_budget_prevents_slot_overruns() {
    let mut pruner = TriePruner::default();

    // Enqueue 20 epochs
    pruner.on_epoch_finalized(276, 1000).unwrap();
    assert_eq!(pruner.queue[0].to_epoch, 20);

    // Nominal entry budget of 100 allows 2 epochs per step (50 entries/epoch)
    let step1 = pruner.step_prune(100);
    assert_eq!(step1.epochs_completed, 2);
    assert_eq!(pruner.checkpoint.last_pruned_epoch, 2);
    assert_eq!(step1.is_caught_up, false);

    let step2 = pruner.step_prune(200);
    assert_eq!(step2.epochs_completed, 4);
    assert_eq!(pruner.checkpoint.last_pruned_epoch, 6);
    assert_eq!(step2.is_caught_up, false);
}
