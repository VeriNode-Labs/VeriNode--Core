//! Integration tests for backup verification and restore testing (issue #70).
//!
//! Exercises the full snapshot lifecycle: scheduling, creation, integrity
//! verification, cache eviction, and restore testing.

use sorosusu_contracts::backup::state_snapshot::{
    BackupScheduler, RestoreResult, SnapshotHealth, StateChunk, StateSnapshot, MAX_SNAPSHOT_COUNT,
    SNAPSHOT_INTERVAL_SECONDS,
};

#[test]
fn test_full_snapshot_lifecycle() {
    let mut scheduler = BackupScheduler::new();
    assert!(scheduler.is_empty());

    // Create chunks representing different parts of system state.
    let chunks = vec![
        (1u64, &b"committee_cache"[..]),
        (2u64, &b"validator_set"[..]),
        (3u64, &b"slashing_events"[..]),
        (4u64, &b"reputation_scores"[..]),
    ];

    // Take snapshot at epoch 42.
    let snap = scheduler
        .take_snapshot(42, SNAPSHOT_INTERVAL_SECONDS, &chunks)
        .unwrap();
    assert_eq!(snap.epoch, 42);
    assert_eq!(snap.chunk_count(), 4);
    assert_eq!(snap.verify_integrity(), SnapshotHealth::Healthy);

    // Verify via scheduler.
    assert_eq!(scheduler.verify_snapshot(42), SnapshotHealth::Healthy);
    assert_eq!(scheduler.verify_snapshot(999), SnapshotHealth::Missing);
}

#[test]
fn test_restore_with_matching_state() {
    let mut scheduler = BackupScheduler::new();
    let chunks = vec![
        (10u64, &b"accounts"[..]),
        (20u64, &b"balances"[..]),
        (30u64, &b"contracts"[..]),
    ];
    scheduler.take_snapshot(1, 1000, &chunks);

    // "Restore" the same data.
    let restored = vec![
        (10u64, &b"accounts"[..]),
        (20u64, &b"balances"[..]),
        (30u64, &b"contracts"[..]),
    ];

    let result = sorosusu_contracts::backup::state_snapshot::test_restore(&scheduler, 1, &restored);
    assert_eq!(result, RestoreResult::Success);
}

#[test]
fn test_restore_detects_corruption() {
    let mut scheduler = BackupScheduler::new();
    scheduler.take_snapshot(5, 500, &[(1u64, &b"critical_data"[..])]);

    let corrupted = vec![(1u64, &b"corrupted_data"[..])];
    let result =
        sorosusu_contracts::backup::state_snapshot::test_restore(&scheduler, 5, &corrupted);
    match result {
        RestoreResult::ChunkMismatch { chunk_id, .. } => {
            assert_eq!(chunk_id, 1);
        }
        other => panic!("Expected ChunkMismatch, got {:?}", other),
    }
}

#[test]
fn test_restore_missing_chunk() {
    let mut scheduler = BackupScheduler::new();
    scheduler.take_snapshot(3, 300, &[(100u64, &b"must_exist"[..])]);

    // Restored data is missing chunk 100.
    let incomplete = vec![(99u64, &b"something_else"[..])];
    let result =
        sorosusu_contracts::backup::state_snapshot::test_restore(&scheduler, 3, &incomplete);
    match result {
        RestoreResult::ChunkMismatch { chunk_id, .. } => {
            assert_eq!(chunk_id, 100);
        }
        other => panic!(
            "Expected ChunkMismatch due to missing chunk, got {:?}",
            other
        ),
    }
}

#[test]
fn test_scheduler_does_not_snapshot_before_interval() {
    let mut scheduler = BackupScheduler::with_interval(100);
    scheduler.take_snapshot(1, 50, &[(1u64, &b"a"[..])]);
    // last_snapshot_time is now 50; next is due at 150.
    assert!(!scheduler.is_due(120));
    assert!(scheduler.is_due(150));
}

#[test]
fn test_multiple_snapshots_and_eviction() {
    let mut scheduler = BackupScheduler::with_interval(1);

    // Store more than the max.
    let total = MAX_SNAPSHOT_COUNT + 50;
    for epoch in 0..total as u64 {
        scheduler.take_snapshot(epoch, epoch, &[(epoch, &b"data"[..])]);
    }

    assert_eq!(scheduler.len(), MAX_SNAPSHOT_COUNT);

    // Oldest entries evicted.
    for epoch in 0..50u64 {
        assert_eq!(scheduler.verify_snapshot(epoch), SnapshotHealth::Missing);
    }
    // Newest entries present.
    for epoch in (total - 10) as u64..total as u64 {
        assert_eq!(scheduler.verify_snapshot(epoch), SnapshotHealth::Healthy);
    }
}

#[test]
fn test_snapshot_deterministic_across_identical_inputs() {
    let chunks = vec![(1u64, &b"const_data"[..]), (2u64, &b"immutable"[..])];
    let snap1 = StateSnapshot::create(10, 1000, &chunks);
    let snap2 = StateSnapshot::create(10, 1000, &chunks);
    assert_eq!(snap1.root_hash, snap2.root_hash);
    assert_eq!(snap1.verify_integrity(), SnapshotHealth::Healthy);
    assert_eq!(snap2.verify_integrity(), SnapshotHealth::Healthy);
}

#[test]
fn test_snapshot_with_empty_chunks() {
    let snapshot = StateSnapshot::create(0, 0, &[]);
    assert_eq!(snapshot.chunk_count(), 0);
    assert_eq!(snapshot.verify_integrity(), SnapshotHealth::Healthy);
    // Root hash for empty input is still a valid hash.
    assert_eq!(snapshot.root_hash.len(), 32);
}

#[test]
fn test_chunk_verification_edge_cases() {
    // Large data chunk.
    let large_data = vec![0xABu8; 10_000];
    let chunk = StateChunk::new(1, &large_data);
    assert!(chunk.verify());

    // Empty data chunk.
    let empty_chunk = StateChunk::new(2, &[]);
    assert!(empty_chunk.verify());
}

#[test]
fn test_scheduled_backup_interval_defaults() {
    let scheduler = BackupScheduler::new();
    assert_eq!(scheduler.interval_seconds, SNAPSHOT_INTERVAL_SECONDS);
    assert!(scheduler.is_empty());
}

#[test]
fn test_restore_result_equality() {
    assert_eq!(RestoreResult::Success, RestoreResult::Success);
    assert_eq!(
        RestoreResult::SnapshotMissing,
        RestoreResult::SnapshotMissing
    );

    let mismatch = RestoreResult::ChunkMismatch {
        chunk_id: 1,
        expected_hash: [1u8; 32],
        actual_hash: [2u8; 32],
    };
    match mismatch {
        RestoreResult::ChunkMismatch {
            chunk_id,
            expected_hash,
            actual_hash,
        } => {
            assert_eq!(chunk_id, 1);
            assert_eq!(expected_hash, [1u8; 32]);
            assert_eq!(actual_hash, [2u8; 32]);
        }
        _ => panic!("Expected ChunkMismatch"),
    }
}
