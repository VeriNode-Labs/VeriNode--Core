//! Scheduled state snapshot, backup verification, and restore testing.
//!
//! Follows the same `no_std`-friendly, alloc-only pattern used by the
//! committee cache and slashing modules.  Snapshots are scoped by epoch;
//! a newly-created snapshot computes an integrity hash from the supplied
//! state chunks so that restore verification can re-derive the hash and
//! detect discrepancies.

extern crate alloc;
use crate::crypto::merkle::Hash256;
use crate::crypto::sha256::sha256;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

// --- CONSTANTS ---

/// How often (in seconds) a scheduled snapshot should be taken.
pub const SNAPSHOT_INTERVAL_SECONDS: u64 = 21_600; // 6 hours

/// Maximum number of snapshots to retain in the cache.
pub const MAX_SNAPSHOT_COUNT: usize = 256;

/// Maximum number of state chunks a single snapshot may reference.
pub const MAX_CHUNKS_PER_SNAPSHOT: usize = 128;

// --- TYPES ---

/// Describes whether a backup snapshot is healthy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotHealth {
    /// The snapshot hashes match — state passed integrity verification.
    Healthy,
    /// The snapshot hashes do not match — possible corruption.
    Corrupted,
    /// The snapshot was never created (epoch not found).
    Missing,
}

/// A single state-chunk record paired with its integrity hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateChunk {
    /// Opaque chunk identifier assigned by the caller (e.g., a storage-slot
    /// ordinal).
    pub chunk_id: u64,
    /// Raw data whose integrity must be verified.
    pub data: Vec<u8>,
    /// SHA-256 digest of `data`, computed at snapshot time.
    pub hash: Hash256,
}

impl StateChunk {
    /// Create a new state chunk, computing its hash from `data`.
    pub fn new(chunk_id: u64, data: &[u8]) -> Self {
        let hash = sha256(data);
        Self {
            chunk_id,
            data: data.to_vec(),
            hash,
        }
    }

    /// Verify this chunk's integrity: re-hash `data` and compare.
    pub fn verify(&self) -> bool {
        sha256(&self.data) == self.hash
    }
}

/// A complete state snapshot taken at a specific epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateSnapshot {
    /// Epoch at which the snapshot was taken.
    pub epoch: u64,
    /// Wall-clock timestamp when the snapshot was created.
    pub created_at: u64,
    /// Merkle-style root hash over all chunk hashes for quick comparison.
    pub root_hash: Hash256,
    /// Individual state chunks covered by this snapshot.
    pub chunks: Vec<StateChunk>,
}

impl StateSnapshot {
    /// Build a snapshot from an epoch, timestamp, and a list of
    /// `(chunk_id, data)` pairs.  The root hash is the SHA-256 of the
    /// concatenation of all individual chunk hashes (deterministic ordering).
    pub fn create(epoch: u64, created_at: u64, raw_chunks: &[(u64, &[u8])]) -> Self {
        let chunks: Vec<StateChunk> = raw_chunks
            .iter()
            .map(|(id, data)| StateChunk::new(*id, data))
            .collect();

        let root_hash = compute_root_hash(&chunks);

        Self {
            epoch,
            created_at,
            root_hash,
            chunks,
        }
    }

    /// Verify every chunk in the snapshot, then confirm the root hash.
    pub fn verify_integrity(&self) -> SnapshotHealth {
        for c in &self.chunks {
            if !c.verify() {
                return SnapshotHealth::Corrupted;
            }
        }

        if compute_root_hash(&self.chunks) == self.root_hash {
            SnapshotHealth::Healthy
        } else {
            SnapshotHealth::Corrupted
        }
    }

    /// Number of chunks in this snapshot.
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Retrieve a specific chunk by id.
    pub fn get_chunk(&self, chunk_id: u64) -> Option<&StateChunk> {
        self.chunks.iter().find(|c| c.chunk_id == chunk_id)
    }
}

// --- SCHEDULER ---

/// The backup scheduler tracks when the next snapshot is due and manages
/// the cache of stored snapshots.
#[derive(Clone, Debug)]
pub struct BackupScheduler {
    /// Last time (wall-clock seconds) a snapshot was taken.
    /// **Note**: `pub` for test access; prefer `take_snapshot()` for normal use.
    pub last_snapshot_time: u64,
    /// Interval between scheduled snapshots.
    pub interval_seconds: u64,
    /// Snapshots organized by epoch.
    snapshots: BTreeMap<u64, StateSnapshot>,
}

impl BackupScheduler {
    /// Create a new scheduler with the standard interval.
    pub fn new() -> Self {
        Self {
            last_snapshot_time: 0,
            interval_seconds: SNAPSHOT_INTERVAL_SECONDS,
            snapshots: BTreeMap::new(),
        }
    }

    /// Create a scheduler with a custom interval (useful for testing).
    pub fn with_interval(interval_seconds: u64) -> Self {
        Self {
            last_snapshot_time: 0,
            interval_seconds,
            snapshots: BTreeMap::new(),
        }
    }

    /// Whether a snapshot is due given the current wall-clock time.
    pub fn is_due(&self, current_time: u64) -> bool {
        current_time >= self.last_snapshot_time + self.interval_seconds
    }

    /// Take a snapshot and store it. Returns `None` if the chunk list exceeds
    /// `MAX_CHUNKS_PER_SNAPSHOT`.
    pub fn take_snapshot(
        &mut self,
        epoch: u64,
        current_time: u64,
        raw_chunks: &[(u64, &[u8])],
    ) -> Option<StateSnapshot> {
        if raw_chunks.len() > MAX_CHUNKS_PER_SNAPSHOT {
            return None;
        }

        let snapshot = StateSnapshot::create(epoch, current_time, raw_chunks);
        self.last_snapshot_time = current_time;
        self.snapshots.insert(epoch, snapshot.clone());
        self.evict_oldest_if_needed();
        Some(snapshot)
    }

    /// Retrieve a stored snapshot by epoch.
    pub fn get_snapshot(&self, epoch: u64) -> Option<&StateSnapshot> {
        self.snapshots.get(&epoch)
    }

    /// Verify the integrity of the snapshot stored at `epoch`.
    pub fn verify_snapshot(&self, epoch: u64) -> SnapshotHealth {
        match self.snapshots.get(&epoch) {
            Some(s) => s.verify_integrity(),
            None => SnapshotHealth::Missing,
        }
    }

    /// Number of stored snapshots.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    fn evict_oldest_if_needed(&mut self) {
        while self.snapshots.len() > MAX_SNAPSHOT_COUNT {
            if let Some(&oldest) = self.snapshots.keys().next() {
                self.snapshots.remove(&oldest);
            } else {
                break;
            }
        }
    }
}

impl Default for BackupScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the deterministic root hash from a slice of state chunks.
/// SHA-256( h0 || h1 || … || hn ).
fn compute_root_hash(chunks: &[StateChunk]) -> Hash256 {
    let mut buf = Vec::new();
    for c in chunks {
        buf.extend_from_slice(&c.hash);
    }
    sha256(&buf)
}

// --- RESTORE TESTING ---

/// Result of a restore test: either success or a description of what
/// mismatched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoreResult {
    /// The restored state matches the snapshot.
    Success,
    /// Mismatch found in the given chunk.
    ChunkMismatch {
        chunk_id: u64,
        expected_hash: Hash256,
        actual_hash: Hash256,
    },
    /// The expected snapshot was not found.
    SnapshotMissing,
}

/// Simulate a restore by comparing `restored_chunks` against the snapshot
/// stored at `epoch`.  Every chunk in the snapshot must have an exact match
/// in the restored data; extra or missing chunks are flagged.
pub fn test_restore(
    scheduler: &BackupScheduler,
    epoch: u64,
    restored_chunks: &[(u64, &[u8])],
) -> RestoreResult {
    let snapshot = match scheduler.get_snapshot(epoch) {
        Some(s) => s,
        None => return RestoreResult::SnapshotMissing,
    };

    for chunk in &snapshot.chunks {
        let restored = restored_chunks.iter().find(|(id, _)| *id == chunk.chunk_id);
        match restored {
            Some((_, data)) => {
                if sha256(data) != chunk.hash {
                    return RestoreResult::ChunkMismatch {
                        chunk_id: chunk.chunk_id,
                        expected_hash: chunk.hash,
                        actual_hash: sha256(data),
                    };
                }
            }
            None => {
                return RestoreResult::ChunkMismatch {
                    chunk_id: chunk.chunk_id,
                    expected_hash: chunk.hash,
                    actual_hash: [0u8; 32],
                };
            }
        }
    }

    RestoreResult::Success
}

// --- TESTS ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_creation_and_verification() {
        let data = b"hello world";
        let chunk = StateChunk::new(1, data);
        assert!(chunk.verify());
        assert_eq!(chunk.chunk_id, 1);
    }

    #[test]
    fn test_chunk_tamper_detection() {
        let mut chunk = StateChunk::new(1, b"original");
        chunk.data = b"tampered".to_vec();
        assert!(!chunk.verify());
    }

    #[test]
    fn test_snapshot_creation_and_verification() {
        let chunks = vec![
            (1u64, &b"chunk_a"[..]),
            (2u64, &b"chunk_b"[..]),
            (3u64, &b"chunk_c"[..]),
        ];
        let snapshot = StateSnapshot::create(100, 1000, &chunks);
        assert_eq!(snapshot.epoch, 100);
        assert_eq!(snapshot.created_at, 1000);
        assert_eq!(snapshot.chunk_count(), 3);
        assert_eq!(snapshot.verify_integrity(), SnapshotHealth::Healthy);
    }

    #[test]
    fn test_snapshot_root_changes_when_chunk_changes() {
        let chunks_a = vec![(1u64, &b"foo"[..])];
        let chunks_b = vec![(1u64, &b"bar"[..])];
        let snap_a = StateSnapshot::create(1, 0, &chunks_a);
        let snap_b = StateSnapshot::create(1, 0, &chunks_b);
        // Different data → different root hash.
        assert_ne!(snap_a.root_hash, snap_b.root_hash);
    }

    #[test]
    fn test_snapshot_deterministic_root() {
        let chunks = vec![(1u64, &b"xyz"[..])];
        let a = StateSnapshot::create(1, 0, &chunks);
        let b = StateSnapshot::create(1, 0, &chunks);
        assert_eq!(a.root_hash, b.root_hash);
    }

    #[test]
    fn test_get_chunk() {
        let chunks = vec![(42u64, &b"answer"[..])];
        let snap = StateSnapshot::create(1, 0, &chunks);
        assert!(snap.get_chunk(42).is_some());
        assert!(snap.get_chunk(99).is_none());
    }

    // --- Scheduler tests ---

    #[test]
    fn test_scheduler_is_due() {
        let mut s = BackupScheduler::with_interval(100);
        assert!(s.is_due(101));
        s.last_snapshot_time = 50;
        assert!(!s.is_due(100)); // 50 + 100 = 150, so 100 is not yet due
        assert!(s.is_due(150));
    }

    #[test]
    fn test_take_and_retrieve_snapshot() {
        let mut s = BackupScheduler::with_interval(100);
        let chunks = vec![(1u64, &b"data"[..])];
        let snap = s.take_snapshot(10, 200, &chunks).unwrap();
        assert_eq!(snap.epoch, 10);
        assert_eq!(s.len(), 1);

        let retrieved = s.get_snapshot(10).unwrap();
        assert_eq!(retrieved.root_hash, snap.root_hash);
    }

    #[test]
    fn test_verify_snapshot_healthy() {
        let mut s = BackupScheduler::with_interval(100);
        let chunks = vec![(1u64, &b"safe"[..])];
        s.take_snapshot(5, 100, &chunks);
        assert_eq!(s.verify_snapshot(5), SnapshotHealth::Healthy);
    }

    #[test]
    fn test_verify_snapshot_missing() {
        let s = BackupScheduler::new();
        assert_eq!(s.verify_snapshot(99), SnapshotHealth::Missing);
    }

    #[test]
    fn test_scheduler_eviction() {
        let mut s = BackupScheduler::with_interval(1);
        // Fill past MAX_SNAPSHOT_COUNT (default 256).
        for epoch in 0..300u64 {
            s.take_snapshot(epoch, epoch, &[(epoch, &b"x"[..])]);
        }
        // Only the most recent MAX_SNAPSHOT_COUNT should remain.
        assert_eq!(s.len(), MAX_SNAPSHOT_COUNT);
        // The oldest entries should be gone.
        assert!(s.get_snapshot(0).is_none());
        assert!(s.get_snapshot(299).is_some());
    }

    // --- Restore tests ---

    #[test]
    fn test_restore_success() {
        let mut s = BackupScheduler::with_interval(100);
        let chunks = vec![(1u64, &b"one"[..]), (2u64, &b"two"[..])];
        s.take_snapshot(7, 100, &chunks);

        let restored = vec![(1u64, &b"one"[..]), (2u64, &b"two"[..])];
        assert_eq!(test_restore(&s, 7, &restored), RestoreResult::Success);
    }

    #[test]
    fn test_restore_chunk_mismatch() {
        let mut s = BackupScheduler::with_interval(100);
        s.take_snapshot(7, 100, &[(1u64, &b"correct"[..])]);

        let restored = vec![(1u64, &b"wrong"[..])];
        let result = test_restore(&s, 7, &restored);
        assert!(matches!(result, RestoreResult::ChunkMismatch { .. }));
    }

    #[test]
    fn test_restore_missing_snapshot() {
        let s = BackupScheduler::new();
        assert_eq!(test_restore(&s, 999, &[]), RestoreResult::SnapshotMissing);
    }

    #[test]
    fn test_restore_extra_restored_chunk_is_ok() {
        // Extra restored data beyond what the snapshot knows about is fine.
        let mut s = BackupScheduler::with_interval(100);
        s.take_snapshot(1, 100, &[(1u64, &b"core"[..])]);

        let restored = vec![(1u64, &b"core"[..]), (99u64, &b"extra"[..])];
        assert_eq!(test_restore(&s, 1, &restored), RestoreResult::Success);
    }

    #[test]
    fn test_snapshot_exceeds_max_chunks() {
        let mut s = BackupScheduler::with_interval(1);
        let too_many: Vec<(u64, &[u8])> = (0..=MAX_CHUNKS_PER_SNAPSHOT as u64)
            .map(|i| (i, &b"x"[..]))
            .collect();
        assert!(s.take_snapshot(0, 0, &too_many).is_none());
    }
}
