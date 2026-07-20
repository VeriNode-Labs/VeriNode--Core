//! Recent nonce deduplication cache with epoch-based expiry.
//!
//! ## Epoch expiry (issue #54)
//!
//! Each cache entry records the `epoch_id` at which the nonce was first seen.
//! When [`NonceCache::expire`] is called with the current epoch, any entry
//! whose `epoch_id` is more than [`REPLAY_EPOCH_WINDOW`] behind the current
//! epoch is unconditionally removed.  This bounds the in-memory set to at
//! most three consecutive epochs worth of nonces and ensures that a nonce
//! from a disconnected epoch is removed before it can be replayed.
//!
//! The combination of:
//! - epoch-derived nonces (nonce-generator.rs), and
//! - epoch-based cache expiry (this file),
//!
//! means an attacker cannot replay a nonce: if it is within the window the
//! cache rejects it as a duplicate; if it is outside the window the verifier
//! (proof-of-connectivity.rs) rejects the epoch as too old before the cache
//! is even consulted.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::attestation::types::{EpochId, Nonce, REPLAY_EPOCH_WINDOW};

/// A single cache entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CacheEntry {
    epoch_id: EpochId,
}

/// A nonce deduplication cache that expires entries outside the replay window.
///
/// Nonces are stored in a [`BTreeMap`] keyed by the raw 32-byte value.
/// Lookup and insertion are O(log n).
#[derive(Clone, Debug, Default)]
pub struct NonceCache {
    entries: BTreeMap<Nonce, CacheEntry>,
}

impl NonceCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Returns `true` if `nonce` is already present in the cache.
    pub fn contains(&self, nonce: &Nonce) -> bool {
        self.entries.contains_key(nonce)
    }

    /// Insert `nonce` tagged with `epoch_id`.  Returns `false` (and does NOT
    /// insert) if the nonce is already present — this is the duplicate-nonce
    /// detection path that prevents replay within the live window.
    pub fn insert(&mut self, nonce: Nonce, epoch_id: EpochId) -> bool {
        if self.entries.contains_key(&nonce) {
            return false;
        }
        self.entries.insert(nonce, CacheEntry { epoch_id });
        true
    }

    /// Expire all entries whose `epoch_id` is more than [`REPLAY_EPOCH_WINDOW`]
    /// behind `current_epoch`.
    ///
    /// Called by the connectivity scheduler at each epoch transition.
    ///
    /// # Expiry predicate
    ///
    /// An entry is expired when:
    /// ```text
    /// current_epoch.saturating_sub(entry.epoch_id) > REPLAY_EPOCH_WINDOW
    /// ```
    pub fn expire(&mut self, current_epoch: EpochId) {
        let expired_nonces: Vec<Nonce> = self
            .entries
            .iter()
            .filter(|(_, entry)| current_epoch.saturating_sub(entry.epoch_id) > REPLAY_EPOCH_WINDOW)
            .map(|(nonce, _)| *nonce)
            .collect();

        for nonce in expired_nonces {
            self.entries.remove(&nonce);
        }
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce(seed: u8) -> Nonce {
        let mut n = [0u8; 32];
        n[0] = seed;
        n
    }

    #[test]
    fn test_insert_and_lookup() {
        let mut cache = NonceCache::new();
        let n = nonce(1);
        assert!(!cache.contains(&n));
        assert!(cache.insert(n, 0));
        assert!(cache.contains(&n));
    }

    #[test]
    fn test_duplicate_insert_returns_false() {
        let mut cache = NonceCache::new();
        let n = nonce(2);
        assert!(cache.insert(n, 1));
        assert!(!cache.insert(n, 1), "duplicate must be rejected");
    }

    #[test]
    fn test_expire_removes_old_epochs() {
        let mut cache = NonceCache::new();
        // Epoch 0 nonces — will be expired when current epoch reaches 3.
        cache.insert(nonce(10), 0);
        cache.insert(nonce(11), 0);
        // Epoch 1 nonces — still inside the window at epoch 3.
        cache.insert(nonce(20), 1);
        // Epoch 3 nonce — always inside the window.
        cache.insert(nonce(30), 3);

        // Current epoch = 3: entries from epoch 0 are >2 behind → expired.
        cache.expire(3);

        assert!(!cache.contains(&nonce(10)), "epoch-0 nonce must be expired");
        assert!(!cache.contains(&nonce(11)), "epoch-0 nonce must be expired");
        assert!(
            cache.contains(&nonce(20)),
            "epoch-1 nonce must still be live"
        );
        assert!(
            cache.contains(&nonce(30)),
            "epoch-3 nonce must still be live"
        );
    }

    #[test]
    fn test_expire_keeps_entries_within_window() {
        let mut cache = NonceCache::new();
        for epoch in 0u32..=4 {
            cache.insert(nonce(epoch as u8), epoch);
        }
        // At current_epoch = 4: epochs 0 and 1 are >2 behind (4-0=4, 4-1=3).
        cache.expire(4);
        assert!(!cache.contains(&nonce(0)));
        assert!(!cache.contains(&nonce(1)));
        assert!(cache.contains(&nonce(2)));
        assert!(cache.contains(&nonce(3)));
        assert!(cache.contains(&nonce(4)));
    }

    #[test]
    fn test_expire_at_epoch_boundary() {
        let mut cache = NonceCache::new();
        // Exactly at the window boundary: epoch 0 at current epoch 2.
        cache.insert(nonce(1), 0);
        // 2 - 0 = 2, which is NOT > REPLAY_EPOCH_WINDOW (2) → retained.
        cache.expire(2);
        assert!(
            cache.contains(&nonce(1)),
            "nonce exactly at boundary must be retained"
        );

        // Now advance one more epoch: 3 - 0 = 3 > 2 → expired.
        cache.expire(3);
        assert!(
            !cache.contains(&nonce(1)),
            "nonce past boundary must be expired"
        );
    }

    #[test]
    fn test_empty_expire_is_noop() {
        let mut cache = NonceCache::new();
        cache.expire(100); // Must not panic.
        assert!(cache.is_empty());
    }
}
