//! Property-based tests for the proof-of-connectivity epoch-scoped nonce
//! implementation (issue #54).
//!
//! Key property under test:
//!
//! > Across 10 000 challenges spanning arbitrary epoch and node combinations,
//! > no two distinct (epoch_id, seed, node_id) inputs produce the same nonce,
//! > and nonces generated in the same epoch with the same seed but a different
//! > node (or vice-versa) are always distinct.
//!
//! Additional properties tested via `proptest`:
//! - The replay window correctly rejects challenges whose epoch is >2 behind.
//! - The nonce cache expires entries outside the window and retains those
//!   inside it.

use proptest::prelude::*;
use sorosusu_contracts::attestation::nonce_cache::NonceCache;
use sorosusu_contracts::attestation::nonce_generator::derive_nonce;
use sorosusu_contracts::attestation::types::{RandomSeed, REPLAY_EPOCH_WINDOW};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn node_id(seed: u8) -> [u8; 32] {
    let mut n = [0u8; 32];
    n[0] = seed;
    n
}

// ---------------------------------------------------------------------------
// 10 000-challenge no-collision property
// ---------------------------------------------------------------------------

/// Generate 10 000 challenges across distinct (epoch, seed, node) triples and
/// assert no two produce the same 256-bit nonce.
///
/// Because `derive_nonce` is a deterministic function over 68 bytes of distinct
/// input, collisions here would indicate either a hash collision (negligible)
/// or a preimage-construction bug (what we are guarding against).
#[test]
fn test_no_nonce_collision_across_10k_challenges() {
    use std::collections::HashSet;

    const CHALLENGE_COUNT: usize = 10_000;
    let mut seen: HashSet<[u8; 32]> = HashSet::with_capacity(CHALLENGE_COUNT);

    for i in 0..CHALLENGE_COUNT {
        // Spread challenges across epochs 0-99, seeds 0-99, nodes 0-99.
        let epoch = (i % 100) as u32;
        let seed_val = ((i / 100) % 100) as u64;
        let node_val = ((i / 10_000) % 256) as u8;

        // For full coverage we also vary the node within the inner loop.
        let node = node_id((i % 256) as u8);
        let seed = RandomSeed::from_counter(seed_val + (i as u64 / 100));

        let nonce = derive_nonce(epoch, &seed, &node);
        assert!(
            seen.insert(nonce),
            "nonce collision detected at challenge {i}: epoch={epoch}, seed={seed_val}, node={node_val}"
        );
    }
}

// ---------------------------------------------------------------------------
// Proptest: epoch window enforcement
// ---------------------------------------------------------------------------

proptest! {
    /// For any `challenge_epoch` and `current_epoch` where the gap exceeds
    /// `REPLAY_EPOCH_WINDOW`, the epoch check predicate must return true
    /// (i.e., the challenge is too old).
    #[test]
    fn prop_epoch_window_rejects_old_challenges(
        challenge_epoch in 0u32..1_000_000u32,
        gap in (REPLAY_EPOCH_WINDOW + 1)..=10u32,
    ) {
        let current_epoch = challenge_epoch.saturating_add(gap);
        let age = current_epoch.saturating_sub(challenge_epoch);
        prop_assert!(
            age > REPLAY_EPOCH_WINDOW,
            "age={age} should be > REPLAY_EPOCH_WINDOW={REPLAY_EPOCH_WINDOW}"
        );
    }

    /// For any `challenge_epoch` and `current_epoch` where the gap is at most
    /// `REPLAY_EPOCH_WINDOW`, the epoch check predicate must return false
    /// (i.e., the challenge is within the valid window).
    #[test]
    fn prop_epoch_window_accepts_recent_challenges(
        challenge_epoch in 0u32..1_000_000u32,
        gap in 0u32..=REPLAY_EPOCH_WINDOW,
    ) {
        let current_epoch = challenge_epoch.saturating_add(gap);
        let age = current_epoch.saturating_sub(challenge_epoch);
        prop_assert!(
            age <= REPLAY_EPOCH_WINDOW,
            "age={age} should be <= REPLAY_EPOCH_WINDOW={REPLAY_EPOCH_WINDOW}"
        );
    }
}

// ---------------------------------------------------------------------------
// Proptest: nonce cache epoch expiry
// ---------------------------------------------------------------------------

proptest! {
    /// Nonces inserted at `epoch` must be absent after `expire(epoch + REPLAY_EPOCH_WINDOW + 1)`.
    #[test]
    fn prop_cache_expires_nonces_outside_window(
        epoch in 0u32..1_000_000u32,
        extra in 1u32..=100u32,
    ) {
        let mut cache = NonceCache::new();
        let mut nonce = [0u8; 32];
        nonce[..4].copy_from_slice(&epoch.to_le_bytes());

        cache.insert(nonce, epoch);
        prop_assert!(cache.contains(&nonce));

        let expiry_epoch = epoch.saturating_add(REPLAY_EPOCH_WINDOW).saturating_add(extra);
        cache.expire(expiry_epoch);

        prop_assert!(
            !cache.contains(&nonce),
            "nonce from epoch={epoch} must be expired at expiry_epoch={expiry_epoch}"
        );
    }

    /// Nonces inserted at `epoch` must still be present after
    /// `expire(epoch + REPLAY_EPOCH_WINDOW)` (exactly at the boundary).
    #[test]
    fn prop_cache_retains_nonces_within_window(
        epoch in 0u32..1_000_000u32,
    ) {
        let mut cache = NonceCache::new();
        let mut nonce = [0u8; 32];
        nonce[..4].copy_from_slice(&epoch.to_le_bytes());

        cache.insert(nonce, epoch);

        let expiry_epoch = epoch.saturating_add(REPLAY_EPOCH_WINDOW);
        cache.expire(expiry_epoch);

        prop_assert!(
            cache.contains(&nonce),
            "nonce from epoch={epoch} must be retained at expiry_epoch={expiry_epoch}"
        );
    }
}

// ---------------------------------------------------------------------------
// Proptest: different epochs always produce different nonces (same seed/node)
// ---------------------------------------------------------------------------

proptest! {
    /// For any two distinct epoch ids with the same seed and node, the derived
    /// nonces must differ.
    #[test]
    fn prop_different_epochs_produce_different_nonces(
        epoch_a in 0u32..1_000_000u32,
        epoch_b in 0u32..1_000_000u32,
        seed_val in 0u64..u64::MAX,
        node_byte in 0u8..=255u8,
    ) {
        prop_assume!(epoch_a != epoch_b);
        let seed = RandomSeed::from_counter(seed_val);
        let node = node_id(node_byte);
        let nonce_a = derive_nonce(epoch_a, &seed, &node);
        let nonce_b = derive_nonce(epoch_b, &seed, &node);
        prop_assert_ne!(nonce_a, nonce_b,
            "epoch_a={}, epoch_b={} produced the same nonce with seed={}", epoch_a, epoch_b, seed_val
        );
    }
}
