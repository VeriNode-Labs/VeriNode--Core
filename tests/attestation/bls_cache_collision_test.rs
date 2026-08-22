//! Comprehensive BLS Signature Batch Verification Cache Collision & Security Tests
//!
//! Fixes #144: BLS signature batch verification cache index collision via truncated message root.
//!
//! Tests:
//! 1. Synthetic 32-bit prefix collisions (distinct 256-bit message roots sharing the same 32-bit prefix).
//! 2. Synthetic 32-bit XOR-fold collisions (distinct 256-bit message roots sharing the same XOR fold).
//! 3. High-density collision stress test (100 distinct 256-bit roots sharing prefix & XOR-fold with alternating validity).
//! 4. Multi-aggregator index isolation on identical message roots.
//! 5. Cache hit/miss/eviction telemetry accounting and basis-point ratios.
//! 6. Strict LRU eviction and key replacement behavior under bounded capacity.
//! 7. Subgroup check enforcement integration with cached verification outcomes.
//! 8. Batch verification items helper (`verify_batch_items_with_cache`).
//! 9. Preimage and collision resistance of `hash_message_to_root`.

use sorosusu_contracts::attestation::bls_aggregator::{
    hash_message_to_root, sign_message, truncated_prefix_32, verify_batch_items_with_cache,
    verify_batch_root_with_cache, verify_batch_with_cache, xor_fold_32, BLSBatchItem,
    BLSBatchVerificationCache, BLSCacheKey, SignatureVerifierConfig,
};
use sorosusu_contracts::crypto::bls_keys::{
    low_order_point, subgroup_member, G2Point,
};
use sorosusu_contracts::crypto::sha256::sha256;

#[test]
fn test_hash_message_to_root_preimage_resistance() {
    let msg1 = b"VeriNode-Attestation-Slot-1000";
    let msg2 = b"VeriNode-Attestation-Slot-1001";

    let root1 = hash_message_to_root(msg1);
    let root2 = hash_message_to_root(msg2);

    assert_eq!(root1, sha256(msg1));
    assert_eq!(root2, sha256(msg2));
    assert_ne!(root1, root2);
    assert_eq!(root1.len(), 32);
}

#[test]
fn test_synthetic_32bit_prefix_collision_guard() {
    let mut cache = BLSBatchVerificationCache::new(64);
    let cfg = SignatureVerifierConfig::REQUIRE_SUBGROUP_CHECK;

    let pk = subgroup_member(7);
    let agg_idx = 101u64;

    // Construct two distinct 256-bit message roots that share the exact same 32-bit prefix.
    let mut root_valid = [0u8; 32];
    let mut root_invalid = [0u8; 32];

    let shared_prefix = [0xFE, 0xED, 0xFA, 0xCE];
    root_valid[0..4].copy_from_slice(&shared_prefix);
    root_invalid[0..4].copy_from_slice(&shared_prefix);

    root_valid[4..8].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    root_invalid[4..8].copy_from_slice(&[0x99, 0x88, 0x77, 0x66]);

    // Verify 32-bit prefix matches exactly
    assert_eq!(
        truncated_prefix_32(&root_valid),
        truncated_prefix_32(&root_invalid)
    );
    assert_ne!(root_valid, root_invalid);

    // Create valid signature for root_valid and invalid signature for root_invalid
    let valid_sig = sign_message(&pk, &root_valid);
    let corrupted_sig = [0x55u8; 32];

    let pks = vec![pk];
    let valid_sigs = vec![valid_sig];
    let invalid_sigs = vec![corrupted_sig];

    // Step 1: Verify valid root -> should succeed and cache `true`
    assert!(verify_batch_root_with_cache(
        cfg,
        &mut cache,
        &pks,
        &root_valid,
        &valid_sigs,
        agg_idx,
    ));
    assert_eq!(cache.metrics().misses, 1);
    assert_eq!(cache.metrics().hits, 0);

    // Step 2: Verify colliding root with invalid signature -> must NOT return false-positive `true`!
    assert!(!verify_batch_root_with_cache(
        cfg,
        &mut cache,
        &pks,
        &root_invalid,
        &invalid_sigs,
        agg_idx,
    ));
    assert_eq!(cache.metrics().misses, 2);
    assert_eq!(cache.metrics().hits, 0);

    // Step 3: Query valid root again -> cache hit returning `true`
    assert!(verify_batch_root_with_cache(
        cfg,
        &mut cache,
        &pks,
        &root_valid,
        &valid_sigs,
        agg_idx,
    ));
    assert_eq!(cache.metrics().hits, 1);

    // Step 4: Query invalid root again -> cache hit returning `false` (no false negative on valid root)
    assert!(!verify_batch_root_with_cache(
        cfg,
        &mut cache,
        &pks,
        &root_invalid,
        &invalid_sigs,
        agg_idx,
    ));
    assert_eq!(cache.metrics().hits, 2);
}

#[test]
fn test_synthetic_xor_fold_collision_guard() {
    let mut cache = BLSBatchVerificationCache::new(64);
    let cfg = SignatureVerifierConfig::REQUIRE_SUBGROUP_CHECK;

    let pk = subgroup_member(13);
    let agg_idx = 202u64;

    // Construct two distinct 256-bit message roots with identical 32-bit XOR fold
    let mut root_a = [0u8; 32];
    let mut root_b = [0u8; 32];

    root_a[0..4].copy_from_slice(&[0x10, 0x20, 0x30, 0x40]);
    root_a[4..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);

    root_b[0..4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    root_b[4..8].copy_from_slice(&[0x10, 0x20, 0x30, 0x40]);

    assert_eq!(xor_fold_32(&root_a), xor_fold_32(&root_b));
    assert_ne!(root_a, root_b);

    let sig_a = sign_message(&pk, &root_a);
    let bad_sig_b = [0xFFu8; 32];

    let pks = vec![pk];
    let sigs_a = vec![sig_a];
    let sigs_b = vec![bad_sig_b];

    // Verify root_a (valid) -> true
    assert!(verify_batch_root_with_cache(
        cfg,
        &mut cache,
        &pks,
        &root_a,
        &sigs_a,
        agg_idx,
    ));

    // Verify root_b (invalid, colliding fold) -> must return false
    assert!(!verify_batch_root_with_cache(
        cfg,
        &mut cache,
        &pks,
        &root_b,
        &sigs_b,
        agg_idx,
    ));

    // Re-verify both from cache
    assert!(verify_batch_root_with_cache(
        cfg,
        &mut cache,
        &pks,
        &root_a,
        &sigs_a,
        agg_idx,
    ));
    assert!(!verify_batch_root_with_cache(
        cfg,
        &mut cache,
        &pks,
        &root_b,
        &sigs_b,
        agg_idx,
    ));
}

#[test]
fn test_high_density_collision_stress() {
    let count = 100;
    let mut cache = BLSBatchVerificationCache::new(256);
    let cfg = SignatureVerifierConfig::REQUIRE_SUBGROUP_CHECK;

    let pk = subgroup_member(21);
    let pks = vec![pk];
    let agg_idx = 303u64;

    let mut roots: Vec<[u8; 32]> = Vec::with_capacity(count);
    let mut sigs: Vec<Vec<[u8; 32]>> = Vec::with_capacity(count);
    let mut expected: Vec<bool> = Vec::with_capacity(count);

    let shared_prefix = [0xDE, 0xAD, 0xBE, 0xEF];

    for i in 0..count {
        let mut r = [0u8; 32];
        r[0..4].copy_from_slice(&shared_prefix);
        r[4..8].copy_from_slice(&(i as u32).to_le_bytes());
        r[8..12].copy_from_slice(&((count - i) as u32).to_le_bytes());

        // Even indices get valid signatures, odd indices get corrupted signatures
        let is_valid = i % 2 == 0;
        let sig = if is_valid {
            sign_message(&pk, &r)
        } else {
            [0xEEu8; 32]
        };

        roots.push(r);
        sigs.push(vec![sig]);
        expected.push(is_valid);
    }

    // Verify all 100 roots - first pass (all misses)
    for i in 0..count {
        let outcome = verify_batch_root_with_cache(
            cfg,
            &mut cache,
            &pks,
            &roots[i],
            &sigs[i],
            agg_idx,
        );
        assert_eq!(
            outcome, expected[i],
            "Root {i} returned incorrect verification outcome on first check"
        );
    }

    assert_eq!(cache.metrics().misses, count as u64);
    assert_eq!(cache.metrics().hits, 0);

    // Verify all 100 roots - second pass (all hits)
    for i in 0..count {
        let outcome = verify_batch_root_with_cache(
            cfg,
            &mut cache,
            &pks,
            &roots[i],
            &sigs[i],
            agg_idx,
        );
        assert_eq!(
            outcome, expected[i],
            "Root {i} returned incorrect cached outcome on second check"
        );
    }

    assert_eq!(cache.metrics().hits, count as u64);
    assert_eq!(cache.metrics().total_lookups(), (count * 2) as u64);
    assert_eq!(cache.metrics().hit_ratio_bps(), 5_000);
}

#[test]
fn test_multi_aggregator_index_isolation() {
    let mut cache = BLSBatchVerificationCache::new(32);
    let cfg = SignatureVerifierConfig::REQUIRE_SUBGROUP_CHECK;

    let pk = subgroup_member(35);
    let msg = b"same-message-different-aggregators";
    let root = hash_message_to_root(msg);

    let valid_sig = sign_message(&pk, msg);
    let invalid_sig = [0x11u8; 32];

    let pks = vec![pk];

    // Aggregator 1: valid signature
    assert!(verify_batch_with_cache(
        cfg,
        &mut cache,
        &pks,
        msg,
        &[valid_sig],
        1,
    ));

    // Aggregator 2: invalid signature on SAME message root
    assert!(!verify_batch_with_cache(
        cfg,
        &mut cache,
        &pks,
        msg,
        &[invalid_sig],
        2,
    ));

    // Aggregator 1 is still cached as true
    assert_eq!(cache.peek(&root, 1), Some(true));
    // Aggregator 2 is cached as false
    assert_eq!(cache.peek(&root, 2), Some(false));
    // Aggregator 3 is not present
    assert_eq!(cache.peek(&root, 3), None);
}

#[test]
fn test_cache_hit_miss_metrics_and_reset() {
    let mut cache = BLSBatchVerificationCache::new(10);
    assert_eq!(cache.metrics().total_lookups(), 0);
    assert_eq!(cache.metrics().hit_ratio_bps(), 0);

    let key1 = BLSCacheKey::new([1u8; 32], 0);
    let key2 = BLSCacheKey::new([2u8; 32], 0);

    assert_eq!(cache.get_by_key(&key1), None);
    assert_eq!(cache.metrics().misses, 1);

    cache.insert_key(key1, true);
    assert_eq!(cache.get_by_key(&key1), Some(true));
    assert_eq!(cache.metrics().hits, 1);
    assert_eq!(cache.metrics().total_lookups(), 2);
    assert_eq!(cache.metrics().hit_ratio_bps(), 5_000);

    assert_eq!(cache.get_by_key(&key2), None);
    assert_eq!(cache.metrics().misses, 2);
    assert_eq!(cache.metrics().total_lookups(), 3);
    assert_eq!(cache.metrics().hit_ratio_bps(), 3_333);

    cache.reset_metrics();
    assert_eq!(cache.metrics().hits, 0);
    assert_eq!(cache.metrics().misses, 0);
    assert_eq!(cache.metrics().evictions, 0);
}

#[test]
fn test_lru_eviction_and_replacement() {
    let mut cache = BLSBatchVerificationCache::new(3);

    let r1 = [1u8; 32];
    let r2 = [2u8; 32];
    let r3 = [3u8; 32];
    let r4 = [4u8; 32];

    cache.insert(r1, 0, true);
    cache.insert(r2, 0, true);
    cache.insert(r3, 0, true);
    assert_eq!(cache.len(), 3);
    assert_eq!(cache.metrics().evictions, 0);

    // Touch r1 and r2 so r3 becomes least recently used
    assert_eq!(cache.get(&r1, 0), Some(true));
    assert_eq!(cache.get(&r2, 0), Some(true));

    // Insert r4 -> r3 should be evicted
    cache.insert(r4, 0, true);
    assert_eq!(cache.len(), 3);
    assert_eq!(cache.metrics().evictions, 1);

    assert_eq!(cache.get(&r3, 0), None); // Miss
    assert_eq!(cache.get(&r1, 0), Some(true)); // Hit
    assert_eq!(cache.get(&r2, 0), Some(true)); // Hit
    assert_eq!(cache.get(&r4, 0), Some(true)); // Hit

    // Key update/replacement should NOT increase length or trigger eviction
    cache.insert(r1, 0, false);
    assert_eq!(cache.len(), 3);
    assert_eq!(cache.metrics().evictions, 1);
    assert_eq!(cache.get(&r1, 0), Some(false));
}

#[test]
fn test_subgroup_check_enforcement_with_cache() {
    let mut cache = BLSBatchVerificationCache::new(10);
    let strict_cfg = SignatureVerifierConfig::REQUIRE_SUBGROUP_CHECK;
    let test_cfg = SignatureVerifierConfig::TEST_NETWORK;

    let rogue_key = low_order_point(1);
    let msg = b"subgroup-enforcement-test";
    let sig = sign_message(&rogue_key, msg);

    let pks = vec![rogue_key];
    let sigs = vec![sig];

    // Under strict policy, rogue key fails and caches false
    assert!(!verify_batch_with_cache(
        strict_cfg,
        &mut cache,
        &pks,
        msg,
        &sigs,
        500,
    ));
    assert_eq!(
        cache.peek(&hash_message_to_root(msg), 500),
        Some(false)
    );

    // Clear cache and test under TEST_NETWORK (vulnerability demo)
    cache.clear();
    assert!(verify_batch_with_cache(
        test_cfg,
        &mut cache,
        &pks,
        msg,
        &sigs,
        500,
    ));
    assert_eq!(
        cache.peek(&hash_message_to_root(msg), 500),
        Some(true)
    );
}

#[test]
fn test_verify_batch_items_with_cache_all_valid_and_partial_failure() {
    let mut cache = BLSBatchVerificationCache::new(64);
    let cfg = SignatureVerifierConfig::REQUIRE_SUBGROUP_CHECK;

    let pk1 = subgroup_member(1);
    let pk2 = subgroup_member(2);
    let pk3 = subgroup_member(3);

    let msg1 = b"batch-item-1";
    let msg2 = b"batch-item-2";
    let msg3 = b"batch-item-3";

    let sig1 = sign_message(&pk1, msg1);
    let sig2 = sign_message(&pk2, msg2);
    let sig3 = sign_message(&pk3, msg3);

    let pks1 = vec![pk1];
    let pks2 = vec![pk2];
    let pks3 = vec![pk3];

    let sigs1 = vec![sig1];
    let sigs2 = vec![sig2];
    let sigs3 = vec![sig3];

    let items = vec![
        BLSBatchItem {
            public_keys: &pks1,
            msg: msg1,
            signatures: &sigs1,
            aggregator_index: 1,
        },
        BLSBatchItem {
            public_keys: &pks2,
            msg: msg2,
            signatures: &sigs2,
            aggregator_index: 2,
        },
        BLSBatchItem {
            public_keys: &pks3,
            msg: msg3,
            signatures: &sigs3,
            aggregator_index: 3,
        },
    ];

    // All items valid -> batch verification returns true
    assert!(verify_batch_items_with_cache(cfg, &mut cache, &items));

    // Tamper with item 2's signature
    let corrupted_sig2 = vec![[0x99u8; 32]];
    let tampered_items = vec![
        BLSBatchItem {
            public_keys: &pks1,
            msg: msg1,
            signatures: &sigs1,
            aggregator_index: 1,
        },
        BLSBatchItem {
            public_keys: &pks2,
            msg: msg2,
            signatures: &corrupted_sig2,
            aggregator_index: 99,
        },
    ];

    assert!(!verify_batch_items_with_cache(
        cfg,
        &mut cache,
        &tampered_items
    ));
}

#[test]
fn test_empty_and_mismatched_batch_inputs() {
    let mut cache = BLSBatchVerificationCache::new(10);
    let cfg = SignatureVerifierConfig::REQUIRE_SUBGROUP_CHECK;

    let empty_pks: Vec<G2Point> = vec![];
    let empty_sigs: Vec<[u8; 32]> = vec![];
    let msg = b"empty-test";

    // Empty batch returns false
    assert!(!verify_batch_with_cache(
        cfg,
        &mut cache,
        &empty_pks,
        msg,
        &empty_sigs,
        1,
    ));

    // Mismatched lengths
    let pks = vec![subgroup_member(1)];
    let sigs = vec![[0u8; 32], [0u8; 32]];
    assert!(!verify_batch_with_cache(
        cfg,
        &mut cache,
        &pks,
        msg,
        &sigs,
        2,
    ));

    // Empty batch items slice
    assert!(!verify_batch_items_with_cache(cfg, &mut cache, &[]));
}
