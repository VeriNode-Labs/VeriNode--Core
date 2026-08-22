//! BLS single and aggregate signature verification with subgroup enforcement
//! and 256-bit collision-resistant batch verification caching.
//!
//! Fixes #12: every untrusted public key is subgroup-checked before its
//! signature is trusted. The signature primitive itself is the same mock MAC
//! used elsewhere in this crate (a stand-in for BLS pairing verification); the
//! security-relevant gate under test is the subgroup check, not the MAC.
//!
//! Fixes #144: BLS signature batch verification cache index collision via
//! truncated message root. Previously, caches indexing signatures via truncated
//! 32-bit prefixes or XOR-folded hashes were vulnerable to collisions where
//! distinct 256-bit message roots mapped to the same cache entry, causing false
//! positives (accepting invalid signatures) or false negatives (rejecting valid
//! signatures). The cache now indexes on the full 256-bit message root and
//! aggregator index, performs full 256-bit comparison on lookup, and maintains
//! bounded LRU capacity.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::crypto::bls_keys::{subgroup_check_g2, G2Point};
use crate::crypto::sha256::sha256;

/// Default maximum capacity for the BLS batch verification cache (8192 entries).
pub const DEFAULT_BLS_CACHE_CAPACITY: usize = 8192;

/// A signature (mock: a MAC keyed by the serialized public key).
pub type Signature = [u8; 32];

/// A 256-bit message root.
pub type MessageRoot = [u8; 32];

/// Verifier configuration toggle (#12, step 4).
///
/// Production networks require the subgroup check; only test networks may
/// disable it. Default is `require_subgroup_check = true`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureVerifierConfig {
    pub require_subgroup_check: bool,
}

impl Default for SignatureVerifierConfig {
    fn default() -> Self {
        Self {
            require_subgroup_check: true,
        }
    }
}

impl SignatureVerifierConfig {
    /// Production policy: subgroup checks enabled (the `RequireSubgroupCheck`
    /// toggle in its on position).
    pub const REQUIRE_SUBGROUP_CHECK: Self = Self {
        require_subgroup_check: true,
    };

    /// Test-network policy: subgroup checks disabled. Reproduces the
    /// pre-#12 (vulnerable) verification path.
    pub const TEST_NETWORK: Self = Self {
        require_subgroup_check: false,
    };
}

/// A 256-bit cryptographic cache key pairing the full message root and the aggregator index.
///
/// Fixes #144: Prevents hash collision attacks and false-positive verification by
/// retaining the full 256-bit root instead of truncated 32-bit or XOR-folded representations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BLSCacheKey {
    pub message_root_256: [u8; 32],
    pub aggregator_index: u64,
}

impl BLSCacheKey {
    /// Create a new 256-bit cache key.
    pub const fn new(message_root_256: [u8; 32], aggregator_index: u64) -> Self {
        Self {
            message_root_256,
            aggregator_index,
        }
    }
}

/// A batch verification cache entry storing the verification outcome and full message root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BLSCacheEntry {
    pub full_message_root: [u8; 32],
    pub aggregator_index: u64,
    pub is_valid: bool,
    pub access_seq: u64,
}

impl BLSCacheEntry {
    /// Create a new cache entry.
    pub const fn new(
        full_message_root: [u8; 32],
        aggregator_index: u64,
        is_valid: bool,
        access_seq: u64,
    ) -> Self {
        Self {
            full_message_root,
            aggregator_index,
            is_valid,
            access_seq,
        }
    }
}

/// Cache telemetry counters for BLS batch verification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BLSCacheMetrics {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

impl BLSCacheMetrics {
    /// Total number of cache lookups.
    pub fn total_lookups(&self) -> u64 {
        self.hits.saturating_add(self.misses)
    }

    /// Hit ratio in basis points (0 to 10,000).
    pub fn hit_ratio_bps(&self) -> u64 {
        let total = self.total_lookups();
        if total == 0 {
            0
        } else {
            (self.hits.saturating_mul(10_000)) / total
        }
    }
}

/// Bounded LRU cache for BLS aggregate and batch signature verification results.
///
/// Ensures full 256-bit message root validation on every lookup to eliminate
/// false-positive and false-negative verification collisions (Issue #144).
#[derive(Clone, Debug)]
pub struct BLSBatchVerificationCache {
    max_capacity: usize,
    entries: BTreeMap<BLSCacheKey, (BLSCacheEntry, u64)>,
    lru_order: BTreeMap<(u64, BLSCacheKey), ()>,
    next_seq: u64,
    metrics: BLSCacheMetrics,
}

impl Default for BLSBatchVerificationCache {
    fn default() -> Self {
        Self::new(DEFAULT_BLS_CACHE_CAPACITY)
    }
}

impl BLSBatchVerificationCache {
    /// Create a new cache with the specified capacity limit.
    pub fn new(max_capacity: usize) -> Self {
        Self {
            max_capacity,
            entries: BTreeMap::new(),
            lru_order: BTreeMap::new(),
            next_seq: 0,
            metrics: BLSCacheMetrics::default(),
        }
    }

    /// Convenience alias for `new`.
    pub fn with_capacity(max_capacity: usize) -> Self {
        Self::new(max_capacity)
    }

    /// Configured maximum capacity.
    pub fn capacity(&self) -> usize {
        self.max_capacity
    }

    /// Number of entries currently in cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache contains zero entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Current telemetry metrics snapshot.
    pub fn metrics(&self) -> BLSCacheMetrics {
        self.metrics
    }

    /// Reset telemetry metrics to zero.
    pub fn reset_metrics(&mut self) {
        self.metrics = BLSCacheMetrics::default();
    }

    /// Clear all entries from cache.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.lru_order.clear();
    }

    /// Check if an entry exists in cache without mutating access order or metrics.
    pub fn contains(&self, message_root: &[u8; 32], aggregator_index: u64) -> bool {
        let key = BLSCacheKey::new(*message_root, aggregator_index);
        self.entries.contains_key(&key)
    }

    /// Peek at a cached result without updating metrics or LRU order.
    pub fn peek(&self, message_root: &[u8; 32], aggregator_index: u64) -> Option<bool> {
        let key = BLSCacheKey::new(*message_root, aggregator_index);
        self.entries.get(&key).map(|(entry, _)| entry.is_valid)
    }

    /// Lookup a verification result with full 256-bit root validation and LRU promotion.
    pub fn get(&mut self, message_root: &[u8; 32], aggregator_index: u64) -> Option<bool> {
        let key = BLSCacheKey::new(*message_root, aggregator_index);
        self.get_by_key(&key)
    }

    /// Lookup by `BLSCacheKey`.
    pub fn get_by_key(&mut self, key: &BLSCacheKey) -> Option<bool> {
        if let Some(&(entry, old_seq)) = self.entries.get(key) {
            // Full 256-bit message root validation + aggregator index validation (#144)
            if entry.full_message_root == key.message_root_256
                && entry.aggregator_index == key.aggregator_index
            {
                self.metrics.hits = self.metrics.hits.saturating_add(1);
                self.lru_order.remove(&(old_seq, *key));
                self.next_seq = self.next_seq.wrapping_add(1);
                let new_seq = self.next_seq;
                let mut updated_entry = entry;
                updated_entry.access_seq = new_seq;
                self.entries.insert(*key, (updated_entry, new_seq));
                self.lru_order.insert((new_seq, *key), ());
                return Some(entry.is_valid);
            }
        }
        self.metrics.misses = self.metrics.misses.saturating_add(1);
        None
    }

    /// Insert or update a verification outcome in the cache with LRU eviction if full.
    pub fn insert(&mut self, message_root: [u8; 32], aggregator_index: u64, is_valid: bool) {
        let key = BLSCacheKey::new(message_root, aggregator_index);
        self.insert_key(key, is_valid);
    }

    /// Insert or update by `BLSCacheKey`.
    pub fn insert_key(&mut self, key: BLSCacheKey, is_valid: bool) {
        if self.max_capacity == 0 {
            return;
        }

        if let Some(&(_, old_seq)) = self.entries.get(&key) {
            self.lru_order.remove(&(old_seq, key));
            self.next_seq = self.next_seq.wrapping_add(1);
            let new_seq = self.next_seq;
            let updated_entry = BLSCacheEntry::new(
                key.message_root_256,
                key.aggregator_index,
                is_valid,
                new_seq,
            );
            self.entries.insert(key, (updated_entry, new_seq));
            self.lru_order.insert((new_seq, key), ());
            return;
        }

        while self.entries.len() >= self.max_capacity {
            if let Some(&(oldest_seq, oldest_key)) = self.lru_order.keys().next() {
                self.lru_order.remove(&(oldest_seq, oldest_key));
                self.entries.remove(&oldest_key);
                self.metrics.evictions = self.metrics.evictions.saturating_add(1);
            } else {
                break;
            }
        }

        self.next_seq = self.next_seq.wrapping_add(1);
        let new_seq = self.next_seq;
        let entry = BLSCacheEntry::new(
            key.message_root_256,
            key.aggregator_index,
            is_valid,
            new_seq,
        );
        self.entries.insert(key, (entry, new_seq));
        self.lru_order.insert((new_seq, key), ());
    }
}

/// Mock signature: `SHA-256(pk_bytes || msg)`. Stands in for BLS pairing
/// verification — a holder of `pk` (or an attacker who supplies their own
/// `pk`) can produce a matching signature, which is exactly why the subgroup
/// check on `pk` is the load-bearing defense.
fn mac(public_key: &G2Point, msg: &[u8]) -> Signature {
    let mut buf = Vec::with_capacity(8 + msg.len());
    buf.extend_from_slice(&public_key.to_bytes());
    buf.extend_from_slice(msg);
    sha256(&buf)
}

/// Produce a signature over `msg` for `public_key`.
pub fn sign_message(public_key: &G2Point, msg: &[u8]) -> Signature {
    mac(public_key, msg)
}

/// Cryptographically hash an arbitrary message slice into a full 256-bit message root.
///
/// Retains full preimage and collision resistance (256-bit SHA-256 digest).
pub fn hash_message_to_root(msg: &[u8]) -> [u8; 32] {
    sha256(msg)
}

/// Extract the truncated 32-bit prefix of a 256-bit root (little-endian).
/// Provided for vulnerability regression and collision analysis.
pub fn truncated_prefix_32(root: &[u8; 32]) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&root[..4]);
    u32::from_le_bytes(bytes)
}

/// Compute the 32-bit XOR fold of a 256-bit root.
/// Provided for vulnerability regression and collision analysis.
pub fn xor_fold_32(root: &[u8; 32]) -> u32 {
    let mut folded = 0u32;
    for chunk in root.chunks_exact(4) {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(chunk);
        folded ^= u32::from_le_bytes(bytes);
    }
    folded
}

/// Verify a single signature.
///
/// Defense-in-depth (#12, step 3): when enabled, the public key is rejected
/// unless it lies in the prime-order subgroup — even if ingress validation was
/// somehow bypassed.
pub fn verify_single_signature(
    config: SignatureVerifierConfig,
    public_key: &G2Point,
    msg: &[u8],
    signature: &Signature,
) -> bool {
    if config.require_subgroup_check && !subgroup_check_g2(public_key) {
        return false;
    }
    ct_eq(&mac(public_key, msg), signature)
}

/// Verify an aggregate over a common message: every `(public_key, signature)`
/// pair must validate (and every key must pass the subgroup check when
/// enabled). Returns `false` on empty or length-mismatched inputs.
pub fn verify_aggregate(
    config: SignatureVerifierConfig,
    public_keys: &[G2Point],
    msg: &[u8],
    signatures: &[Signature],
) -> bool {
    if public_keys.is_empty() || public_keys.len() != signatures.len() {
        return false;
    }
    public_keys
        .iter()
        .zip(signatures.iter())
        .all(|(pk, sig)| verify_single_signature(config, pk, msg, sig))
}

/// Batch verification of BLS aggregate signatures with full 256-bit cache collision guard.
///
/// On cache hit (matching full 256-bit message root and aggregator index), returns the
/// cached verification boolean result without repeating expensive group operations.
/// On cache miss, performs full subgroup and aggregate signature verification, caches the
/// result, and maintains LRU cache bounds.
pub fn verify_batch_with_cache(
    config: SignatureVerifierConfig,
    cache: &mut BLSBatchVerificationCache,
    public_keys: &[G2Point],
    msg: &[u8],
    signatures: &[Signature],
    aggregator_index: u64,
) -> bool {
    let message_root = hash_message_to_root(msg);
    if let Some(valid) = cache.get(&message_root, aggregator_index) {
        return valid;
    }

    let is_valid = verify_aggregate(config, public_keys, msg, signatures);
    cache.insert(message_root, aggregator_index, is_valid);
    is_valid
}

/// Batch verification with a precomputed 256-bit message root and cache lookup.
pub fn verify_batch_root_with_cache(
    config: SignatureVerifierConfig,
    cache: &mut BLSBatchVerificationCache,
    public_keys: &[G2Point],
    message_root: &[u8; 32],
    signatures: &[Signature],
    aggregator_index: u64,
) -> bool {
    if let Some(valid) = cache.get(message_root, aggregator_index) {
        return valid;
    }

    let is_valid = verify_aggregate(config, public_keys, message_root, signatures);
    cache.insert(*message_root, aggregator_index, is_valid);
    is_valid
}

/// A single batch item for multi-message or multi-aggregator batch verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BLSBatchItem<'a> {
    pub public_keys: &'a [G2Point],
    pub msg: &'a [u8],
    pub signatures: &'a [Signature],
    pub aggregator_index: u64,
}

/// Batch verify multiple distinct items using the batch verification cache.
pub fn verify_batch_items_with_cache(
    config: SignatureVerifierConfig,
    cache: &mut BLSBatchVerificationCache,
    items: &[BLSBatchItem],
) -> bool {
    if items.is_empty() {
        return false;
    }
    let mut all_valid = true;
    for item in items {
        let valid = verify_batch_with_cache(
            config,
            cache,
            item.public_keys,
            item.msg,
            item.signatures,
            item.aggregator_index,
        );
        if !valid {
            all_valid = false;
        }
    }
    all_valid
}

/// Constant-time comparison of two 32-byte values.
fn ct_eq(a: &Signature, b: &Signature) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::bls_keys::{low_order_point, subgroup_member};

    #[test]
    fn test_cache_hit_and_miss_accounting() {
        let mut cache = BLSBatchVerificationCache::new(10);
        let root = [1u8; 32];
        let agg_idx = 100u64;

        assert_eq!(cache.get(&root, agg_idx), None);
        assert_eq!(cache.metrics().misses, 1);
        assert_eq!(cache.metrics().hits, 0);

        cache.insert(root, agg_idx, true);
        assert_eq!(cache.get(&root, agg_idx), Some(true));
        assert_eq!(cache.metrics().hits, 1);
        assert_eq!(cache.metrics().misses, 1);
        assert_eq!(cache.metrics().total_lookups(), 2);
        assert_eq!(cache.metrics().hit_ratio_bps(), 5_000);
    }

    #[test]
    fn test_full_256_bit_collision_guard() {
        let mut cache = BLSBatchVerificationCache::new(10);
        let mut root_a = [0u8; 32];
        let mut root_b = [0u8; 32];

        // Share the same 32-bit prefix (first 4 bytes)
        root_a[0..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        root_b[0..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        // Differ in remaining bytes
        root_a[4] = 0x01;
        root_b[4] = 0x02;

        assert_eq!(truncated_prefix_32(&root_a), truncated_prefix_32(&root_b));
        assert_ne!(root_a, root_b);

        let agg_idx = 1;
        cache.insert(root_a, agg_idx, true);

        // root_b must NOT hit root_a's cached true
        assert_eq!(cache.get(&root_b, agg_idx), None);

        // Insert root_b as false
        cache.insert(root_b, agg_idx, false);

        // root_a returns true, root_b returns false
        assert_eq!(cache.get(&root_a, agg_idx), Some(true));
        assert_eq!(cache.get(&root_b, agg_idx), Some(false));
    }

    #[test]
    fn test_xor_fold_collision_guard() {
        let mut cache = BLSBatchVerificationCache::new(10);
        let mut root_a = [0u8; 32];
        let mut root_b = [0u8; 32];

        // Same XOR fold by swapping chunks
        root_a[0] = 0x01;
        root_a[4] = 0x02;

        root_b[0] = 0x02;
        root_b[4] = 0x01;

        assert_eq!(xor_fold_32(&root_a), xor_fold_32(&root_b));
        assert_ne!(root_a, root_b);

        cache.insert(root_a, 42, true);
        assert_eq!(cache.get(&root_b, 42), None);
        assert_eq!(cache.get(&root_a, 42), Some(true));
    }

    #[test]
    fn test_lru_eviction() {
        let mut cache = BLSBatchVerificationCache::new(2);
        let r1 = [1u8; 32];
        let r2 = [2u8; 32];
        let r3 = [3u8; 32];

        cache.insert(r1, 1, true);
        cache.insert(r2, 1, true);
        assert_eq!(cache.len(), 2);

        // Access r1 to make r2 the least recently used
        assert_eq!(cache.get(&r1, 1), Some(true));

        // Insert r3 -> should evict r2
        cache.insert(r3, 1, false);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.metrics().evictions, 1);

        assert_eq!(cache.get(&r2, 1), None);
        assert_eq!(cache.get(&r1, 1), Some(true));
        assert_eq!(cache.get(&r3, 1), Some(false));
    }

    #[test]
    fn test_verify_batch_with_cache_integration() {
        let mut cache = BLSBatchVerificationCache::new(10);
        let cfg = SignatureVerifierConfig::REQUIRE_SUBGROUP_CHECK;

        let pk1 = subgroup_member(1);
        let pk2 = subgroup_member(2);
        let rogue = low_order_point(0);

        let msg = b"signed-payload";
        let sig1 = sign_message(&pk1, msg);
        let sig2 = sign_message(&pk2, msg);

        let valid_pks = vec![pk1, pk2];
        let valid_sigs = vec![sig1, sig2];

        let agg_idx = 10;

        // First verification: cache miss
        assert!(verify_batch_with_cache(
            cfg,
            &mut cache,
            &valid_pks,
            msg,
            &valid_sigs,
            agg_idx
        ));
        assert_eq!(cache.metrics().misses, 1);
        assert_eq!(cache.metrics().hits, 0);

        // Second verification: cache hit
        assert!(verify_batch_with_cache(
            cfg,
            &mut cache,
            &valid_pks,
            msg,
            &valid_sigs,
            agg_idx
        ));
        assert_eq!(cache.metrics().hits, 1);

        // Rogue key verification fails and caches false
        let invalid_pks = vec![rogue];
        let invalid_sigs = vec![sign_message(&rogue, msg)];
        let bad_agg_idx = 20;

        assert!(!verify_batch_with_cache(
            cfg,
            &mut cache,
            &invalid_pks,
            msg,
            &invalid_sigs,
            bad_agg_idx
        ));
        assert_eq!(
            cache.peek(&hash_message_to_root(msg), bad_agg_idx),
            Some(false)
        );
    }
}
