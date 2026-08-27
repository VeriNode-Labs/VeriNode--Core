//! Attestation signing-root computation and signature verification.
//!
//! Also contains the proof-of-connectivity protocol with epoch-scoped nonces
//! (issue #54): `types`, `nonce_generator`, `nonce_cache`, and
//! `proof_of_connectivity`.
//!
//! `relay_ticket` (issue #140) applies the same domain-separated signing model
//! to STUN/TURN relay endpoint claims, so the endpoint cache in
//! `crate::network::relay` can authenticate *and authorize* every write.

pub mod bitfield;
pub mod bls_aggregator;
pub mod inclusion_tracker;
pub mod key_registry;
pub mod nonce_cache;
pub mod nonce_generator;
pub mod proof_of_connectivity;
#[path = "relay-ticket.rs"]
pub mod relay_ticket;
pub mod types;
pub mod verifier;

pub use bls_aggregator::{
    hash_message_to_root, truncated_prefix_32, verify_batch_items_with_cache,
    verify_batch_root_with_cache, verify_batch_with_cache, xor_fold_32, BLSBatchItem,
    BLSBatchVerificationCache, BLSCacheEntry, BLSCacheKey, BLSCacheMetrics,
    DEFAULT_BLS_CACHE_CAPACITY,
};
