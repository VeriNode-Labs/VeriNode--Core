//! Attestation signing-root computation and signature verification.
//!
//! Also contains the proof-of-connectivity protocol with epoch-scoped nonces
//! (issue #54): `types`, `nonce_generator`, `nonce_cache`, and
//! `proof_of_connectivity`.

pub mod bitfield;
pub mod bls_aggregator;
pub mod inclusion_tracker;
pub mod key_registry;
pub mod nonce_cache;
pub mod nonce_generator;
pub mod proof_of_connectivity;
pub mod types;
pub mod verifier;
