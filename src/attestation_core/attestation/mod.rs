//! Distributed Node Attestation.
//!
//! Validators submit BLS signatures over node identity attestations.
//! These are aggregated per-node into a single compact signature.

pub mod aggregator;