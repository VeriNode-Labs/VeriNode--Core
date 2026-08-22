//! BFT View-Change Quorum Certificate Validation and Partition Resolver (issue #142).
//!
//! Under network partitions, divergent Quorum Certificates (QCs) can be generated
//! concurrently by split validator subsets for the same consensus view.
//! When network connectivity is restored, nodes must deterministically resolve
//! divergent certificates to avoid split-brain and converge on a single canonical view.
//!
//! # Architecture
//!
//! * [`types`] — [`QuorumCertificate`] ([`QC`]), [`QcConflictDetected`],
//!   [`ViewChangeEvent`], and the deterministic tie-breaking logic:
//!   1. Highest `qc_epoch` wins (monotonic proposal counter).
//!   2. If epochs are equal, highest lexicographical SHA-256 hash of the sorted public-key set wins.
//!   3. If key hashes match, lexicographical `block_hash` tie-breaker.
//! * [`quarantine`] — [`QuarantineBuffer`] holding losing conflicting QCs for
//!   [`QUARANTINE_ROUND_LIMIT`] (2) view-change rounds before garbage collection.
//! * [`resolver`] — [`ViewChangeResolver`] orchestrating proposal increments,
//!   cross-partition QC conflict resolution, quarantine management, and observability event emission.
//!
//! All logic is pure Rust, integer-based, deterministic, and `no_std` compatible.

pub mod quarantine;
pub mod resolver;
pub mod types;

pub use quarantine::{QuarantineBuffer, QuarantinedQc};
pub use resolver::{create_conflict_event, QcProcessOutcome, ViewChangeResolver};
pub use types::{
    compute_public_key_set_hash, AggregateSignature, BlockHash, PublicKey, QcConflictDetected,
    QuorumCertificate, ViewChangeError, ViewChangeEvent, CONVERGENCE_ROUND_LIMIT, QC,
    QUARANTINE_ROUND_LIMIT,
};
