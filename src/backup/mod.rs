//! State snapshot backup and restore verification (issue #70).
//!
//! This module provides scheduled state snapshot creation, integrity
//! verification, and restore testing. Snapshots are identified by epoch and
//! carry a Merkle-style integrity hash derived from the stored state so that
//! corruption or incomplete restores can be detected deterministically.

pub mod state_snapshot;
