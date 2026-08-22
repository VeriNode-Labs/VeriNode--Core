//! Leader election subsystem (issue #137).
//!
//! Provides timeout-based leader rotation with Byzantine equivocation
//! fast-path: upon receiving an [`EquivocationProof`] the current view is
//! immediately advanced without waiting for the normal timeout.

pub mod timeout_leader;

pub use timeout_leader::{LeaderElectionEvent, TimeoutLeader, TimeoutLeaderError};
