//! Main consensus engine (issue #137).
//!
//! Wires together equivocation detection, timeout-based leader election,
//! and synchronous fallback recovery into a single consensus loop.

pub mod consensus_engine;

pub use consensus_engine::{ConsensusEngine, ConsensusEngineError, ConsensusEngineEvent};
