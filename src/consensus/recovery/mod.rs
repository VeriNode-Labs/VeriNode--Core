//! Consensus recovery subsystem (issue #137).
//!
//! Provides synchronous Byzantine-fault-tolerant fallback consensus when the
//! primary consensus engine deadlocks after repeated equivocation attacks.

pub mod fallback_sync;

pub use fallback_sync::{FallbackSyncEngine, FallbackSyncError, FallbackSyncEvent, LockedValue};
