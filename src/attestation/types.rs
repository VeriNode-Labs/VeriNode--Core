//! Core data structures for the proof-of-connectivity challenge/response protocol.
//!
//! ## Epoch-scoped nonce replay protection (issue #54)
//!
//! The original `Challenge` struct held only a bare nonce with no epoch binding.
//! Under rapid reconnect a node could reuse a nonce from a previously
//! disconnected epoch, bypassing connectivity verification entirely (replay
//! attack).
//!
//! The fix adds an `epoch_id: u32` field to `Challenge`. The nonce is now
//! derived as `BLAKE2b(epoch_id || random_seed || node_id)`, so two challenges
//! in different epochs with the same random seed are guaranteed to produce
//! distinct nonces.  The verifier rejects any challenge whose epoch is more
//! than 2 behind the current epoch, and the nonce cache expires entries on the
//! same boundary.

extern crate alloc;

/// Epoch identifier — a monotonically incrementing `u32`, advanced every
/// `EPOCH_DURATION_SECS` seconds by the connectivity scheduler.
pub type EpochId = u32;

/// A node identifier (32 bytes).
pub type NodeId = [u8; 32];

/// A 256-bit nonce produced by the nonce generator.
pub type Nonce = [u8; 32];

/// Protocol timing constants.
///
/// | Constant                | Value |
/// |-------------------------|-------|
/// | `CHALLENGE_TIMEOUT_SECS`| 5 s   |
/// | `EPOCH_DURATION_SECS`   | 30 s  |
/// | `REPLAY_EPOCH_WINDOW`   | 2     |
/// | `MAX_FAILED_CHALLENGES` | 3     |
/// | `BLACKLIST_DURATION_SECS`| 60 s |
pub const CHALLENGE_TIMEOUT_SECS: u64 = 5;
pub const EPOCH_DURATION_SECS: u64 = 30;
/// Nonces from more than this many epochs ago are unconditionally rejected.
pub const REPLAY_EPOCH_WINDOW: u32 = 2;
/// Maximum failed challenges before a node is blacklisted.
pub const MAX_FAILED_CHALLENGES: u32 = 3;
/// Duration (seconds) a node is blacklisted after exceeding the failure limit.
pub const BLACKLIST_DURATION_SECS: u64 = 60;

/// A proof-of-connectivity challenge issued to a peer node.
///
/// The `epoch_id` field scopes the nonce to a specific epoch.  Challenges
/// from an epoch more than [`REPLAY_EPOCH_WINDOW`] behind the current epoch
/// are rejected by the verifier, preventing cross-epoch nonce replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// The epoch in which this challenge was generated.
    pub epoch_id: EpochId,
    /// The 256-bit epoch-scoped nonce (`BLAKE2b(epoch_id || seed || node_id)`).
    pub nonce: Nonce,
    /// Identifier of the challenged node.
    pub node_id: NodeId,
    /// Unix timestamp (seconds) at which the challenge was issued.
    pub issued_at: u64,
}

impl Challenge {
    /// Construct a new challenge.
    pub fn new(epoch_id: EpochId, nonce: Nonce, node_id: NodeId, issued_at: u64) -> Self {
        Self {
            epoch_id,
            nonce,
            node_id,
            issued_at,
        }
    }

    /// Returns `true` if this challenge has exceeded the per-round timeout.
    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.issued_at) > CHALLENGE_TIMEOUT_SECS
    }
}

/// A response to a [`Challenge`] returned by the challenged node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeResponse {
    /// Must echo the epoch_id of the original challenge.
    pub epoch_id: EpochId,
    /// Must echo the nonce of the original challenge.
    pub nonce: Nonce,
    /// Identifier of the responding node.
    pub node_id: NodeId,
}

impl ChallengeResponse {
    /// Construct a response from an original challenge.
    pub fn from_challenge(challenge: &Challenge) -> Self {
        Self {
            epoch_id: challenge.epoch_id,
            nonce: challenge.nonce,
            node_id: challenge.node_id,
        }
    }
}

/// Errors produced by challenge verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectivityError {
    /// The challenge epoch is more than [`REPLAY_EPOCH_WINDOW`] behind the
    /// current epoch — unconditional replay rejection.
    EpochTooOld,
    /// The nonce was already seen in the current replay window.
    NonceReused,
    /// The challenge has exceeded its per-round timeout.
    ChallengeExpired,
    /// The response does not match the pending challenge.
    ResponseMismatch,
    /// The node has exceeded [`MAX_FAILED_CHALLENGES`] and is blacklisted.
    NodeBlacklisted,
}

/// Per-node failure tracking used by the proof-of-connectivity protocol.
#[derive(Clone, Debug, Default)]
pub struct NodeFailureRecord {
    /// Number of consecutive failed challenges.
    pub failed_count: u32,
    /// Unix timestamp when the blacklist expires (0 = not blacklisted).
    pub blacklisted_until: u64,
}

impl NodeFailureRecord {
    /// Returns `true` if the node is currently blacklisted.
    pub fn is_blacklisted(&self, now: u64) -> bool {
        self.blacklisted_until > now
    }

    /// Record a failed challenge.  Applies blacklisting when the failure
    /// count reaches [`MAX_FAILED_CHALLENGES`].
    pub fn record_failure(&mut self, now: u64) {
        self.failed_count += 1;
        if self.failed_count >= MAX_FAILED_CHALLENGES {
            self.blacklisted_until = now + BLACKLIST_DURATION_SECS;
            self.failed_count = 0;
        }
    }

    /// Reset on a successful challenge.
    pub fn record_success(&mut self) {
        self.failed_count = 0;
    }
}

/// A random 32-byte seed used by the nonce generator.  In production this is
/// sourced from the platform's CSPRNG; in tests it is constructed explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomSeed(pub [u8; 32]);

impl RandomSeed {
    /// Construct a seed from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// A deterministic seed derived from a counter — useful in property tests.
    pub fn from_counter(n: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        Self(bytes)
    }
}
