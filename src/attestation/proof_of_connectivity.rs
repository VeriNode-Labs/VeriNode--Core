//! Proof-of-connectivity challenge/response logic with epoch-scoped nonces.
//!
//! ## Replay attack prevention (issue #54)
//!
//! The central invariant enforced here:
//!
//! > A challenge is **invalid** if `challenge.epoch_id < current_epoch - 2`.
//!
//! This unconditional check runs before the nonce cache is consulted, so even
//! if the cache were manipulated or exhausted, an out-of-window challenge is
//! always rejected.
//!
//! The full verification sequence for an incoming challenge:
//!
//! 1. **Blacklist check** — reject if the node is currently blacklisted.
//! 2. **Epoch window check** — reject if `challenge.epoch_id < current_epoch - 2`.
//! 3. **Timeout check** — reject if the challenge has exceeded its 5 s timeout.
//! 4. **Nonce-cache insert** — reject (and record failure) if the nonce was
//!    already seen; this is the anti-replay gate within the window.
//! 5. **Response match** — reject if the response echoes a different nonce or
//!    epoch than the pending challenge.
//!
//! On any rejection the per-node failure counter is incremented; after
//! [`MAX_FAILED_CHALLENGES`] failures the node is blacklisted for
//! [`BLACKLIST_DURATION_SECS`] seconds.

extern crate alloc;
use alloc::collections::BTreeMap;

use crate::attestation::nonce_cache::NonceCache;
use crate::attestation::nonce_generator::derive_nonce;
use crate::attestation::types::{
    Challenge, ChallengeResponse, ConnectivityError, EpochId, NodeFailureRecord, NodeId,
    RandomSeed, REPLAY_EPOCH_WINDOW,
};

/// The proof-of-connectivity protocol state machine.
///
/// Holds the nonce deduplication cache, per-node failure records, and the map
/// of pending challenges awaiting responses.
#[derive(Debug, Default)]
pub struct ConnectivityProtocol {
    cache: NonceCache,
    failures: BTreeMap<NodeId, NodeFailureRecord>,
    /// Pending challenges indexed by node id.
    pending: BTreeMap<NodeId, Challenge>,
}

impl ConnectivityProtocol {
    /// Create a new, empty protocol instance.
    pub fn new() -> Self {
        Self {
            cache: NonceCache::new(),
            failures: BTreeMap::new(),
            pending: BTreeMap::new(),
        }
    }

    /// Issue a new challenge to `node_id` for `current_epoch`.
    ///
    /// The nonce is derived as `BLAKE2b-256(epoch_id || seed || node_id)`.
    /// Returns the [`Challenge`] to be sent to the peer, or
    /// [`ConnectivityError::NodeBlacklisted`] if the node is currently
    /// blacklisted.
    pub fn issue_challenge(
        &mut self,
        node_id: NodeId,
        current_epoch: EpochId,
        seed: &RandomSeed,
        now: u64,
    ) -> Result<Challenge, ConnectivityError> {
        if let Some(record) = self.failures.get(&node_id) {
            if record.is_blacklisted(now) {
                return Err(ConnectivityError::NodeBlacklisted);
            }
        }

        let nonce = derive_nonce(current_epoch, seed, &node_id);
        let challenge = Challenge::new(current_epoch, nonce, node_id, now);
        self.pending.insert(node_id, challenge);
        Ok(challenge)
    }

    /// Verify a challenge/response pair.
    ///
    /// Enforces, in order:
    /// 1. Node is not blacklisted.
    /// 2. `challenge.epoch_id >= current_epoch - REPLAY_EPOCH_WINDOW`.
    /// 3. Challenge has not expired (issued_at + 5 s).
    /// 4. Nonce has not been seen before (replay gate).
    /// 5. Response echoes the correct nonce and epoch.
    ///
    /// On success the nonce is recorded in the cache, the pending entry is
    /// cleared, and the failure counter is reset.  On failure the failure
    /// counter is incremented (with possible blacklisting).
    ///
    /// Returns `Ok(())` on success or the first [`ConnectivityError`] variant
    /// that triggered a rejection.
    pub fn verify(
        &mut self,
        challenge: &Challenge,
        response: &ChallengeResponse,
        current_epoch: EpochId,
        now: u64,
    ) -> Result<(), ConnectivityError> {
        let node_id = challenge.node_id;

        // 1. Blacklist check.
        if let Some(record) = self.failures.get(&node_id) {
            if record.is_blacklisted(now) {
                return Err(ConnectivityError::NodeBlacklisted);
            }
        }

        // 2. Epoch window check — unconditional replay rejection.
        if current_epoch.saturating_sub(challenge.epoch_id) > REPLAY_EPOCH_WINDOW {
            self.record_failure(node_id, now);
            return Err(ConnectivityError::EpochTooOld);
        }

        // 3. Timeout check.
        if challenge.is_expired(now) {
            self.record_failure(node_id, now);
            return Err(ConnectivityError::ChallengeExpired);
        }

        // 4. Nonce-cache insert — replay gate within the epoch window.
        if !self.cache.insert(challenge.nonce, challenge.epoch_id) {
            self.record_failure(node_id, now);
            return Err(ConnectivityError::NonceReused);
        }

        // 5. Response match.
        if response.nonce != challenge.nonce || response.epoch_id != challenge.epoch_id {
            self.record_failure(node_id, now);
            return Err(ConnectivityError::ResponseMismatch);
        }

        // Success path: clear pending entry and reset failure counter.
        self.pending.remove(&node_id);
        self.failures.entry(node_id).or_default().record_success();
        Ok(())
    }

    /// Advance the epoch, expiring stale nonces from the cache.
    ///
    /// Must be called by the connectivity scheduler whenever `current_epoch`
    /// increments.  Removes all cache entries whose epoch is more than
    /// [`REPLAY_EPOCH_WINDOW`] behind `current_epoch`.
    pub fn advance_epoch(&mut self, current_epoch: EpochId) {
        self.cache.expire(current_epoch);
    }

    /// Returns `true` if `node_id` is currently blacklisted.
    pub fn is_blacklisted(&self, node_id: &NodeId, now: u64) -> bool {
        self.failures
            .get(node_id)
            .map(|r| r.is_blacklisted(now))
            .unwrap_or(false)
    }

    /// Retrieve the pending challenge for `node_id`, if any.
    pub fn pending_challenge(&self, node_id: &NodeId) -> Option<&Challenge> {
        self.pending.get(node_id)
    }

    // --- Private helpers ---

    fn record_failure(&mut self, node_id: NodeId, now: u64) {
        self.failures
            .entry(node_id)
            .or_default()
            .record_failure(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::types::{
        BLACKLIST_DURATION_SECS, CHALLENGE_TIMEOUT_SECS, MAX_FAILED_CHALLENGES,
    };

    fn node(seed: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = seed;
        n
    }

    fn seed(v: u64) -> RandomSeed {
        RandomSeed::from_counter(v)
    }

    /// Happy path: fresh nonce, correct response, within epoch window.
    #[test]
    fn test_verify_valid_challenge() {
        let mut proto = ConnectivityProtocol::new();
        let nid = node(1);
        let epoch: EpochId = 5;
        let now: u64 = 1000;

        let challenge = proto.issue_challenge(nid, epoch, &seed(1), now).unwrap();
        let response = ChallengeResponse::from_challenge(&challenge);
        assert!(proto.verify(&challenge, &response, epoch, now).is_ok());
    }

    /// Epoch too old: challenge is from epoch 0, current is 3 → rejected.
    #[test]
    fn test_reject_epoch_too_old() {
        let mut proto = ConnectivityProtocol::new();
        let nid = node(2);
        let now: u64 = 500;

        let challenge = proto.issue_challenge(nid, 0, &seed(2), now).unwrap();
        let response = ChallengeResponse::from_challenge(&challenge);
        let err = proto.verify(&challenge, &response, 3, now).unwrap_err();
        assert_eq!(err, ConnectivityError::EpochTooOld);
    }

    /// Boundary: exactly REPLAY_EPOCH_WINDOW behind → still accepted.
    #[test]
    fn test_epoch_at_replay_window_boundary_accepted() {
        let mut proto = ConnectivityProtocol::new();
        let nid = node(3);
        let now: u64 = 100;

        // Issued at epoch 1; current epoch is 3. Difference = 2 = REPLAY_EPOCH_WINDOW → OK.
        let challenge = proto.issue_challenge(nid, 1, &seed(3), now).unwrap();
        let response = ChallengeResponse::from_challenge(&challenge);
        assert!(proto.verify(&challenge, &response, 3, now).is_ok());
    }

    /// Boundary + 1: issued at epoch 0, current epoch 3 → rejected.
    #[test]
    fn test_epoch_one_past_boundary_rejected() {
        let mut proto = ConnectivityProtocol::new();
        let nid = node(4);
        let now: u64 = 100;

        let challenge = proto.issue_challenge(nid, 0, &seed(4), now).unwrap();
        let response = ChallengeResponse::from_challenge(&challenge);
        let err = proto.verify(&challenge, &response, 3, now).unwrap_err();
        assert_eq!(err, ConnectivityError::EpochTooOld);
    }

    /// Nonce reuse within the same epoch window is rejected.
    #[test]
    fn test_reject_nonce_reuse() {
        let mut proto = ConnectivityProtocol::new();
        let nid = node(5);
        let epoch: EpochId = 10;
        let now: u64 = 2000;

        let challenge = proto.issue_challenge(nid, epoch, &seed(5), now).unwrap();
        let response = ChallengeResponse::from_challenge(&challenge);

        // First verify succeeds and inserts nonce into cache.
        assert!(proto.verify(&challenge, &response, epoch, now).is_ok());

        // Re-submit the same challenge — nonce is already in cache.
        assert_eq!(
            proto.verify(&challenge, &response, epoch, now).unwrap_err(),
            ConnectivityError::NonceReused
        );
    }

    /// Expired challenge (wall clock > issued_at + CHALLENGE_TIMEOUT_SECS).
    #[test]
    fn test_reject_expired_challenge() {
        let mut proto = ConnectivityProtocol::new();
        let nid = node(6);
        let epoch: EpochId = 4;
        let issued_at: u64 = 0;

        let challenge = proto
            .issue_challenge(nid, epoch, &seed(6), issued_at)
            .unwrap();
        let response = ChallengeResponse::from_challenge(&challenge);

        // Advance wall clock past the 5 s timeout.
        let now = issued_at + CHALLENGE_TIMEOUT_SECS + 1;
        let err = proto.verify(&challenge, &response, epoch, now).unwrap_err();
        assert_eq!(err, ConnectivityError::ChallengeExpired);
    }

    /// Response mismatch: echo the wrong nonce.
    #[test]
    fn test_reject_response_mismatch() {
        let mut proto = ConnectivityProtocol::new();
        let nid = node(7);
        let epoch: EpochId = 2;
        let now: u64 = 100;

        let challenge = proto.issue_challenge(nid, epoch, &seed(7), now).unwrap();
        let mut response = ChallengeResponse::from_challenge(&challenge);
        // Tamper with the echoed nonce.
        response.nonce[0] ^= 0xff;

        let err = proto.verify(&challenge, &response, epoch, now).unwrap_err();
        // The tampered nonce is novel so cache accepts it, but the match check fails.
        assert_eq!(err, ConnectivityError::ResponseMismatch);
    }

    /// Node blacklisting after MAX_FAILED_CHALLENGES consecutive failures.
    #[test]
    fn test_blacklist_after_max_failures() {
        let mut proto = ConnectivityProtocol::new();
        let nid = node(8);
        let epoch: EpochId = 1;
        let now: u64 = 0;

        // Drive MAX_FAILED_CHALLENGES failures using out-of-epoch challenges.
        for _ in 0..MAX_FAILED_CHALLENGES {
            // Issue at epoch 0; verify at epoch 3 → EpochTooOld → failure.
            let challenge = proto.issue_challenge(nid, 0, &seed(99), now).unwrap();
            let response = ChallengeResponse::from_challenge(&challenge);
            let _ = proto.verify(&challenge, &response, 3, now);
        }

        // Node must now be blacklisted.
        assert!(proto.is_blacklisted(&nid, now));

        // Attempting to issue a new challenge while blacklisted → error.
        let err = proto
            .issue_challenge(nid, epoch, &seed(99), now)
            .unwrap_err();
        assert_eq!(err, ConnectivityError::NodeBlacklisted);
    }

    /// After BLACKLIST_DURATION_SECS the node is no longer blacklisted.
    #[test]
    fn test_blacklist_expires() {
        let mut proto = ConnectivityProtocol::new();
        let nid = node(9);
        let now: u64 = 0;

        // Trigger blacklisting.
        for _ in 0..MAX_FAILED_CHALLENGES {
            let challenge = proto.issue_challenge(nid, 0, &seed(77), now).unwrap();
            let response = ChallengeResponse::from_challenge(&challenge);
            let _ = proto.verify(&challenge, &response, 3, now);
        }

        assert!(proto.is_blacklisted(&nid, now));

        // Advance time past the blacklist window.
        let later = now + BLACKLIST_DURATION_SECS + 1;
        assert!(!proto.is_blacklisted(&nid, later));
    }

    /// `advance_epoch` must expire old nonces from the cache so they cannot
    /// occupy memory forever.
    #[test]
    fn test_advance_epoch_expires_cache() {
        let mut proto = ConnectivityProtocol::new();
        let nid = node(10);
        let now: u64 = 0;

        // Issue and verify a challenge at epoch 0.
        let challenge = proto.issue_challenge(nid, 0, &seed(10), now).unwrap();
        let response = ChallengeResponse::from_challenge(&challenge);
        proto.verify(&challenge, &response, 0, now).unwrap();

        // Advance to epoch 3 — epoch-0 nonce must be purged.
        proto.advance_epoch(3);

        // The same nonce can now be inserted again (it was evicted).
        assert!(proto.cache.insert(challenge.nonce, 3));
    }
}
