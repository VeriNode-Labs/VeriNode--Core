//! Webhook delivery engine with retry, exponential backoff, and signature
//! verification.
//!
//! Every outbound payload carries a BLS signature over a domain-separated
//! signing root so the receiver can verify authenticity and integrity without
//! trusting the transport.  Failed deliveries are retried with exponential
//! backoff up to a maximum number of attempts, after which they are considered
//! permanently failed.

extern crate alloc;
use crate::crypto::bls_keys::{scalar_mul, subgroup_check_g2, G2Point};
use crate::crypto::domain::{compute_domain, Domain};
use crate::crypto::sha256::sha256;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

// --- CONSTANTS ---

/// Domain type tag for webhook payloads (`0x5742484b` = "WHBK").
pub const DOMAIN_WEBHOOK: [u8; 4] = [0x57, 0x48, 0x42, 0x4b];

/// Maximum number of retry attempts for a delivery.
pub const MAX_RETRY_ATTEMPTS: u32 = 5;

/// Base backoff in seconds.
pub const BASE_BACKOFF_SECONDS: u64 = 2;

/// Maximum backoff cap in seconds.
pub const MAX_BACKOFF_SECONDS: u64 = 3600; // 1 hour

// --- TYPES ---

/// Status of a webhook delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryStatus {
    /// Delivery is queued but not yet attempted.
    Pending,
    /// Delivery succeeded (ACK received / signature verified on receiver side).
    Delivered,
    /// Delivery is being retried.
    Retrying,
    /// All retries exhausted — permanently failed.
    Failed,
}

/// A signed webhook payload ready for delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookPayload {
    /// Unique event identifier (ensures idempotency).
    pub event_id: u64,
    /// The raw data being delivered.
    pub data: Vec<u8>,
    /// BLS signature over the domain-separated signing root.
    pub signature: G2Point,
    /// The public key of the signer.
    pub public_key: G2Point,
    /// Domain under which the payload was signed.
    pub domain: Domain,
}

impl WebhookPayload {
    /// Create a new signed payload.
    ///
    /// `signing_scalar` is the signer's private scalar in the toy group;
    /// the public key is derived as `scalar * GENERATOR`.  The signature
    /// is `signing_scalar * H(signing_root)` where `H` maps the signing
    /// root to a group element by interpreting the first 8 bytes as a
    /// little-endian u64 (toy group model).
    pub fn sign(event_id: u64, data: &[u8], signing_scalar: u64, fork_version: [u8; 4]) -> Self {
        let domain = compute_domain(DOMAIN_WEBHOOK, fork_version);
        let signing_root = compute_webhook_signing_root(event_id, data, &domain);
        // Map signing root to group element: use first 8 bytes as little-endian u64.
        let message_point = G2Point::from_bytes(&hash_to_8_bytes(&signing_root));
        let signature = scalar_mul(signing_scalar, &message_point);

        // Derive public key: signing_scalar * generator (scalar 6 in the toy group).
        let generator = G2Point::new(6);
        let public_key = scalar_mul(signing_scalar, &generator);

        Self {
            event_id,
            data: data.to_vec(),
            signature,
            public_key,
            domain,
        }
    }

    /// Verify the payload's BLS signature.
    ///
    /// Re-derives the signing root, maps it to a group point, and checks
    /// that the signature is consistent with the claimed public key.
    /// Also enforces subgroup membership on the public key (issue #12 fix).
    pub fn verify(&self) -> bool {
        // Subgroup check on the public key.
        if !subgroup_check_g2(&self.public_key) {
            return false;
        }

        let signing_root = compute_webhook_signing_root(self.event_id, &self.data, &self.domain);
        let message_point = G2Point::from_bytes(&hash_to_8_bytes(&signing_root));

        // In the toy group, verification means:
        //   public_key * H(root) == signature * generator
        // Since multiplication is commutative here, we check:
        //   scalar_mul(public_key.value, &message_point) == scalar_mul(signature.value, &generator)
        let generator = G2Point::new(6);
        let lhs = scalar_mul(self.public_key.value, &message_point);
        let rhs = scalar_mul(self.signature.value, &generator);
        lhs == rhs
    }
}

/// Compute the domain-separated signing root for a webhook payload.
fn compute_webhook_signing_root(event_id: u64, data: &[u8], domain: &Domain) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&event_id.to_le_bytes());
    preimage.extend_from_slice(data);
    preimage.extend_from_slice(domain);
    sha256(&preimage)
}

/// Map a 32-byte hash to 8 bytes suitable for the toy group.
fn hash_to_8_bytes(hash: &[u8; 32]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    out
}

// --- DELIVERY ENGINE ---

/// Tracks the state of a single delivery attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryRecord {
    pub event_id: u64,
    pub payload: WebhookPayload,
    pub status: DeliveryStatus,
    pub attempt_count: u32,
    pub next_attempt_time: u64,
    pub last_error: Option<Vec<u8>>,
}

/// The webhook delivery engine manages pending deliveries, schedules retries
/// with exponential backoff, and tracks delivery outcomes.
#[derive(Clone, Debug)]
pub struct DeliveryEngine {
    /// All tracked deliveries, keyed by event_id.
    deliveries: BTreeMap<u64, DeliveryRecord>,
}

impl DeliveryEngine {
    /// Create a new, empty delivery engine.
    pub fn new() -> Self {
        Self {
            deliveries: BTreeMap::new(),
        }
    }

    /// Enqueue a signed payload for delivery.
    /// Returns `false` if an event with the same id already exists
    /// (idempotency guard).
    pub fn enqueue(&mut self, payload: WebhookPayload, current_time: u64) -> bool {
        if self.deliveries.contains_key(&payload.event_id) {
            return false;
        }

        let record = DeliveryRecord {
            event_id: payload.event_id,
            payload,
            status: DeliveryStatus::Pending,
            attempt_count: 0,
            next_attempt_time: current_time,
            last_error: None,
        };

        self.deliveries.insert(record.event_id, record);
        true
    }

    /// Attempt delivery for all pending/retrying events that are due.
    ///
    /// `deliver_fn` is a closure that the caller provides to simulate or
    /// perform the actual delivery; it should return `Ok(())` on success and
    /// `Err(error_description)` on failure.
    ///
    /// **Important**: `deliver_fn` MUST NOT panic — if it does, the delivery
    /// record will be left with an incremented attempt count but no status
    /// update, which could cause it to be skipped on future ticks.
    ///
    /// Returns the number of events that were successfully delivered in this
    /// tick.
    pub fn tick<F>(&mut self, current_time: u64, mut deliver_fn: F) -> u32
    where
        F: FnMut(&WebhookPayload) -> Result<(), Vec<u8>>,
    {
        let mut delivered_count = 0u32;

        // Collect keys first to avoid borrow issues.
        let due_ids: Vec<u64> = self
            .deliveries
            .iter()
            .filter(|(_, r)| {
                (r.status == DeliveryStatus::Pending || r.status == DeliveryStatus::Retrying)
                    && current_time >= r.next_attempt_time
            })
            .map(|(id, _)| *id)
            .collect();

        for id in due_ids {
            // Re-fetch to satisfy borrow checker — we know it exists.
            let record = match self.deliveries.get_mut(&id) {
                Some(r) => r,
                None => continue,
            };

            record.attempt_count += 1;

            // Deliver; if the closure panics the record will be inconsistent.
            let result = deliver_fn(&record.payload);

            match result {
                Ok(()) => {
                    record.status = DeliveryStatus::Delivered;
                    delivered_count += 1;
                }
                Err(err) => {
                    record.last_error = Some(err);

                    if record.attempt_count >= MAX_RETRY_ATTEMPTS {
                        record.status = DeliveryStatus::Failed;
                    } else {
                        record.status = DeliveryStatus::Retrying;
                        record.next_attempt_time =
                            current_time + compute_backoff(record.attempt_count);
                    }
                }
            }
        }

        delivered_count
    }

    /// Get the current status of a delivery.
    pub fn get_status(&self, event_id: u64) -> Option<DeliveryStatus> {
        self.deliveries.get(&event_id).map(|r| r.status)
    }

    /// Get the full delivery record.
    pub fn get_record(&self, event_id: u64) -> Option<&DeliveryRecord> {
        self.deliveries.get(&event_id)
    }

    /// Number of tracked deliveries.
    pub fn len(&self) -> usize {
        self.deliveries.len()
    }

    /// Whether the engine has no deliveries.
    pub fn is_empty(&self) -> bool {
        self.deliveries.is_empty()
    }
}

impl Default for DeliveryEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute exponential backoff delay for the given attempt number (1-based).
pub fn compute_backoff(attempt: u32) -> u64 {
    let shift = (attempt - 1).min(20); // prevent overflow
    let delay = BASE_BACKOFF_SECONDS.saturating_mul(1u64 << shift);
    delay.min(MAX_BACKOFF_SECONDS)
}

// --- TESTS ---

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_FORK_VERSION: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

    #[test]
    fn test_sign_and_verify_valid_payload() {
        let payload = WebhookPayload::sign(1, b"hello", 7, TEST_FORK_VERSION);
        assert!(payload.verify());
    }

    #[test]
    fn test_verify_rejects_wrong_data() {
        let mut payload = WebhookPayload::sign(1, b"hello", 7, TEST_FORK_VERSION);
        payload.data = b"tampered".to_vec();
        assert!(!payload.verify());
    }

    #[test]
    fn test_verify_rejects_wrong_event_id() {
        let mut payload = WebhookPayload::sign(1, b"data", 7, TEST_FORK_VERSION);
        payload.event_id = 2;
        assert!(!payload.verify());
    }

    #[test]
    fn test_verify_rejects_off_subgroup_key() {
        // Use a low-order point (off-subgroup) as the public key manually.
        let off_subgroup_key = G2Point::new(101); // model small-order point
        let payload = WebhookPayload {
            event_id: 1,
            data: b"data".to_vec(),
            signature: G2Point::new(3),
            public_key: off_subgroup_key,
            domain: compute_domain(DOMAIN_WEBHOOK, TEST_FORK_VERSION),
        };
        assert!(!payload.verify());
    }

    #[test]
    fn test_signatures_are_deterministic() {
        let a = WebhookPayload::sign(42, b"same", 5, TEST_FORK_VERSION);
        let b = WebhookPayload::sign(42, b"same", 5, TEST_FORK_VERSION);
        assert_eq!(a.signature, b.signature);
        assert_eq!(a.public_key, b.public_key);
    }

    #[test]
    fn test_different_fork_versions_produce_different_signatures() {
        let a = WebhookPayload::sign(1, b"data", 7, [0x00, 0x00, 0x00, 0x00]);
        let b = WebhookPayload::sign(1, b"data", 7, [0xFF, 0xFF, 0xFF, 0xFF]);
        assert_ne!(a.domain, b.domain);
        assert_ne!(a.signature, b.signature);
    }

    // --- Delivery engine tests ---

    #[test]
    fn test_enqueue_and_deliver() {
        let mut engine = DeliveryEngine::new();
        let payload = WebhookPayload::sign(1, b"event1", 7, TEST_FORK_VERSION);

        assert!(engine.enqueue(payload, 0));
        assert_eq!(engine.len(), 1);
        assert_eq!(engine.get_status(1), Some(DeliveryStatus::Pending));
    }

    #[test]
    fn test_enqueue_duplicate_rejected() {
        let mut engine = DeliveryEngine::new();
        let payload = WebhookPayload::sign(1, b"event1", 7, TEST_FORK_VERSION);
        assert!(engine.enqueue(payload.clone(), 0));
        assert!(!engine.enqueue(payload, 0));
    }

    #[test]
    fn test_tick_delivers_pending() {
        let mut engine = DeliveryEngine::new();
        let payload = WebhookPayload::sign(1, b"ev", 7, TEST_FORK_VERSION);
        engine.enqueue(payload, 0);

        let delivered = engine.tick(10, |_| Ok(()));
        assert_eq!(delivered, 1);
        assert_eq!(engine.get_status(1), Some(DeliveryStatus::Delivered));
    }

    #[test]
    fn test_tick_retries_on_failure() {
        let mut engine = DeliveryEngine::new();
        let payload = WebhookPayload::sign(1, b"flaky", 7, TEST_FORK_VERSION);
        engine.enqueue(payload, 0);

        // First attempt fails.
        let delivered = engine.tick(10, |_| Err(b"timeout".to_vec()));
        assert_eq!(delivered, 0);
        assert_eq!(engine.get_status(1), Some(DeliveryStatus::Retrying));

        let record = engine.get_record(1).unwrap();
        assert_eq!(record.attempt_count, 1);
        assert!(record.next_attempt_time > 10);
    }

    #[test]
    fn test_tick_fails_after_max_retries() {
        let mut engine = DeliveryEngine::new();
        let payload = WebhookPayload::sign(1, b"doomed", 7, TEST_FORK_VERSION);
        engine.enqueue(payload, 0);

        // Fail repeatedly.
        for t in 0..MAX_RETRY_ATTEMPTS {
            engine.tick(t as u64 * 1000, |_| Err(b"fail".to_vec()));
        }

        let record = engine.get_record(1).unwrap();
        assert_eq!(record.attempt_count, MAX_RETRY_ATTEMPTS);
        assert_eq!(record.status, DeliveryStatus::Failed);
    }

    #[test]
    fn test_tick_succeeds_on_retry() {
        let mut engine = DeliveryEngine::new();
        let payload = WebhookPayload::sign(1, b"retry-me", 7, TEST_FORK_VERSION);
        engine.enqueue(payload, 0);

        // First tick fails.
        engine.tick(10, |_| Err(b"fail".to_vec()));
        assert_eq!(engine.get_status(1), Some(DeliveryStatus::Retrying));

        // Advance time past backoff and succeed.
        let record = engine.get_record(1).unwrap();
        let next_time = record.next_attempt_time;
        engine.tick(next_time, |_| Ok(()));
        assert_eq!(engine.get_status(1), Some(DeliveryStatus::Delivered));
    }

    #[test]
    fn test_tick_does_not_retry_delivered() {
        let mut engine = DeliveryEngine::new();
        let payload = WebhookPayload::sign(1, b"done", 7, TEST_FORK_VERSION);
        engine.enqueue(payload, 0);
        engine.tick(10, |_| Ok(()));
        assert_eq!(engine.get_status(1), Some(DeliveryStatus::Delivered));

        // Another tick should not change the status or increment attempts.
        let record_before = engine.get_record(1).unwrap().attempt_count;
        engine.tick(20, |_| Err(b"ignored".to_vec()));
        assert_eq!(engine.get_status(1), Some(DeliveryStatus::Delivered));
        assert_eq!(engine.get_record(1).unwrap().attempt_count, record_before);
    }

    // --- Backoff tests ---

    #[test]
    fn test_backoff_sequence() {
        assert_eq!(compute_backoff(1), 2); // 2 * 2^0
        assert_eq!(compute_backoff(2), 4); // 2 * 2^1
        assert_eq!(compute_backoff(3), 8); // 2 * 2^2
        assert_eq!(compute_backoff(4), 16); // 2 * 2^3
        assert_eq!(compute_backoff(5), 32); // 2 * 2^4
    }

    #[test]
    fn test_backoff_caps_at_max() {
        let capped = compute_backoff(30);
        assert!(capped <= MAX_BACKOFF_SECONDS);
    }
}
