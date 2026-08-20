//! Integration tests for webhook delivery service (issue #68).
//!
//! Exercises signing, verification, delivery engine enqueue/dequeue lifecycle,
//! exponential backoff scheduling, and idempotency guarantees.

use sorosusu_contracts::crypto::bls_keys::{low_order_point, subgroup_check_g2, G2Point};
use sorosusu_contracts::crypto::domain::compute_domain;
use sorosusu_contracts::webhook::delivery::{
    compute_backoff, DeliveryEngine, DeliveryStatus, WebhookPayload, BASE_BACKOFF_SECONDS,
    MAX_BACKOFF_SECONDS, MAX_RETRY_ATTEMPTS,
};

const FORK: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

#[test]
fn test_payload_sign_and_verify_roundtrip() {
    let payload = WebhookPayload::sign(42, b"test_payload", 3, FORK);
    assert!(payload.verify());
    assert_eq!(payload.event_id, 42);
}

#[test]
fn test_payload_verify_rejects_tampered_payload() {
    let mut payload = WebhookPayload::sign(10, b"original", 5, FORK);
    payload.data = b"modified".to_vec();
    assert!(!payload.verify());
}

#[test]
fn test_payload_verify_rejects_tampered_event_id() {
    let mut payload = WebhookPayload::sign(10, b"data", 5, FORK);
    payload.event_id = 11;
    assert!(!payload.verify());
}

#[test]
fn test_payload_verify_rejects_tampered_public_key() {
    let mut payload = WebhookPayload::sign(10, b"data", 5, FORK);
    payload.public_key = G2Point::new(123);
    assert!(!payload.verify());
}

#[test]
fn test_payload_verify_rejects_tampered_signature() {
    let mut payload = WebhookPayload::sign(10, b"data", 5, FORK);
    payload.signature = G2Point::new(999);
    assert!(!payload.verify());
}

#[test]
fn test_payload_rejects_off_subgroup_public_key() {
    let off_sub = low_order_point(0);
    assert!(!subgroup_check_g2(&off_sub));

    let evil_payload = WebhookPayload {
        event_id: 1,
        data: b"bad_key".to_vec(),
        signature: G2Point::new(99),
        public_key: off_sub,
        domain: compute_domain([0x57, 0x48, 0x42, 0x4b], FORK),
    };
    assert!(!evil_payload.verify());
}

#[test]
fn test_payload_domain_separation() {
    let a = WebhookPayload::sign(1, b"data", 7, [0x00, 0x00, 0x00, 0x00]);
    let b = WebhookPayload::sign(1, b"data", 7, [0x00, 0x00, 0x00, 0x01]);
    assert_ne!(a.domain, b.domain);
    assert_ne!(a.signature, b.signature);
    // Neither should verify with the other's domain.
    assert!(!{
        let mut cross = a.clone();
        cross.domain = b.domain;
        cross.verify()
    });
}

#[test]
fn test_delivery_engine_enqueue_and_deliver() {
    let mut engine = DeliveryEngine::new();
    let payload = WebhookPayload::sign(1, b"event_data", 7, FORK);

    assert!(engine.enqueue(payload, 0));
    assert_eq!(engine.len(), 1);
    assert_eq!(engine.get_status(1), Some(DeliveryStatus::Pending));

    // Deliver.
    engine.tick(10, |_| Ok(()));
    assert_eq!(engine.get_status(1), Some(DeliveryStatus::Delivered));
}

#[test]
fn test_delivery_engine_multiple_events() {
    let mut engine = DeliveryEngine::new();

    for id in 0..10u64 {
        engine.enqueue(WebhookPayload::sign(id, b"batch", 3, FORK), 0);
    }
    assert_eq!(engine.len(), 10);

    // Deliver all in one tick.
    let delivered = engine.tick(10, |_| Ok(()));
    assert_eq!(delivered, 10);

    for id in 0..10u64 {
        assert_eq!(engine.get_status(id), Some(DeliveryStatus::Delivered));
    }
}

#[test]
fn test_delivery_idempotency() {
    let mut engine = DeliveryEngine::new();
    let p = WebhookPayload::sign(1, b"uniq", 7, FORK);

    assert!(engine.enqueue(p.clone(), 0));
    assert!(!engine.enqueue(p, 0));
    assert_eq!(engine.len(), 1);
}

#[test]
fn test_delivery_retry_then_succeed() {
    let mut engine = DeliveryEngine::new();
    engine.enqueue(WebhookPayload::sign(1, b"flaky", 7, FORK), 0);

    // Fail twice.
    engine.tick(10, |_| Err(b"err1".to_vec()));
    let rec = engine.get_record(1).unwrap();
    assert_eq!(rec.status, DeliveryStatus::Retrying);
    let next = rec.next_attempt_time;

    // Time not yet advanced — should not attempt.
    let before = engine.tick(next - 1, |_| unreachable!());
    assert_eq!(before, 0);

    // Advance to backoff time and succeed.
    let delivered = engine.tick(next, |_| Ok(()));
    assert_eq!(delivered, 1);
    assert_eq!(engine.get_status(1), Some(DeliveryStatus::Delivered));
}

#[test]
fn test_delivery_exhausts_retries() {
    let mut engine = DeliveryEngine::new();
    engine.enqueue(WebhookPayload::sign(1, b"doomed", 7, FORK), 0);

    for t in 0..MAX_RETRY_ATTEMPTS {
        engine.tick(t as u64 * 1000, |_| Err(b"fail".to_vec()));
    }

    let rec = engine.get_record(1).unwrap();
    assert_eq!(rec.status, DeliveryStatus::Failed);
    assert_eq!(rec.attempt_count, MAX_RETRY_ATTEMPTS);
}

#[test]
fn test_delivery_does_not_retry_delivered() {
    let mut engine = DeliveryEngine::new();
    engine.enqueue(WebhookPayload::sign(1, b"done", 7, FORK), 0);
    engine.tick(10, |_| Ok(()));
    assert_eq!(engine.get_status(1), Some(DeliveryStatus::Delivered));

    let attempts = engine.get_record(1).unwrap().attempt_count;
    engine.tick(100, |_| Err(b"ignored".to_vec()));
    assert_eq!(engine.get_record(1).unwrap().attempt_count, attempts);
}

#[test]
fn test_delivery_error_persistence() {
    let mut engine = DeliveryEngine::new();
    engine.enqueue(WebhookPayload::sign(1, b"err", 7, FORK), 0);

    engine.tick(10, |_| Err(b"connection refused".to_vec()));
    let rec = engine.get_record(1).unwrap();
    assert_eq!(rec.last_error.as_deref(), Some(&b"connection refused"[..]));
}

#[test]
fn test_compute_backoff_values() {
    assert_eq!(compute_backoff(1), BASE_BACKOFF_SECONDS); // 2 * 2^0
    assert_eq!(compute_backoff(2), 4); // 2 * 2^1
    assert_eq!(compute_backoff(3), 8); // 2 * 2^2
    assert_eq!(compute_backoff(4), 16); // 2 * 2^3
    assert_eq!(compute_backoff(5), 32); // 2 * 2^4
}

#[test]
fn test_backoff_capped() {
    let large = compute_backoff(50);
    assert!(large <= MAX_BACKOFF_SECONDS);
}

#[test]
fn test_delivery_engine_empty() {
    let engine = DeliveryEngine::new();
    assert!(engine.is_empty());
    assert_eq!(engine.len(), 0);
    assert_eq!(engine.get_status(1), None);
    assert!(engine.get_record(1).is_none());
}

#[test]
fn test_payload_with_empty_data() {
    let payload = WebhookPayload::sign(0, b"", 3, FORK);
    assert!(payload.verify());
}

#[test]
fn test_payload_with_large_data() {
    let large = vec![0xC0u8; 65_536];
    let payload = WebhookPayload::sign(99, &large, 7, FORK);
    assert!(payload.verify());
}
