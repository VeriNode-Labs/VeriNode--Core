//! Webhook delivery service with retry and signature verification (issue #68).
//!
//! Provides an event delivery mechanism where outbound payloads are signed
//! and delivered with exponential-backoff retry. Signature verification on
//! the receiver side ensures payload integrity and authenticity, reusing the
//! domain-separated BLS key infrastructure already in the crate.

pub mod delivery;
