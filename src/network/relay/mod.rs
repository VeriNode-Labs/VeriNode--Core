//! STUN/TURN relay endpoint discovery with authenticated binding claims
//! (issue #140).
//!
//! A peer learns where to reach another peer from a relay's STUN binding
//! report, and that report is cached. With no authentication on the cache write
//! path, any peer could claim to be relaying for any other and redirect its
//! traffic — endpoint cache poisoning.
//!
//! * [`relay_registry`] — the relays this node treats as authoritative, and the
//!   verification key for each.
//! * [`endpoint_cache`] — the cache itself: ticket-authorized writes, a sliding
//!   -window penalty counter, blacklist eviction, and capacity limits.
//! * [`stun_bind`] — the binding request/response exchange that authors a
//!   claim, with a ticket attached to every response.
//!
//! The ticket scheme those two share lives in
//! [`crate::attestation::relay_ticket`], alongside the crate's other
//! domain-separated signing roots.

#[path = "endpoint-cache.rs"]
pub mod endpoint_cache;
#[path = "relay-registry.rs"]
pub mod relay_registry;
#[path = "stun-bind.rs"]
pub mod stun_bind;
