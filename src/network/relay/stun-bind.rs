//! STUN binding request/response handling with ticket attachment (issue #140).
//!
//! This is where an endpoint claim is born. A peer behind a NAT asks a relay
//! "what address do you see me at?"; the relay observes the source address of
//! the request and reports it back. That reported address is what gets cached
//! and what traffic is subsequently steered to, so it is exactly the value an
//! attacker wants to control.
//!
//! Two sides live here:
//!
//! * [`StunRelay::handle_binding_request`] — the relay side. It attaches a
//!   [`RelayTicket`] signed over the whole claim, including the reflexive
//!   address it observed, to every binding response.
//! * [`apply_binding_response`] — the receiving side. It matches the response
//!   to the request that provoked it, then hands the claim to
//!   [`EndpointCache::put`], which is the authoritative gate.
//!
//! ## Two layers of checking, and which one is load-bearing
//!
//! The transaction-id and target checks here are ordinary STUN hygiene: a
//! response must answer the request that was actually sent (RFC 5389 uses the
//! transaction id for the same purpose). They cheaply discard off-path noise,
//! but they are **not** the security boundary — an attacker who can see the
//! request can echo both fields.
//!
//! The boundary is the ticket. Because the signing root covers the reflexive
//! endpoint as well as the target (see [`crate::attestation::relay_ticket`]),
//! every structural tamper with a response reduces to one of two outcomes:
//! either a signed field changed and the MAC fails, or an unsigned field
//! changed and it no longer matches the signed one. There is no third path that
//! reaches the cache.

use crate::attestation::relay_ticket::{PeerId, RelayId, RelayTicket, SocketEndpoint};
use crate::attestation::types::EpochId;
use crate::attestation::verifier::SecretKey;
use crate::crypto::domain::ForkVersion;
use crate::network::relay::endpoint_cache::{EndpointCache, EndpointCacheError};
use crate::network::relay::relay_registry::RelayRegistry;

// --- CONSTANTS ---

/// Length of a STUN transaction id, in bytes (RFC 5389 §6).
pub const STUN_TRANSACTION_ID_LEN: usize = 12;

/// Default validity of an issued ticket, in seconds.
///
/// Matched to [`crate::network::relay::endpoint_cache::ENDPOINT_ENTRY_TTL_SECS`]
/// so that under default configuration the cache TTL is the binding constraint;
/// a relay that wants claims to lapse sooner shortens this and the cache
/// follows, because an entry never outlives its ticket.
pub const DEFAULT_TICKET_LIFETIME_SECS: u64 = 300;

// --- TYPES ---

/// A STUN transaction id, echoed by the relay to pair a response with its
/// request.
pub type TransactionId = [u8; STUN_TRANSACTION_ID_LEN];

/// A binding request sent to a relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StunBindingRequest {
    /// Randomly chosen per request; the response must echo it.
    pub transaction_id: TransactionId,
    /// The peer whose reflexive address is being discovered.
    pub target_id: PeerId,
}

impl StunBindingRequest {
    /// Construct a binding request.
    pub fn new(transaction_id: TransactionId, target_id: PeerId) -> Self {
        Self {
            transaction_id,
            target_id,
        }
    }
}

/// A relay's binding response, carrying the ticket that authorizes the claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StunBindingResponse {
    /// Echo of the request's transaction id.
    pub transaction_id: TransactionId,
    /// The peer this response is about.
    pub target_id: PeerId,
    /// The server-reflexive address the relay observed.
    pub reflexive: SocketEndpoint,
    /// The relay's signature over `(relay_id, target_id, reflexive, epoch,
    /// expires_at)`.
    pub ticket: RelayTicket,
}

/// Why a binding response was not applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StunBindingError {
    /// The response does not echo the outstanding request's transaction id.
    TransactionMismatch,
    /// The response is about a different peer than the request asked about.
    TargetMismatch,
    /// The cache refused the claim; carries the specific reason.
    Cache(EndpointCacheError),
}

// --- RELAY SIDE ---

/// A relay's signing identity for issuing binding tickets.
///
/// Holds the relay's secret key. Under the crate's MAC model this is the same
/// value the registry verifies with, so it must not leave the relay — see the
/// trust-boundary note in [`crate::attestation::relay_ticket`].
#[derive(Clone, Debug)]
pub struct StunRelay {
    relay_id: RelayId,
    key: SecretKey,
    fork_version: ForkVersion,
    ticket_lifetime_secs: u64,
}

impl StunRelay {
    /// Create a relay identity that issues tickets valid for
    /// [`DEFAULT_TICKET_LIFETIME_SECS`].
    pub fn new(relay_id: RelayId, key: SecretKey, fork_version: ForkVersion) -> Self {
        Self {
            relay_id,
            key,
            fork_version,
            ticket_lifetime_secs: DEFAULT_TICKET_LIFETIME_SECS,
        }
    }

    /// Override how long issued tickets remain valid.
    pub fn with_ticket_lifetime(mut self, secs: u64) -> Self {
        self.ticket_lifetime_secs = secs;
        self
    }

    /// This relay's identifier.
    pub fn relay_id(&self) -> RelayId {
        self.relay_id
    }

    /// Answer a binding request, attaching a ticket over the observed address.
    ///
    /// `reflexive` is the source address the relay saw the request arrive from;
    /// the relay vouches for it by signing it into the ticket alongside the
    /// target and the freshness bounds. Nothing else in the response is
    /// trusted downstream, so this is the only place the claim is authored.
    pub fn handle_binding_request(
        &self,
        request: &StunBindingRequest,
        reflexive: SocketEndpoint,
        epoch: EpochId,
        now: u64,
    ) -> StunBindingResponse {
        let ticket = RelayTicket::sign(
            &self.key,
            self.relay_id,
            request.target_id,
            reflexive,
            epoch,
            now.saturating_add(self.ticket_lifetime_secs),
            self.fork_version,
        );
        StunBindingResponse {
            transaction_id: request.transaction_id,
            target_id: request.target_id,
            reflexive,
            ticket,
        }
    }
}

// --- RECEIVING SIDE ---

/// Apply a binding response to the endpoint cache.
///
/// `submitter` is the authenticated identity of the relay the response arrived
/// from; the cache attributes any penalty to it rather than to the `relay_id`
/// written inside the ticket. See the attribution note in
/// [`crate::network::relay::endpoint_cache`].
///
/// The transaction-id and target checks run first and are pure hygiene — they
/// discard responses that do not answer `request` without consuming a
/// verification. Everything that matters happens in [`EndpointCache::put`],
/// which re-derives the ticket's signing root over `response.target_id` and
/// `response.reflexive` and so refuses any response whose signed and unsigned
/// halves disagree.
pub fn apply_binding_response(
    cache: &mut EndpointCache,
    registry: &RelayRegistry,
    request: &StunBindingRequest,
    response: &StunBindingResponse,
    submitter: RelayId,
    current_epoch: EpochId,
    now: u64,
) -> Result<(), StunBindingError> {
    if response.transaction_id != request.transaction_id {
        return Err(StunBindingError::TransactionMismatch);
    }
    if response.target_id != request.target_id {
        return Err(StunBindingError::TargetMismatch);
    }

    cache
        .put(
            registry,
            submitter,
            &response.ticket,
            response.target_id,
            response.reflexive,
            current_epoch,
            now,
        )
        .map_err(StunBindingError::Cache)
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use crate::attestation::relay_ticket::RelayTicketError;
    use crate::crypto::domain::GENESIS_FORK_VERSION as FORK;
    use alloc::vec::Vec;

    const RELAY: RelayId = [0xAA; 32];
    const RELAY_KEY: SecretKey = [0x11; 32];
    const IMPOSTOR: RelayId = [0xCC; 32];
    const IMPOSTOR_KEY: SecretKey = [0x33; 32];

    const EPOCH: EpochId = 10;
    const NOW: u64 = 1_000;
    const TXN: TransactionId = [0x5A; STUN_TRANSACTION_ID_LEN];

    fn peer(n: u16) -> PeerId {
        let mut id = [0u8; 32];
        id[..2].copy_from_slice(&n.to_le_bytes());
        id
    }

    fn observed() -> SocketEndpoint {
        SocketEndpoint::v4([203, 0, 113, 7], 51_820)
    }

    /// The address an attacker would rather traffic went to.
    fn attacker_controlled() -> SocketEndpoint {
        SocketEndpoint::v4([198, 51, 100, 66], 9_999)
    }

    fn registry() -> RelayRegistry {
        let mut registry = RelayRegistry::new(FORK);
        registry.register(RELAY, RELAY_KEY);
        registry
    }

    fn relay() -> StunRelay {
        StunRelay::new(RELAY, RELAY_KEY, FORK)
    }

    /// The honest exchange: request out, relay observes an address, response
    /// back with a ticket attached.
    fn honest_exchange() -> (StunBindingRequest, StunBindingResponse) {
        let request = StunBindingRequest::new(TXN, peer(1));
        let response = relay().handle_binding_request(&request, observed(), EPOCH, NOW);
        (request, response)
    }

    // -----------------------------------------------------------------------
    // End-to-end: the legitimate path
    // -----------------------------------------------------------------------

    /// A legitimate binding flows request -> ticket-attach -> cache-PUT ->
    /// verification and lands in the cache, readable at the address the relay
    /// actually observed.
    #[test]
    fn a_legitimate_binding_flows_end_to_end_into_the_cache() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let (request, response) = honest_exchange();

        assert_eq!(response.transaction_id, request.transaction_id);
        assert_eq!(
            apply_binding_response(&mut cache, &registry, &request, &response, RELAY, EPOCH, NOW),
            Ok(())
        );

        assert_eq!(cache.lookup(&peer(1), NOW), alloc::vec![observed()]);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.records(&peer(1))[0].relay_id, RELAY);
        assert_eq!(cache.recent_failure_count(&RELAY, NOW), 0);
    }

    /// A relay re-reports the same peer at a new address as the NAT binding
    /// moves, and the cache follows. Confirms the authenticated path supports
    /// the update that STUN exists to perform, rather than pinning the first
    /// answer forever.
    #[test]
    fn a_relay_can_update_a_peers_address_on_a_later_binding() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let moved_to = SocketEndpoint::v4([203, 0, 113, 7], 51_821);

        let (request, response) = honest_exchange();
        apply_binding_response(
            &mut cache, &registry, &request, &response, RELAY, EPOCH, NOW,
        )
        .unwrap();

        let later = NOW + 30;
        let refreshed = relay().handle_binding_request(&request, moved_to, EPOCH, later);
        assert_eq!(
            apply_binding_response(
                &mut cache, &registry, &request, &refreshed, RELAY, EPOCH, later
            ),
            Ok(())
        );

        let mut served = cache.lookup(&peer(1), later);
        served.sort();
        assert_eq!(served, alloc::vec![observed(), moved_to]);
    }

    // -----------------------------------------------------------------------
    // Tampering anywhere in the flow
    // -----------------------------------------------------------------------

    /// **Tamper with any part of the response and it is refused, with nothing
    /// written.**
    ///
    /// Each case is a distinct interception the attacker could mount on the
    /// path between the relay and the peer applying the answer. They are
    /// enumerated as a table rather than as separate tests because the point
    /// being proven is *coverage of the whole response* — that no field, signed
    /// or unsigned, offers a way through. Every case runs against a fresh cache
    /// so the penalty counter from one cannot mask the outcome of the next.
    #[test]
    fn tampering_with_any_part_of_the_response_is_refused_and_caches_nothing() {
        type Tamper = fn(&mut StunBindingResponse);

        let cases: Vec<(&str, Tamper, StunBindingError)> = alloc::vec![
            (
                "transaction id no longer answers the request",
                (|r: &mut StunBindingResponse| r.transaction_id = [0xFF; STUN_TRANSACTION_ID_LEN])
                    as Tamper,
                StunBindingError::TransactionMismatch,
            ),
            (
                "response redirected to a different peer",
                |r: &mut StunBindingResponse| r.target_id = peer(2),
                StunBindingError::TargetMismatch,
            ),
            (
                "reflexive address swapped, genuine ticket kept",
                |r: &mut StunBindingResponse| r.reflexive = attacker_controlled(),
                StunBindingError::Cache(EndpointCacheError::Ticket(
                    RelayTicketError::EndpointMismatch,
                )),
            ),
            (
                "ticket signature forged",
                |r: &mut StunBindingResponse| r.ticket.signature = [0x00; 32],
                StunBindingError::Cache(EndpointCacheError::Ticket(
                    RelayTicketError::InvalidSignature,
                )),
            ),
            (
                "ticket endpoint edited to match a swapped address",
                |r: &mut StunBindingResponse| {
                    r.reflexive = attacker_controlled();
                    r.ticket.endpoint = attacker_controlled();
                },
                StunBindingError::Cache(EndpointCacheError::Ticket(
                    RelayTicketError::InvalidSignature,
                )),
            ),
            (
                "ticket target edited to name another peer",
                |r: &mut StunBindingResponse| r.ticket.target_id = peer(2),
                StunBindingError::Cache(EndpointCacheError::Ticket(
                    RelayTicketError::InvalidSignature,
                )),
            ),
            (
                "ticket expiry extended",
                |r: &mut StunBindingResponse| r.ticket.expires_at = u64::MAX,
                StunBindingError::Cache(EndpointCacheError::Ticket(
                    RelayTicketError::InvalidSignature,
                )),
            ),
            (
                "ticket epoch rewritten",
                |r: &mut StunBindingResponse| r.ticket.epoch = EPOCH + 1,
                StunBindingError::Cache(EndpointCacheError::Ticket(
                    RelayTicketError::InvalidSignature,
                )),
            ),
            (
                "ticket relabelled as another relay",
                |r: &mut StunBindingResponse| r.ticket.relay_id = IMPOSTOR,
                StunBindingError::Cache(EndpointCacheError::SubmitterMismatch),
            ),
        ];

        for (label, tamper, expected) in cases {
            let registry = registry();
            let mut cache = EndpointCache::new();
            let (request, mut response) = honest_exchange();
            tamper(&mut response);

            assert_eq!(
                apply_binding_response(
                    &mut cache, &registry, &request, &response, RELAY, EPOCH, NOW
                ),
                Err(expected),
                "tamper case: {label}"
            );
            assert!(
                cache.is_empty(),
                "tamper case wrote to the cache anyway: {label}"
            );
            assert!(cache.lookup(&peer(1), NOW).is_empty(), "case: {label}");
            assert!(cache.lookup(&peer(2), NOW).is_empty(), "case: {label}");
        }
    }

    /// A relay that is not in the registry cannot bind anything, however
    /// well-formed its response is and however faithfully it signed. This is
    /// the check that keeps "any peer that can speak the protocol" from
    /// becoming an authority on where traffic goes.
    #[test]
    fn a_response_from_an_unregistered_relay_is_refused() {
        let registry = registry();
        let mut cache = EndpointCache::new();

        let request = StunBindingRequest::new(TXN, peer(1));
        let impostor = StunRelay::new(IMPOSTOR, IMPOSTOR_KEY, FORK);
        let response = impostor.handle_binding_request(&request, attacker_controlled(), EPOCH, NOW);

        assert_eq!(
            apply_binding_response(
                &mut cache, &registry, &request, &response, IMPOSTOR, EPOCH, NOW
            ),
            Err(StunBindingError::Cache(EndpointCacheError::Ticket(
                RelayTicketError::UnknownRelay
            )))
        );
        assert!(cache.is_empty());
    }

    /// A response captured and re-applied long after its ticket lapsed is
    /// refused. The freshness bound is what stops an address the relay vouched
    /// for once from steering traffic indefinitely.
    #[test]
    fn a_response_replayed_after_its_ticket_expires_is_refused() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let request = StunBindingRequest::new(TXN, peer(1));
        let response = relay().with_ticket_lifetime(30).handle_binding_request(
            &request,
            observed(),
            EPOCH,
            NOW,
        );

        assert_eq!(
            apply_binding_response(
                &mut cache,
                &registry,
                &request,
                &response,
                RELAY,
                EPOCH,
                NOW + 31
            ),
            Err(StunBindingError::Cache(EndpointCacheError::Ticket(
                RelayTicketError::Expired
            )))
        );
        assert!(cache.is_empty());
    }
}
