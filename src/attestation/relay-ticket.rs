//! Signed relay endpoint tickets (issue #140).
//!
//! ## The bug
//!
//! A STUN/TURN relay reports a peer's server-reflexive endpoint, and that
//! endpoint is written into a shared endpoint cache. With no authentication on
//! the write, *any* peer able to speak the relay protocol could claim to be
//! relaying for *any* other peer and overwrite that peer's cached endpoint —
//! redirecting the victim's traffic to an attacker-controlled address. This is
//! endpoint cache poisoning, and signature checking alone does not fix it: a
//! relay holding a perfectly valid key could still sign a claim about a peer it
//! has no business speaking for.
//!
//! ## The fix
//!
//! Every endpoint claim travels as a [`RelayTicket`] that the relay signs over
//! the *whole* claim, and the cache accepts a write only when the ticket
//! verifies against **the exact cache key being written**:
//!
//! ```text
//! root = SHA-256( domain(8) || relay_id(32) || target_id(32)
//!                          || endpoint(19) || epoch_le(4) || expires_at_le(8) )
//! sig  = SHA-256( relay_secret_key(32) || root(32) )
//! ```
//!
//! The four properties that follow from binding those fields:
//!
//! 1. **Target binding.** `target_id` is inside the signed root, and
//!    [`verify_relay_ticket`] compares it against the cache key the caller is
//!    about to write. A ticket the relay legitimately signed for peer A is
//!    rejected — [`RelayTicketError::TargetMismatch`] — when presented to
//!    poison peer B's entry. Signature validity alone is *not* sufficient.
//! 2. **Endpoint binding.** `endpoint` is inside the signed root too, so a
//!    captured-but-genuine ticket cannot be re-presented with the address
//!    swapped. See the deviation note below.
//! 3. **Epoch scoping.** A ticket is valid only within
//!    [`RELAY_TICKET_EPOCH_WINDOW`] epochs of the current one, and never for a
//!    future epoch — so tickets cannot be minted ahead of time and banked.
//! 4. **Absolute expiry.** `expires_at` is inside the signed root, so a ticket
//!    cannot be extended without the relay's key. An expired ticket is rejected
//!    exactly as hard as a forged one.
//!
//! ## Deviation from the issue's blueprint
//!
//! Issue #140 specifies the signed tuple as `(relay_id, target_id, epoch,
//! expiry)`. That authenticates *who may write which cache key* but leaves the
//! claimed endpoint — the actual payload, and the actual thing the attacker
//! wants to control — unsigned. An attacker who captured or relayed one genuine
//! ticket could swap the address in transit and poison the cache under a fully
//! valid ticket, which is precisely the traffic-misdirection attack the issue
//! exists to prevent. `endpoint` is therefore part of the signed tuple here: a
//! deliberate superset of the blueprint.
//!
//! ## Signature primitive and its trust boundary
//!
//! Signing reuses the crate's established model — the domain-separated SHA-256
//! keyed MAC documented in [`crate::attestation::verifier`] — via
//! [`sign_root`]/[`verify_root`], rather than introducing a signature
//! dependency. That model is **symmetric**: the value the relay signs with is
//! the value the registry verifies with. Compromising the relay registry
//! therefore confers the ability to forge tickets for any registered relay.
//! Every property above is independent of the primitive (they live in the
//! signing root, not the MAC), so substituting an asymmetric scheme later is a
//! drop-in change that would narrow that trust boundary without touching the
//! verification logic.

use crate::attestation::types::EpochId;
use crate::attestation::verifier::{sign_root, verify_root, SecretKey, Signature};
use crate::crypto::domain::{compute_domain, Domain, DomainType, ForkVersion};
use crate::crypto::merkle::Hash256;
use crate::crypto::sha256::sha256;

// --- CONSTANTS ---

/// Domain type tag for relay endpoint tickets (`0x52544b54` = "RTKT").
///
/// Distinct from every tag in [`crate::crypto::domain`] and from
/// [`crate::webhook::delivery::DOMAIN_WEBHOOK`], so a MAC produced for another
/// message kind under the same key can never be reinterpreted as a ticket.
pub const DOMAIN_RELAY_TICKET: DomainType = [0x52, 0x54, 0x4b, 0x54];

/// How many epochs behind the current one a ticket stays valid.
///
/// A relay signs for the epoch it observed the binding in; allowing one epoch
/// of lag absorbs in-flight tickets crossing an epoch boundary without opening
/// a meaningful replay window. Tickets also carry an absolute [`RelayTicket::expires_at`],
/// so this is the coarser of two independent freshness bounds.
pub const RELAY_TICKET_EPOCH_WINDOW: EpochId = 1;

/// Wire size of a [`SocketEndpoint`]: `tag(1) || address(16) || port_le(2)`.
pub const SOCKET_ENDPOINT_ENCODED_LEN: usize = 19;

/// Wire size of an encoded [`RelayTicket`].
///
/// `relay_id(32) || target_id(32) || endpoint(19) || epoch_le(4)
///  || expires_at_le(8) || signature(32)`.
pub const RELAY_TICKET_ENCODED_LEN: usize = 32 + 32 + SOCKET_ENDPOINT_ENCODED_LEN + 4 + 8 + 32;

/// Length of the signing-root preimage: `domain(8) || relay_id(32)
/// || target_id(32) || endpoint(19) || epoch_le(4) || expires_at_le(8)`.
const SIGNING_PREIMAGE_LEN: usize = 8 + 32 + 32 + SOCKET_ENDPOINT_ENCODED_LEN + 4 + 8;

/// Address-family tag for an IPv4 endpoint.
const IP_TAG_V4: u8 = 4;
/// Address-family tag for an IPv6 endpoint.
const IP_TAG_V6: u8 = 6;

// --- TYPES ---

/// Identifier of a STUN/TURN relay (32 bytes).
pub type RelayId = [u8; 32];

/// Identifier of a peer whose endpoint is being claimed (32 bytes).
///
/// This is also the endpoint cache's key, which is what makes target binding
/// checkable: the ticket names the key it authorizes.
pub type PeerId = [u8; 32];

/// An IP address, in the two families STUN reports.
///
/// Defined here rather than reusing `std::net::IpAddr` because this crate is
/// `no_std` on WASM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpAddress {
    /// IPv4, four octets in network order.
    V4([u8; 4]),
    /// IPv6, sixteen octets in network order.
    V6([u8; 16]),
}

/// A server-reflexive transport address as reported by a relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SocketEndpoint {
    /// The reflexive IP address.
    pub ip: IpAddress,
    /// The reflexive UDP port.
    pub port: u16,
}

impl SocketEndpoint {
    /// Construct an IPv4 endpoint.
    pub const fn v4(octets: [u8; 4], port: u16) -> Self {
        Self {
            ip: IpAddress::V4(octets),
            port,
        }
    }

    /// Construct an IPv6 endpoint.
    pub const fn v6(octets: [u8; 16], port: u16) -> Self {
        Self {
            ip: IpAddress::V6(octets),
            port,
        }
    }

    /// Encode canonically as `tag(1) || address(16, zero-padded) || port_le(2)`.
    ///
    /// The encoding is injective — the family tag disambiguates, and IPv4's
    /// twelve trailing pad bytes are fixed zeros — so two distinct endpoints can
    /// never share a signing root.
    pub fn encode(&self) -> [u8; SOCKET_ENDPOINT_ENCODED_LEN] {
        let mut out = [0u8; SOCKET_ENDPOINT_ENCODED_LEN];
        match self.ip {
            IpAddress::V4(octets) => {
                out[0] = IP_TAG_V4;
                out[1..5].copy_from_slice(&octets);
            }
            IpAddress::V6(octets) => {
                out[0] = IP_TAG_V6;
                out[1..17].copy_from_slice(&octets);
            }
        }
        out[17..19].copy_from_slice(&self.port.to_le_bytes());
        out
    }

    /// Decode an endpoint from exactly [`SOCKET_ENDPOINT_ENCODED_LEN`] bytes.
    ///
    /// Rejects unknown family tags and non-canonical IPv4 padding, so every
    /// accepted byte string has exactly one interpretation.
    pub fn decode(bytes: &[u8; SOCKET_ENDPOINT_ENCODED_LEN]) -> Result<Self, RelayTicketError> {
        let ip = match bytes[0] {
            IP_TAG_V4 => {
                // Reject non-canonical padding rather than silently ignoring it.
                if bytes[5..17].iter().any(|b| *b != 0) {
                    return Err(RelayTicketError::Malformed);
                }
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&bytes[1..5]);
                IpAddress::V4(octets)
            }
            IP_TAG_V6 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&bytes[1..17]);
                IpAddress::V6(octets)
            }
            _ => return Err(RelayTicketError::Malformed),
        };
        let port = u16::from_le_bytes([bytes[17], bytes[18]]);
        Ok(Self { ip, port })
    }
}

/// Why a relay ticket was refused.
///
/// Every variant is a hard rejection: an expired or stale-epoch ticket is
/// refused exactly as a forged one is, and neither ever reaches the cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayTicketError {
    /// The wire bytes were truncated, over-long, or not a canonical encoding.
    Malformed,
    /// `relay_id` is not registered, so no verification key could be resolved.
    UnknownRelay,
    /// The MAC did not match the recomputed signing root.
    InvalidSignature,
    /// The ticket is validly signed but names a *different* peer than the cache
    /// key being written — the core cache-poisoning rejection.
    TargetMismatch,
    /// The ticket is validly signed but names a different endpoint than the one
    /// being written.
    EndpointMismatch,
    /// The ticket's epoch is more than [`RELAY_TICKET_EPOCH_WINDOW`] behind.
    EpochStale,
    /// The ticket names an epoch that has not started yet.
    EpochFuture,
    /// The ticket's absolute expiry has passed.
    Expired,
}

/// A relay's signed claim that `target_id` is reachable at `endpoint`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayTicket {
    /// The relay that issued and signed this claim.
    pub relay_id: RelayId,
    /// The peer the claim is about — and the only cache key it authorizes.
    pub target_id: PeerId,
    /// The server-reflexive endpoint being claimed for `target_id`.
    pub endpoint: SocketEndpoint,
    /// The epoch the relay observed the binding in.
    pub epoch: EpochId,
    /// Unix timestamp (seconds) after which the ticket is no longer accepted.
    pub expires_at: u64,
    /// MAC over the domain-separated signing root.
    pub signature: Signature,
}

// --- SIGNING ROOT ---

/// Compute the domain-separated signing root for a relay ticket.
///
/// Every field is fixed-width, so the preimage is unambiguous without length
/// prefixes: no two distinct field tuples can produce the same byte string.
pub fn compute_relay_ticket_signing_root(
    domain: &Domain,
    relay_id: &RelayId,
    target_id: &PeerId,
    endpoint: &SocketEndpoint,
    epoch: EpochId,
    expires_at: u64,
) -> Hash256 {
    let mut preimage = [0u8; SIGNING_PREIMAGE_LEN];
    preimage[..8].copy_from_slice(domain);
    preimage[8..40].copy_from_slice(relay_id);
    preimage[40..72].copy_from_slice(target_id);
    preimage[72..91].copy_from_slice(&endpoint.encode());
    preimage[91..95].copy_from_slice(&epoch.to_le_bytes());
    preimage[95..103].copy_from_slice(&expires_at.to_le_bytes());
    sha256(&preimage)
}

impl RelayTicket {
    /// Issue a ticket, signing over the full claim under `fork_version`.
    pub fn sign(
        key: &SecretKey,
        relay_id: RelayId,
        target_id: PeerId,
        endpoint: SocketEndpoint,
        epoch: EpochId,
        expires_at: u64,
        fork_version: ForkVersion,
    ) -> Self {
        let domain = compute_domain(DOMAIN_RELAY_TICKET, fork_version);
        let root = compute_relay_ticket_signing_root(
            &domain, &relay_id, &target_id, &endpoint, epoch, expires_at,
        );
        Self {
            relay_id,
            target_id,
            endpoint,
            epoch,
            expires_at,
            signature: sign_root(key, &root),
        }
    }

    /// Recompute this ticket's signing root under `fork_version`.
    pub fn signing_root(&self, fork_version: ForkVersion) -> Hash256 {
        let domain = compute_domain(DOMAIN_RELAY_TICKET, fork_version);
        compute_relay_ticket_signing_root(
            &domain,
            &self.relay_id,
            &self.target_id,
            &self.endpoint,
            self.epoch,
            self.expires_at,
        )
    }

    /// Serialize to exactly [`RELAY_TICKET_ENCODED_LEN`] bytes.
    pub fn encode(&self) -> [u8; RELAY_TICKET_ENCODED_LEN] {
        let mut out = [0u8; RELAY_TICKET_ENCODED_LEN];
        out[..32].copy_from_slice(&self.relay_id);
        out[32..64].copy_from_slice(&self.target_id);
        out[64..83].copy_from_slice(&self.endpoint.encode());
        out[83..87].copy_from_slice(&self.epoch.to_le_bytes());
        out[87..95].copy_from_slice(&self.expires_at.to_le_bytes());
        out[95..127].copy_from_slice(&self.signature);
        out
    }

    /// Parse a ticket from inbound bytes.
    ///
    /// Rejects any input that is not exactly [`RELAY_TICKET_ENCODED_LEN`] bytes
    /// of canonical encoding. Every read is a fixed-range copy behind that
    /// length check, so no input — truncated, over-long, or arbitrary — can
    /// panic this function.
    pub fn decode(bytes: &[u8]) -> Result<Self, RelayTicketError> {
        if bytes.len() != RELAY_TICKET_ENCODED_LEN {
            return Err(RelayTicketError::Malformed);
        }
        let mut relay_id = [0u8; 32];
        relay_id.copy_from_slice(&bytes[..32]);
        let mut target_id = [0u8; 32];
        target_id.copy_from_slice(&bytes[32..64]);
        let mut endpoint_bytes = [0u8; SOCKET_ENDPOINT_ENCODED_LEN];
        endpoint_bytes.copy_from_slice(&bytes[64..83]);
        let endpoint = SocketEndpoint::decode(&endpoint_bytes)?;
        let mut epoch_bytes = [0u8; 4];
        epoch_bytes.copy_from_slice(&bytes[83..87]);
        let mut expiry_bytes = [0u8; 8];
        expiry_bytes.copy_from_slice(&bytes[87..95]);
        let mut signature = [0u8; 32];
        signature.copy_from_slice(&bytes[95..127]);
        Ok(Self {
            relay_id,
            target_id,
            endpoint,
            epoch: EpochId::from_le_bytes(epoch_bytes),
            expires_at: u64::from_le_bytes(expiry_bytes),
            signature,
        })
    }
}

// --- VERIFICATION ---

/// Verify a relay ticket against the write it is being used to authorize.
///
/// `relay_key` is the verification key the caller resolved for
/// `ticket.relay_id`; [`crate::network::relay::relay_registry::RelayRegistry`]
/// does that lookup and maps an unregistered relay to
/// [`RelayTicketError::UnknownRelay`].
///
/// Checks run in authenticate-then-authorize order:
///
/// 1. **Signature** — is this claim genuinely the relay's?
/// 2. **Target binding** — does this genuine claim authorize *this* cache key?
///    Because it runs after the signature check, [`RelayTicketError::TargetMismatch`]
///    is reachable only with a valid signature, which is exactly the property:
///    a relay's own valid ticket for peer A must not write peer B's entry.
/// 3. **Endpoint binding** — does it authorize *this* address?
/// 4. **Epoch window** — not stale, not minted for a future epoch.
/// 5. **Absolute expiry** — not past `expires_at`.
pub fn verify_relay_ticket(
    ticket: &RelayTicket,
    expected_target: &PeerId,
    expected_endpoint: &SocketEndpoint,
    relay_key: &SecretKey,
    current_epoch: EpochId,
    now: u64,
    fork_version: ForkVersion,
) -> Result<(), RelayTicketError> {
    // 1. Authenticate. The root covers relay_id, so a key resolved for a
    //    different relay than the ticket claims cannot validate either.
    let root = ticket.signing_root(fork_version);
    if !verify_root(relay_key, &root, &ticket.signature) {
        return Err(RelayTicketError::InvalidSignature);
    }

    // 2. Authorize the cache key. This is the cache-poisoning gate: signature
    //    validity alone is deliberately not sufficient to write an entry.
    if ticket.target_id != *expected_target {
        return Err(RelayTicketError::TargetMismatch);
    }

    // 3. Authorize the claimed address, so a genuine ticket cannot be replayed
    //    with the endpoint swapped.
    if ticket.endpoint != *expected_endpoint {
        return Err(RelayTicketError::EndpointMismatch);
    }

    // 4. Epoch window. Future epochs are refused so tickets cannot be minted
    //    ahead of time; stale epochs are refused as replay.
    if ticket.epoch > current_epoch {
        return Err(RelayTicketError::EpochFuture);
    }
    if current_epoch.saturating_sub(ticket.epoch) > RELAY_TICKET_EPOCH_WINDOW {
        return Err(RelayTicketError::EpochStale);
    }

    // 5. Absolute expiry — independent of, and finer-grained than, the epoch
    //    window.
    if now > ticket.expires_at {
        return Err(RelayTicketError::Expired);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::domain::{
        DOMAIN_BEACON_ATTESTER, DOMAIN_RANDAO, GENESIS_FORK_VERSION as FORK,
    };

    /// The relay's registered key. Under the MAC model this is both the signing
    /// and the verification key (see the module-level trust-boundary note).
    const RELAY_KEY: SecretKey = [0x11; 32];
    /// A key the attacker holds; deliberately *not* the relay's.
    const ATTACKER_KEY: SecretKey = [0x99; 32];

    const RELAY: RelayId = [0xAA; 32];
    const EPOCH: EpochId = 10;
    const EXPIRES_AT: u64 = 1_000;

    fn peer(tag: u8) -> PeerId {
        let mut id = [0u8; 32];
        id[0] = tag;
        id
    }

    fn stun_endpoint() -> SocketEndpoint {
        SocketEndpoint::v4([203, 0, 113, 7], 3478)
    }

    /// A ticket the real relay genuinely issued for `target` at `endpoint`.
    fn genuine(target: PeerId, endpoint: SocketEndpoint) -> RelayTicket {
        RelayTicket::sign(&RELAY_KEY, RELAY, target, endpoint, EPOCH, EXPIRES_AT, FORK)
    }

    /// Verify `ticket` as authorization for writing `target` -> `endpoint`,
    /// with the epoch and clock both inside every freshness bound.
    fn verify_fresh(
        ticket: &RelayTicket,
        target: &PeerId,
        endpoint: &SocketEndpoint,
    ) -> Result<(), RelayTicketError> {
        verify_relay_ticket(
            ticket,
            target,
            endpoint,
            &RELAY_KEY,
            EPOCH,
            EXPIRES_AT - 1,
            FORK,
        )
    }

    // -----------------------------------------------------------------------
    // Baseline
    // -----------------------------------------------------------------------

    /// A relay's own ticket authorizes exactly the write it names. Guards
    /// against a verifier so strict it rejects legitimate traffic — the
    /// false-positive direction of this fix.
    #[test]
    fn a_valid_ticket_authorizes_the_write_it_names() {
        let target = peer(1);
        let endpoint = stun_endpoint();
        assert_eq!(
            verify_fresh(&genuine(target, endpoint), &target, &endpoint),
            Ok(())
        );
    }

    // -----------------------------------------------------------------------
    // Forgery
    // -----------------------------------------------------------------------

    /// An attacker who does not hold the relay's key cannot mint a ticket in
    /// its name, however well-formed the ticket is. Guards against a
    /// verification path that parses the ticket but never checks the MAC.
    #[test]
    fn a_ticket_signed_with_the_wrong_key_is_rejected() {
        let target = peer(1);
        let endpoint = stun_endpoint();
        let forged = RelayTicket::sign(
            &ATTACKER_KEY,
            RELAY,
            target,
            endpoint,
            EPOCH,
            EXPIRES_AT,
            FORK,
        );
        assert_eq!(
            verify_fresh(&forged, &target, &endpoint),
            Err(RelayTicketError::InvalidSignature)
        );
    }

    /// A relay cannot be impersonated by re-labelling someone else's genuine
    /// ticket: `relay_id` is inside the signing root, so swapping it breaks the
    /// MAC even though the attacker's own key signed the original.
    #[test]
    fn relabelling_a_ticket_with_another_relay_id_breaks_the_signature() {
        let target = peer(1);
        let endpoint = stun_endpoint();
        let attacker_relay = [0xBB; 32];
        let mut ticket = RelayTicket::sign(
            &ATTACKER_KEY,
            attacker_relay,
            target,
            endpoint,
            EPOCH,
            EXPIRES_AT,
            FORK,
        );
        // Claim to be the honest relay, keeping the attacker's own signature.
        ticket.relay_id = RELAY;
        assert_eq!(
            verify_fresh(&ticket, &target, &endpoint),
            Err(RelayTicketError::InvalidSignature)
        );
    }

    // -----------------------------------------------------------------------
    // PROPERTY 1 — target binding is exact
    // -----------------------------------------------------------------------

    /// **The core cache-poisoning rejection, tested standalone.**
    ///
    /// The relay genuinely issued this ticket — nothing is forged, and the
    /// first assertion proves the signature verifies. Presented as
    /// authorization to overwrite a *different* peer's cache entry it must
    /// still be refused. A verifier that checked only signature validity would
    /// pass the second assertion and let one peer redirect another's traffic.
    #[test]
    fn a_valid_ticket_for_one_peer_cannot_authorize_writing_anothers_entry() {
        let peer_a = peer(1);
        let peer_b = peer(2);
        let endpoint = stun_endpoint();
        let ticket = genuine(peer_a, endpoint);

        // The signature is genuine: this ticket is accepted for its own target.
        assert_eq!(verify_fresh(&ticket, &peer_a, &endpoint), Ok(()));

        // Same untampered ticket, aimed at peer B's cache key.
        assert_eq!(
            verify_fresh(&ticket, &peer_b, &endpoint),
            Err(RelayTicketError::TargetMismatch),
            "a validly-signed ticket for peer A must not authorize a write to peer B"
        );
    }

    /// Rewriting `target_id` to match the victim does not help either: the
    /// field is signed, so the MAC fails before the binding check is reached.
    #[test]
    fn rewriting_target_id_to_the_victim_breaks_the_signature() {
        let peer_a = peer(1);
        let peer_b = peer(2);
        let endpoint = stun_endpoint();
        let mut ticket = genuine(peer_a, endpoint);
        ticket.target_id = peer_b;
        assert_eq!(
            verify_fresh(&ticket, &peer_b, &endpoint),
            Err(RelayTicketError::InvalidSignature)
        );
    }

    // -----------------------------------------------------------------------
    // Endpoint binding (the documented deviation from the issue's blueprint)
    // -----------------------------------------------------------------------

    /// Both halves of the endpoint-swap attack the issue's literal blueprint
    /// leaves open. Capturing a genuine ticket and pointing the write at an
    /// attacker-controlled address fails the binding check; editing the
    /// ticket's own endpoint to match fails the MAC.
    #[test]
    fn a_genuine_ticket_cannot_be_replayed_with_a_swapped_endpoint() {
        let target = peer(1);
        let honest = stun_endpoint();
        let attacker_controlled = SocketEndpoint::v4([198, 51, 100, 66], 9999);
        let ticket = genuine(target, honest);

        assert_eq!(
            verify_fresh(&ticket, &target, &attacker_controlled),
            Err(RelayTicketError::EndpointMismatch)
        );

        let mut edited = ticket;
        edited.endpoint = attacker_controlled;
        assert_eq!(
            verify_fresh(&edited, &target, &attacker_controlled),
            Err(RelayTicketError::InvalidSignature)
        );
    }

    // -----------------------------------------------------------------------
    // PROPERTY 2 — expiry and epoch are enforced as hard as forgery
    // -----------------------------------------------------------------------

    /// A validly-signed ticket stops being accepted the moment its absolute
    /// expiry passes. Guards against replaying an old, genuine ticket forever.
    #[test]
    fn a_validly_signed_but_expired_ticket_is_rejected() {
        let target = peer(1);
        let endpoint = stun_endpoint();
        let ticket = genuine(target, endpoint);

        // Accepted right up to and including the expiry second.
        assert_eq!(
            verify_relay_ticket(&ticket, &target, &endpoint, &RELAY_KEY, EPOCH, EXPIRES_AT, FORK),
            Ok(())
        );
        // Refused one second later.
        assert_eq!(
            verify_relay_ticket(
                &ticket,
                &target,
                &endpoint,
                &RELAY_KEY,
                EPOCH,
                EXPIRES_AT + 1,
                FORK
            ),
            Err(RelayTicketError::Expired)
        );
    }

    /// A validly-signed ticket from an epoch outside the acceptance window is
    /// rejected as replay. Guards against a verifier that trusts the signature
    /// and ignores freshness.
    #[test]
    fn a_validly_signed_but_stale_epoch_ticket_is_rejected() {
        let target = peer(1);
        let endpoint = stun_endpoint();
        let ticket = genuine(target, endpoint);
        let now = EXPIRES_AT - 1;

        // One epoch of lag is inside the window.
        assert_eq!(
            verify_relay_ticket(
                &ticket,
                &target,
                &endpoint,
                &RELAY_KEY,
                EPOCH + RELAY_TICKET_EPOCH_WINDOW,
                now,
                FORK
            ),
            Ok(())
        );
        // One more is not.
        assert_eq!(
            verify_relay_ticket(
                &ticket,
                &target,
                &endpoint,
                &RELAY_KEY,
                EPOCH + RELAY_TICKET_EPOCH_WINDOW + 1,
                now,
                FORK
            ),
            Err(RelayTicketError::EpochStale)
        );
    }

    /// A relay cannot mint tickets for epochs that have not started and bank
    /// them, which would defeat the epoch window entirely.
    #[test]
    fn a_ticket_minted_for_a_future_epoch_is_rejected() {
        let target = peer(1);
        let endpoint = stun_endpoint();
        let ticket = genuine(target, endpoint);
        assert_eq!(
            verify_relay_ticket(
                &ticket,
                &target,
                &endpoint,
                &RELAY_KEY,
                EPOCH - 1,
                EXPIRES_AT - 1,
                FORK
            ),
            Err(RelayTicketError::EpochFuture)
        );
    }

    // -----------------------------------------------------------------------
    // Domain separation
    // -----------------------------------------------------------------------

    /// A MAC produced under any other domain — another message kind, or the
    /// same ticket under a different fork version — must not verify as a
    /// ticket. Without this, a signature harvested from another subsystem
    /// signed with the same key could be replayed as an endpoint claim.
    #[test]
    fn the_ticket_signing_root_is_domain_separated() {
        let target = peer(1);
        let endpoint = stun_endpoint();

        let ticket_domain = compute_domain(DOMAIN_RELAY_TICKET, FORK);
        let root = |domain| {
            compute_relay_ticket_signing_root(
                &domain, &RELAY, &target, &endpoint, EPOCH, EXPIRES_AT,
            )
        };
        for other in [DOMAIN_BEACON_ATTESTER, DOMAIN_RANDAO] {
            assert_ne!(
                root(ticket_domain),
                root(compute_domain(other, FORK)),
                "identical ticket fields must not share a root across domains"
            );
        }

        // Behaviourally: a ticket signed under one fork version does not
        // verify under another.
        let other_fork = [0x01, 0x00, 0x00, 0x00];
        let ticket = genuine(target, endpoint);
        assert_eq!(
            verify_relay_ticket(
                &ticket,
                &target,
                &endpoint,
                &RELAY_KEY,
                EPOCH,
                EXPIRES_AT - 1,
                other_fork
            ),
            Err(RelayTicketError::InvalidSignature)
        );
    }

    // -----------------------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------------------

    /// The wire format must round-trip every field. A field the encoder drops
    /// or misplaces would silently change the signing root computed by the
    /// receiver, breaking either verification or — worse — a binding check.
    #[test]
    fn encode_decode_round_trips_every_field() {
        for endpoint in [
            stun_endpoint(),
            SocketEndpoint::v6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                5349,
            ),
        ] {
            let ticket = genuine(peer(7), endpoint);
            let decoded = RelayTicket::decode(&ticket.encode()).expect("round-trip must decode");
            assert_eq!(decoded, ticket);
            assert_eq!(ticket.encode().len(), RELAY_TICKET_ENCODED_LEN);
        }
    }

    /// Malformed input is refused without panicking, at every truncation
    /// length and for every non-canonical encoding. A slice index outside a
    /// length check here would be a remotely-triggerable panic on the relay
    /// ingress path.
    #[test]
    fn decode_rejects_malformed_input_without_panicking() {
        let valid = genuine(peer(1), stun_endpoint()).encode();

        // Every truncation, including empty.
        for len in 0..RELAY_TICKET_ENCODED_LEN {
            assert_eq!(
                RelayTicket::decode(&valid[..len]),
                Err(RelayTicketError::Malformed),
                "truncation to {len} bytes must be refused"
            );
        }

        // Over-long input.
        let mut long = [0u8; RELAY_TICKET_ENCODED_LEN + 1];
        long[..RELAY_TICKET_ENCODED_LEN].copy_from_slice(&valid);
        assert_eq!(RelayTicket::decode(&long), Err(RelayTicketError::Malformed));

        // Unknown address-family tag (endpoint tag lives at offset 64).
        let mut bad_family = valid;
        bad_family[64] = 7;
        assert_eq!(
            RelayTicket::decode(&bad_family),
            Err(RelayTicketError::Malformed)
        );

        // Non-canonical IPv4 padding (offsets 69..81 must be zero).
        let mut bad_padding = valid;
        bad_padding[70] = 1;
        assert_eq!(
            RelayTicket::decode(&bad_padding),
            Err(RelayTicketError::Malformed)
        );
    }

    /// Every byte of the signed prefix must actually be covered by the signing
    /// root. Flipping any one of them and re-verifying the ticket **against its
    /// own fields** — so no binding or freshness check can mask the result —
    /// must fail the MAC. This is what catches a root that forgets a field:
    /// omit `expires_at` and an attacker extends any ticket indefinitely; omit
    /// `endpoint` and the swap attack above comes straight back.
    #[test]
    fn flipping_any_signed_byte_invalidates_the_signature() {
        const SIGNED_PREFIX_LEN: usize = RELAY_TICKET_ENCODED_LEN - 32;
        let valid = genuine(peer(1), stun_endpoint()).encode();
        let mut checked = 0usize;

        for i in 0..SIGNED_PREFIX_LEN {
            let mut mutated = valid;
            mutated[i] ^= 0xFF;
            let ticket = match RelayTicket::decode(&mutated) {
                Ok(ticket) => ticket,
                // Non-canonical encodings are refused earlier — also a rejection.
                Err(RelayTicketError::Malformed) => continue,
                Err(other) => panic!("unexpected decode error at byte {i}: {other:?}"),
            };
            checked += 1;
            assert_eq!(
                verify_relay_ticket(
                    &ticket,
                    &ticket.target_id,
                    &ticket.endpoint,
                    &RELAY_KEY,
                    ticket.epoch,
                    0,
                    FORK
                ),
                Err(RelayTicketError::InvalidSignature),
                "byte {i} of the ticket is not covered by the signing root"
            );
        }

        assert!(
            checked >= 80,
            "expected most of the signed prefix to be exercised, only {checked} bytes were"
        );
    }
}
