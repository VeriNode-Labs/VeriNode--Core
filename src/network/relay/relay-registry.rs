//! Registry of authoritative STUN/TURN relays (issue #140).
//!
//! The endpoint cache needs to answer one question before it will accept a
//! binding claim: *is this relay one we recognise, and is this claim really
//! theirs?* This registry holds that answer — the set of relay identities the
//! node treats as authoritative, and the verification key for each — and is the
//! single place a `relay_id` is turned into a key.
//!
//! It follows the shape of [`crate::attestation::key_registry::KeyRegistry`]:
//! a `BTreeMap` from identity to key material, with lookup failure surfaced as
//! an explicit error rather than a silent accept.
//!
//! ## Trust model (deliberately narrow, see issue #140 follow-ups)
//!
//! "Authoritative" here means exactly "present in this map". There is no PKI,
//! no enrolment proof, and no revocation list — registering a relay is an
//! operator action the registry takes on trust, matching how `KeyRegistry`
//! treats validator keys today. Combined with the symmetric MAC model
//! documented in [`crate::attestation::relay_ticket`], that means write access
//! to this registry is equivalent to the ability to forge tickets for every
//! relay in it. Narrowing that boundary is out of scope for this fix.

extern crate alloc;

use alloc::collections::BTreeMap;

use crate::attestation::relay_ticket::{
    verify_relay_ticket, PeerId, RelayId, RelayTicket, RelayTicketError, SocketEndpoint,
};
use crate::attestation::types::EpochId;
use crate::attestation::verifier::SecretKey;
use crate::crypto::domain::ForkVersion;

/// A relay's verification key.
///
/// Under the crate's MAC signature model this is the same 32-byte value the
/// relay signs with — see the trust-boundary note in
/// [`crate::attestation::relay_ticket`].
pub type RelayVerifyKey = SecretKey;

/// The set of relays whose endpoint claims this node will consider.
#[derive(Clone, Debug)]
pub struct RelayRegistry {
    relays: BTreeMap<RelayId, RelayVerifyKey>,
    fork_version: ForkVersion,
}

impl RelayRegistry {
    /// Create an empty registry scoped to `fork_version`.
    ///
    /// The fork version is folded into every ticket's signing domain, so a
    /// registry on one fork will not accept tickets minted on another.
    pub fn new(fork_version: ForkVersion) -> Self {
        Self {
            relays: BTreeMap::new(),
            fork_version,
        }
    }

    /// Register `relay_id` with `key`, returning any key it replaces.
    pub fn register(&mut self, relay_id: RelayId, key: RelayVerifyKey) -> Option<RelayVerifyKey> {
        self.relays.insert(relay_id, key)
    }

    /// Remove a relay, returning its key if it was registered.
    ///
    /// Deregistration stops future claims from being accepted. It deliberately
    /// does *not* touch the endpoint cache: purging what a relay already wrote
    /// is [`crate::network::relay::endpoint_cache::EndpointCache::evict_relay`],
    /// which the caller invokes when the removal is punitive.
    pub fn deregister(&mut self, relay_id: &RelayId) -> Option<RelayVerifyKey> {
        self.relays.remove(relay_id)
    }

    /// Returns `true` if `relay_id` is registered.
    pub fn is_registered(&self, relay_id: &RelayId) -> bool {
        self.relays.contains_key(relay_id)
    }

    /// Look up a relay's verification key.
    pub fn verify_key(&self, relay_id: &RelayId) -> Option<&RelayVerifyKey> {
        self.relays.get(relay_id)
    }

    /// The fork version every ticket is verified under.
    pub fn fork_version(&self) -> ForkVersion {
        self.fork_version
    }

    /// Number of registered relays.
    pub fn len(&self) -> usize {
        self.relays.len()
    }

    /// Returns `true` if no relay is registered.
    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    /// Verify `ticket` as authorization to write `expected_target` ->
    /// `expected_endpoint`.
    ///
    /// Resolves the claimed relay's key — an unregistered relay is
    /// [`RelayTicketError::UnknownRelay`], never a silent accept — then applies
    /// the full check sequence in [`verify_relay_ticket`]: signature, target
    /// binding, endpoint binding, epoch window, expiry.
    pub fn verify_ticket(
        &self,
        ticket: &RelayTicket,
        expected_target: &PeerId,
        expected_endpoint: &SocketEndpoint,
        current_epoch: EpochId,
        now: u64,
    ) -> Result<(), RelayTicketError> {
        let key = self
            .verify_key(&ticket.relay_id)
            .ok_or(RelayTicketError::UnknownRelay)?;
        verify_relay_ticket(
            ticket,
            expected_target,
            expected_endpoint,
            key,
            current_epoch,
            now,
            self.fork_version,
        )
    }
}
