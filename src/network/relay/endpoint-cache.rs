//! Authenticated STUN/TURN endpoint cache (issue #140).
//!
//! ## What this cache holds
//!
//! For each peer, the set of server-reflexive transport addresses a relay has
//! claimed for it. Traffic is sent to whatever this cache says, which is what
//! makes an unauthenticated write path so damaging: overwrite a peer's entry
//! and you redirect that peer's traffic to an address you control.
//!
//! ## The write path
//!
//! [`EndpointCache::put`] accepts a claim only when a
//! [`RelayTicket`] authorizes *exactly* the write being attempted — see
//! [`crate::attestation::relay_ticket`] for the ticket scheme and the
//! target/endpoint binding checks. Beyond that authorization, `put` enforces
//! three independent controls:
//!
//! 1. **A sliding-window penalty counter** over the last
//!    [`PENALTY_WINDOW_SECS`] seconds. More than
//!    [`MAX_FAILED_CLAIMS_PER_WINDOW`] rejected claims inside *any* such window
//!    blacklists the submitter.
//! 2. **Eviction on blacklist.** Blacklisting deletes every entry the offender
//!    wrote. Capping future writes alone would leave already-poisoned entries
//!    live and readable.
//! 3. **Capacity limits** — [`ENDPOINT_CACHE_MAX_ENTRIES`] overall and
//!    [`ENDPOINT_CACHE_MAX_PER_PEER`] per peer — applied to *every* new entry,
//!    including perfectly-ticketed ones, so cache exhaustion is bounded
//!    independently of whether anyone is behaving maliciously.
//!
//! ## Attribution, and why `put` takes a `submitter`
//!
//! A penalty counter that can be aimed at somebody else is worse than no
//! penalty counter, because triggering it *evicts that party's cache entries*.
//! If failures were attributed to the `relay_id` written inside the ticket —
//! an attacker-controlled field until the signature verifies — then replaying
//! an honest relay's genuine ticket against the wrong peer six times would
//! blacklist that honest relay and purge its bindings. The fix would have
//! introduced a sharper denial-of-service than the one it closes.
//!
//! So `put` takes `submitter`: the authenticated identity of the peer that
//! actually delivered the claim, which the transport layer supplies.
//! Every penalty, every blacklist, and every eviction is attributed to that
//! identity, and a claim whose ticket names a *different* relay than the
//! submitter is refused outright ([`EndpointCacheError::SubmitterMismatch`]) —
//! so a relayed or replayed ticket penalises the party that replayed it, never
//! the relay that signed it.
//!
//! This cache trusts the caller's identification of the submitter. Providing
//! it is the transport's job; see the module-level notes in
//! [`crate::network::relay::relay_registry`] for the surrounding trust model.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::attestation::relay_ticket::{
    PeerId, RelayId, RelayTicket, RelayTicketError, SocketEndpoint,
};
use crate::attestation::types::EpochId;
use crate::network::relay::relay_registry::RelayRegistry;

// --- CONSTANTS ---

/// Maximum entries the cache holds in total, across every peer.
pub const ENDPOINT_CACHE_MAX_ENTRIES: usize = 10_000;

/// Maximum entries cached for any one *target* peer.
///
/// "Per peer" is per cache key — a peer may be reachable at several addresses
/// (IPv4 and IPv6, multiple relays), but not at an unbounded number.
pub const ENDPOINT_CACHE_MAX_PER_PEER: usize = 16;

/// Lifetime of a cached entry, in seconds.
pub const ENDPOINT_ENTRY_TTL_SECS: u64 = 300;

/// Width of the penalty window, in seconds.
pub const PENALTY_WINDOW_SECS: u64 = 60;

/// Rejected claims tolerated within [`PENALTY_WINDOW_SECS`]; the next one
/// blacklists the submitter.
pub const MAX_FAILED_CLAIMS_PER_WINDOW: u32 = 5;

/// How long a blacklisting lasts, in seconds.
pub const RELAY_BLACKLIST_DURATION_SECS: u64 = 300;

// --- TYPES ---

/// Why an endpoint write was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointCacheError {
    /// The ticket did not authorize this write. Carries the specific reason so
    /// callers and monitoring can distinguish a forgery from a stale ticket.
    Ticket(RelayTicketError),
    /// The ticket names a different relay than the peer that submitted it — a
    /// relayed or replayed ticket. Penalised against the submitter.
    SubmitterMismatch,
    /// The submitter is currently blacklisted.
    RelayBlacklisted,
    /// This peer already holds [`ENDPOINT_CACHE_MAX_PER_PEER`] entries.
    PeerCapacityExceeded,
    /// The cache already holds [`ENDPOINT_CACHE_MAX_ENTRIES`] entries.
    TotalCapacityExceeded,
}

/// One cached endpoint claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointRecord {
    /// The peer this endpoint belongs to — the cache key.
    pub target_id: PeerId,
    /// The submitter this entry is attributed to, used for eviction on
    /// blacklist. For an accepted write this equals the ticket's `relay_id`.
    pub relay_id: RelayId,
    /// The claimed server-reflexive address.
    pub endpoint: SocketEndpoint,
    /// The epoch the authorizing ticket was issued in.
    pub epoch: EpochId,
    /// When this entry was written, in unix seconds.
    pub written_at: u64,
    /// When this entry stops being served, in unix seconds.
    pub expires_at: u64,
}

/// Counters for monitoring a security control that is supposed to be quiet.
///
/// `rejected_claims` and `capacity_rejections` are kept apart on purpose: the
/// first counts failed authorization (someone is probing), the second counts
/// resource pressure from traffic that authorized fine. Conflating them would
/// hide exactly the distinction the two controls are meant to preserve.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EndpointCacheMetrics {
    /// New entries accepted.
    pub writes: u64,
    /// Existing entries refreshed in place.
    pub refreshes: u64,
    /// Claims refused because they were not authorized.
    pub rejected_claims: u64,
    /// Writes refused because a capacity limit was reached.
    pub capacity_rejections: u64,
    /// Submitters blacklisted.
    pub blacklists: u64,
    /// Entries deleted by blacklist eviction.
    pub evicted_on_blacklist: u64,
    /// Entries dropped because their TTL elapsed.
    pub expirations: u64,
}

/// Per-submitter failure history: a sliding window of rejection timestamps
/// plus the current blacklist deadline.
///
/// The window is a log of the individual timestamps of recent failures, pruned
/// against `now` on every touch — *not* a running total and *not* a fixed
/// per-minute bucket. Both of those alternatives fail:
///
/// * A running total never forgets, so failures from an hour ago eventually
///   blacklist a relay that has since behaved perfectly. Here a failure at
///   `t` contributes nothing from `t + PENALTY_WINDOW_SECS` onward.
/// * Fixed buckets reset on a boundary, so an attacker who paces five failures
///   just before the boundary and five just after never trips a
///   five-per-bucket threshold — ten failures, no blacklist. Because this
///   window slides continuously, those ten are all inside the window measured
///   from the last one, and the sixth trips it.
#[derive(Clone, Debug, Default)]
struct PenaltyWindow {
    /// Timestamps of recent rejected claims, in unix seconds.
    failures: Vec<u64>,
    /// Unix second the blacklist lifts; `0` means not blacklisted.
    blacklisted_until: u64,
}

impl PenaltyWindow {
    /// Drop failures that have aged out of the window.
    fn prune(&mut self, now: u64) {
        self.failures
            .retain(|at| now.saturating_sub(*at) < PENALTY_WINDOW_SECS);
    }

    /// Failures inside the window ending at `now`, without mutating.
    fn count(&self, now: u64) -> u32 {
        self.failures
            .iter()
            .filter(|at| now.saturating_sub(**at) < PENALTY_WINDOW_SECS)
            .count() as u32
    }

    /// Record a failure at `now` and return the resulting windowed count.
    ///
    /// The log is capped at one entry past the threshold: once the submitter is
    /// over the line the precise count carries no further information, and the
    /// cap keeps a burst of failures from growing memory without bound. Entries
    /// still age out normally, so the cap can only ever release the window
    /// *sooner* than an uncapped log — never hold a submitter blacklisted on
    /// stale evidence, which is the failure mode that matters.
    fn record(&mut self, now: u64) -> u32 {
        self.prune(now);
        if self.failures.len() <= MAX_FAILED_CLAIMS_PER_WINDOW as usize {
            self.failures.push(now);
        }
        self.failures.len() as u32
    }

    /// Returns `true` if the blacklist is still in force at `now`.
    fn is_blacklisted(&self, now: u64) -> bool {
        self.blacklisted_until > now
    }
}

/// The endpoint cache.
#[derive(Clone, Debug, Default)]
pub struct EndpointCache {
    /// Entries grouped by target peer.
    entries: BTreeMap<PeerId, Vec<EndpointRecord>>,
    /// Failure history and blacklist state, by submitter.
    penalties: BTreeMap<RelayId, PenaltyWindow>,
    /// Running total of entries across every peer bucket.
    total_entries: usize,
    /// The `now` of the most recent automatic expiry sweep, so a burst of
    /// writes within one second scans once rather than once per write.
    last_expiry_sweep: Option<u64>,
    metrics: EndpointCacheMetrics,
}

impl EndpointCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    // --- write path ---

    /// Apply a relay's endpoint claim.
    ///
    /// `submitter` is the authenticated identity of the peer delivering the
    /// claim; see the module docs for why attribution uses it rather than the
    /// ticket's own `relay_id`.
    ///
    /// The sequence is:
    ///
    /// 1. Sweep expired entries so capacity is measured against live state.
    /// 2. Refuse blacklisted submitters.
    /// 3. Refuse a ticket that names a relay other than the submitter.
    /// 4. Verify the ticket against *this* target and *this* endpoint.
    /// 5. Enforce capacity.
    /// 6. Insert, or refresh an existing entry in place.
    ///
    /// Steps 3 and 4 record a penalty against `submitter`; step 5 deliberately
    /// does not — a well-behaved relay that runs into a capacity limit has not
    /// made an incorrect claim, and must never be blacklisted for it.
    pub fn put(
        &mut self,
        registry: &RelayRegistry,
        submitter: RelayId,
        ticket: &RelayTicket,
        target_id: PeerId,
        endpoint: SocketEndpoint,
        current_epoch: EpochId,
        now: u64,
    ) -> Result<(), EndpointCacheError> {
        self.sweep_expired(now);

        // 2. A blacklisted submitter is refused before anything else, and
        //    without a further penalty — it is already over the line.
        if self.is_blacklisted(&submitter, now) {
            return Err(EndpointCacheError::RelayBlacklisted);
        }

        // 3. Only a relay's own tickets may be submitted by it. This is what
        //    stops a captured ticket being replayed to frame its signer.
        if ticket.relay_id != submitter {
            self.record_failure(submitter, now);
            return Err(EndpointCacheError::SubmitterMismatch);
        }

        // 4. Authorization proper: signature, target binding, endpoint binding,
        //    epoch window, expiry.
        if let Err(err) = registry.verify_ticket(ticket, &target_id, &endpoint, current_epoch, now)
        {
            self.record_failure(submitter, now);
            return Err(EndpointCacheError::Ticket(err));
        }

        // 5. Capacity, enforced independently of everything above.
        let bucket_len = self.entries.get(&target_id).map_or(0, Vec::len);
        let is_refresh = self
            .entries
            .get(&target_id)
            .is_some_and(|bucket| bucket.iter().any(|record| record.endpoint == endpoint));
        if !is_refresh {
            if self.total_entries >= ENDPOINT_CACHE_MAX_ENTRIES {
                self.metrics.capacity_rejections += 1;
                return Err(EndpointCacheError::TotalCapacityExceeded);
            }
            if bucket_len >= ENDPOINT_CACHE_MAX_PER_PEER {
                self.metrics.capacity_rejections += 1;
                return Err(EndpointCacheError::PeerCapacityExceeded);
            }
        }

        // 6. Insert. An entry never outlives the ticket that authorized it, so
        //    cached data is always covered by a claim that was valid when read.
        let record = EndpointRecord {
            target_id,
            relay_id: submitter,
            endpoint,
            epoch: ticket.epoch,
            written_at: now,
            expires_at: now
                .saturating_add(ENDPOINT_ENTRY_TTL_SECS)
                .min(ticket.expires_at),
        };
        let bucket = self.entries.entry(target_id).or_default();
        match bucket.iter_mut().find(|slot| slot.endpoint == endpoint) {
            Some(slot) => {
                *slot = record;
                self.metrics.refreshes += 1;
            }
            None => {
                bucket.push(record);
                self.total_entries += 1;
                self.metrics.writes += 1;
            }
        }
        Ok(())
    }

    // --- read path ---

    /// Every record cached for `target_id`, expired ones included.
    ///
    /// Callers routing traffic want [`EndpointCache::lookup`]; this is the raw
    /// view, useful for inspection and for asserting that eviction really
    /// removed something.
    pub fn records(&self, target_id: &PeerId) -> &[EndpointRecord] {
        self.entries
            .get(target_id)
            .map_or(&[], |bucket| bucket.as_slice())
    }

    /// The endpoints currently served for `target_id`.
    pub fn lookup(&self, target_id: &PeerId, now: u64) -> Vec<SocketEndpoint> {
        self.entries
            .get(target_id)
            .map(|bucket| {
                bucket
                    .iter()
                    .filter(|record| now < record.expires_at)
                    .map(|record| record.endpoint)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Total entries held, across every peer.
    pub fn len(&self) -> usize {
        self.total_entries
    }

    /// Returns `true` if the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.total_entries == 0
    }

    /// Number of peers with at least one entry.
    pub fn peer_count(&self) -> usize {
        self.entries.len()
    }

    /// Snapshot the counters.
    pub fn metrics(&self) -> EndpointCacheMetrics {
        self.metrics
    }

    // --- penalty and blacklist state ---

    /// Returns `true` if `relay` is blacklisted at `now`.
    pub fn is_blacklisted(&self, relay: &RelayId, now: u64) -> bool {
        self.penalties
            .get(relay)
            .is_some_and(|record| record.is_blacklisted(now))
    }

    /// Rejected claims attributed to `relay` within the window ending at `now`.
    pub fn recent_failure_count(&self, relay: &RelayId, now: u64) -> u32 {
        self.penalties
            .get(relay)
            .map_or(0, |record| record.count(now))
    }

    /// Delete every entry attributed to `relay`, returning how many went.
    ///
    /// This is a real removal from the backing maps — the records are dropped
    /// and emptied peer buckets are removed with them, so nothing stale stays
    /// readable behind a flag.
    pub fn evict_relay(&mut self, relay: &RelayId) -> usize {
        let mut removed = 0usize;
        self.entries.retain(|_, bucket| {
            let before = bucket.len();
            bucket.retain(|record| record.relay_id != *relay);
            removed += before - bucket.len();
            !bucket.is_empty()
        });
        self.total_entries -= removed;
        removed
    }

    /// Drop every entry whose TTL has elapsed, returning how many went.
    pub fn expire(&mut self, now: u64) -> usize {
        let mut removed = 0usize;
        self.entries.retain(|_, bucket| {
            let before = bucket.len();
            bucket.retain(|record| now < record.expires_at);
            removed += before - bucket.len();
            !bucket.is_empty()
        });
        self.total_entries -= removed;
        self.metrics.expirations += removed as u64;
        removed
    }

    /// Attribute a rejected claim to `submitter`, blacklisting and evicting if
    /// the sliding window has been exceeded.
    fn record_failure(&mut self, submitter: RelayId, now: u64) {
        self.metrics.rejected_claims += 1;

        let record = self.penalties.entry(submitter).or_default();
        let count = record.record(now);
        if count <= MAX_FAILED_CLAIMS_PER_WINDOW {
            return;
        }
        record.blacklisted_until = now.saturating_add(RELAY_BLACKLIST_DURATION_SECS);
        self.metrics.blacklists += 1;

        // PROPERTY: blacklisting must undo the damage, not just cap it. Every
        // entry this submitter wrote is deleted here and now.
        let evicted = self.evict_relay(&submitter);
        self.metrics.evicted_on_blacklist += evicted as u64;
    }

    /// Run at most one automatic expiry sweep per distinct `now`.
    ///
    /// `expire` is idempotent within a second, so re-scanning for every write
    /// in a burst is pure cost. Calling [`EndpointCache::expire`] directly is
    /// unaffected.
    fn sweep_expired(&mut self, now: u64) {
        if self.last_expiry_sweep == Some(now) {
            return;
        }
        self.expire(now);
        self.last_expiry_sweep = Some(now);
    }

    /// Recompute the entry total from the buckets.
    ///
    /// The running total is maintained incrementally on every insert, eviction,
    /// and expiry; tests use this to prove those paths never drift apart.
    #[cfg(test)]
    fn recomputed_len(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::verifier::SecretKey;
    use crate::crypto::domain::GENESIS_FORK_VERSION as FORK;

    const RELAY: RelayId = [0xAA; 32];
    const RELAY_KEY: SecretKey = [0x11; 32];
    const OTHER: RelayId = [0xBB; 32];
    const OTHER_KEY: SecretKey = [0x22; 32];

    const EPOCH: EpochId = 10;
    /// How long each test ticket stays valid — comfortably inside the entry TTL
    /// so expiry never interferes with a test that is about something else.
    const TICKET_LIFETIME: u64 = 120;

    fn peer(n: u16) -> PeerId {
        let mut id = [0u8; 32];
        id[..2].copy_from_slice(&n.to_le_bytes());
        id
    }

    fn endpoint(n: u16) -> SocketEndpoint {
        SocketEndpoint::v4([203, 0, 113, 7], 3478 + n)
    }

    fn registry() -> RelayRegistry {
        let mut registry = RelayRegistry::new(FORK);
        registry.register(RELAY, RELAY_KEY);
        registry.register(OTHER, OTHER_KEY);
        registry
    }

    /// A ticket the named relay genuinely issued, valid from `now`.
    fn signed(
        key: &SecretKey,
        relay: RelayId,
        target: PeerId,
        endpoint: SocketEndpoint,
        now: u64,
    ) -> RelayTicket {
        RelayTicket::sign(
            key,
            relay,
            target,
            endpoint,
            EPOCH,
            now + TICKET_LIFETIME,
            FORK,
        )
    }

    /// Perform a fully legitimate write.
    fn put_valid(
        cache: &mut EndpointCache,
        registry: &RelayRegistry,
        relay: RelayId,
        key: &SecretKey,
        target: PeerId,
        endpoint: SocketEndpoint,
        now: u64,
    ) -> Result<(), EndpointCacheError> {
        let ticket = signed(key, relay, target, endpoint, now);
        cache.put(registry, relay, &ticket, target, endpoint, EPOCH, now)
    }

    /// Commit one rejected-but-attributable claim: a ticket the relay really
    /// signed for one peer, aimed at a different peer's cache key. The
    /// signature is valid, so the failure is unambiguously the submitter's.
    fn commit_rejected_claim(
        cache: &mut EndpointCache,
        registry: &RelayRegistry,
        relay: RelayId,
        key: &SecretKey,
        now: u64,
    ) {
        let ticket = signed(key, relay, peer(900), endpoint(0), now);
        let outcome = cache.put(registry, relay, &ticket, peer(901), endpoint(0), EPOCH, now);
        assert_eq!(
            outcome,
            Err(EndpointCacheError::Ticket(RelayTicketError::TargetMismatch)),
            "helper must produce an attributable rejection"
        );
    }

    // -----------------------------------------------------------------------
    // Write path
    // -----------------------------------------------------------------------

    /// A correctly-ticketed claim is cached and served. The false-positive
    /// guard for everything below.
    #[test]
    fn a_ticket_authorized_claim_is_cached_and_served() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let target = peer(1);

        assert_eq!(
            put_valid(
                &mut cache,
                &registry,
                RELAY,
                &RELAY_KEY,
                target,
                endpoint(1),
                1_000
            ),
            Ok(())
        );
        assert_eq!(cache.lookup(&target, 1_000), alloc::vec![endpoint(1)]);
        assert_eq!(cache.len(), 1);
    }

    /// The end of the poisoning path: a ticket the relay validly signed for one
    /// peer, presented to overwrite another peer's entry, is refused *and*
    /// leaves nothing behind. Asserting the error alone would not catch a
    /// verifier that rejected after already writing.
    #[test]
    fn a_ticket_for_another_peer_never_reaches_the_targeted_entry() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let victim = peer(2);
        let ticket = signed(&RELAY_KEY, RELAY, peer(1), endpoint(1), 1_000);

        assert_eq!(
            cache.put(&registry, RELAY, &ticket, victim, endpoint(1), EPOCH, 1_000),
            Err(EndpointCacheError::Ticket(RelayTicketError::TargetMismatch))
        );
        assert!(cache.records(&victim).is_empty());
        assert!(cache.lookup(&victim, 1_000).is_empty());
        assert_eq!(cache.len(), 0);
    }

    /// A cached entry never outlives the ticket that authorized it, even though
    /// the entry TTL is far longer. Otherwise a short-lived claim would keep
    /// steering traffic long after the relay stopped vouching for it.
    #[test]
    fn an_entry_never_outlives_the_ticket_that_authorized_it() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let target = peer(1);
        let now = 1_000;
        let short_lived = RelayTicket::sign(
            &RELAY_KEY,
            RELAY,
            target,
            endpoint(1),
            EPOCH,
            now + 10,
            FORK,
        );

        assert_eq!(
            cache.put(
                &registry,
                RELAY,
                &short_lived,
                target,
                endpoint(1),
                EPOCH,
                now
            ),
            Ok(())
        );
        const {
            assert!(
                ENDPOINT_ENTRY_TTL_SECS > 10,
                "the entry TTL must be the looser of the two bounds for this test to mean anything"
            )
        };
        assert_eq!(cache.records(&target)[0].expires_at, now + 10);
        assert!(cache.lookup(&target, now + 9).len() == 1);
        assert!(cache.lookup(&target, now + 10).is_empty());
    }

    // -----------------------------------------------------------------------
    // PROPERTY 3 — the penalty counter is a real sliding window
    // -----------------------------------------------------------------------

    /// Failures that have aged out of the window contribute nothing. A running
    /// total would blacklist this relay on the sixth failure however long ago
    /// the first five were — a permanent ban earned from stale evidence.
    #[test]
    fn failures_older_than_the_window_do_not_count_toward_the_blacklist() {
        let registry = registry();
        let mut cache = EndpointCache::new();

        for now in 0..MAX_FAILED_CLAIMS_PER_WINDOW as u64 {
            commit_rejected_claim(&mut cache, &registry, RELAY, &RELAY_KEY, now);
        }
        assert_eq!(cache.recent_failure_count(&RELAY, 4), 5);

        // Long after those five have aged out.
        let much_later = 1_000;
        assert_eq!(cache.recent_failure_count(&RELAY, much_later), 0);
        commit_rejected_claim(&mut cache, &registry, RELAY, &RELAY_KEY, much_later);

        assert_eq!(cache.recent_failure_count(&RELAY, much_later), 1);
        assert!(
            !cache.is_blacklisted(&RELAY, much_later),
            "stale failures must not accumulate into a blacklist"
        );
    }

    /// Five rejected claims inside the window are tolerated; the sixth trips
    /// the blacklist. Pins the threshold at ">5 within 60s" in both directions.
    #[test]
    fn the_sixth_failure_inside_the_window_blacklists_the_submitter() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let start = 1_000;

        for i in 0..MAX_FAILED_CLAIMS_PER_WINDOW as u64 {
            commit_rejected_claim(&mut cache, &registry, RELAY, &RELAY_KEY, start + i);
        }
        assert!(
            !cache.is_blacklisted(&RELAY, start + 5),
            "exactly MAX_FAILED_CLAIMS_PER_WINDOW failures must be tolerated"
        );

        commit_rejected_claim(&mut cache, &registry, RELAY, &RELAY_KEY, start + 5);
        assert!(cache.is_blacklisted(&RELAY, start + 5));
    }

    /// **The pacing-evasion test.**
    ///
    /// Five failures land at t=55..59 and a sixth at t=61. A counter bucketed
    /// per fixed minute sees 5 in the first bucket and 1 in the second and
    /// never trips, letting an attacker sustain ten failures a minute forever
    /// by straddling the boundary. A continuously sliding window measures from
    /// the newest failure backwards: all six are within 60s of t=61, so it
    /// trips.
    #[test]
    fn failures_paced_across_a_fixed_bucket_boundary_still_blacklist() {
        let registry = registry();
        let mut cache = EndpointCache::new();

        for now in 55..60 {
            commit_rejected_claim(&mut cache, &registry, RELAY, &RELAY_KEY, now);
        }
        assert!(!cache.is_blacklisted(&RELAY, 60));

        // A per-minute bucket would have reset here.
        commit_rejected_claim(&mut cache, &registry, RELAY, &RELAY_KEY, 61);

        assert_eq!(cache.recent_failure_count(&RELAY, 61), 6);
        assert!(
            cache.is_blacklisted(&RELAY, 61),
            "pacing across a bucket boundary must not evade the window"
        );
    }

    /// A blacklist lifts on schedule and the relay can write again. Guards the
    /// other end of Property 3: the penalty must be a window, not a life
    /// sentence.
    #[test]
    fn a_blacklist_lifts_and_the_relay_can_write_again() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let start = 1_000;

        for i in 0..=MAX_FAILED_CLAIMS_PER_WINDOW as u64 {
            commit_rejected_claim(&mut cache, &registry, RELAY, &RELAY_KEY, start + i);
        }
        let blacklisted_at = start + MAX_FAILED_CLAIMS_PER_WINDOW as u64;
        assert!(cache.is_blacklisted(&RELAY, blacklisted_at));

        // Still barred one second before the deadline.
        let lifts_at = blacklisted_at + RELAY_BLACKLIST_DURATION_SECS;
        assert!(cache.is_blacklisted(&RELAY, lifts_at - 1));
        assert_eq!(
            put_valid(
                &mut cache,
                &registry,
                RELAY,
                &RELAY_KEY,
                peer(1),
                endpoint(1),
                lifts_at - 1
            ),
            Err(EndpointCacheError::RelayBlacklisted)
        );

        assert!(!cache.is_blacklisted(&RELAY, lifts_at));
        assert_eq!(
            put_valid(
                &mut cache,
                &registry,
                RELAY,
                &RELAY_KEY,
                peer(1),
                endpoint(1),
                lifts_at
            ),
            Ok(())
        );
    }

    /// While blacklisted, even a flawless claim is refused — the control blocks
    /// future writes as well as removing past ones.
    #[test]
    fn a_blacklisted_submitter_cannot_write() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let now = 1_000;

        for i in 0..=MAX_FAILED_CLAIMS_PER_WINDOW as u64 {
            commit_rejected_claim(&mut cache, &registry, RELAY, &RELAY_KEY, now + i);
        }
        let after = now + MAX_FAILED_CLAIMS_PER_WINDOW as u64;

        assert_eq!(
            put_valid(
                &mut cache,
                &registry,
                RELAY,
                &RELAY_KEY,
                peer(1),
                endpoint(1),
                after
            ),
            Err(EndpointCacheError::RelayBlacklisted)
        );
        assert!(cache.records(&peer(1)).is_empty());
    }

    // -----------------------------------------------------------------------
    // Attribution — a penalty must never be aimable at someone else
    // -----------------------------------------------------------------------

    /// Replaying a relay's genuine ticket penalises the replayer, not the
    /// signer. Without this, capturing one honest ticket and firing it at the
    /// wrong peer six times would blacklist the honest relay and purge its
    /// bindings — turning the defence into a sharper attack than the one it
    /// closes.
    #[test]
    fn replaying_a_relays_ticket_penalises_the_replayer_not_the_signer() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let now = 1_000;

        // The honest relay has legitimate bindings in place.
        assert_eq!(
            put_valid(
                &mut cache,
                &registry,
                RELAY,
                &RELAY_KEY,
                peer(1),
                endpoint(1),
                now
            ),
            Ok(())
        );

        // The attacker captures one of the honest relay's tickets and replays
        // it under its own identity, repeatedly.
        let captured = signed(&RELAY_KEY, RELAY, peer(1), endpoint(1), now);
        for i in 0..=MAX_FAILED_CLAIMS_PER_WINDOW as u64 {
            assert_eq!(
                cache.put(
                    &registry,
                    OTHER,
                    &captured,
                    peer(1),
                    endpoint(1),
                    EPOCH,
                    now + i
                ),
                Err(EndpointCacheError::SubmitterMismatch)
            );
        }

        let after = now + MAX_FAILED_CLAIMS_PER_WINDOW as u64;
        assert!(
            cache.is_blacklisted(&OTHER, after),
            "the replayer is punished"
        );
        assert!(
            !cache.is_blacklisted(&RELAY, after),
            "the signer must not be blacklisted by someone else's replays"
        );
        assert_eq!(cache.recent_failure_count(&RELAY, after), 0);
        assert_eq!(
            cache.lookup(&peer(1), after),
            alloc::vec![endpoint(1)],
            "the signer's own bindings must survive"
        );
    }

    // -----------------------------------------------------------------------
    // PROPERTY 4 — blacklisting deletes existing damage
    // -----------------------------------------------------------------------

    /// Blacklisting removes every entry the offender wrote, verified by reading
    /// the cache back — not by inspecting a flag. A soft "blocked" marker that
    /// left the rows in place would keep serving poisoned endpoints for the
    /// whole of their TTL. Entries another relay wrote for the *same* peers
    /// must survive, so eviction is proven to be by attribution rather than a
    /// blunt purge of the affected keys.
    #[test]
    fn blacklisting_deletes_the_entries_the_offender_already_wrote() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let now = 1_000;

        for n in 1..=3u16 {
            assert_eq!(
                put_valid(
                    &mut cache,
                    &registry,
                    RELAY,
                    &RELAY_KEY,
                    peer(n),
                    endpoint(n),
                    now
                ),
                Ok(())
            );
        }
        // An innocent relay's entry, sharing peer(1) as its cache key.
        assert_eq!(
            put_valid(
                &mut cache,
                &registry,
                OTHER,
                &OTHER_KEY,
                peer(1),
                endpoint(9),
                now
            ),
            Ok(())
        );
        assert_eq!(cache.len(), 4);

        for i in 0..=MAX_FAILED_CLAIMS_PER_WINDOW as u64 {
            commit_rejected_claim(&mut cache, &registry, RELAY, &RELAY_KEY, now + i);
        }
        let after = now + MAX_FAILED_CLAIMS_PER_WINDOW as u64;
        assert!(cache.is_blacklisted(&RELAY, after));

        // Read the cache back: the offender's rows are gone, not flagged.
        for n in 1..=3u16 {
            assert!(
                !cache
                    .records(&peer(n))
                    .iter()
                    .any(|record| record.relay_id == RELAY),
                "peer({n}) still holds a record attributed to the blacklisted relay"
            );
            assert!(!cache.lookup(&peer(n), after).contains(&endpoint(n)));
        }
        assert!(cache.records(&peer(2)).is_empty());
        assert!(cache.records(&peer(3)).is_empty());

        // The innocent relay's entry is untouched.
        assert_eq!(cache.lookup(&peer(1), after), alloc::vec![endpoint(9)]);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.metrics().evicted_on_blacklist, 3);
    }

    // -----------------------------------------------------------------------
    // PROPERTY 5 — capacity limits hold independently of the poisoning logic
    // -----------------------------------------------------------------------

    /// The total cap refuses further writes that are otherwise perfectly
    /// authorized, so a flood of valid claims cannot exhaust the cache as a
    /// separate denial-of-service vector.
    #[test]
    fn the_total_entry_cap_rejects_further_correctly_ticketed_writes() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let now = 1_000;

        let peers = ENDPOINT_CACHE_MAX_ENTRIES / ENDPOINT_CACHE_MAX_PER_PEER;
        for p in 0..peers as u16 {
            for e in 0..ENDPOINT_CACHE_MAX_PER_PEER as u16 {
                assert_eq!(
                    put_valid(
                        &mut cache,
                        &registry,
                        RELAY,
                        &RELAY_KEY,
                        peer(p),
                        endpoint(e),
                        now
                    ),
                    Ok(())
                );
            }
        }
        assert_eq!(cache.len(), ENDPOINT_CACHE_MAX_ENTRIES);

        // A fresh peer, a fresh endpoint, a flawless ticket.
        assert_eq!(
            put_valid(
                &mut cache,
                &registry,
                RELAY,
                &RELAY_KEY,
                peer(9_000),
                endpoint(1),
                now
            ),
            Err(EndpointCacheError::TotalCapacityExceeded)
        );
        assert_eq!(cache.len(), ENDPOINT_CACHE_MAX_ENTRIES);
        assert!(cache.records(&peer(9_000)).is_empty());
    }

    /// The per-peer cap refuses a seventeenth endpoint for one peer, again on
    /// fully valid traffic, so no single peer can monopolise the cache.
    #[test]
    fn the_per_peer_cap_rejects_the_seventeenth_endpoint() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let now = 1_000;
        let target = peer(1);

        for e in 0..ENDPOINT_CACHE_MAX_PER_PEER as u16 {
            assert_eq!(
                put_valid(
                    &mut cache,
                    &registry,
                    RELAY,
                    &RELAY_KEY,
                    target,
                    endpoint(e),
                    now
                ),
                Ok(())
            );
        }
        assert_eq!(cache.records(&target).len(), ENDPOINT_CACHE_MAX_PER_PEER);

        assert_eq!(
            put_valid(
                &mut cache,
                &registry,
                RELAY,
                &RELAY_KEY,
                target,
                endpoint(ENDPOINT_CACHE_MAX_PER_PEER as u16),
                now
            ),
            Err(EndpointCacheError::PeerCapacityExceeded)
        );
        assert_eq!(cache.records(&target).len(), ENDPOINT_CACHE_MAX_PER_PEER);
    }

    /// Hitting a capacity limit is resource pressure, not an incorrect claim.
    /// A relay that runs into a cap far more often than the blacklist threshold
    /// must still not be penalised — otherwise a busy honest relay gets
    /// blacklisted and its bindings purged, and the two controls are not
    /// actually independent.
    #[test]
    fn hitting_a_capacity_limit_never_penalises_the_submitter() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let now = 1_000;
        let target = peer(1);

        for e in 0..ENDPOINT_CACHE_MAX_PER_PEER as u16 {
            put_valid(
                &mut cache,
                &registry,
                RELAY,
                &RELAY_KEY,
                target,
                endpoint(e),
                now,
            )
            .unwrap();
        }

        let attempts = (MAX_FAILED_CLAIMS_PER_WINDOW as u64 + 1) * 2;
        for i in 0..attempts {
            let overflow = ENDPOINT_CACHE_MAX_PER_PEER as u16 + i as u16;
            assert_eq!(
                put_valid(
                    &mut cache,
                    &registry,
                    RELAY,
                    &RELAY_KEY,
                    target,
                    endpoint(overflow),
                    now
                ),
                Err(EndpointCacheError::PeerCapacityExceeded)
            );
        }

        assert_eq!(cache.recent_failure_count(&RELAY, now), 0);
        assert!(!cache.is_blacklisted(&RELAY, now));
        assert_eq!(cache.metrics().rejected_claims, 0);
        assert_eq!(cache.metrics().capacity_rejections, attempts);
    }

    /// Refreshing an endpoint already cached for a peer is not a new entry, so
    /// the caps must not block it. Otherwise a peer sitting at sixteen
    /// endpoints could never renew any of them and would fall out of the cache
    /// entirely once its TTLs elapsed.
    #[test]
    fn refreshing_an_existing_endpoint_is_not_capacity_rejected() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let now = 1_000;
        let target = peer(1);

        for e in 0..ENDPOINT_CACHE_MAX_PER_PEER as u16 {
            put_valid(
                &mut cache,
                &registry,
                RELAY,
                &RELAY_KEY,
                target,
                endpoint(e),
                now,
            )
            .unwrap();
        }

        let later = now + 30;
        assert_eq!(
            put_valid(
                &mut cache,
                &registry,
                RELAY,
                &RELAY_KEY,
                target,
                endpoint(0),
                later
            ),
            Ok(())
        );
        assert_eq!(cache.records(&target).len(), ENDPOINT_CACHE_MAX_PER_PEER);
        assert_eq!(cache.records(&target)[0].written_at, later);
        assert_eq!(cache.metrics().refreshes, 1);
    }

    // -----------------------------------------------------------------------
    // Bookkeeping
    // -----------------------------------------------------------------------

    /// The running entry total is maintained incrementally on insert, eviction,
    /// and expiry. If any of those paths miscounted, the total cap would start
    /// rejecting valid writes early or stop rejecting them at all — a silent
    /// failure of Property 5 that no capacity test would catch. This pins the
    /// counter to the actual bucket contents after each kind of removal.
    #[test]
    fn the_entry_total_tracks_the_buckets_through_eviction_and_expiry() {
        let registry = registry();
        let mut cache = EndpointCache::new();
        let now = 1_000;

        for n in 0..5u16 {
            put_valid(
                &mut cache,
                &registry,
                RELAY,
                &RELAY_KEY,
                peer(n),
                endpoint(n),
                now,
            )
            .unwrap();
            put_valid(
                &mut cache,
                &registry,
                OTHER,
                &OTHER_KEY,
                peer(n),
                endpoint(n + 50),
                now,
            )
            .unwrap();
        }
        assert_eq!(cache.len(), cache.recomputed_len());
        assert_eq!(cache.len(), 10);

        assert_eq!(cache.evict_relay(&RELAY), 5);
        assert_eq!(cache.len(), cache.recomputed_len());
        assert_eq!(cache.len(), 5);

        assert_eq!(cache.expire(now + TICKET_LIFETIME), 5);
        assert_eq!(cache.len(), cache.recomputed_len());
        assert!(cache.is_empty());
        assert_eq!(cache.peer_count(), 0, "emptied buckets must be dropped");
    }
}
