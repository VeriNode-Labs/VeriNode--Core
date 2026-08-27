//! Integration tests for STUN/TURN endpoint cache poisoning defence (issue #140).
//!
//! Unit-level coverage of each component lives beside it in `src`; this file
//! holds the properties that need arbitrary inputs (`proptest`) and the
//! end-to-end tests that exercise the STUN binding path through the registry
//! and into the cache.

use proptest::prelude::*;
use sorosusu_contracts::attestation::relay_ticket::{
    RelayTicket, RelayTicketError, RELAY_TICKET_ENCODED_LEN,
};

// ---------------------------------------------------------------------------
// Ticket decoding: no input may panic the relay ingress path
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// `RelayTicket::decode` runs on bytes straight off the wire, before any
    /// authentication. It must terminate with `Ok` or `Err` for *every* input —
    /// a slice index escaping its length check here would be a remotely
    /// triggerable panic. Inputs are drawn across and around the exact encoded
    /// length so truncation, over-length, and correct-length-but-garbage
    /// framings are all covered.
    #[test]
    fn prop_decode_never_panics_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..=(RELAY_TICKET_ENCODED_LEN * 2)),
    ) {
        match RelayTicket::decode(&bytes) {
            // A decode can only succeed at exactly the encoded length.
            Ok(ticket) => {
                prop_assert_eq!(bytes.len(), RELAY_TICKET_ENCODED_LEN);
                // Round-tripping a successfully decoded ticket must reproduce
                // the input, which is what makes the encoding canonical: no two
                // byte strings decode to the same ticket.
                let reencoded = ticket.encode();
                prop_assert_eq!(reencoded.as_slice(), bytes.as_slice());
            }
            Err(err) => prop_assert_eq!(err, RelayTicketError::Malformed),
        }
    }
}

use sorosusu_contracts::attestation::relay_ticket::{PeerId, RelayId, SocketEndpoint};
use sorosusu_contracts::attestation::types::EpochId;
use sorosusu_contracts::attestation::verifier::SecretKey;
use sorosusu_contracts::crypto::domain::GENESIS_FORK_VERSION as FORK;
use sorosusu_contracts::crypto::sha256::sha256;
use sorosusu_contracts::network::relay::endpoint_cache::{
    EndpointCache, EndpointCacheError, EndpointRecord, ENDPOINT_CACHE_MAX_ENTRIES,
};
use sorosusu_contracts::network::relay::relay_registry::RelayRegistry;
use sorosusu_contracts::network::relay::stun_bind::{
    apply_binding_response, StunBindingError, StunBindingRequest, StunBindingResponse, StunRelay,
    TransactionId,
};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Deterministic input stream
// ---------------------------------------------------------------------------

/// A reproducible byte stream built from the crate's own SHA-256 in counter
/// mode.
///
/// The repo's existing high-volume test
/// (`proof_of_connectivity_epoch_nonce_test::test_no_nonce_collision_across_10k_challenges`)
/// uses a plain deterministic loop rather than `proptest`, for the same reasons
/// this does: the issue calls for an exact number of attempts, and a failure
/// must be reproducible from the seed alone, with no shrinking in between.
struct Stream {
    counter: u64,
}

impl Stream {
    fn new(seed: u64) -> Self {
        Self { counter: seed }
    }

    fn next_bytes(&mut self) -> [u8; 32] {
        self.counter = self.counter.wrapping_add(1);
        sha256(&self.counter.to_le_bytes())
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(self.next_bytes()[..8].try_into().unwrap())
    }

    /// A value in `0..n`.
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const EPOCH: EpochId = 100;
/// Where a run starts, in simulated unix seconds.
const START: u64 = 1_000_000;

/// Honest relays whose bindings must survive a run untouched.
const HONEST_RELAYS: usize = 4;
/// The peers honest relays report on — and the only peers any attempt targets,
/// so the post-run comparison covers every key that could have been written.
const HONEST_PEERS: usize = 5;
/// Distinct attacker identities. Rotating through a pool keeps the verification
/// path exercised instead of every attempt bouncing off one blacklist.
const ATTACKER_IDENTITIES: usize = 100;

fn peer(n: u16) -> PeerId {
    let mut id = [0u8; 32];
    id[0] = 0xE0;
    id[1..3].copy_from_slice(&n.to_le_bytes());
    id
}

fn relay_id(tag: u8, n: u16) -> RelayId {
    let mut id = [0u8; 32];
    id[0] = tag;
    id[1..3].copy_from_slice(&n.to_le_bytes());
    id
}

fn key_for(id: &RelayId) -> SecretKey {
    sha256(id)
}

fn honest_relay(n: u16) -> RelayId {
    relay_id(0xAA, n)
}

fn attacker_relay(n: u16) -> RelayId {
    relay_id(0xCC, n)
}

/// An identity deliberately absent from the registry.
fn stranger_relay(n: u16) -> RelayId {
    relay_id(0xDD, n)
}

fn honest_endpoint(relay: u16, target: u16) -> SocketEndpoint {
    SocketEndpoint::v4([203, 0, 113, relay as u8], 30_000 + target)
}

fn attacker_endpoint(n: u16) -> SocketEndpoint {
    SocketEndpoint::v4([198, 51, 100, 66], 9_000 + n)
}

fn txn(n: u64) -> TransactionId {
    let bytes = sha256(&n.to_le_bytes());
    let mut id = [0u8; 12];
    id.copy_from_slice(&bytes[..12]);
    id
}

/// The registry for the fuzz run.
///
/// It holds the honest relays **and every attacker identity**. That is the
/// threat this issue is actually about: not an outsider shouting into the
/// protocol, but a relay that enrolled legitimately and then makes claims about
/// peers it has no business speaking for. Leaving attackers unregistered would
/// let `UnknownRelay` absorb almost every attempt before it reached the check
/// it was built to probe, and the run would prove far less than it appeared to.
/// Only the [`Forgery::UnregisteredRelay`] class uses an identity outside it.
fn fuzz_registry() -> RelayRegistry {
    let mut registry = RelayRegistry::new(FORK);
    for n in 0..HONEST_RELAYS as u16 {
        let id = honest_relay(n);
        registry.register(id, key_for(&id));
    }
    for n in 0..ATTACKER_IDENTITIES as u16 {
        let id = attacker_relay(n);
        registry.register(id, key_for(&id));
    }
    registry
}

/// Seed the cache with legitimate bindings from every honest relay.
fn seed_honest_bindings(cache: &mut EndpointCache, registry: &RelayRegistry, now: u64) {
    for r in 0..HONEST_RELAYS as u16 {
        let id = honest_relay(r);
        let relay = StunRelay::new(id, key_for(&id), FORK);
        for p in 0..HONEST_PEERS as u16 {
            let request =
                StunBindingRequest::new(txn((u64::from(r) << 32) | u64::from(p)), peer(p));
            let response =
                relay.handle_binding_request(&request, honest_endpoint(r, p), EPOCH, now);
            apply_binding_response(cache, registry, &request, &response, id, EPOCH, now)
                .expect("seeding must use only legitimate bindings");
        }
    }
}

/// Every record the cache holds for the peers a run can reach, keyed by peer.
fn snapshot(cache: &EndpointCache) -> BTreeMap<PeerId, Vec<EndpointRecord>> {
    (0..HONEST_PEERS as u16)
        .map(|p| (peer(p), cache.records(&peer(p)).to_vec()))
        .collect()
}

// ---------------------------------------------------------------------------
// The 1 000-attempt fuzz run
// ---------------------------------------------------------------------------

/// The nine ways an attacker can malform a binding update.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Forgery {
    /// A registered relay's ticket, signed with a key it does not hold.
    WrongSignature,
    /// A ticket the attacker validly signed for its own peer, aimed at a
    /// victim's cache key. **The cache-poisoning attempt proper.**
    WrongTarget,
    /// A correctly-signed ticket whose expiry has passed.
    Expired,
    /// A correctly-signed ticket from outside the epoch window.
    StaleEpoch,
    /// A correctly-signed ticket minted for an epoch that has not started.
    FutureEpoch,
    /// A genuine ticket with the reflexive address swapped in transit.
    SwappedEndpoint,
    /// An honest relay's genuine ticket, replayed by someone else.
    ReplayedTicket,
    /// A perfectly-formed ticket from a relay nobody registered.
    UnregisteredRelay,
    /// Garbage on the wire, refused before it becomes a ticket at all.
    MalformedBytes,
}

const ALL_FORGERIES: [Forgery; 9] = [
    Forgery::WrongSignature,
    Forgery::WrongTarget,
    Forgery::Expired,
    Forgery::StaleEpoch,
    Forgery::FutureEpoch,
    Forgery::SwappedEndpoint,
    Forgery::ReplayedTicket,
    Forgery::UnregisteredRelay,
    Forgery::MalformedBytes,
];

/// The single rejection each class must produce.
///
/// Asserting the *specific* error, not merely that something failed, is what
/// makes the run meaningful: it proves each attempt was stopped by the control
/// aimed at it. A run that only checked for `Err` would still pass with the
/// target-binding check deleted, because some other check would happen to catch
/// most attempts — which is exactly the bug this suite exists to detect.
fn expected_rejection(forgery: Forgery) -> StunBindingError {
    use RelayTicketError as T;
    let ticket = |err| StunBindingError::Cache(EndpointCacheError::Ticket(err));
    match forgery {
        Forgery::WrongSignature => ticket(T::InvalidSignature),
        Forgery::WrongTarget => ticket(T::TargetMismatch),
        Forgery::Expired => ticket(T::Expired),
        Forgery::StaleEpoch => ticket(T::EpochStale),
        Forgery::FutureEpoch => ticket(T::EpochFuture),
        Forgery::SwappedEndpoint => ticket(T::EndpointMismatch),
        Forgery::ReplayedTicket => StunBindingError::Cache(EndpointCacheError::SubmitterMismatch),
        Forgery::UnregisteredRelay => ticket(T::UnknownRelay),
        // Never reaches the cache; asserted at the call site.
        Forgery::MalformedBytes => ticket(T::Malformed),
    }
}

/// Build one malicious binding update, returning it with the identity it is
/// submitted under.
///
/// `None` is the malformed-bytes class, where the payload never survives
/// decoding and so never becomes a response at all.
fn forge(
    stream: &mut Stream,
    forgery: Forgery,
    submitter: RelayId,
    victim: PeerId,
    request: &StunBindingRequest,
    now: u64,
) -> Option<(StunBindingResponse, RelayId)> {
    let mine = StunRelay::new(submitter, key_for(&submitter), FORK);

    let forged = match forgery {
        Forgery::WrongSignature => {
            // Labelled as the submitter, so the registry resolves the
            // submitter's key — which is not the key that signed this.
            let wrong_key = sha256(&stream.next_bytes());
            let liar = StunRelay::new(submitter, wrong_key, FORK);
            (
                liar.handle_binding_request(request, attacker_endpoint(0), EPOCH, now),
                submitter,
            )
        }
        Forgery::WrongTarget => {
            // Genuinely signed by a registered relay, for a peer it may speak
            // for, then pointed at the victim's cache key instead. Nothing here
            // is forged; only the binding is wrong.
            let own = StunBindingRequest::new(request.transaction_id, peer(9_000));
            let mut response = mine.handle_binding_request(&own, attacker_endpoint(1), EPOCH, now);
            response.target_id = victim;
            (response, submitter)
        }
        Forgery::Expired => {
            let lapsed =
                StunRelay::new(submitter, key_for(&submitter), FORK).with_ticket_lifetime(1);
            (
                lapsed.handle_binding_request(request, attacker_endpoint(2), EPOCH, now - 60),
                submitter,
            )
        }
        Forgery::StaleEpoch => (
            mine.handle_binding_request(
                request,
                attacker_endpoint(3),
                EPOCH - 2 - (stream.below(5) as EpochId),
                now,
            ),
            submitter,
        ),
        Forgery::FutureEpoch => (
            mine.handle_binding_request(
                request,
                attacker_endpoint(4),
                EPOCH + 1 + (stream.below(5) as EpochId),
                now,
            ),
            submitter,
        ),
        Forgery::SwappedEndpoint => {
            let mut response =
                mine.handle_binding_request(request, attacker_endpoint(5), EPOCH, now);
            // Keep the genuine ticket, redirect the payload.
            response.reflexive = attacker_endpoint(6 + stream.below(16) as u16);
            (response, submitter)
        }
        Forgery::ReplayedTicket => {
            // Captured from an honest relay and replayed under the attacker's
            // own identity. Must penalise the replayer, never the signer.
            let signer = honest_relay(stream.below(HONEST_RELAYS) as u16);
            let honest = StunRelay::new(signer, key_for(&signer), FORK);
            (
                honest.handle_binding_request(request, attacker_endpoint(7), EPOCH, now),
                submitter,
            )
        }
        Forgery::UnregisteredRelay => {
            let stranger = stranger_relay(stream.below(256) as u16);
            let outsider = StunRelay::new(stranger, key_for(&stranger), FORK);
            (
                outsider.handle_binding_request(request, attacker_endpoint(8), EPOCH, now),
                stranger,
            )
        }
        Forgery::MalformedBytes => return None,
    };
    Some(forged)
}

/// **Zero successful cache poisonings across 1 000 malicious binding updates.**
///
/// The run seeds the cache with legitimate bindings from four honest relays,
/// snapshots it, fires 1 000 forged updates spanning nine attack classes, then
/// compares the cache against that snapshot record by record. Checking only
/// that each call returned `Err` would miss a write that landed before the
/// rejection, or a rejection that disturbed a neighbouring entry, so the
/// verdict is the cache's own contents.
///
/// Two things keep the run honest:
///
/// * **Attackers are registered relays.** The threat is an enrolled relay
///   making claims it has no right to, not an outsider. Unregistered attackers
///   would be turned away at the registry before reaching the check under test.
/// * **Each class must produce its own specific rejection**, not just any
///   error, and must do so on its merits rather than because its submitter was
///   already blacklisted.
#[test]
fn fuzz_1000_malicious_binding_updates_poison_nothing() {
    const ATTEMPTS: usize = 1_000;

    let registry = fuzz_registry();
    let mut cache = EndpointCache::new();
    seed_honest_bindings(&mut cache, &registry, START);

    let before = snapshot(&cache);
    let entries_before = cache.len();
    let peers_before = cache.peer_count();
    assert_eq!(entries_before, HONEST_RELAYS * HONEST_PEERS);

    let mut stream = Stream::new(0x140);
    let mut poisonings = 0usize;
    // Rejections produced by the control aimed at the class, rather than by the
    // submitter already being barred.
    let mut refused_on_merit: BTreeMap<Forgery, usize> = BTreeMap::new();
    let mut refused_as_blacklisted = 0usize;

    for attempt in 0..ATTEMPTS {
        let forgery = ALL_FORGERIES[attempt % ALL_FORGERIES.len()];
        let submitter = attacker_relay(stream.below(ATTACKER_IDENTITIES) as u16);
        let victim = peer(stream.below(HONEST_PEERS) as u16);
        // Stay inside the honest bindings' lifetime, so anything missing at the
        // end went missing because of an attack, not because it timed out.
        let now = START + 1 + (attempt as u64 % 200);
        let request = StunBindingRequest::new(txn(attempt as u64), victim);

        let Some((response, submitted_by)) =
            forge(&mut stream, forgery, submitter, victim, &request, now)
        else {
            // Garbage on the wire: refused at decode, never reaching the cache.
            // Modelled exactly as ingress does it.
            let mut garbage = stream.next_bytes().to_vec();
            garbage.extend_from_slice(&stream.next_bytes());
            garbage.extend_from_slice(&stream.next_bytes());
            garbage.truncate(RELAY_TICKET_ENCODED_LEN);
            assert_eq!(
                RelayTicket::decode(&garbage),
                Err(RelayTicketError::Malformed),
                "attempt {attempt}: malformed wire bytes must not decode"
            );
            *refused_on_merit.entry(forgery).or_default() += 1;
            continue;
        };

        let outcome = apply_binding_response(
            &mut cache,
            &registry,
            &request,
            &response,
            submitted_by,
            EPOCH,
            now,
        );

        match outcome {
            Ok(()) => poisonings += 1,
            Err(StunBindingError::Cache(EndpointCacheError::RelayBlacklisted)) => {
                refused_as_blacklisted += 1;
            }
            Err(err) => {
                assert_eq!(
                    err,
                    expected_rejection(forgery),
                    "attempt {attempt} ({forgery:?}) was refused by the wrong control"
                );
                *refused_on_merit.entry(forgery).or_default() += 1;
            }
        }
    }

    assert_eq!(
        poisonings, 0,
        "{poisonings} of {ATTEMPTS} malicious updates were accepted"
    );

    // The verdict: the cache itself, read back.
    let after = snapshot(&cache);
    assert_eq!(
        before, after,
        "the cache contents changed during the malicious run"
    );
    assert_eq!(cache.len(), entries_before, "entry count changed");
    assert_eq!(
        cache.peer_count(),
        peers_before,
        "a peer key was created or destroyed"
    );

    // No honest relay was implicated by anything an attacker did.
    let end = START + 201;
    for r in 0..HONEST_RELAYS as u16 {
        let id = honest_relay(r);
        assert!(
            !cache.is_blacklisted(&id, end),
            "honest relay {r} was blacklisted by an attacker's traffic"
        );
        assert_eq!(
            cache.recent_failure_count(&id, end),
            0,
            "honest relay {r} accrued a penalty it did not earn"
        );
    }

    // Every class was genuinely exercised by its own control.
    for forgery in ALL_FORGERIES {
        let count = refused_on_merit.get(&forgery).copied().unwrap_or(0);
        assert!(
            count > 0,
            "{forgery:?} was never refused on its own merits — the run degenerated"
        );
    }

    assert_eq!(
        cache.metrics().writes as usize,
        entries_before,
        "no write beyond the honest seeding was accepted"
    );
    assert_eq!(cache.metrics().refreshes, 0);
    assert!(
        cache.metrics().blacklists > 0,
        "sustained forgery should have blacklisted attacker identities"
    );

    let on_merit: usize = refused_on_merit.values().sum();
    println!(
        "1000 attempts: 0 poisonings; {on_merit} refused by the control aimed at them, \
         {refused_as_blacklisted} refused as already-blacklisted; \
         {} attacker identities blacklisted; per class: {refused_on_merit:?}",
        cache.metrics().blacklists,
    );
}

// ---------------------------------------------------------------------------
// The companion: legitimate traffic must not be caught in the net
// ---------------------------------------------------------------------------

/// **A stream of valid traffic from many honest relays draws no rejection and
/// no blacklist.**
///
/// A defence that refuses forgeries by refusing everything is not a fix. Eight
/// relays report on fifty shared peers across five rounds — 2 000 correctly
/// ticketed updates — with the clock and the epoch advancing between rounds,
/// and the run must be spotless: every update accepted, no penalty recorded, no
/// blacklist, every binding still served at the end.
///
/// Two details make this a real false-positive probe rather than a happy path:
///
/// * **Half of each round arrives an epoch late.** A response minted in epoch
///   `n` and applied in epoch `n+1` is ordinary in a live network — a binding
///   in flight across an epoch tick. It is also exactly what an
///   over-tightened epoch window would start rejecting, so it is exercised
///   directly rather than assumed.
/// * **Relays share peers.** Several relays observing the same peer is the
///   normal shape, and it puts eight entries on each peer key, proving the
///   per-peer cap is not tripped by ordinary multi-relay traffic.
#[test]
fn legitimate_traffic_from_many_relays_is_never_rejected_or_blacklisted() {
    const RELAYS: u16 = 8;
    const PEERS: u16 = 50;
    const ROUNDS: u64 = 5;

    let mut registry = RelayRegistry::new(FORK);
    let relays: Vec<StunRelay> = (0..RELAYS)
        .map(|n| {
            let id = relay_id(0xB0, n);
            registry.register(id, key_for(&id));
            StunRelay::new(id, key_for(&id), FORK)
        })
        .collect();

    let mut cache = EndpointCache::new();
    let mut accepted = 0usize;
    let mut late_arrivals = 0usize;

    for round in 0..ROUNDS {
        let now = START + round * 60;
        let epoch = EPOCH + round as EpochId;

        for (r, relay) in relays.iter().enumerate() {
            // Half the relays' responses were minted in the previous epoch and
            // are only now being applied.
            let late = r % 2 == 1 && round > 0;
            let minted_in = if late { epoch - 1 } else { epoch };

            for p in 0..PEERS {
                let request = StunBindingRequest::new(
                    txn((round << 40) | ((r as u64) << 20) | u64::from(p)),
                    peer(p),
                );
                let response = relay.handle_binding_request(
                    &request,
                    honest_endpoint(r as u16, p),
                    minted_in,
                    now,
                );
                assert_eq!(
                    apply_binding_response(
                        &mut cache,
                        &registry,
                        &request,
                        &response,
                        relay.relay_id(),
                        epoch,
                        now,
                    ),
                    Ok(()),
                    "round {round}, relay {r}, peer {p} (late={late}): \
                     a legitimate update was rejected"
                );
                accepted += 1;
                if late {
                    late_arrivals += 1;
                }
            }
        }
    }

    let end = START + (ROUNDS - 1) * 60;
    let expected_entries = (RELAYS as usize) * (PEERS as usize);
    assert_eq!(accepted, (ROUNDS as usize) * expected_entries);
    assert!(
        late_arrivals > 0,
        "the epoch-lag path must actually be exercised"
    );

    // Zero false positives, stated every way it can be observed.
    let metrics = cache.metrics();
    assert_eq!(
        metrics.rejected_claims, 0,
        "a legitimate update was penalised"
    );
    assert_eq!(metrics.capacity_rejections, 0);
    assert_eq!(metrics.blacklists, 0, "an honest relay was blacklisted");
    assert_eq!(metrics.evicted_on_blacklist, 0);
    for relay in &relays {
        let id = relay.relay_id();
        assert!(!cache.is_blacklisted(&id, end));
        assert_eq!(cache.recent_failure_count(&id, end), 0);
    }

    // The first round wrote the entries; the rest refreshed them in place.
    assert_eq!(metrics.writes as usize, expected_entries);
    assert_eq!(
        metrics.refreshes as usize,
        accepted - expected_entries,
        "repeat reports must refresh rather than accumulate"
    );

    // And every binding is still being served.
    assert_eq!(cache.len(), expected_entries);
    for p in 0..PEERS {
        assert_eq!(
            cache.lookup(&peer(p), end).len(),
            RELAYS as usize,
            "peer {p} should be reachable via all {RELAYS} relays"
        );
    }

    println!(
        "{accepted} legitimate updates from {RELAYS} relays across {ROUNDS} rounds \
         ({late_arrivals} arriving an epoch late): 0 rejected, 0 blacklisted, \
         {} bindings served",
        cache.len()
    );
}

// ---------------------------------------------------------------------------
// A residual risk, pinned as executable fact
// ---------------------------------------------------------------------------

/// **One registered relay can fill the entire cache with valid tickets.**
///
/// This is not a failure of the fix — every write here is correctly ticketed
/// and correctly authorized, and the total cap does bound the damage at
/// `ENDPOINT_CACHE_MAX_ENTRIES` rather than letting it run away. It is a
/// residual property of the trust model: a relay that enrolls legitimately may
/// mint a valid ticket for *any* target id, and 10 000 distinct targets means
/// the per-peer cap of 16 never engages. The consequence is that one relay can
/// crowd every other relay out of the cache until entries age out.
///
/// It is asserted here so the behaviour is known and deliberate rather than
/// discovered later, and so a future change that alters it — a per-relay quota,
/// say — fails this test loudly instead of shifting the boundary in silence.
/// See the maintainer notes accompanying issue #140.
#[test]
fn one_registered_relay_can_fill_the_whole_cache_with_valid_tickets() {
    let hog = relay_id(0xF0, 0);
    let bystander = relay_id(0xF1, 0);
    let mut registry = RelayRegistry::new(FORK);
    registry.register(hog, key_for(&hog));
    registry.register(bystander, key_for(&bystander));

    let hog_relay = StunRelay::new(hog, key_for(&hog), FORK);
    let mut cache = EndpointCache::new();

    // 10 000 distinct targets, one endpoint each, every ticket impeccable.
    for n in 0..ENDPOINT_CACHE_MAX_ENTRIES as u32 {
        let mut target = [0u8; 32];
        target[..4].copy_from_slice(&n.to_le_bytes());
        let request = StunBindingRequest::new(txn(u64::from(n)), target);
        let response = hog_relay.handle_binding_request(
            &request,
            SocketEndpoint::v4([198, 51, 100, 1], 1024 + (n % 1024) as u16),
            EPOCH,
            START,
        );
        assert_eq!(
            apply_binding_response(&mut cache, &registry, &request, &response, hog, EPOCH, START),
            Ok(()),
            "target {n}: a correctly-ticketed write must be accepted"
        );
    }

    assert_eq!(cache.len(), ENDPOINT_CACHE_MAX_ENTRIES);
    assert_eq!(cache.peer_count(), ENDPOINT_CACHE_MAX_ENTRIES);

    // The per-peer cap never engaged: every target holds exactly one entry.
    let mut sole = [0u8; 32];
    sole[..4].copy_from_slice(&7u32.to_le_bytes());
    assert_eq!(cache.records(&sole).len(), 1);

    // The damage is bounded, not unbounded — but a well-behaved relay is now
    // locked out until entries age out.
    let request = StunBindingRequest::new(txn(u64::MAX), peer(0));
    let response = StunRelay::new(bystander, key_for(&bystander), FORK).handle_binding_request(
        &request,
        honest_endpoint(0, 0),
        EPOCH,
        START,
    );
    assert_eq!(
        apply_binding_response(&mut cache, &registry, &request, &response, bystander, EPOCH, START),
        Err(StunBindingError::Cache(
            EndpointCacheError::TotalCapacityExceeded
        )),
        "the total cap must hold even against an honest relay"
    );

    // And the flood earned no penalty, because none of it was an incorrect
    // claim — which is precisely why a quota, not the penalty counter, would be
    // the tool for this if it were in scope.
    assert_eq!(cache.recent_failure_count(&hog, START), 0);
    assert!(!cache.is_blacklisted(&hog, START));
    assert_eq!(cache.metrics().rejected_claims, 0);
    assert_eq!(cache.metrics().capacity_rejections, 1);
}
