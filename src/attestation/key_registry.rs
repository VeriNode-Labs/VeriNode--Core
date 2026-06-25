//! Validator key registry and rotation-safe verification cache (#5).
//!
//! ## The bug
//!
//! `verify_attestation()` cached each validator's public key keyed only by
//! validator id, refreshed on a timer. `rotate_key()` cleared the cache entry
//! and updated the on-chain registry, but the on-chain write is not visible for
//! 3–5s (Soroban finality). A verify landing in that window missed the cache,
//! reloaded the *old* key from the registry, re-cached it, and rejected every
//! attestation now signed with the new key — a multi-second outage per
//! rotation.
//!
//! ## The fix
//!
//! Three reinforcing measures from the resolution blueprint:
//!
//! 1. **Two-phase rotation (step 1):** a rotation keeps the old key valid as a
//!    `previous_key` for a bounded window of ledgers, so attestations still
//!    in flight under the old key continue to verify.
//! 2. **Key-generation counter + versioned cache (steps 2 & 4):** each
//!    validator carries a `key_gen` bumped on every rotation. The cache stores
//!    the generation it was populated at; a verify whose registry generation is
//!    newer than the cached one forces a reload, so a stale entry is never
//!    reused after a rotation.
//! 3. **Multi-key cache (step 3):** the reloaded entry holds *both* the new and
//!    (within the window) the old key; verification accepts if any cached key
//!    matches. The previous key is dropped once the window elapses.
//!
//! Together these guarantee `verify(attestation, keys) == true` for every
//! attestation signed after a rotation — both late old-key attestations (within
//! the window) and new-key attestations.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::attestation::verifier::{verify_attestation_signature, AttestationData, SecretKey, Signature};
use crate::crypto::domain::Domain;

/// Validator identifier.
pub type ValidatorId = u32;

/// A validator verification key. (In this crate's signing model the key type is
/// the same 32-byte value used by [`verify_attestation_signature`].)
pub type VerifyKey = SecretKey;

/// Number of ledgers the previous key stays valid after a rotation (~10 per the
/// blueprint, covering the on-chain finality gap with margin).
pub const ROTATION_WINDOW_LEDGERS: u64 = 10;

/// An immutable snapshot of a validator's key state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeySnapshot {
    pub key_gen: u64,
    pub active_key: VerifyKey,
    pub previous_key: Option<VerifyKey>,
    pub rotated_at_ledger: u64,
}

/// On-chain validator key registry.
#[derive(Clone, Debug, Default)]
pub struct KeyRegistry {
    records: BTreeMap<ValidatorId, KeySnapshot>,
}

impl KeyRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    /// Register a validator's initial key at generation 0.
    pub fn register(&mut self, validator: ValidatorId, key: VerifyKey) {
        self.records.insert(
            validator,
            KeySnapshot {
                key_gen: 0,
                active_key: key,
                previous_key: None,
                rotated_at_ledger: 0,
            },
        );
    }

    /// Rotate a validator's key: bump `key_gen`, promote `new_key` to active,
    /// and retain the prior key as `previous_key` (valid during the rotation
    /// window). Returns the new generation, or `None` if the validator is
    /// unknown.
    pub fn rotate_key(
        &mut self,
        validator: ValidatorId,
        new_key: VerifyKey,
        current_ledger: u64,
    ) -> Option<u64> {
        let record = self.records.get_mut(&validator)?;
        record.previous_key = Some(record.active_key);
        record.active_key = new_key;
        record.key_gen += 1;
        record.rotated_at_ledger = current_ledger;
        Some(record.key_gen)
    }

    /// Current key generation for `validator`.
    pub fn key_gen(&self, validator: ValidatorId) -> Option<u64> {
        self.records.get(&validator).map(|r| r.key_gen)
    }

    /// Immutable snapshot of `validator`'s key state.
    pub fn snapshot(&self, validator: ValidatorId) -> Option<KeySnapshot> {
        self.records.get(&validator).copied()
    }
}

/// In-memory verification cache, versioned by `key_gen`.
#[derive(Clone, Debug)]
pub struct VerificationCache {
    window_ledgers: u64,
    entries: BTreeMap<ValidatorId, KeySnapshot>,
}

impl Default for VerificationCache {
    fn default() -> Self {
        Self::new()
    }
}

impl VerificationCache {
    /// Cache with the default rotation window.
    pub fn new() -> Self {
        Self::with_window(ROTATION_WINDOW_LEDGERS)
    }

    /// Cache with a custom rotation window (ledgers).
    pub fn with_window(window_ledgers: u64) -> Self {
        Self {
            window_ledgers,
            entries: BTreeMap::new(),
        }
    }

    /// Generation the cache currently holds for `validator`, if any.
    pub fn cached_key_gen(&self, validator: ValidatorId) -> Option<u64> {
        self.entries.get(&validator).map(|c| c.key_gen)
    }

    /// Resolve the set of keys currently valid for `validator`, reloading from
    /// the registry whenever the cached generation is behind. The previous key
    /// is included only while inside the rotation window.
    fn resolve_keys(
        &mut self,
        registry: &KeyRegistry,
        validator: ValidatorId,
        current_ledger: u64,
    ) -> Option<Vec<VerifyKey>> {
        let snapshot = registry.snapshot(validator)?;

        let needs_reload = match self.entries.get(&validator) {
            Some(cached) => cached.key_gen < snapshot.key_gen,
            None => true,
        };
        if needs_reload {
            self.entries.insert(validator, snapshot);
        }

        // Post-reload the cached entry equals the registry snapshot; otherwise
        // it carries the same generation, so its keys are still current.
        let cached = self.entries.get(&validator).copied()?;

        let mut keys = Vec::new();
        keys.push(cached.active_key);
        if let Some(previous) = cached.previous_key {
            if current_ledger.saturating_sub(cached.rotated_at_ledger) < self.window_ledgers {
                keys.push(previous);
            }
        }
        Some(keys)
    }
}

/// Verify an attestation signature for `validator`, tolerating an in-flight key
/// rotation. Accepts the signature if it validates under any key currently
/// valid for the validator (the active key, plus the previous key while inside
/// the rotation window). Refreshes the cache when the registry generation has
/// advanced, so a rotation never leaves the cache serving a stale key.
pub fn verify_with_rotation(
    cache: &mut VerificationCache,
    registry: &KeyRegistry,
    validator: ValidatorId,
    domain: &Domain,
    data: &AttestationData,
    signature: &Signature,
    current_ledger: u64,
) -> bool {
    let keys = match cache.resolve_keys(registry, validator, current_ledger) {
        Some(keys) => keys,
        None => return false,
    };
    keys.iter()
        .any(|key| verify_attestation_signature(key, domain, data, signature))
}
