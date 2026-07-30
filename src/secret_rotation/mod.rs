//! Secret rotation service for database credentials and API keys.
//!
//! The module implements a versioned credential store with scheduled expiry,
//! dual-ended grace windows, and atomic rotation that keeps old credentials
//! live long enough for in-flight requests to drain. It is intentionally free
//! of platform-specific IO so off-chain services and on-chain contracts can
//! share the same rotation semantics and observability hooks.
//!
//! Closes #79

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

// --- Constants ----------------------------------------------------------------

/// Default lifetime of a credential before it is eligible for rotation (seconds).
pub const DEFAULT_CREDENTIAL_TTL_SECS: u64 = 86_400; // 24 hours
/// Maximum number of active credential versions retained during rotation.
pub const MAX_ACTIVE_VERSIONS: usize = 3;
/// Default grace window during which old credentials remain valid after rotation.
pub const DEFAULT_GRACE_WINDOW_SECS: u64 = 300; // 5 minutes
/// Minimum credential length to reject empty or stub secrets.
pub const MIN_CREDENTIAL_LENGTH: usize = 16;
/// Maximum credential length to prevent oversized payloads.
pub const MAX_CREDENTIAL_LENGTH: usize = 4_096;

// --- Types --------------------------------------------------------------------

/// Monotonically increasing credential version.
pub type CredentialVersion = u64;

/// A service or resource that credentials are bound to.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CredentialBinding {
    /// Logical service name, e.g. "postgres-main", "infura-eth".
    pub service: String,
    /// Optional scope discriminator (read/write, region, etc.).
    pub scope: Option<String>,
}

/// Versioned credential envelope stored in the rotation registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credential {
    pub version: CredentialVersion,
    pub binding: CredentialBinding,
    /// Opaque secret material.
    pub secret: Vec<u8>,
    /// Unix timestamp when this credential was issued.
    pub issued_at: u64,
    /// Unix timestamp when this credential expires (issued_at + ttl).
    pub expires_at: u64,
    /// Whether this is the currently active credential.
    pub is_active: bool,
}

/// Observability snapshot exported to monitoring and alerting pipelines.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RotationMetrics {
    pub bindings_tracked: u64,
    pub active_credentials: u64,
    pub pending_rotations: u64,
    pub expired_credentials: u64,
    pub rotation_failures: u64,
}

/// Errors that can occur during credential operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RotationError {
    SecretTooShort { length: usize, min: usize },
    SecretTooLong { length: usize, max: usize },
    BindingNotFound,
    NoActiveCredential,
    RotationNotDue { expires_at: u64, now: u64 },
    TooManyActiveVersions { count: usize, max: usize },
    VersionConflict { existing: CredentialVersion },
}

/// Configuration for the secret rotation service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationConfig {
    /// How long a new credential is valid before rotation is recommended.
    pub credential_ttl_secs: u64,
    /// How long old credentials remain valid after a new one is issued.
    pub grace_window_secs: u64,
    /// Whether automatic rotation during expiry is enabled.
    pub auto_rotate: bool,
    /// Target for alerting when credentials are approaching expiry.
    pub expiry_warning_secs: u64,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            credential_ttl_secs: DEFAULT_CREDENTIAL_TTL_SECS,
            grace_window_secs: DEFAULT_GRACE_WINDOW_SECS,
            auto_rotate: true,
            expiry_warning_secs: 3_600, // warn 1 hour before expiry
        }
    }
}

// --- Secret Rotation Service --------------------------------------------------

/// The core secret rotation registry.
///
/// Credentials are stored per [`CredentialBinding`] with up to
/// [`MAX_ACTIVE_VERSIONS`] active versions to support overlapping
/// rotations without breaking in-flight requests.
#[derive(Clone, Debug)]
pub struct SecretRotationService {
    config: RotationConfig,
    /// All credential versions keyed by binding, ordered by version.
    credentials: BTreeMap<CredentialBinding, Vec<Credential>>,
    /// Global version counter.
    next_version: CredentialVersion,
    metrics: RotationMetrics,
}

impl SecretRotationService {
    /// Create a new rotation service with the given config.
    pub fn new(config: RotationConfig) -> Self {
        Self {
            config,
            credentials: BTreeMap::new(),
            next_version: 1,
            metrics: RotationMetrics::default(),
        }
    }

    /// Register a new credential for a service binding.
    ///
    /// Returns the version assigned to the new credential.  If an active
    /// credential already exists for the binding, the old one is NOT
    /// deactivated immediately — callers must call [`rotate`] to perform
    /// an atomic rotation.
    pub fn register(
        &mut self,
        binding: CredentialBinding,
        secret: Vec<u8>,
        now: u64,
    ) -> Result<CredentialVersion, RotationError> {
        // Validate secret length
        if secret.len() < MIN_CREDENTIAL_LENGTH {
            return Err(RotationError::SecretTooShort {
                length: secret.len(),
                min: MIN_CREDENTIAL_LENGTH,
            });
        }
        if secret.len() > MAX_CREDENTIAL_LENGTH {
            return Err(RotationError::SecretTooLong {
                length: secret.len(),
                max: MAX_CREDENTIAL_LENGTH,
            });
        }

        let version = self.next_version;
        let expires_at = now.saturating_add(self.config.credential_ttl_secs);
        let credential = Credential {
            version,
            binding: binding.clone(),
            secret,
            issued_at: now,
            expires_at,
            is_active: true,
        };

        let entry = self.credentials.entry(binding).or_default();

        // Enforce max active versions
        let active_count = entry.iter().filter(|c| c.is_active).count();
        if active_count >= MAX_ACTIVE_VERSIONS {
            return Err(RotationError::TooManyActiveVersions {
                count: active_count,
                max: MAX_ACTIVE_VERSIONS,
            });
        }

        entry.push(credential);

        self.next_version = self.next_version.saturating_add(1);
        Ok(version)
    }

    /// Rotate a credential for the given binding: deactivate the current
    /// active credential and register a new one.  The old credential remains
    /// valid for the grace window to allow in-flight requests to drain.
    ///
    /// Returns the version of the newly issued credential.
    pub fn rotate(
        &mut self,
        binding: &CredentialBinding,
        new_secret: Vec<u8>,
        now: u64,
    ) -> Result<CredentialVersion, RotationError> {
        let entry = self.credentials.get_mut(binding).ok_or(RotationError::BindingNotFound)?;

        // Find the active credential
        let active = entry
            .iter_mut()
            .find(|c| c.is_active)
            .ok_or(RotationError::NoActiveCredential)?;

        // Enforce minimum lifetime before rotation
        if now < active.expires_at {
            return Err(RotationError::RotationNotDue {
                expires_at: active.expires_at,
                now,
            });
        }

        // Deactivate the current active credential
        active.is_active = false;

        // Register the new credential
        let new_version = self.next_version;
        let expires_at = now.saturating_add(self.config.credential_ttl_secs);
        let new_credential = Credential {
            version: new_version,
            binding: binding.clone(),
            secret: new_secret,
            issued_at: now,
            expires_at,
            is_active: true,
        };

        entry.push(new_credential);
        self.next_version = self.next_version.saturating_add(1);

        Ok(new_version)
    }

    /// Retrieve the currently active credential for a binding.
    pub fn get_active(&self, binding: &CredentialBinding) -> Option<&Credential> {
        self.credentials
            .get(binding)?
            .iter()
            .rev() // newest first
            .find(|c| c.is_active)
    }

    /// Retrieve a specific credential version.
    pub fn get_version(
        &self,
        binding: &CredentialBinding,
        version: CredentialVersion,
    ) -> Option<&Credential> {
        self.credentials
            .get(binding)?
            .iter()
            .find(|c| c.version == version)
    }

    /// List all credentials for a binding, newest first.
    pub fn list_binding(&self, binding: &CredentialBinding) -> Vec<&Credential> {
        self.credentials
            .get(binding)
            .map(|creds| creds.iter().rev().collect())
            .unwrap_or_default()
    }

    /// Check if any credentials are approaching or past expiry.
    /// Returns a list of bindings that need attention.
    pub fn check_expiry(&self, now: u64) -> Vec<CredentialBinding> {
        let warning_threshold = now.saturating_add(self.config.expiry_warning_secs);
        self.credentials
            .iter()
            .filter_map(|(binding, creds)| {
                let needs_attention = creds.iter().any(|c| {
                    c.is_active && (c.expires_at <= warning_threshold || c.expires_at <= now)
                });
                if needs_attention {
                    Some(binding.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Purge expired credentials past their grace window.
    /// Returns the number of credentials removed.
    pub fn purge_expired(&mut self, now: u64) -> u64 {
        let cutoff = now.saturating_sub(self.config.grace_window_secs);
        let mut removed = 0u64;

        for entry in self.credentials.values_mut() {
            let before = entry.len();
            entry.retain(|c| c.is_active || c.expires_at > cutoff);
            removed = removed.saturating_add((before - entry.len()) as u64);
        }

        // Remove empty bindings
        self.credentials.retain(|_, creds| !creds.is_empty());
        self.metrics.expired_credentials = self.metrics.expired_credentials.saturating_add(removed);
        removed
    }

    /// Remove all credentials for a binding (e.g., service decommissioned).
    pub fn revoke_binding(&mut self, binding: &CredentialBinding) {
        self.credentials.remove(binding);
    }

    /// Export metrics snapshot for monitoring and alerting dashboards.
    pub fn metrics(&self) -> RotationMetrics {
        let active_credentials = self
            .credentials
            .values()
            .map(|creds| creds.iter().filter(|c| c.is_active).count() as u64)
            .sum();

        RotationMetrics {
            bindings_tracked: self.credentials.len() as u64,
            active_credentials,
            pending_rotations: self.metrics.pending_rotations,
            expired_credentials: self.metrics.expired_credentials,
            rotation_failures: self.metrics.rotation_failures,
        }
    }
}

impl Default for SecretRotationService {
    fn default() -> Self {
        Self::new(RotationConfig::default())
    }
}

// --- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(name: &str) -> CredentialBinding {
        CredentialBinding {
            service: name.into(),
            scope: None,
        }
    }

    fn secret(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    #[test]
    fn register_new_credential_returns_version() {
        let mut svc = SecretRotationService::default();
        let s = secret(&[0xAB; 32]);
        let version = svc.register(binding("postgres-main"), s.clone(), 1000).unwrap();
        assert_eq!(version, 1);

        let active = svc.get_active(&binding("postgres-main")).unwrap();
        assert_eq!(active.secret, s);
        assert!(active.is_active);
    }

    #[test]
    fn register_rejects_too_short_secret() {
        let mut svc = SecretRotationService::default();
        let result = svc.register(binding("db"), secret(&[0x01; 8]), 1000);
        assert!(matches!(result, Err(RotationError::SecretTooShort { length: 8, min: 16 })));
    }

    #[test]
    fn register_rejects_too_long_secret() {
        let mut svc = SecretRotationService::default();
        let long = vec![0xFF; MAX_CREDENTIAL_LENGTH + 1];
        let result = svc.register(binding("db"), long, 1000);
        assert!(matches!(result, Err(RotationError::SecretTooLong { .. })));
    }

    #[test]
    fn register_enforces_max_active_versions() {
        let mut svc = SecretRotationService::default();
        let b = binding("api-key");

        // Register 3 active credentials
        for i in 0..MAX_ACTIVE_VERSIONS {
            svc.register(b.clone(), secret(&[i as u8; 32]), 1000 + i as u64).unwrap();
        }

        // 4th should fail
        let result = svc.register(b.clone(), secret(&[0xEE; 32]), 2000);
        assert!(matches!(result, Err(RotationError::TooManyActiveVersions { count: 3, max: 3 })));
    }

    #[test]
    fn rotate_produces_new_version_and_deactivates_old() {
        let mut svc = SecretRotationService::default();
        let b = binding("redis-cache");

        let v1 = svc.register(b.clone(), secret(&[0x01; 32]), 1000).unwrap();
        assert_eq!(v1, 1);

        // Advance time past expiry
        let now = 1000 + DEFAULT_CREDENTIAL_TTL_SECS + 1;
        let v2 = svc.rotate(&b, secret(&[0x02; 32]), now).unwrap();
        assert_eq!(v2, 2);

        let active = svc.get_active(&b).unwrap();
        assert_eq!(active.version, 2);
        assert_eq!(active.secret, secret(&[0x02; 32]));

        let old = svc.get_version(&b, 1).unwrap();
        assert!(!old.is_active);
    }

    #[test]
    fn rotate_before_expiry_fails() {
        let mut svc = SecretRotationService::default();
        let b = binding("db");

        svc.register(b.clone(), secret(&[0x01; 32]), 1000).unwrap();

        // Try to rotate immediately (well before expiry)
        let result = svc.rotate(&b, secret(&[0x02; 32]), 1001);
        assert!(matches!(result, Err(RotationError::RotationNotDue { .. })));
    }

    #[test]
    fn rotate_nonexistent_binding_fails() {
        let mut svc = SecretRotationService::default();
        let result = svc.rotate(&binding("ghost"), secret(&[0x01; 32]), 1000);
        assert!(matches!(result, Err(RotationError::BindingNotFound)));
    }

    #[test]
    fn check_expiry_detects_approaching_and_past_expiry() {
        let mut svc = SecretRotationService::default();
        let b = binding("service-a");

        // Register with TTL of 86400, issued at 1000 → expires at 87400
        svc.register(b.clone(), secret(&[0x01; 32]), 1000).unwrap();

        // Well before expiry warning (3600s) → no alerts
        let alerts = svc.check_expiry(1000);
        assert!(alerts.is_empty());

        // Within warning window
        let alerts = svc.check_expiry(87400 - 1800); // 1800s before expiry, within 3600s warning
        assert_eq!(alerts.len(), 1);

        // Past expiry
        let alerts = svc.check_expiry(88000);
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn purge_expired_removes_non_active_expired_credentials() {
        let mut svc = SecretRotationService::default();
        let b = binding("db");

        svc.register(b.clone(), secret(&[0x01; 32]), 1000).unwrap();
        let now = 1000 + DEFAULT_CREDENTIAL_TTL_SECS + 1;
        svc.rotate(&b, secret(&[0x02; 32]), now).unwrap();

        // At time of rotation the old one is inactive but not yet past grace
        assert_eq!(svc.list_binding(&b).len(), 2);

        // Advance past grace window
        let purge_now = now + DEFAULT_GRACE_WINDOW_SECS + 1;
        let removed = svc.purge_expired(purge_now);
        assert_eq!(removed, 1);
        assert_eq!(svc.list_binding(&b).len(), 1); // only active remains
    }

    #[test]
    fn revoke_binding_removes_all_credentials() {
        let mut svc = SecretRotationService::default();
        let b = binding("temp-service");
        svc.register(b.clone(), secret(&[0x01; 32]), 1000).unwrap();
        assert!(svc.get_active(&b).is_some());

        svc.revoke_binding(&b);
        assert!(svc.get_active(&b).is_none());
    }

    #[test]
    fn metrics_tracks_bindings_and_active_credentials() {
        let mut svc = SecretRotationService::default();
        svc.register(binding("svc-a"), secret(&[0x01; 32]), 1000).unwrap();
        svc.register(binding("svc-b"), secret(&[0xAA; 32]), 1000).unwrap();

        let m = svc.metrics();
        assert_eq!(m.bindings_tracked, 2);
        assert_eq!(m.active_credentials, 2);
    }

    #[test]
    fn list_binding_returns_newest_first() {
        let mut svc = SecretRotationService::default();
        let b = binding("svc");

        svc.register(b.clone(), secret(&[0x01; 32]), 1000).unwrap();
        let now = 1000 + DEFAULT_CREDENTIAL_TTL_SECS + 1;
        svc.rotate(&b, secret(&[0x02; 32]), now).unwrap();

        let list = svc.list_binding(&b);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].version, 2); // newest first
        assert_eq!(list[1].version, 1);
    }

    #[test]
    fn config_defaults_match_constants() {
        let cfg = RotationConfig::default();
        assert_eq!(cfg.credential_ttl_secs, DEFAULT_CREDENTIAL_TTL_SECS);
        assert_eq!(cfg.grace_window_secs, DEFAULT_GRACE_WINDOW_SECS);
        assert!(cfg.auto_rotate);
    }

    #[test]
    fn multiple_bindings_are_independent() {
        let mut svc = SecretRotationService::default();
        svc.register(binding("db"), secret(&[0x01; 32]), 1000).unwrap();
        svc.register(binding("api"), secret(&[0x02; 32]), 1000).unwrap();

        let db = svc.get_active(&binding("db")).unwrap();
        let api = svc.get_active(&binding("api")).unwrap();

        assert_eq!(db.secret, secret(&[0x01; 32]));
        assert_eq!(api.secret, secret(&[0x02; 32]));
        assert_ne!(db.version, api.version);
    }
}
