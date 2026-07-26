//! Versioned database migration coordinator with rollback support.
//!
//! The coordinator is storage-agnostic so every service can plug in its own
//! persistence adapter while sharing the same ordering, rollback, and audit
//! semantics. Apply and rollback operations are O(number of migrations), keep
//! no heap data proportional to database size, and are intended to stay outside
//! critical request paths after service startup.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Monotonically increasing schema version.
pub type MigrationVersion = u64;

/// Current schema state persisted by a service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaState {
    /// Applied schema version. Version `0` means a fresh, un-migrated store.
    pub version: MigrationVersion,
    /// Ordered history of successfully applied migration versions.
    pub applied_versions: Vec<MigrationVersion>,
}

impl SchemaState {
    /// Create a new state at version zero.
    pub fn new() -> Self {
        Self {
            version: 0,
            applied_versions: Vec::new(),
        }
    }
}

impl Default for SchemaState {
    fn default() -> Self {
        Self::new()
    }
}

/// Execution record suitable for logs, metrics, alerts, and runbooks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationEvent {
    pub version: MigrationVersion,
    pub name: &'static str,
    pub direction: MigrationDirection,
}

/// Direction of a schema transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationDirection {
    Up,
    Down,
}

/// Lightweight metrics snapshot exported by the coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationMetrics {
    pub current_version: MigrationVersion,
    pub target_version: MigrationVersion,
    pub pending_migrations: usize,
    pub rollback_available: bool,
}

/// Error returned for invalid plans or migration execution failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationError {
    DuplicateVersion(MigrationVersion),
    NonContiguousVersion {
        expected: MigrationVersion,
        found: MigrationVersion,
    },
    UnknownTarget(MigrationVersion),
    RollbackUnavailable(MigrationVersion),
    ApplyFailed {
        version: MigrationVersion,
        reason: String,
    },
    RollbackFailed {
        version: MigrationVersion,
        reason: String,
    },
}

/// A reversible database migration.
pub trait Migration<DB> {
    /// Version reached after this migration is applied.
    fn version(&self) -> MigrationVersion;
    /// Human-readable name for logs and dashboards.
    fn name(&self) -> &'static str;
    /// Apply the schema/data change.
    fn up(&self, db: &mut DB) -> Result<(), String>;
    /// Undo the schema/data change.
    fn down(&self, db: &mut DB) -> Result<(), String>;
}

/// Coordinates migration ordering, version persistence, rollback, and events.
pub struct MigrationManager<DB> {
    migrations: Vec<Box<dyn Migration<DB>>>,
    events: Vec<MigrationEvent>,
}

impl<DB> MigrationManager<DB> {
    /// Build a manager from a service's migration list.
    pub fn new(mut migrations: Vec<Box<dyn Migration<DB>>>) -> Result<Self, MigrationError> {
        migrations.sort_by_key(|migration| migration.version());
        let mut expected = 1;
        let mut previous = 0;

        for migration in &migrations {
            let version = migration.version();
            if version == previous {
                return Err(MigrationError::DuplicateVersion(version));
            }
            if version != expected {
                return Err(MigrationError::NonContiguousVersion {
                    expected,
                    found: version,
                });
            }
            previous = version;
            expected += 1;
        }

        Ok(Self {
            migrations,
            events: Vec::new(),
        })
    }

    /// Apply migrations until `target_version` is reached.
    pub fn migrate_to(
        &mut self,
        db: &mut DB,
        state: &mut SchemaState,
        target_version: MigrationVersion,
    ) -> Result<(), MigrationError> {
        self.ensure_target_exists(target_version)?;

        if target_version < state.version {
            return self.rollback_to(db, state, target_version);
        }

        let current_version = state.version;
        for migration in self.migrations.iter().filter(|migration| {
            migration.version() > current_version && migration.version() <= target_version
        }) {
            migration
                .up(db)
                .map_err(|reason| MigrationError::ApplyFailed {
                    version: migration.version(),
                    reason,
                })?;
            state.version = migration.version();
            state.applied_versions.push(migration.version());
            self.events.push(MigrationEvent {
                version: migration.version(),
                name: migration.name(),
                direction: MigrationDirection::Up,
            });
        }

        Ok(())
    }

    /// Roll back applied migrations until `target_version` is reached.
    pub fn rollback_to(
        &mut self,
        db: &mut DB,
        state: &mut SchemaState,
        target_version: MigrationVersion,
    ) -> Result<(), MigrationError> {
        self.ensure_target_exists(target_version)?;

        while state.version > target_version {
            let migration = self
                .migrations
                .iter()
                .find(|migration| migration.version() == state.version)
                .ok_or(MigrationError::RollbackUnavailable(state.version))?;

            migration
                .down(db)
                .map_err(|reason| MigrationError::RollbackFailed {
                    version: migration.version(),
                    reason,
                })?;
            state.applied_versions.pop();
            state.version -= 1;
            self.events.push(MigrationEvent {
                version: migration.version(),
                name: migration.name(),
                direction: MigrationDirection::Down,
            });
        }

        Ok(())
    }

    /// Latest migration version known by this manager.
    pub fn latest_version(&self) -> MigrationVersion {
        self.migrations
            .last()
            .map(|migration| migration.version())
            .unwrap_or(0)
    }

    /// Export current observability fields for dashboards and alerts.
    pub fn metrics(&self, state: &SchemaState) -> MigrationMetrics {
        let latest = self.latest_version();
        MigrationMetrics {
            current_version: state.version,
            target_version: latest,
            pending_migrations: latest.saturating_sub(state.version) as usize,
            rollback_available: state.version > 0,
        }
    }

    /// Audit log of successful migration transitions.
    pub fn events(&self) -> &[MigrationEvent] {
        &self.events
    }

    fn ensure_target_exists(&self, target_version: MigrationVersion) -> Result<(), MigrationError> {
        if target_version <= self.latest_version() {
            Ok(())
        } else {
            Err(MigrationError::UnknownTarget(target_version))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestDb {
        columns: Vec<&'static str>,
    }

    struct AddColumn {
        version: MigrationVersion,
        name: &'static str,
        column: &'static str,
    }

    impl Migration<TestDb> for AddColumn {
        fn version(&self) -> MigrationVersion {
            self.version
        }
        fn name(&self) -> &'static str {
            self.name
        }
        fn up(&self, db: &mut TestDb) -> Result<(), String> {
            db.columns.push(self.column);
            Ok(())
        }
        fn down(&self, db: &mut TestDb) -> Result<(), String> {
            db.columns.pop();
            Ok(())
        }
    }

    fn migrations() -> Vec<Box<dyn Migration<TestDb>>> {
        vec![
            Box::new(AddColumn {
                version: 1,
                name: "create_nodes",
                column: "nodes",
            }),
            Box::new(AddColumn {
                version: 2,
                name: "add_health",
                column: "health",
            }),
            Box::new(AddColumn {
                version: 3,
                name: "add_rewards",
                column: "rewards",
            }),
        ]
    }

    #[test]
    fn migrate_to_latest_records_versions_and_events() {
        let mut manager = MigrationManager::new(migrations()).unwrap();
        let mut db = TestDb::default();
        let mut state = SchemaState::new();

        manager.migrate_to(&mut db, &mut state, 3).unwrap();

        assert_eq!(db.columns, vec!["nodes", "health", "rewards"]);
        assert_eq!(state.version, 3);
        assert_eq!(state.applied_versions, vec![1, 2, 3]);
        assert_eq!(manager.events().len(), 3);
        assert_eq!(manager.events()[0].direction, MigrationDirection::Up);
    }

    #[test]
    fn rollback_to_prior_version_runs_down_in_reverse_order() {
        let mut manager = MigrationManager::new(migrations()).unwrap();
        let mut db = TestDb::default();
        let mut state = SchemaState::new();
        manager.migrate_to(&mut db, &mut state, 3).unwrap();

        manager.rollback_to(&mut db, &mut state, 1).unwrap();

        assert_eq!(db.columns, vec!["nodes"]);
        assert_eq!(state.version, 1);
        assert_eq!(state.applied_versions, vec![1]);
        assert_eq!(manager.events()[3].direction, MigrationDirection::Down);
        assert_eq!(manager.events()[4].version, 2);
    }

    #[test]
    fn migrate_to_lower_version_delegates_to_rollback() {
        let mut manager = MigrationManager::new(migrations()).unwrap();
        let mut db = TestDb::default();
        let mut state = SchemaState::new();
        manager.migrate_to(&mut db, &mut state, 2).unwrap();

        manager.migrate_to(&mut db, &mut state, 0).unwrap();

        assert!(db.columns.is_empty());
        assert_eq!(state.version, 0);
        assert!(!manager.metrics(&state).rollback_available);
    }

    #[test]
    fn rejects_duplicate_and_gap_versions() {
        let duplicate = MigrationManager::new(vec![
            Box::new(AddColumn {
                version: 1,
                name: "a",
                column: "a",
            }),
            Box::new(AddColumn {
                version: 1,
                name: "b",
                column: "b",
            }),
        ]);
        assert_eq!(duplicate.err(), Some(MigrationError::DuplicateVersion(1)));

        let gap = MigrationManager::new(vec![
            Box::new(AddColumn {
                version: 1,
                name: "a",
                column: "a",
            }),
            Box::new(AddColumn {
                version: 3,
                name: "c",
                column: "c",
            }),
        ]);
        assert_eq!(
            gap.err(),
            Some(MigrationError::NonContiguousVersion {
                expected: 2,
                found: 3
            })
        );
    }

    #[test]
    fn metrics_report_pending_work_for_dashboards() {
        let manager = MigrationManager::new(migrations()).unwrap();
        let state = SchemaState {
            version: 1,
            applied_versions: vec![1],
        };

        assert_eq!(
            manager.metrics(&state),
            MigrationMetrics {
                current_version: 1,
                target_version: 3,
                pending_migrations: 2,
                rollback_available: true,
            }
        );
    }
}
