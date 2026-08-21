//! Tenant lifecycle management for the shard connection pool (issue #141).
//!
//! The [`TenantRegistry`] is the single point of contact for tenant
//! connect/disconnect operations.  It delegates shard slot allocation to
//! [`ShardAllocator`] and triggers the [`ShardDefragmenter`] when the pool is
//! idle and the fragmentation ratio exceeds the alarm threshold.
//!
//! ## Slot remapping
//!
//! When the defragmenter completes a pass it emits a
//! [`DefragEvent::ShardDefragComplete`] event containing a list of
//! `(old_slot, new_slot)` pairs.  The registry applies this mapping atomically
//! so tenants always reference valid slot indices.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::pool::shard_allocator::{ShardAllocResult, ShardAllocator, ShardSlot};
use crate::pool::shard_defragmenter::{DefragEvent, ShardDefragmenter};

/// Unique tenant identifier.
pub type TenantId = u64;

/// Error variants for tenant registry operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantRegistryError {
    /// Tenant is already connected.
    AlreadyConnected,
    /// No free shard slot is available in the pool.
    OutOfMemory,
    /// No tenant with the given identifier is connected.
    NotConnected,
}

/// Tenant connection record.
#[derive(Clone, Copy, Debug)]
pub struct TenantRecord {
    /// The tenant's current shard slot index.
    pub slot: ShardSlot,
    /// Timestamp (milliseconds) when the tenant connected.
    pub connected_at_ms: u64,
}

/// Registry that manages the full tenant lifecycle.
///
/// ```text
/// connect(tenant_id, now_ms)
///     └─ allocates a shard slot via ShardAllocator
///        └─ records TenantRecord in tenant map
///
/// disconnect(tenant_id, now_ms)
///     └─ frees the shard slot via ShardAllocator
///        └─ removes TenantRecord from tenant map
///        └─ may trigger ShardDefragmenter if pool is idle & fragmented
/// ```
#[derive(Debug)]
pub struct TenantRegistry {
    allocator: ShardAllocator,
    defragmenter: ShardDefragmenter,
    /// Active tenants mapped by tenant ID.
    tenants: BTreeMap<TenantId, TenantRecord>,
    /// Timestamp of the last allocation or free (milliseconds).
    last_activity_ms: u64,
}

impl TenantRegistry {
    /// Creates a new registry with all shard slots available.
    pub fn new() -> Self {
        Self {
            allocator: ShardAllocator::new(),
            defragmenter: ShardDefragmenter::new(),
            tenants: BTreeMap::new(),
            last_activity_ms: 0,
        }
    }

    /// Connects `tenant_id` to the pool, allocating a shard slot for it.
    ///
    /// Returns [`TenantRegistryError::AlreadyConnected`] if the tenant is
    /// already active, or [`TenantRegistryError::OutOfMemory`] when no free
    /// shard slot exists.
    pub fn connect(
        &mut self,
        tenant_id: TenantId,
        now_ms: u64,
    ) -> Result<TenantRecord, TenantRegistryError> {
        if self.tenants.contains_key(&tenant_id) {
            return Err(TenantRegistryError::AlreadyConnected);
        }
        match self.allocator.allocate() {
            ShardAllocResult::Allocated(slot) => {
                let record = TenantRecord {
                    slot,
                    connected_at_ms: now_ms,
                };
                self.tenants.insert(tenant_id, record);
                self.last_activity_ms = now_ms;
                Ok(record)
            }
            ShardAllocResult::OutOfMemory => Err(TenantRegistryError::OutOfMemory),
        }
    }

    /// Disconnects `tenant_id`, freeing its shard slot.
    ///
    /// After freeing, the defragmenter is given the opportunity to run if the
    /// pool has been idle for at least the coalescing window and the
    /// fragmentation ratio is above the alarm threshold.
    ///
    /// Returns any [`DefragEvent`]s emitted by the defragmenter.
    pub fn disconnect(
        &mut self,
        tenant_id: TenantId,
        now_ms: u64,
    ) -> Result<Vec<DefragEvent>, TenantRegistryError> {
        let record = self
            .tenants
            .remove(&tenant_id)
            .ok_or(TenantRegistryError::NotConnected)?;

        self.allocator.free(record.slot);
        self.last_activity_ms = now_ms;

        // Give the defragmenter an opportunity to run.
        let events =
            self.defragmenter
                .run_if_needed(&mut self.allocator, self.last_activity_ms, now_ms);

        // Apply any slot remappings produced by the defragmenter.
        if let Some(DefragEvent::ShardDefragComplete { ref relocated, .. }) = events
            .iter()
            .find(|e| matches!(e, DefragEvent::ShardDefragComplete { .. }))
        {
            self.apply_relocations(relocated);
        }

        Ok(events)
    }

    /// Looks up the [`TenantRecord`] for an active tenant.
    pub fn lookup(&self, tenant_id: TenantId) -> Option<&TenantRecord> {
        self.tenants.get(&tenant_id)
    }

    /// Returns the number of currently-connected tenants.
    pub fn tenant_count(&self) -> usize {
        self.tenants.len()
    }

    /// Returns the per-pool fragmentation ratio gauge.
    pub fn fragmentation_gauge(&self) -> crate::pool::shard_allocator::PoolFragmentationGauge {
        self.allocator.fragmentation_gauge()
    }

    /// Explicitly runs a defragmentation pass regardless of idle time or
    /// fragmentation level.  Intended for operator-triggered compaction.
    ///
    /// Returns the events emitted (always [`DefragEvent::ShardDefragStarted`]
    /// followed by [`DefragEvent::ShardDefragComplete`]).
    pub fn force_defrag(&mut self) -> Vec<DefragEvent> {
        let events = self.defragmenter.run_pass(&mut self.allocator);
        if let Some(DefragEvent::ShardDefragComplete { ref relocated, .. }) = events
            .iter()
            .find(|e| matches!(e, DefragEvent::ShardDefragComplete { .. }))
        {
            self.apply_relocations(relocated);
        }
        events
    }

    /// Returns the number of defragmentation passes completed.
    pub fn defrag_passes_completed(&self) -> u64 {
        self.defragmenter.passes_completed()
    }

    // --- helpers -----------------------------------------------------------

    /// Applies a list of `(old_slot, new_slot)` remappings from the
    /// defragmenter to the tenant map.
    fn apply_relocations(&mut self, relocated: &[(ShardSlot, ShardSlot)]) {
        if relocated.is_empty() {
            return;
        }
        // Build a reverse map: old_slot → new_slot.
        let remap: BTreeMap<ShardSlot, ShardSlot> = relocated.iter().copied().collect();
        for record in self.tenants.values_mut() {
            if let Some(&new_slot) = remap.get(&record.slot) {
                record.slot = new_slot;
            }
        }
    }
}

impl Default for TenantRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_and_disconnect_single_tenant() {
        let mut reg = TenantRegistry::new();
        let record = reg.connect(1, 0).expect("connect should succeed");
        assert!(reg.lookup(1).is_some());
        assert_eq!(reg.tenant_count(), 1);
        assert!(reg.allocator.is_allocated(record.slot));

        reg.disconnect(1, 100).expect("disconnect should succeed");
        assert!(reg.lookup(1).is_none());
        assert_eq!(reg.tenant_count(), 0);
        assert!(!reg.allocator.is_allocated(record.slot));
    }

    #[test]
    fn connect_same_tenant_twice_returns_error() {
        let mut reg = TenantRegistry::new();
        reg.connect(42, 0).unwrap();
        assert_eq!(
            reg.connect(42, 1).unwrap_err(),
            TenantRegistryError::AlreadyConnected
        );
    }

    #[test]
    fn disconnect_unknown_tenant_returns_error() {
        let mut reg = TenantRegistry::new();
        assert_eq!(
            reg.disconnect(99, 0).unwrap_err(),
            TenantRegistryError::NotConnected
        );
    }

    #[test]
    fn connect_max_tenants_then_out_of_memory() {
        let mut reg = TenantRegistry::new();
        for id in 0..crate::mem::buddy_allocator::MAX_TENANTS as u64 {
            reg.connect(id, 0)
                .expect("should connect up to MAX_TENANTS");
        }
        assert_eq!(
            reg.connect(crate::mem::buddy_allocator::MAX_TENANTS as u64, 0)
                .unwrap_err(),
            TenantRegistryError::OutOfMemory
        );
    }

    #[test]
    fn tenant_slots_are_valid_after_fragmentation_and_defrag() {
        let mut reg = TenantRegistry::new();

        // Connect 20 tenants.
        for id in 0..20u64 {
            reg.connect(id, 0).unwrap();
        }

        // Disconnect every other tenant to fragment the pool.
        for id in (0..20u64).step_by(2) {
            reg.disconnect(id, 500).unwrap();
        }

        // Force defragmentation.
        reg.force_defrag();

        // Verify remaining tenants still have valid allocated slots.
        for id in (1..20u64).step_by(2) {
            let record = reg.lookup(id).expect("tenant should still be connected");
            assert!(
                reg.allocator.is_allocated(record.slot),
                "slot {} for tenant {} should be allocated",
                record.slot,
                id
            );
        }
    }

    #[test]
    fn fragmentation_gauge_returns_valid_data() {
        let reg = TenantRegistry::new();
        let gauge = reg.fragmentation_gauge();
        assert!((0.0..=1.0).contains(&gauge.fragmentation_ratio));
        assert!(!gauge.alarm_active);
    }

    #[test]
    fn defrag_passes_completed_tracks_force_defrag() {
        let mut reg = TenantRegistry::new();
        assert_eq!(reg.defrag_passes_completed(), 0);
        reg.force_defrag();
        assert_eq!(reg.defrag_passes_completed(), 1);
    }

    #[test]
    fn connect_records_timestamp() {
        let mut reg = TenantRegistry::new();
        let record = reg.connect(7, 12_345).unwrap();
        assert_eq!(record.connected_at_ms, 12_345);
    }
}
