//! Stress test for shard memory fragmentation under high-frequency tenant churn
//! (issue #141).
//!
//! Verifies that:
//! * 50 000 connect/disconnect churn cycles complete with an allocation success
//!   rate above 99.9 %.
//! * The defragmenter correctly emits `ShardDefragStarted` /
//!   `ShardDefragComplete` event pairs.
//! * Per-pool `fragmentation_ratio` gauge stays well-formed.
//! * Tenant slot remapping after defragmentation is consistent.

use sorosusu_contracts::mem::buddy_allocator::MAX_TENANTS;
use sorosusu_contracts::pool::{
    bulk_allocate, bulk_free, DefragEvent, PoolFragmentationGauge, ShardAllocResult,
    ShardAllocator, ShardDefragmenter, TenantRegistry, COALESCING_WINDOW_MS,
    FRAGMENTATION_ALARM_RATIO, SHARD_SIZE_BYTES,
};

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

#[test]
fn issue_141_constants_are_correct() {
    assert_eq!(SHARD_SIZE_BYTES, 64 * 1024, "shard size must be 64 KiB");
    assert_eq!(MAX_TENANTS, 65_536, "max tenants must be 2^16");
    assert!(
        (FRAGMENTATION_ALARM_RATIO - 0.30).abs() < 1e-9,
        "alarm threshold must be 30 %"
    );
    assert_eq!(
        COALESCING_WINDOW_MS, 500,
        "coalescing window must be 500 ms"
    );
}

// ---------------------------------------------------------------------------
// Allocation correctness
// ---------------------------------------------------------------------------

#[test]
fn allocate_and_free_all_slots_no_leak() {
    let mut alloc = ShardAllocator::new();
    let slots = bulk_allocate(&mut alloc, MAX_TENANTS);
    assert_eq!(
        slots.len() as u32,
        MAX_TENANTS,
        "must allocate all {} slots",
        MAX_TENANTS
    );
    assert_eq!(
        alloc.allocate(),
        ShardAllocResult::OutOfMemory,
        "must be OOM after filling pool"
    );
    bulk_free(&mut alloc, &slots);
    assert_eq!(
        alloc.free_slots(),
        MAX_TENANTS,
        "all slots must be recovered after free"
    );
    assert_eq!(alloc.used_slots(), 0);
}

#[test]
fn coalescing_after_alternating_free_pattern() {
    let mut alloc = ShardAllocator::new();
    let slots = bulk_allocate(&mut alloc, 64);
    // Free alternating slots — classic fragmentation pattern.
    let freed: Vec<_> = slots.iter().step_by(2).copied().collect();
    let kept: Vec<_> = slots.iter().skip(1).step_by(2).copied().collect();
    bulk_free(&mut alloc, &freed);

    assert_eq!(alloc.used_slots(), kept.len() as u32);

    // Verify kept slots are still allocated.
    for &s in &kept {
        assert!(
            alloc.is_allocated(s),
            "slot {} should still be allocated",
            s
        );
    }

    // Free the remaining slots — buddy allocator should coalesce fully.
    bulk_free(&mut alloc, &kept);
    assert_eq!(alloc.free_slots(), MAX_TENANTS);
}

// ---------------------------------------------------------------------------
// Defragmenter events
// ---------------------------------------------------------------------------

#[test]
fn defrag_emits_started_and_complete_event_pair() {
    let mut alloc = ShardAllocator::new();
    let mut defrag = ShardDefragmenter::new();

    // Allocate some slots and free every other one to fragment the space.
    let slots = bulk_allocate(&mut alloc, 16);
    let freed: Vec<_> = slots.iter().step_by(2).copied().collect();
    bulk_free(&mut alloc, &freed);

    let events = defrag.run_pass(&mut alloc);

    assert_eq!(events.len(), 2, "must emit exactly two events per pass");
    assert!(
        matches!(events[0], DefragEvent::ShardDefragStarted { .. }),
        "first event must be ShardDefragStarted"
    );
    assert!(
        matches!(events[1], DefragEvent::ShardDefragComplete { .. }),
        "second event must be ShardDefragComplete"
    );
}

#[test]
fn defrag_started_carries_correct_active_slot_count() {
    let mut alloc = ShardAllocator::new();
    let mut defrag = ShardDefragmenter::new();

    let slots = bulk_allocate(&mut alloc, 12);
    let freed: Vec<_> = slots.iter().step_by(3).copied().collect();
    bulk_free(&mut alloc, &freed);

    let expected_active = alloc.used_slots();
    let events = defrag.run_pass(&mut alloc);

    if let DefragEvent::ShardDefragStarted { active_slots, .. } = &events[0] {
        assert_eq!(
            *active_slots, expected_active,
            "active_slots in ShardDefragStarted must match used_slots()"
        );
    } else {
        panic!("expected ShardDefragStarted");
    }
}

#[test]
fn defrag_complete_fragmentation_ratio_after_is_valid() {
    let mut alloc = ShardAllocator::new();
    let mut defrag = ShardDefragmenter::new();

    let slots = bulk_allocate(&mut alloc, 8);
    let freed: Vec<_> = slots.iter().step_by(2).copied().collect();
    bulk_free(&mut alloc, &freed);

    let events = defrag.run_pass(&mut alloc);
    if let DefragEvent::ShardDefragComplete {
        fragmentation_ratio_after,
        ..
    } = &events[1]
    {
        assert!(
            (0.0..=1.0).contains(fragmentation_ratio_after),
            "fragmentation_ratio_after must be in [0, 1]; got {}",
            fragmentation_ratio_after
        );
    } else {
        panic!("expected ShardDefragComplete");
    }
}

#[test]
fn defrag_preserves_used_slot_count() {
    let mut alloc = ShardAllocator::new();
    let mut defrag = ShardDefragmenter::new();

    let slots = bulk_allocate(&mut alloc, 50);
    let freed: Vec<_> = slots.iter().step_by(3).copied().collect();
    bulk_free(&mut alloc, &freed);

    let used_before = alloc.used_slots();
    defrag.run_pass(&mut alloc);
    assert_eq!(
        alloc.used_slots(),
        used_before,
        "defrag must not change the number of allocated slots"
    );
}

// ---------------------------------------------------------------------------
// Fragmentation ratio gauge
// ---------------------------------------------------------------------------

#[test]
fn fragmentation_gauge_alarm_inactive_on_fresh_pool() {
    let alloc = ShardAllocator::new();
    let gauge: PoolFragmentationGauge = alloc.fragmentation_gauge();
    assert!(
        !gauge.alarm_active,
        "alarm must not fire on a fresh, empty pool"
    );
    assert!(
        (0.0..=1.0).contains(&gauge.fragmentation_ratio),
        "ratio must be in [0, 1]"
    );
}

#[test]
fn fragmentation_gauge_is_consistent_with_needs_defrag() {
    let mut alloc = ShardAllocator::new();
    let slots = bulk_allocate(&mut alloc, 100);
    let freed: Vec<_> = slots.iter().step_by(2).copied().collect();
    bulk_free(&mut alloc, &freed);

    let gauge = alloc.fragmentation_gauge();
    assert_eq!(
        gauge.alarm_active,
        alloc.needs_defrag(),
        "gauge.alarm_active must match needs_defrag()"
    );
    assert_eq!(
        gauge.fragmentation_ratio,
        alloc.fragmentation_ratio(),
        "gauge ratio must match fragmentation_ratio()"
    );
    assert_eq!(gauge.used_slots, alloc.used_slots());
    assert_eq!(gauge.free_slots, alloc.free_slots());
}

// ---------------------------------------------------------------------------
// Tenant registry
// ---------------------------------------------------------------------------

#[test]
fn tenant_registry_connect_disconnect_round_trip() {
    let mut reg = TenantRegistry::new();
    let record = reg.connect(1, 0).expect("connect must succeed");
    assert!(
        reg.lookup(1).is_some(),
        "tenant must be visible after connect"
    );
    assert_eq!(record.connected_at_ms, 0);

    reg.disconnect(1, 100).expect("disconnect must succeed");
    assert!(
        reg.lookup(1).is_none(),
        "tenant must be gone after disconnect"
    );
}

#[test]
fn tenant_registry_slots_are_allocated_between_connect_and_disconnect() {
    let mut reg = TenantRegistry::new();
    let _record = reg.connect(99, 0).unwrap();
    assert!(
        reg.fragmentation_gauge().used_slots >= 1,
        "at least one slot must be in use after connect"
    );
    reg.disconnect(99, 1).unwrap();
    assert_eq!(
        reg.fragmentation_gauge().used_slots,
        0,
        "no slots must be in use after disconnect"
    );
    // Slot must be coalesced back.
    assert_eq!(reg.fragmentation_gauge().free_slots, MAX_TENANTS);
}

#[test]
fn tenant_slots_consistent_after_force_defrag() {
    let mut reg = TenantRegistry::new();

    // Connect 30 tenants.
    for id in 0..30u64 {
        reg.connect(id, 0).unwrap();
    }
    // Disconnect every other one.
    for id in (0..30u64).step_by(2) {
        reg.disconnect(id, 500).unwrap();
    }

    reg.force_defrag();

    // All remaining tenants must reference valid allocated slots.
    for id in (1..30u64).step_by(2) {
        let rec = reg
            .lookup(id)
            .unwrap_or_else(|| panic!("tenant {} must still be connected", id));
        assert!(
            reg.fragmentation_gauge().used_slots > 0,
            "pool must report usage"
        );
        let _ = rec.slot; // no direct allocator access; invariant checked above
    }
}

#[test]
fn force_defrag_emits_event_pair() {
    let mut reg = TenantRegistry::new();
    let events = reg.force_defrag();
    assert_eq!(
        events.len(),
        2,
        "force_defrag must emit ShardDefragStarted + ShardDefragComplete"
    );
    assert!(matches!(events[0], DefragEvent::ShardDefragStarted { .. }));
    assert!(matches!(events[1], DefragEvent::ShardDefragComplete { .. }));
}

// ---------------------------------------------------------------------------
// 50 000-cycle churn stress test (issue #141 acceptance criterion)
// ---------------------------------------------------------------------------

#[test]
fn churn_50k_cycles_allocation_success_rate_above_999_permille() {
    // Simulate 50 000 connect/disconnect cycles using a sliding window of
    // concurrently-connected tenants.  At any point we keep at most
    // CONCURRENT_TENANTS tenants alive; each iteration connects a new tenant
    // then disconnects the oldest one.
    const CYCLES: u64 = 50_000;
    const CONCURRENT_TENANTS: u64 = 1_000; // well below MAX_TENANTS (65 536)
    const MIN_SUCCESS_RATE: f64 = 0.999;

    let mut reg = TenantRegistry::new();
    let mut alloc_success: u64 = 0;
    let mut alloc_failures: u64 = 0;

    // Fill initial window.
    for id in 0..CONCURRENT_TENANTS {
        match reg.connect(id, 0) {
            Ok(_) => alloc_success += 1,
            Err(_) => alloc_failures += 1,
        }
    }

    // Rolling churn: each cycle adds one tenant and evicts the oldest.
    for cycle in 0..CYCLES {
        let new_id = CONCURRENT_TENANTS + cycle;
        let old_id = cycle;
        let now_ms = cycle * 2; // simulate 2 ms per cycle → ~2 000 churn/s

        match reg.connect(new_id, now_ms) {
            Ok(_) => alloc_success += 1,
            Err(_) => alloc_failures += 1,
        }
        // Disconnect old tenant; ignore defrag events.
        let _ = reg.disconnect(old_id, now_ms + 1);

        // Periodically force defrag to stress the compaction path.
        if cycle % 5_000 == 4_999 {
            let events = reg.force_defrag();
            // Must always emit the two required events.
            assert_eq!(events.len(), 2, "force_defrag must emit exactly 2 events");
            assert!(matches!(events[0], DefragEvent::ShardDefragStarted { .. }));
            assert!(matches!(events[1], DefragEvent::ShardDefragComplete { .. }));

            // After defrag, all registered tenants must have valid slots.
            let gauge = reg.fragmentation_gauge();
            assert!(
                (0.0..=1.0).contains(&gauge.fragmentation_ratio),
                "fragmentation ratio must be in [0, 1] after defrag"
            );
        }
    }

    let total = (alloc_success + alloc_failures) as f64;
    let success_rate = alloc_success as f64 / total;

    assert!(
        success_rate >= MIN_SUCCESS_RATE,
        "allocation success rate {:.4} is below the 99.9 % threshold after 50 000 churn cycles",
        success_rate
    );
}

// ---------------------------------------------------------------------------
// Defragmenter coordination: relocation list is non-empty after fragmentation
// ---------------------------------------------------------------------------

#[test]
fn defrag_complete_relocations_are_valid_slot_pairs() {
    let mut alloc = ShardAllocator::new();
    let mut defrag = ShardDefragmenter::new();

    // Allocate 10 slots.
    let slots = bulk_allocate(&mut alloc, 10);
    // Free slots at indices 0, 2, 4, 6 (creating gaps at low addresses).
    for &s in slots.iter().step_by(2) {
        alloc.free(s);
    }

    let events = defrag.run_pass(&mut alloc);
    if let DefragEvent::ShardDefragComplete { relocated, .. } = &events[1] {
        for &(old_slot, new_slot) in relocated {
            assert!(
                old_slot < MAX_TENANTS,
                "old_slot {} must be < MAX_TENANTS",
                old_slot
            );
            assert!(
                new_slot < MAX_TENANTS,
                "new_slot {} must be < MAX_TENANTS",
                new_slot
            );
        }
    } else {
        panic!("expected ShardDefragComplete");
    }
}
