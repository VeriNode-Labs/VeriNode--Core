use proptest::prelude::*;
use sorosusu_contracts::db::slashing_store::{SlashingStore, SlashingStoreError};
use sorosusu_contracts::slashing::accumulator::SlashingAccumulator;
use sorosusu_contracts::slashing::condition_engine::SlashingConditionEngine;
use sorosusu_contracts::slashing::types::{
    EpochIndex, SlashingError, ValidatorIndex, WindowOffset, WINDOW,
};


#[test]
fn test_window_offset_safe_arithmetic() {
    let offset = WindowOffset::new(4090);
    assert_eq!(offset.as_u16(), 4090);
    assert_eq!(offset.as_usize(), 4090);

    // Saturating add
    assert_eq!(offset.saturating_add(10), WindowOffset(4100));
    assert_eq!(WindowOffset(u16::MAX - 5).saturating_add(10), WindowOffset(u16::MAX));

    // Saturating sub
    assert_eq!(offset.saturating_sub(10), WindowOffset(4080));
    assert_eq!(WindowOffset(5).saturating_sub(10), WindowOffset(0));

    // Checked operations
    assert_eq!(offset.checked_add(5), Some(WindowOffset(4095)));
    assert_eq!(WindowOffset(u16::MAX).checked_add(1), None);
    assert_eq!(offset.checked_sub(4090), Some(WindowOffset(0)));
    assert_eq!(WindowOffset(0).checked_sub(1), None);

    // Wrapping add mod
    assert_eq!(offset.wrapping_add_mod(10, 4096), WindowOffset(4));
}

#[test]
fn test_window_boundary_transitions_4095_to_4096() {
    let mut acc = SlashingAccumulator::new();

    let val_a: ValidatorIndex = 100;
    let val_b: ValidatorIndex = 200;
    let val_c: ValidatorIndex = 300;

    // Slashes:
    // val_c at epoch 0 (gen 0, offset 0)
    // val_a at epoch 4095 (gen 0, offset 4095)
    // val_b at epoch 4096 (gen 1, offset 0)
    acc.record_slashing(val_c, 0);
    acc.record_slashing(val_a, 4095);
    acc.record_slashing(val_b, 4096);

    // Verify val_a
    assert!(acc.check_slashed(val_a, 4095), "val_a must be slashed at 4095");
    assert!(!acc.check_slashed(val_a, 4096), "val_a must not be slashed at 4096");
    assert!(!acc.check_slashed(val_a, 0), "val_a must not be slashed at 0");

    // Verify val_b (offset 0 in generation 1)
    assert!(acc.check_slashed(val_b, 4096), "val_b must be slashed at 4096");
    assert!(!acc.check_slashed(val_b, 0), "val_b must NOT collide with epoch 0 (gen 1 != gen 0)");
    assert!(!acc.check_slashed(val_b, 4095), "val_b must not be slashed at 4095");

    // Verify val_c (offset 0 in generation 0)
    assert!(acc.check_slashed(val_c, 0), "val_c must be slashed at 0");
    assert!(!acc.check_slashed(val_c, 4096), "val_c must NOT collide with epoch 4096 (gen 0 != gen 1)");
    assert!(!acc.check_slashed(val_c, 4095), "val_c must not be slashed at 4095");

    // Generational tag verification
    let tag_a = acc.get_generational_tag(val_a).unwrap();
    assert_eq!(tag_a.window_generation, 0);
    assert_eq!(tag_a.offset, WindowOffset(4095));

    let tag_b = acc.get_generational_tag(val_b).unwrap();
    assert_eq!(tag_b.window_generation, 1);
    assert_eq!(tag_b.offset, WindowOffset(0));

    let tag_c = acc.get_generational_tag(val_c).unwrap();
    assert_eq!(tag_c.window_generation, 0);
    assert_eq!(tag_c.offset, WindowOffset(0));
}

#[test]
fn test_epoch_rollover_above_2_16_zero_false_positives_and_negatives() {
    let mut acc = SlashingAccumulator::new();

    // High epochs past 2^16 (65536)
    let epochs: &[(ValidatorIndex, EpochIndex)] = &[
        (1, 65535),             // gen 15, offset 4095
        (2, 65536),             // gen 16, offset 0
        (3, 65537),             // gen 16, offset 1
        (4, 70000),             // gen 17, offset 368
        (5, 100000),            // gen 24, offset 1696
        (6, 131072),            // gen 32, offset 0 (2^17)
        (7, 1000000),           // gen 244, offset 576
        (8, 10000000),          // gen 2441, offset 1664
    ];

    for &(val, epoch) in epochs {
        acc.record_slashing(val, epoch);
    }

    // 1. Verify ZERO false negatives: all slashed validators must be detected at their epoch
    for &(val, epoch) in epochs {
        assert!(
            acc.check_slashed(val, epoch),
            "False negative: validator {} at epoch {} must be detected as slashed",
            val,
            epoch
        );
    }

    // 2. Verify ZERO false positives across modulo-colliding epochs
    // For validator 2 slashed at 65536 (offset 0, gen 16):
    // Epochs 0, 4096, 8192, 61440, 69632 all share offset 0, but differ in generation!
    let colliding_offsets_with_val2: &[EpochIndex] = &[0, 4096, 8192, 12288, 61440, 69632, 131072];
    for &col_epoch in colliding_offsets_with_val2 {
        assert!(
            !acc.check_slashed(2, col_epoch),
            "False positive: validator 2 at colliding epoch {} must NOT be detected as slashed",
            col_epoch
        );
    }

    // For validator 6 slashed at 131072 (offset 0, gen 32):
    assert!(!acc.check_slashed(6, 0));
    assert!(!acc.check_slashed(6, 4096));
    assert!(!acc.check_slashed(6, 65536));
    assert!(acc.check_slashed(6, 131072));

    // For unslashed validators
    for unslashed_val in 900..950 {
        for &(_val, epoch) in epochs {
            assert!(!acc.check_slashed(unslashed_val, epoch));
        }
    }

}

#[test]
fn test_generational_wrap_and_validator_reslashing() {
    let mut acc = SlashingAccumulator::new();
    let val: ValidatorIndex = 42;

    // Initial slashing in generation 0
    acc.record_slashing(val, 100);
    assert!(acc.check_slashed(val, 100));
    assert_eq!(acc.get_generational_tag(val).unwrap().window_generation, 0);

    // Re-slashing in generation 2 (epoch 8292 = 2 * 4096 + 100)
    let record_new = acc.record_slashing(val, 8292);
    assert_eq!(record_new.window_generation, 2);
    assert_eq!(record_new.offset, WindowOffset(100));

    // Current generation check
    assert!(acc.check_slashed(val, 8292), "Must be slashed at new epoch 8292");
    assert!(!acc.check_slashed(val, 100), "Old slashing at epoch 100 must be cleared");

    // Re-slashing in generation 65535 (epoch = 65535 * 4096 + 100 = 268431460)
    let large_epoch: EpochIndex = (65535 * 4096) + 100;
    acc.record_slashing(val, large_epoch);
    assert!(acc.check_slashed(val, large_epoch));
    assert_eq!(acc.get_generational_tag(val).unwrap().window_generation, 65535);

    // Generational wrap: generation 65536 wraps to 0 in 16-bit space
    // epoch = 65536 * 4096 + 100 = 268435556
    let wrapped_epoch: EpochIndex = (65536 * 4096) + 100;
    acc.record_slashing(val, wrapped_epoch);
    assert!(acc.check_slashed(val, wrapped_epoch));
    assert_eq!(acc.get_generational_tag(val).unwrap().window_generation, 0);
    assert!(!acc.check_slashed(val, large_epoch));
}

#[test]
fn test_condition_engine_lifecycle() {
    let mut engine = SlashingConditionEngine::new();

    let val: ValidatorIndex = 77;
    let epoch: EpochIndex = 12345;

    // First infraction succeeds
    let res = engine.verify_and_record_infraction(val, epoch);
    assert!(res.is_ok());

    // Duplicate infraction at same epoch is rejected
    let dup_res = engine.verify_and_record_infraction(val, epoch);
    assert_eq!(dup_res, Err(SlashingError::AlreadySlashed));

    // Status queries
    assert!(engine.is_slashed(val, epoch));
    assert!(!engine.is_slashed(val, epoch + 1));
    assert!(engine.is_slashed_in_window(val, epoch + 10));
    assert!(!engine.is_slashed_in_window(val, epoch + 5000)); // past 4096 window

    // Export and import state
    let state = engine.export_state();
    let mut new_engine = SlashingConditionEngine::new();
    new_engine.import_state(state);

    assert!(new_engine.is_slashed(val, epoch));
    assert_eq!(new_engine.current_epoch(), engine.current_epoch());
}

#[test]
fn test_slashing_store_serialization_roundtrip() {
    let mut store = SlashingStore::new();

    let mut acc = SlashingAccumulator::new();
    acc.record_slashing(1, 10);
    acc.record_slashing(2, 4096);
    acc.record_slashing(3, 70000);
    acc.record_slashing(4, 1000000);

    store.save_accumulator(&acc);

    assert_eq!(store.len(), 4);
    assert!(store.is_slashed_bit(1));
    assert!(store.is_slashed_bit(2));
    assert!(store.is_slashed_bit(3));
    assert!(store.is_slashed_bit(4));

    // Serialize to bytes
    let bytes = store.to_bytes();
    assert!(!bytes.is_empty());

    // Deserialize
    let restored = SlashingStore::from_bytes(&bytes).expect("Deserialization failed");
    assert_eq!(restored.len(), 4);
    assert_eq!(restored.current_epoch(), store.current_epoch());
    assert_eq!(restored.window_generation(), store.window_generation());

    // Reconstruct accumulator from restored store
    let restored_acc = restored.load_accumulator();
    assert!(restored_acc.check_slashed(1, 10));
    assert!(restored_acc.check_slashed(2, 4096));
    assert!(restored_acc.check_slashed(3, 70000));
    assert!(restored_acc.check_slashed(4, 1000000));

    // Corrupted bytes check
    let mut corrupted = bytes.clone();
    corrupted[0] = b'X';
    assert_eq!(SlashingStore::from_bytes(&corrupted), Err(SlashingStoreError::InvalidMagic));

    let truncated = &bytes[0..10];
    assert_eq!(SlashingStore::from_bytes(truncated), Err(SlashingStoreError::PayloadTruncated));
}

proptest! {
    #[test]
    fn prop_generational_rollover_soundness(
        val in 1u64..10000u64,
        epoch in 0u64..1_000_000u64,
        k in 1u64..20u64
    ) {
        let mut acc = SlashingAccumulator::new();
        acc.record_slashing(val, epoch);

        // 1. Must be slashed at exact epoch
        prop_assert!(acc.check_slashed(val, epoch));

        // 2. Modulo-wrapped epochs must NOT collide (Zero false positives)
        let future_epoch = epoch.saturating_add(k * (WINDOW as u64));
        if future_epoch != epoch {
            prop_assert!(!acc.check_slashed(val, future_epoch));
        }

        // 3. Unrelated validator must NOT be slashed
        prop_assert!(!acc.check_slashed(val + 99999, epoch));
    }
}
