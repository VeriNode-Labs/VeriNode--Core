//! Epoch transition: drains the validator exit queue deterministically.

extern crate alloc;
use alloc::vec::Vec;

use crate::validator::exit_queue::ValidatorIndex;
use crate::validator::validator_set::ValidatorSet;

/// Perform the per-epoch transition for `current_epoch`, draining all eligible
/// exits in canonical `(exit_epoch, validator_index)` order. Returns the
/// processed validator indices in application order.
pub fn epoch_transition(set: &mut ValidatorSet, current_epoch: u64) -> Vec<ValidatorIndex> {
    set.process_exit_queue(current_epoch)
}

/// Deterministic 64-bit commitment over the ordered exit-processing result.
///
/// Two epoch transitions that process the same exits must yield an identical
/// root regardless of the order in which the exits were originally submitted.
/// A change in processing order changes the root — which is exactly the
/// cross-client consensus property #18 is about. (FNV-1a is used as a small,
/// dependency-free stand-in for the production state-root hash.)
pub fn exit_queue_root(processed: &[ValidatorIndex]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for index in processed {
        for byte in index.to_le_bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    hash
}
