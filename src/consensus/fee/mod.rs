//! Fee settlement: burn/tip split for finalized blocks (issue #63).

pub mod burn;

pub use burn::split_fee;
