//! IBC packet commitment timeouts across variable block-time chains
//! (issue #138).
//!
//! An IBC packet carries a `timeout_height` denominated in the *destination*
//! chain's blocks. Deriving that height from a fixed, assumed block time
//! mis-times every packet the moment the destination chain's real block time
//! departs from the assumption — and it departs constantly, both because chains
//! differ from one another and because a single chain's block time moves under
//! load.
//!
//! * [`block_time_estimator`] — the per-chain sliding window of block-time
//!   samples and the three statistics derived from it (mean, p95, EMA).
//! * [`packet_timeout`] — the timeout-height formula, its unit derivation, and
//!   the cold-start safety margin.
//! * [`packet_relayer`] — in-flight packet tracking, misestimation
//!   classification, the recalibration trigger, and the observability events.
//!
//! Samples reach the estimator from the existing header-sync pipeline via
//! [`crate::cross_chain::ConnectedChain::observe_header`]; there is no second
//! header path.
//!
//! Like the rest of [`crate::cross_chain`], everything here is deterministic,
//! integer-only, and dependency-free so it compiles to WASM (`no_std`) and is
//! shared verbatim by off-chain relayers.

#[path = "block-time-estimator.rs"]
pub mod block_time_estimator;

#[path = "packet-timeout.rs"]
pub mod packet_timeout;

#[path = "packet-relayer.rs"]
pub mod packet_relayer;
