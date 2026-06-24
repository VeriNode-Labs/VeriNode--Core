/// Maximum reputation score accepted by validator selection.
pub const MAX_REPUTATION: u64 = 1_000_000;

/// EMA window size, expressed in epochs.
pub type WindowSize = u64;

/// Epochs elapsed since the validator reputation was last updated.
pub type TimeSinceLastUpdate = u64;

/// Reputation EMA parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmaWeights {
    pub window_epochs: WindowSize,
}

impl EmaWeights {
    pub const fn new(window_epochs: WindowSize) -> Self {
        Self { window_epochs }
    }
}

impl Default for EmaWeights {
    fn default() -> Self {
        Self::new(2048)
    }
}
