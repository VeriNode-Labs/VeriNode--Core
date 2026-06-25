pub mod fixed_point;
pub mod score;
pub mod score_engine;
pub mod types;

pub use score_engine::{
    apply_decay, decay_for_epochs, ema_update, reputation_weight, update_reputation,
    MAX_DECAY_READOUT_ERROR,
};
pub use types::{
    DecayFactor, EmaWeights, ReputationScore, TimeSinceLastUpdate, WindowSize, DEFAULT_DECAY_Q16,
    DEFAULT_DECAY_Q32, MAX_REPUTATION,
};
