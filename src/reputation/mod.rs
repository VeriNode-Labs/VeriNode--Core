pub mod fixed_point;
pub mod historical_window;
pub mod score;
pub mod score_engine;
pub mod types;

pub use score_engine::{ema_update, update_reputation};
pub use types::{DecayFactor, EmaWeights, MAX_REPUTATION};
