//! Pure normalization, classification, policy, and verification engine.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

pub mod classification;
mod error;
pub mod finding;
pub mod fingerprint;
mod identity;
pub mod normalize;

pub use error::{EngineError, EngineInputError};
pub use identity::deterministic_object_id;
