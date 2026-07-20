//! Pure normalization, classification, policy, and verification engine.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

pub mod classification;
pub mod dedup;
mod error;
pub mod finding;
pub mod fingerprint;
mod identity;
pub mod normalize;
pub mod policy;
pub mod report;

pub use error::{EngineError, EngineInputError};
pub use identity::deterministic_object_id;
