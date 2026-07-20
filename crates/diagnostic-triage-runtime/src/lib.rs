//! Runtime configuration and bounded process orchestration for Diagnostic Triage.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

pub mod config;
pub mod process;

pub use config::{ConfigError, RuntimeConfig};
