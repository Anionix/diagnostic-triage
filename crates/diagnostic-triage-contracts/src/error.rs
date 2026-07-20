//! Contract validation failures.

use thiserror::Error;

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// A stable error category with a human-readable contract violation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractError {
    /// Input was not one complete, duplicate-free JSON value per non-empty line.
    #[error("invalid JSON Lines input: {0}")]
    JsonLines(String),
    /// A typed v1 model object violated a shape or cross-reference invariant.
    #[error("invalid v1 model: {0}")]
    Model(String),
    /// A v1 transcript violated handshake, ordering, capability, or limit rules.
    #[error("invalid v1 protocol session: {0}")]
    Protocol(String),
}
