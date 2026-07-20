//! Versioned, policy-independent wire contracts for Diagnostic Triage.

mod error;
mod jsonl;
pub mod model;
pub mod protocol;
mod scalar;
mod validate;
mod wire;

pub use error::ContractError;
pub use scalar::{
    AdapterId, Capability, Fingerprint, Language, ObjectId, RepoPath, Sha256Digest, SourceRevision,
};
pub use validate::{
    ValidatedSession, validate_report, validate_report_json, validate_session_jsonl,
};
pub use wire::Nullable;

/// Canonical JSON Schema for shared v1 scalar and location types.
pub const COMMON_SCHEMA_V1: &str =
    include_str!("../../../schemas/diagnostic-triage/v1/common.schema.json");
/// Canonical JSON Schema for v1 model objects.
pub const MODEL_SCHEMA_V1: &str =
    include_str!("../../../schemas/diagnostic-triage/v1/model.schema.json");
/// Canonical JSON Schema for the v1 Provider protocol.
pub const PROTOCOL_SCHEMA_V1: &str =
    include_str!("../../../schemas/diagnostic-triage/v1/protocol.schema.json");
/// Canonical JSON Schema for the v1 classification taxonomy.
pub const TAXONOMY_SCHEMA_V1: &str =
    include_str!("../../../schemas/diagnostic-triage/v1/taxonomy.schema.json");

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.
