//! Errors raised by the pure Diagnostic Triage engine.

use diagnostic_triage_contracts::ContractError;
use thiserror::Error;

use crate::{fingerprint::FingerprintError, normalize::NormalizationError};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

#[derive(Debug, Error)]
pub enum EngineInputError {
    #[error("deduplication accepts only CLASSIFIED findings")]
    InvalidDeduplicationState,
    #[error("deduplication received an empty internal group")]
    EmptyDeduplicationGroup,
    #[error("classification rule ID must contain 1..=128 characters: {rule_id:?}")]
    InvalidClassificationRuleId { rule_id: String },
    #[error("classification rule {rule_id} has an invalid tool name")]
    InvalidClassificationToolName { rule_id: String },
    #[error("classification rule {rule_id} has a noncanonical tool name")]
    NonCanonicalClassificationToolName { rule_id: String },
    #[error("classification rule {rule_id} has an invalid native rule ID")]
    InvalidClassificationNativeRuleId { rule_id: String },
    #[error("classification rule {rule_id} has a noncanonical native rule ID")]
    NonCanonicalClassificationNativeRuleId { rule_id: String },
    #[error("classification rule ID is duplicated: {rule_id}")]
    DuplicateClassificationRuleId { rule_id: String },
    #[error("finding field {field} is not normalized")]
    NonCanonicalFindingField { field: &'static str },
    #[error("finding field {field} is empty after normalization")]
    EmptyNormalizedFindingField { field: &'static str },
    #[error("deterministic ID domain must not be empty")]
    EmptyDeterministicIdDomain,
    #[error("deterministic ID field is too large")]
    DeterministicIdFieldTooLarge,
    #[error("derived object ID is invalid: {reason}")]
    InvalidDerivedObjectId { reason: String },
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error(transparent)]
    Fingerprint(#[from] FingerprintError),
    #[error(transparent)]
    Normalization(#[from] NormalizationError),
    #[error(transparent)]
    Input(#[from] EngineInputError),
    #[error("no taxonomy rule matched observation {observation_id}")]
    Unclassified { observation_id: String },
    #[error("taxonomy rules are ambiguous for observation {observation_id}: {rule_ids}")]
    AmbiguousClassification {
        observation_id: String,
        rule_ids: String,
    },
    #[error("findings with fingerprint {fingerprint} have conflicting {field}")]
    ConflictingFinding {
        fingerprint: String,
        field: &'static str,
    },
    #[error("finding {finding_id} has a fingerprint inconsistent with its normalized identity")]
    FingerprintMismatch { finding_id: String },
    #[error("finding ID {finding_id} does not match deterministic ID {expected_id}")]
    FindingIdMismatch {
        finding_id: String,
        expected_id: String,
    },
    #[error("decision ID {decision_id} does not match deterministic ID {expected_id}")]
    DecisionIdMismatch {
        decision_id: String,
        expected_id: String,
    },
    #[error("failed to encode {object} identity: {reason}")]
    IdentityEncoding {
        object: &'static str,
        reason: String,
    },
}
