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
    #[error("deduplication input exceeds the v1 limit of {max} findings: {actual}")]
    DeduplicationInputTooLarge { actual: usize, max: usize },
    #[error("deduplicated finding exceeds the v1 {field} limit of {max}")]
    DeduplicatedReferenceLimit { field: &'static str, max: usize },
    #[error("classification rule ID must contain 1..=128 characters, got {length}")]
    InvalidClassificationRuleId { length: usize },
    #[error("classification rule {rule_id} has an invalid tool name")]
    InvalidClassificationToolName { rule_id: String },
    #[error("classification rule {rule_id} has a noncanonical tool name")]
    NonCanonicalClassificationToolName { rule_id: String },
    #[error("classification rule {rule_id} has an invalid tool version")]
    InvalidClassificationToolVersion { rule_id: String },
    #[error("classification rule {rule_id} has a noncanonical tool version")]
    NonCanonicalClassificationToolVersion { rule_id: String },
    #[error("classification rule {rule_id} has an invalid native rule ID")]
    InvalidClassificationNativeRuleId { rule_id: String },
    #[error("classification rule {rule_id} has a noncanonical native rule ID")]
    NonCanonicalClassificationNativeRuleId { rule_id: String },
    #[error("classification rule ID is duplicated: {rule_id}")]
    DuplicateClassificationRuleId { rule_id: String },
    #[error("classification catalog exceeds the v1 limit of {max} rules: {actual}")]
    ClassificationCatalogTooLarge { actual: usize, max: usize },
    #[error("observation {observation_id} has a noncanonical tool identity")]
    NonCanonicalObservationTool { observation_id: String },
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
    #[error(
        "taxonomy rules are ambiguous for observation {observation_id}: {rule_ids:?} (+{omitted_rule_count} more)"
    )]
    AmbiguousClassification {
        observation_id: String,
        rule_ids: Vec<String>,
        omitted_rule_count: usize,
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
