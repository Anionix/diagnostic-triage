//! Construction and integrity checking for Engine-owned Findings.

use diagnostic_triage_contracts::model::{
    Finding, FindingSchemaVersion, FindingState, Observation, Severity, Taxonomy, Tool,
};
use diagnostic_triage_contracts::{Fingerprint, ObjectId};

use crate::classification::{ClassificationRule, classify_observation};
use crate::fingerprint::fingerprint_finding;
use crate::normalize::{
    DiagnosticText, normalize_context, normalize_diagnostic, normalize_message,
};
use crate::{EngineError, EngineInputError, deterministic_object_id};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// A Finding together with the generic taxonomy rule that classified it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassifiedFinding {
    pub finding: Finding,
    pub classification_rule_id: String,
}

/// Normalize and classify one Provider observation using structured rule identity.
///
/// # Errors
///
/// Returns an error when the Observation, taxonomy catalog, normalized text,
/// or derived contract values violate the v1 invariants.
pub fn build_finding(
    observation: &Observation,
    rules: &[ClassificationRule],
) -> Result<ClassifiedFinding, EngineError> {
    let classification = classify_observation(observation, rules)?;
    let finding = build_finding_with_taxonomy(observation, &classification.taxonomy)?;
    Ok(ClassifiedFinding {
        finding,
        classification_rule_id: classification.rule_id,
    })
}

/// Normalize one Provider observation into a classified, Engine-owned Finding.
///
/// # Errors
///
/// Returns an error when the Observation, taxonomy, normalized identity, or
/// resulting Finding violates the v1 contracts.
pub fn build_finding_with_taxonomy(
    observation: &Observation,
    taxonomy: &Taxonomy,
) -> Result<Finding, EngineError> {
    observation.validate()?;
    taxonomy.validate()?;

    let message = normalize_message(&observation.message)?;
    let symbol = normalize_optional_text(observation.symbol.as_deref(), "symbol")?;
    let expected = normalize_optional_text(observation.expected.as_deref(), "expected")?;
    let observed = normalize_optional_text(observation.observed.as_deref(), "observed")?;
    let tool = normalize_tool(&observation.tool)?;
    let context = normalize_diagnostic(&DiagnosticText::new(
        &message,
        expected.as_deref(),
        observed.as_deref(),
    ))?;
    let path = observation.location.as_ref().map(|location| &location.path);
    let fingerprint = fingerprint_finding(
        &tool,
        &observation.language,
        path,
        symbol.as_deref(),
        &context,
    )?;
    let finding_id = finding_id_from_fields(&fingerprint, &observation.severity, taxonomy)?;

    let finding = Finding {
        schema_version: FindingSchemaVersion::V1,
        finding_id,
        fingerprint,
        observation_ids: vec![observation.observation_id.clone()],
        tool,
        language: observation.language.clone(),
        severity: observation.severity.clone(),
        classification: taxonomy.clone(),
        message,
        location: observation.location.clone(),
        symbol,
        expected,
        observed,
        state: FindingState::Classified,
        evidence_ids: observation.evidence_ids.clone(),
        fix_candidate_id: None,
        verification_execution_ids: None,
    };
    finding.validate()?;
    Ok(finding)
}

/// Recompute a Finding fingerprint from its normalized identity fields.
///
/// # Errors
///
/// Returns an error when the Finding or one of its identity fields is invalid.
pub fn fingerprint_for_finding(finding: &Finding) -> Result<Fingerprint, EngineError> {
    finding.validate()?;
    let context = normalize_diagnostic(&DiagnosticText::new(
        &finding.message,
        finding.expected.as_deref(),
        finding.observed.as_deref(),
    ))?;
    Ok(fingerprint_finding(
        &finding.tool,
        &finding.language,
        finding.location.as_ref().map(|location| &location.path),
        finding.symbol.as_deref(),
        &context,
    )?)
}

/// Derive the Engine-owned Finding ID from stable and policy-significant data.
///
/// # Errors
///
/// Returns an error when the Finding contract, canonical encoding, or
/// deterministic ID derivation fails.
pub fn finding_id_for_finding(finding: &Finding) -> Result<ObjectId, EngineError> {
    finding.validate()?;
    finding_id_from_fields(
        &finding.fingerprint,
        &finding.severity,
        &finding.classification,
    )
}

/// Reject forged or stale Finding identity at every Engine ingress.
///
/// Both the semantic fingerprint and its derived object ID are Engine-owned.
///
/// # Errors
///
/// Returns an error when normalization or identity recomputation fails, or
/// when a recomputed value differs from the stored value.
pub fn validate_finding_integrity(finding: &Finding) -> Result<(), EngineError> {
    finding.validate()?;
    validate_normalized_identity(finding)?;
    if fingerprint_for_finding(finding)? != finding.fingerprint {
        return Err(EngineError::FingerprintMismatch {
            finding_id: finding.finding_id.to_string(),
        });
    }
    let expected_id = finding_id_for_finding(finding)?;
    if finding.finding_id != expected_id {
        return Err(EngineError::FindingIdMismatch {
            finding_id: finding.finding_id.to_string(),
            expected_id: expected_id.to_string(),
        });
    }
    Ok(())
}

fn finding_id_from_fields(
    fingerprint: &Fingerprint,
    severity: &Severity,
    taxonomy: &Taxonomy,
) -> Result<ObjectId, EngineError> {
    let policy_identity = serde_json::to_string(&(severity, taxonomy)).map_err(|error| {
        EngineError::IdentityEncoding {
            object: "finding",
            reason: error.to_string(),
        }
    })?;
    deterministic_object_id(
        "diagnostic-triage.finding-id/v1",
        [fingerprint.as_str(), policy_identity.as_str()],
    )
}

fn validate_normalized_identity(finding: &Finding) -> Result<(), EngineError> {
    if normalize_tool(&finding.tool)? != finding.tool {
        return Err(EngineInputError::NonCanonicalFindingField { field: "tool" }.into());
    }
    if normalize_message(&finding.message)? != finding.message {
        return Err(EngineInputError::NonCanonicalFindingField { field: "message" }.into());
    }
    if normalize_optional_text(finding.symbol.as_deref(), "symbol")? != finding.symbol {
        return Err(EngineInputError::NonCanonicalFindingField { field: "symbol" }.into());
    }
    if normalize_optional_text(finding.expected.as_deref(), "expected")? != finding.expected {
        return Err(EngineInputError::NonCanonicalFindingField { field: "expected" }.into());
    }
    if normalize_optional_text(finding.observed.as_deref(), "observed")? != finding.observed {
        return Err(EngineInputError::NonCanonicalFindingField { field: "observed" }.into());
    }
    Ok(())
}

fn normalize_tool(tool: &Tool) -> Result<Tool, EngineError> {
    let normalized = Tool {
        name: normalize_required_text(&tool.name, "tool.name")?,
        version: normalize_required_text(&tool.version, "tool.version")?,
        rule_id: normalize_optional_text(tool.rule_id.as_deref(), "tool.rule_id")?,
    };
    normalized.validate()?;
    Ok(normalized)
}

fn normalize_required_text(value: &str, field: &'static str) -> Result<String, EngineError> {
    let normalized = normalize_context(value);
    if normalized.is_empty() {
        Err(EngineInputError::EmptyNormalizedFindingField { field }.into())
    } else {
        Ok(normalized)
    }
}

fn normalize_optional_text(
    value: Option<&str>,
    field: &'static str,
) -> Result<Option<String>, EngineError> {
    value
        .map(|value| normalize_required_text(value, field))
        .transpose()
}
