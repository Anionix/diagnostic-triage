//! Deterministic merging of classified Findings with the same fingerprint.

use std::collections::{BTreeMap, BTreeSet};

use diagnostic_triage_contracts::{
    Fingerprint,
    model::{Finding, FindingState, Severity},
};

use crate::{
    EngineError, EngineInputError,
    finding::{finding_id_for_finding, validate_finding_integrity},
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// Merge duplicate classified findings and return fingerprint-sorted output.
///
/// # Errors
///
/// Returns an error when a Finding is invalid, has a forged fingerprint, is
/// not in `CLASSIFIED`, or conflicts with another Finding sharing its digest.
pub fn deduplicate_findings(findings: Vec<Finding>) -> Result<Vec<Finding>, EngineError> {
    let mut groups = BTreeMap::<Fingerprint, Vec<Finding>>::new();
    for finding in findings {
        finding.validate()?;
        validate_finding_integrity(&finding)?;
        if finding.state != FindingState::Classified
            || finding.fix_candidate_id.is_some()
            || finding.verification_execution_ids.is_some()
        {
            return Err(EngineInputError::InvalidDeduplicationState.into());
        }
        groups
            .entry(finding.fingerprint.clone())
            .or_default()
            .push(finding);
    }

    groups
        .into_values()
        .map(merge_group)
        .collect::<Result<Vec<_>, _>>()
}

fn merge_group(mut group: Vec<Finding>) -> Result<Finding, EngineError> {
    group.sort_by_key(canonical_finding);
    let mut canonical = group
        .first()
        .cloned()
        .ok_or(EngineInputError::EmptyDeduplicationGroup)?;
    let fingerprint = canonical.fingerprint.to_string();

    let mut observation_ids = BTreeSet::new();
    let mut evidence_ids = BTreeSet::new();
    for finding in &group {
        require_same(
            &canonical.tool.name,
            &finding.tool.name,
            &fingerprint,
            "tool name",
        )?;
        require_same(
            &canonical.tool.rule_id,
            &finding.tool.rule_id,
            &fingerprint,
            "rule id",
        )?;
        require_same(
            &canonical.language,
            &finding.language,
            &fingerprint,
            "language",
        )?;
        require_same(
            &canonical.classification,
            &finding.classification,
            &fingerprint,
            "classification",
        )?;
        require_same(
            &canonical.location.as_ref().map(|location| &location.path),
            &finding.location.as_ref().map(|location| &location.path),
            &fingerprint,
            "repository path",
        )?;
        require_same(&canonical.symbol, &finding.symbol, &fingerprint, "symbol")?;
        require_same(
            &canonical.message,
            &finding.message,
            &fingerprint,
            "message",
        )?;
        require_same(
            &canonical.expected,
            &finding.expected,
            &fingerprint,
            "expected value",
        )?;
        require_same(
            &canonical.observed,
            &finding.observed,
            &fingerprint,
            "observed value",
        )?;
        observation_ids.extend(finding.observation_ids.iter().cloned());
        evidence_ids.extend(finding.evidence_ids.iter().cloned());
        if severity_rank(&finding.severity) > severity_rank(&canonical.severity) {
            canonical.severity = finding.severity.clone();
        }
    }
    canonical.observation_ids = observation_ids.into_iter().collect();
    canonical.evidence_ids = evidence_ids.into_iter().collect();
    canonical.finding_id = finding_id_for_finding(&canonical)?;
    canonical.validate()?;
    Ok(canonical)
}

fn require_same<T: Eq>(
    left: &T,
    right: &T,
    fingerprint: &str,
    field: &'static str,
) -> Result<(), EngineError> {
    if left == right {
        Ok(())
    } else {
        Err(EngineError::ConflictingFinding {
            fingerprint: fingerprint.into(),
            field,
        })
    }
}

fn canonical_finding(finding: &Finding) -> String {
    // Provider references and severity are merge-owned fields. Keep them out
    // of the representative key; finding_id is only the final deterministic
    // tie-break when all semantic fields are identical.
    serde_json::to_string(&(
        &finding.schema_version,
        &finding.tool,
        &finding.language,
        &finding.classification,
        &finding.message,
        &finding.location,
        &finding.symbol,
        &finding.expected,
        &finding.observed,
        &finding.state,
        &finding.finding_id,
    ))
    .expect("validated Finding semantic fields serialize infallibly")
}

const fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
    }
}
