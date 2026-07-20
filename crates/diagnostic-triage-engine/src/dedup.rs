//! Deterministic merging of classified Findings with the same fingerprint.
//!
//! Provider references form bounded set unions, severity forms the strictest
//! `INFO < WARNING < ERROR` join, and source coordinates use the earliest
//! numeric representative. Tool version and taxonomy conflicts are never
//! merged.

use std::collections::{BTreeMap, BTreeSet};

use diagnostic_triage_contracts::{
    Fingerprint, ObjectId,
    model::{Finding, FindingState, Severity},
};

use crate::{
    EngineError, EngineInputError,
    finding::{finding_id_for_finding, validate_finding_integrity},
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// Maximum number of Findings accepted by one v1 deduplication call.
pub const MAX_DEDUPLICATION_FINDINGS: usize = 10_000;
const MAX_MERGED_OBSERVATION_IDS: usize = 1_024;
const MAX_MERGED_EVIDENCE_IDS: usize = 64;

/// Merge duplicate classified findings and return fingerprint-sorted output.
///
/// # Errors
///
/// Returns an error when a Finding is invalid, has forged Engine identity, is
/// not in `CLASSIFIED`, exceeds v1 bounds, or conflicts with another Finding
/// sharing its fingerprint.
pub fn deduplicate_findings(findings: Vec<Finding>) -> Result<Vec<Finding>, EngineError> {
    if findings.len() > MAX_DEDUPLICATION_FINDINGS {
        return Err(EngineInputError::DeduplicationInputTooLarge {
            actual: findings.len(),
            max: MAX_DEDUPLICATION_FINDINGS,
        }
        .into());
    }

    let mut groups = BTreeMap::<Fingerprint, Vec<Finding>>::new();
    for finding in findings {
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

fn merge_group(group: Vec<Finding>) -> Result<Finding, EngineError> {
    let mut group = group.into_iter();
    let mut canonical = group
        .next()
        .ok_or(EngineInputError::EmptyDeduplicationGroup)?;
    let mut canonical_key = coordinate_key(&canonical);
    let fingerprint = canonical.fingerprint.to_string();
    let mut severity = canonical.severity.clone();
    let mut observation_ids = BTreeSet::new();
    let mut evidence_ids = BTreeSet::new();
    extend_bounded(
        &mut observation_ids,
        &canonical.observation_ids,
        "observation_ids",
        MAX_MERGED_OBSERVATION_IDS,
    )?;
    extend_bounded(
        &mut evidence_ids,
        &canonical.evidence_ids,
        "evidence_ids",
        MAX_MERGED_EVIDENCE_IDS,
    )?;

    for finding in group {
        require_compatible(&canonical, &finding, &fingerprint)?;

        extend_bounded(
            &mut observation_ids,
            &finding.observation_ids,
            "observation_ids",
            MAX_MERGED_OBSERVATION_IDS,
        )?;
        extend_bounded(
            &mut evidence_ids,
            &finding.evidence_ids,
            "evidence_ids",
            MAX_MERGED_EVIDENCE_IDS,
        )?;
        if severity_rank(&finding.severity) > severity_rank(&severity) {
            severity = finding.severity.clone();
        }

        let finding_key = coordinate_key(&finding);
        if finding_key < canonical_key {
            canonical = finding;
            canonical_key = finding_key;
        }
    }

    canonical.severity = severity;
    canonical.observation_ids = observation_ids.into_iter().collect();
    canonical.evidence_ids = evidence_ids.into_iter().collect();
    canonical.finding_id = finding_id_for_finding(&canonical)?;
    canonical.validate()?;
    validate_finding_integrity(&canonical)?;
    Ok(canonical)
}

fn require_compatible(
    canonical: &Finding,
    finding: &Finding,
    fingerprint: &str,
) -> Result<(), EngineError> {
    require_same(
        &canonical.schema_version,
        &finding.schema_version,
        fingerprint,
        "schema version",
    )?;
    require_same(
        &canonical.tool.name,
        &finding.tool.name,
        fingerprint,
        "tool name",
    )?;
    require_same(
        &canonical.tool.version,
        &finding.tool.version,
        fingerprint,
        "tool version",
    )?;
    require_same(
        &canonical.tool.rule_id,
        &finding.tool.rule_id,
        fingerprint,
        "rule id",
    )?;
    require_same(
        &canonical.language,
        &finding.language,
        fingerprint,
        "language",
    )?;
    require_same(
        &canonical.classification,
        &finding.classification,
        fingerprint,
        "classification",
    )?;
    require_same(
        &canonical.location.as_ref().map(|location| &location.path),
        &finding.location.as_ref().map(|location| &location.path),
        fingerprint,
        "repository path",
    )?;
    require_same(&canonical.symbol, &finding.symbol, fingerprint, "symbol")?;
    require_same(&canonical.message, &finding.message, fingerprint, "message")?;
    require_same(
        &canonical.expected,
        &finding.expected,
        fingerprint,
        "expected value",
    )?;
    require_same(
        &canonical.observed,
        &finding.observed,
        fingerprint,
        "observed value",
    )
}

fn extend_bounded(
    output: &mut BTreeSet<ObjectId>,
    values: &[ObjectId],
    field: &'static str,
    max: usize,
) -> Result<(), EngineError> {
    for value in values {
        output.insert(value.clone());
        if output.len() > max {
            return Err(EngineInputError::DeduplicatedReferenceLimit { field, max }.into());
        }
    }
    Ok(())
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

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct CoordinateKey {
    line: u32,
    column: u32,
    end: Option<(u32, u32)>,
}

fn coordinate_key(finding: &Finding) -> Option<CoordinateKey> {
    finding.location.as_ref().map(|location| CoordinateKey {
        line: location.start.line,
        column: location.start.column,
        end: location.end.as_ref().map(|end| (end.line, end.column)),
    })
}

const fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
    }
}
