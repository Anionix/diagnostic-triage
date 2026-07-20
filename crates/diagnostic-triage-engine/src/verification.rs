//! Pure before/after verification for authoritative safe fixes.

use std::collections::{BTreeMap, BTreeSet};

use diagnostic_triage_contracts::model::{
    AdapterKind, Applicability, Evidence, EvidenceSource, Execution, ExecutionStatus, Finding,
    FindingState, FixCandidate, Severity, VerificationAttribution,
};
use diagnostic_triage_contracts::{
    ContractError, Fingerprint, MAX_REPORT_BYTES, ObjectId, RepoPath, Sha256Digest,
};
use thiserror::Error;

use crate::{
    EngineError,
    dedup::{MAX_DEDUPLICATION_FINDINGS, deduplicate_findings},
    finding::validate_finding_integrity,
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// Maximum number of evidence objects or executions accepted by one comparison.
pub const MAX_VERIFICATION_OBJECTS: usize = 10_000;
/// Maximum number of target fingerprints or conflicting paths accepted by v1.
pub const MAX_VERIFICATION_TARGETS: usize = 1_024;

/// Result of applying the candidate patch in a scratch workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PatchApplication {
    Applied {
        patch_sha256: Sha256Digest,
        base_snapshot_sha256: Sha256Digest,
    },
    Conflict {
        patch_sha256: Sha256Digest,
        base_snapshot_sha256: Sha256Digest,
        paths: Vec<RepoPath>,
    },
}

/// Bounded, policy-independent input for one safe-fix comparison.
#[derive(Clone, Copy)]
pub struct SafeFixComparisonInput<'a> {
    pub candidate: &'a FixCandidate,
    pub target_fingerprints: &'a [Fingerprint],
    pub evidence: &'a [Evidence],
    pub executions: &'a [Execution],
    pub patch_application: &'a PatchApplication,
    pub before_findings: &'a [Finding],
    pub after_findings: &'a [Finding],
}

/// A deterministic reason why a well-formed candidate was not verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationRejection {
    CandidateNotSafe { applicability: Applicability },
    PatchConflict { paths: Vec<RepoPath> },
    RequiredProviderIncomplete { execution_ids: Vec<ObjectId> },
    RequiredProviderUnsupported { execution_ids: Vec<ObjectId> },
    TargetStillPresent { fingerprints: Vec<Fingerprint> },
    ExistingSeverityEscalation { fingerprints: Vec<Fingerprint> },
    NewFindingAtOrAboveTargetFloor { fingerprints: Vec<Fingerprint> },
}

/// Canonical artifacts authorized by a successful comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedFix {
    pub verified_targets: Vec<Finding>,
    pub post_fix_findings: Vec<Finding>,
    pub new_lower_severity_fingerprints: Vec<Fingerprint>,
}

/// Safe-fix comparison result. Expected fix failures are not input errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SafeFixVerification {
    Verified(VerifiedFix),
    Rejected { reasons: Vec<VerificationRejection> },
}

/// Malformed or referentially inconsistent comparison input.
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error("{field} exceeds the v1 limit of {max} items: {actual}")]
    InputTooLarge {
        field: &'static str,
        actual: usize,
        max: usize,
    },
    #[error("evidence retained bytes exceed the v1 aggregate limit of {max}: {actual}")]
    EvidenceBytesTooLarge { actual: u64, max: u64 },
    #[error("target_fingerprints must contain 1..={MAX_VERIFICATION_TARGETS} items")]
    InvalidTargetCount,
    #[error("target_fingerprints contains a duplicate: {fingerprint}")]
    DuplicateTarget { fingerprint: Fingerprint },
    #[error("{field} contains a duplicate object ID: {object_id}")]
    DuplicateObjectId {
        field: &'static str,
        object_id: ObjectId,
    },
    #[error("conflict paths exceed the v1 limit of {max} items: {actual}")]
    ConflictPathsTooLarge { actual: usize, max: usize },
    #[error("invalid {phase} finding: {source}")]
    InvalidFinding {
        phase: &'static str,
        #[source]
        source: EngineError,
    },
    #[error("{phase} finding {finding_id} has invalid lifecycle state {state:?}")]
    InvalidFindingState {
        phase: &'static str,
        finding_id: ObjectId,
        state: FindingState,
    },
    #[error("failed to encode {phase} finding for deterministic ordering: {reason}")]
    FindingEncoding { phase: &'static str, reason: String },
    #[error("candidate references an observation absent from before findings: {observation_id}")]
    UnknownCandidateObservation { observation_id: ObjectId },
    #[error("candidate observation {observation_id} crosses tool name or version identity")]
    CandidateToolMismatch { observation_id: ObjectId },
    #[error("target fingerprint is absent from before findings: {fingerprint}")]
    UnknownTarget { fingerprint: Fingerprint },
    #[error("target {fingerprint} is not FIX_PROPOSED for candidate {candidate_id}")]
    TargetNotProposed {
        fingerprint: Fingerprint,
        candidate_id: ObjectId,
    },
    #[error("target {fingerprint} is also proposed for another candidate")]
    TargetCandidateConflict { fingerprint: Fingerprint },
    #[error("target {fingerprint} contains an observation outside the candidate scope")]
    TargetOutsideCandidateScope { fingerprint: Fingerprint },
    #[error("candidate references unknown patch evidence: {evidence_id}")]
    UnknownPatchEvidence { evidence_id: ObjectId },
    #[error("evidence {evidence_id} references unknown execution {execution_id}")]
    UnknownEvidenceExecution {
        evidence_id: ObjectId,
        execution_id: ObjectId,
    },
    #[error("{phase} finding {finding_id} references unknown evidence {evidence_id}")]
    UnknownFindingEvidence {
        phase: &'static str,
        finding_id: ObjectId,
        evidence_id: ObjectId,
    },
    #[error("candidate patch evidence is not a complete inline patch")]
    InvalidPatchEvidence,
    #[error("patch application {field} digest differs from verification attribution")]
    PatchApplicationDigestMismatch { field: &'static str },
    #[error("patch application references no complete inline base snapshot evidence")]
    PatchApplicationBaseSnapshotMissing,
    #[error("verification execution {execution_id} has attribution for another candidate")]
    AttributionCandidateMismatch { execution_id: ObjectId },
    #[error("verification execution {execution_id} must be required")]
    AttributionExecutionNotRequired { execution_id: ObjectId },
    #[error("verification execution {execution_id} patch digest differs from patch evidence")]
    AttributionPatchMismatch { execution_id: ObjectId },
    #[error("verification execution {execution_id} references invalid base snapshot evidence")]
    InvalidBaseSnapshot { execution_id: ObjectId },
    #[error("verification executions disagree on the base snapshot")]
    BaseSnapshotMismatch,
    #[error("verification execution {execution_id} references invalid result evidence")]
    InvalidResultEvidence { execution_id: ObjectId },
    #[error("verification attribution contains an unexpected target: {fingerprint}")]
    UnexpectedAttributedTarget { fingerprint: Fingerprint },
    #[error("verification attribution does not cover target: {fingerprint}")]
    MissingTargetAttribution { fingerprint: Fingerprint },
    #[error("verification execution {execution_id} tool differs from target {fingerprint}")]
    AttributionToolMismatch {
        execution_id: ObjectId,
        fingerprint: Fingerprint,
    },
    #[error("target {fingerprint} exceeds the v1 limit of {max} verification executions: {actual}")]
    TargetExecutionLimit {
        fingerprint: Fingerprint,
        actual: usize,
        max: usize,
    },
}

/// Compare canonical before/after Findings and authorize only a verified safe fix.
///
/// Expected operational failures are returned as [`SafeFixVerification::Rejected`].
/// Malformed contract objects, dangling references, forged Finding identities,
/// and unbounded inputs are returned as [`VerificationError`].
///
/// # Errors
///
/// Returns a typed input error when any supplied object violates the v1
/// contract or its cross-object attribution.
pub fn compare_safe_fix(
    input: SafeFixComparisonInput<'_>,
) -> Result<SafeFixVerification, VerificationError> {
    preflight_bounds(&input)?;
    input.candidate.validate()?;

    let targets = collect_targets(input.target_fingerprints)?;
    let evidence = index_evidence(input.evidence)?;
    let executions = index_executions(input.executions)?;
    validate_object_id_domains(&input)?;
    validate_evidence_execution_references(&evidence, &executions)?;
    validate_finding_evidence_references("before", input.before_findings, &evidence)?;
    validate_finding_evidence_references("after", input.after_findings, &evidence)?;
    let before = canonical_findings("before", input.before_findings, true)?;
    let after = canonical_findings("after", input.after_findings, false)?;

    validate_candidate_scope(input.candidate, input.before_findings, &before, &targets)?;
    let patch = validate_patch(input.candidate, &evidence)?;
    let application_base_sha256 =
        validate_patch_application(input.patch_application, &patch.sha256, &evidence)?;
    let operational_rejections =
        collect_operational_rejections(input.candidate, input.patch_application, &executions);
    if !operational_rejections.is_empty() {
        return Ok(SafeFixVerification::Rejected {
            reasons: operational_rejections,
        });
    }
    let (verification_ids, base_snapshot_sha256) = validate_attributions(
        input.candidate,
        patch,
        &targets,
        &before,
        &evidence,
        &executions,
    )?;
    if application_base_sha256 != base_snapshot_sha256 {
        return Err(VerificationError::PatchApplicationDigestMismatch {
            field: "base_snapshot_sha256",
        });
    }

    let (reasons, new_findings) = collect_finding_rejections(&targets, &before, &after)?;

    if !reasons.is_empty() {
        return Ok(SafeFixVerification::Rejected { reasons });
    }

    let verified_targets =
        build_verified_targets(input.candidate, &targets, &before, &verification_ids)?;
    Ok(SafeFixVerification::Verified(VerifiedFix {
        verified_targets,
        post_fix_findings: after.into_values().collect(),
        new_lower_severity_fingerprints: new_findings,
    }))
}

fn collect_operational_rejections(
    candidate: &FixCandidate,
    patch_application: &PatchApplication,
    executions: &BTreeMap<ObjectId, &Execution>,
) -> Vec<VerificationRejection> {
    let mut reasons = Vec::new();
    if candidate.applicability != Applicability::Safe {
        reasons.push(VerificationRejection::CandidateNotSafe {
            applicability: candidate.applicability,
        });
    }
    if let PatchApplication::Conflict { paths, .. } = patch_application {
        reasons.push(VerificationRejection::PatchConflict {
            paths: paths
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        });
    }
    append_execution_rejections(&mut reasons, executions);
    reasons
}

fn collect_finding_rejections(
    targets: &BTreeSet<Fingerprint>,
    before: &BTreeMap<Fingerprint, Finding>,
    after: &BTreeMap<Fingerprint, Finding>,
) -> Result<(Vec<VerificationRejection>, Vec<Fingerprint>), VerificationError> {
    let mut reasons = Vec::new();
    let residual = targets
        .iter()
        .filter(|fingerprint| after.contains_key(*fingerprint))
        .cloned()
        .collect::<Vec<_>>();
    if !residual.is_empty() {
        reasons.push(VerificationRejection::TargetStillPresent {
            fingerprints: residual,
        });
    }
    let escalated = before
        .iter()
        .filter_map(|(fingerprint, baseline)| {
            after
                .get(fingerprint)
                .filter(|current| {
                    severity_rank(&current.severity) > severity_rank(&baseline.severity)
                })
                .map(|_| fingerprint.clone())
        })
        .collect::<Vec<_>>();
    if !escalated.is_empty() {
        reasons.push(VerificationRejection::ExistingSeverityEscalation {
            fingerprints: escalated,
        });
    }
    let target_floor = targets
        .iter()
        .filter_map(|fingerprint| before.get(fingerprint))
        .map(|finding| severity_rank(&finding.severity))
        .min()
        .ok_or(VerificationError::InvalidTargetCount)?;
    let new_findings = after
        .iter()
        .filter(|(fingerprint, _)| !before.contains_key(*fingerprint))
        .map(|(fingerprint, finding)| (fingerprint.clone(), severity_rank(&finding.severity)))
        .collect::<Vec<_>>();
    let blocking_new = new_findings
        .iter()
        .filter(|(_, severity)| *severity >= target_floor)
        .map(|(fingerprint, _)| fingerprint.clone())
        .collect::<Vec<_>>();
    if !blocking_new.is_empty() {
        reasons.push(VerificationRejection::NewFindingAtOrAboveTargetFloor {
            fingerprints: blocking_new,
        });
    }
    Ok((
        reasons,
        new_findings
            .into_iter()
            .map(|(fingerprint, _)| fingerprint)
            .collect(),
    ))
}

fn preflight_bounds(input: &SafeFixComparisonInput<'_>) -> Result<(), VerificationError> {
    for (field, actual, max) in [
        (
            "before_findings",
            input.before_findings.len(),
            MAX_DEDUPLICATION_FINDINGS,
        ),
        (
            "after_findings",
            input.after_findings.len(),
            MAX_DEDUPLICATION_FINDINGS,
        ),
        ("evidence", input.evidence.len(), MAX_VERIFICATION_OBJECTS),
        (
            "executions",
            input.executions.len(),
            MAX_VERIFICATION_OBJECTS,
        ),
    ] {
        if actual > max {
            return Err(VerificationError::InputTooLarge { field, actual, max });
        }
    }
    if let PatchApplication::Conflict { paths, .. } = input.patch_application {
        if paths.len() > MAX_VERIFICATION_TARGETS {
            return Err(VerificationError::ConflictPathsTooLarge {
                actual: paths.len(),
                max: MAX_VERIFICATION_TARGETS,
            });
        }
    }
    let retained_bytes = input
        .evidence
        .iter()
        .try_fold(0_u64, |total, item| total.checked_add(item.retained_bytes));
    let max_bytes = u64::try_from(MAX_REPORT_BYTES).unwrap_or(u64::MAX);
    if retained_bytes.is_none_or(|actual| actual > max_bytes) {
        return Err(VerificationError::EvidenceBytesTooLarge {
            actual: retained_bytes.unwrap_or(u64::MAX),
            max: max_bytes,
        });
    }
    Ok(())
}

fn collect_targets(values: &[Fingerprint]) -> Result<BTreeSet<Fingerprint>, VerificationError> {
    if values.is_empty() || values.len() > MAX_VERIFICATION_TARGETS {
        return Err(VerificationError::InvalidTargetCount);
    }
    let mut output = BTreeSet::new();
    for value in values {
        if !output.insert(value.clone()) {
            return Err(VerificationError::DuplicateTarget {
                fingerprint: value.clone(),
            });
        }
    }
    Ok(output)
}

fn index_evidence(values: &[Evidence]) -> Result<BTreeMap<ObjectId, &Evidence>, VerificationError> {
    let mut output = BTreeMap::new();
    for value in values {
        value.validate()?;
        if output.insert(value.evidence_id.clone(), value).is_some() {
            return Err(VerificationError::DuplicateObjectId {
                field: "evidence",
                object_id: value.evidence_id.clone(),
            });
        }
    }
    Ok(output)
}

fn index_executions(
    values: &[Execution],
) -> Result<BTreeMap<ObjectId, &Execution>, VerificationError> {
    let mut output = BTreeMap::new();
    for value in values {
        value.validate()?;
        if output.insert(value.execution_id.clone(), value).is_some() {
            return Err(VerificationError::DuplicateObjectId {
                field: "executions",
                object_id: value.execution_id.clone(),
            });
        }
    }
    Ok(output)
}

fn validate_object_id_domains(input: &SafeFixComparisonInput<'_>) -> Result<(), VerificationError> {
    let mut reserved = BTreeSet::from([input.candidate.fix_candidate_id.clone()]);
    for identifier in input
        .evidence
        .iter()
        .map(|value| &value.evidence_id)
        .chain(input.executions.iter().map(|value| &value.execution_id))
    {
        if !reserved.insert(identifier.clone()) {
            return Err(VerificationError::DuplicateObjectId {
                field: "comparison objects",
                object_id: identifier.clone(),
            });
        }
    }
    let mut finding_ids = BTreeSet::new();
    let mut observation_ids = BTreeSet::new();
    for finding in input
        .before_findings
        .iter()
        .chain(input.after_findings.iter())
    {
        if reserved.contains(&finding.finding_id) {
            return Err(VerificationError::DuplicateObjectId {
                field: "comparison objects",
                object_id: finding.finding_id.clone(),
            });
        }
        finding_ids.insert(finding.finding_id.clone());
        observation_ids.extend(finding.observation_ids.iter().cloned());
    }
    reserved.extend(finding_ids);
    for observation_id in observation_ids {
        if reserved.contains(&observation_id) {
            return Err(VerificationError::DuplicateObjectId {
                field: "comparison objects",
                object_id: observation_id,
            });
        }
    }
    Ok(())
}

fn validate_evidence_execution_references(
    evidence: &BTreeMap<ObjectId, &Evidence>,
    executions: &BTreeMap<ObjectId, &Execution>,
) -> Result<(), VerificationError> {
    for item in evidence.values() {
        if let Some(execution_id) = &item.execution_id {
            if !executions.contains_key(execution_id) {
                return Err(VerificationError::UnknownEvidenceExecution {
                    evidence_id: item.evidence_id.clone(),
                    execution_id: execution_id.clone(),
                });
            }
        }
    }
    Ok(())
}

fn validate_finding_evidence_references(
    phase: &'static str,
    findings: &[Finding],
    evidence: &BTreeMap<ObjectId, &Evidence>,
) -> Result<(), VerificationError> {
    for finding in findings {
        for evidence_id in &finding.evidence_ids {
            if !evidence.contains_key(evidence_id) {
                return Err(VerificationError::UnknownFindingEvidence {
                    phase,
                    finding_id: finding.finding_id.clone(),
                    evidence_id: evidence_id.clone(),
                });
            }
        }
    }
    Ok(())
}

fn canonical_findings(
    phase: &'static str,
    values: &[Finding],
    allow_fix_proposed: bool,
) -> Result<BTreeMap<Fingerprint, Finding>, VerificationError> {
    let mut stripped = Vec::with_capacity(values.len());
    for value in values {
        validate_finding_integrity(value)
            .map_err(|source| VerificationError::InvalidFinding { phase, source })?;
        let allowed = value.state == FindingState::Classified
            || (allow_fix_proposed && value.state == FindingState::FixProposed);
        if !allowed || value.pre_report_state.is_some() {
            return Err(VerificationError::InvalidFindingState {
                phase,
                finding_id: value.finding_id.clone(),
                state: value.state,
            });
        }
        let mut canonical = value.clone();
        canonical.state = FindingState::Classified;
        canonical.fix_candidate_id = None;
        canonical.verification_execution_ids = None;
        let encoded =
            serde_json::to_vec(&canonical).map_err(|error| VerificationError::FindingEncoding {
                phase,
                reason: error.to_string(),
            })?;
        stripped.push((encoded, canonical));
    }
    stripped.sort_by(|left, right| left.0.cmp(&right.0));
    deduplicate_findings(stripped.into_iter().map(|(_, finding)| finding).collect())
        .map_err(|source| VerificationError::InvalidFinding { phase, source })
        .map(|findings| {
            findings
                .into_iter()
                .map(|finding| (finding.fingerprint.clone(), finding))
                .collect()
        })
}

fn validate_candidate_scope(
    candidate: &FixCandidate,
    raw_before: &[Finding],
    before: &BTreeMap<Fingerprint, Finding>,
    targets: &BTreeSet<Fingerprint>,
) -> Result<(), VerificationError> {
    let mut sources_by_observation = BTreeMap::<ObjectId, Vec<&Finding>>::new();
    for finding in raw_before {
        for observation_id in &finding.observation_ids {
            sources_by_observation
                .entry(observation_id.clone())
                .or_default()
                .push(finding);
        }
    }
    let mut candidate_tool = None;
    let candidate_observations = candidate.observation_ids.iter().collect::<BTreeSet<_>>();
    for observation_id in candidate_observations {
        let Some(sources) = sources_by_observation.get(observation_id) else {
            return Err(VerificationError::UnknownCandidateObservation {
                observation_id: observation_id.clone(),
            });
        };
        for source in sources {
            let identity = (&source.tool.name, &source.tool.version);
            if candidate_tool.is_some_and(|expected| expected != identity) {
                return Err(VerificationError::CandidateToolMismatch {
                    observation_id: observation_id.clone(),
                });
            }
            candidate_tool = Some(identity);
        }
    }
    let scope = candidate.observation_ids.iter().collect::<BTreeSet<_>>();
    for fingerprint in targets {
        if !before.contains_key(fingerprint) {
            return Err(VerificationError::UnknownTarget {
                fingerprint: fingerprint.clone(),
            });
        }
        if raw_before.iter().any(|finding| {
            &finding.fingerprint == fingerprint
                && finding.state == FindingState::FixProposed
                && finding.fix_candidate_id.as_ref() != Some(&candidate.fix_candidate_id)
        }) {
            return Err(VerificationError::TargetCandidateConflict {
                fingerprint: fingerprint.clone(),
            });
        }
        let proposed = raw_before.iter().find(|finding| {
            &finding.fingerprint == fingerprint
                && finding.state == FindingState::FixProposed
                && finding.fix_candidate_id.as_ref() == Some(&candidate.fix_candidate_id)
        });
        let Some(proposed) = proposed else {
            return Err(VerificationError::TargetNotProposed {
                fingerprint: fingerprint.clone(),
                candidate_id: candidate.fix_candidate_id.clone(),
            });
        };
        let canonical =
            before
                .get(fingerprint)
                .ok_or_else(|| VerificationError::UnknownTarget {
                    fingerprint: fingerprint.clone(),
                })?;
        if proposed
            .observation_ids
            .iter()
            .chain(canonical.observation_ids.iter())
            .any(|identifier| !scope.contains(identifier))
        {
            return Err(VerificationError::TargetOutsideCandidateScope {
                fingerprint: fingerprint.clone(),
            });
        }
    }
    Ok(())
}

fn validate_patch<'a>(
    candidate: &FixCandidate,
    evidence: &'a BTreeMap<ObjectId, &Evidence>,
) -> Result<&'a Evidence, VerificationError> {
    let patch = evidence
        .get(&candidate.patch_evidence_id)
        .copied()
        .ok_or_else(|| VerificationError::UnknownPatchEvidence {
            evidence_id: candidate.patch_evidence_id.clone(),
        })?;
    if patch.source != EvidenceSource::Patch || patch.truncated || patch.content.is_none() {
        return Err(VerificationError::InvalidPatchEvidence);
    }
    Ok(patch)
}

fn validate_attributions(
    candidate: &FixCandidate,
    patch: &Evidence,
    targets: &BTreeSet<Fingerprint>,
    before: &BTreeMap<Fingerprint, Finding>,
    evidence: &BTreeMap<ObjectId, &Evidence>,
    executions: &BTreeMap<ObjectId, &Execution>,
) -> Result<(BTreeMap<Fingerprint, Vec<ObjectId>>, Sha256Digest), VerificationError> {
    let mut base_snapshot = None;
    let mut attributed = BTreeMap::<Fingerprint, BTreeSet<ObjectId>>::new();
    for execution in executions.values() {
        let Some(verification) = execution.verification.as_deref() else {
            continue;
        };
        if !execution.required {
            return Err(VerificationError::AttributionExecutionNotRequired {
                execution_id: execution.execution_id.clone(),
            });
        }
        validate_attribution_identity(candidate, patch, execution, verification)?;
        validate_attribution_evidence(execution, verification, evidence)?;
        let current_base = (
            verification.base_snapshot_evidence_id.clone(),
            verification.base_snapshot_sha256.clone(),
        );
        if base_snapshot
            .as_ref()
            .is_some_and(|expected| expected != &current_base)
        {
            return Err(VerificationError::BaseSnapshotMismatch);
        }
        base_snapshot = Some(current_base);
        for fingerprint in &verification.target_fingerprints {
            if !targets.contains(fingerprint) {
                return Err(VerificationError::UnexpectedAttributedTarget {
                    fingerprint: fingerprint.clone(),
                });
            }
            let target =
                before
                    .get(fingerprint)
                    .ok_or_else(|| VerificationError::UnknownTarget {
                        fingerprint: fingerprint.clone(),
                    })?;
            if execution.tool.name != target.tool.name
                || execution.tool.version != target.tool.version
            {
                return Err(VerificationError::AttributionToolMismatch {
                    execution_id: execution.execution_id.clone(),
                    fingerprint: fingerprint.clone(),
                });
            }
            attributed
                .entry(fingerprint.clone())
                .or_default()
                .insert(execution.execution_id.clone());
        }
    }
    let verification_ids = targets
        .iter()
        .map(|fingerprint| {
            attributed
                .remove(fingerprint)
                .map(|ids| {
                    if ids.len() > 64 {
                        Err(VerificationError::TargetExecutionLimit {
                            fingerprint: fingerprint.clone(),
                            actual: ids.len(),
                            max: 64,
                        })
                    } else {
                        Ok((fingerprint.clone(), ids.into_iter().collect()))
                    }
                })
                .ok_or_else(|| VerificationError::MissingTargetAttribution {
                    fingerprint: fingerprint.clone(),
                })?
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let Some((_, base_snapshot_sha256)) = base_snapshot else {
        let Some(fingerprint) = targets.iter().next() else {
            return Err(VerificationError::InvalidTargetCount);
        };
        return Err(VerificationError::MissingTargetAttribution {
            fingerprint: fingerprint.clone(),
        });
    };
    Ok((verification_ids, base_snapshot_sha256))
}

fn validate_patch_application(
    application: &PatchApplication,
    patch_sha256: &Sha256Digest,
    evidence: &BTreeMap<ObjectId, &Evidence>,
) -> Result<Sha256Digest, VerificationError> {
    let (applied_patch, applied_base) = match application {
        PatchApplication::Applied {
            patch_sha256,
            base_snapshot_sha256,
        }
        | PatchApplication::Conflict {
            patch_sha256,
            base_snapshot_sha256,
            ..
        } => (patch_sha256, base_snapshot_sha256),
    };
    if applied_patch != patch_sha256 {
        return Err(VerificationError::PatchApplicationDigestMismatch {
            field: "patch_sha256",
        });
    }
    let valid_base = evidence.values().any(|snapshot| {
        snapshot.source == EvidenceSource::Artifact
            && !snapshot.truncated
            && snapshot.content.is_some()
            && snapshot.media_type == "application/vnd.diagnostic-triage.snapshot+json"
            && &snapshot.sha256 == applied_base
    });
    if !valid_base {
        return Err(VerificationError::PatchApplicationBaseSnapshotMissing);
    }
    Ok(applied_base.clone())
}

fn validate_attribution_identity(
    candidate: &FixCandidate,
    patch: &Evidence,
    execution: &Execution,
    verification: &VerificationAttribution,
) -> Result<(), VerificationError> {
    if verification.fix_candidate_id != candidate.fix_candidate_id {
        return Err(VerificationError::AttributionCandidateMismatch {
            execution_id: execution.execution_id.clone(),
        });
    }
    if verification.patch_sha256 != patch.sha256 {
        return Err(VerificationError::AttributionPatchMismatch {
            execution_id: execution.execution_id.clone(),
        });
    }
    Ok(())
}

fn validate_attribution_evidence(
    execution: &Execution,
    verification: &VerificationAttribution,
    evidence: &BTreeMap<ObjectId, &Evidence>,
) -> Result<(), VerificationError> {
    let valid_snapshot = evidence
        .get(&verification.base_snapshot_evidence_id)
        .is_some_and(|snapshot| {
            snapshot.source == EvidenceSource::Artifact
                && !snapshot.truncated
                && snapshot.content.is_some()
                && snapshot.media_type == "application/vnd.diagnostic-triage.snapshot+json"
                && snapshot.sha256 == verification.base_snapshot_sha256
        });
    if !valid_snapshot {
        return Err(VerificationError::InvalidBaseSnapshot {
            execution_id: execution.execution_id.clone(),
        });
    }
    if verification.base_snapshot_evidence_id == verification.result_evidence_id {
        return Err(VerificationError::InvalidResultEvidence {
            execution_id: execution.execution_id.clone(),
        });
    }
    let valid_result = evidence
        .get(&verification.result_evidence_id)
        .is_some_and(|result| {
            matches!(
                result.source,
                EvidenceSource::Stdout | EvidenceSource::Diagnostic | EvidenceSource::Artifact
            ) && result.media_type != "application/vnd.diagnostic-triage.snapshot+json"
                && result.execution_id.as_ref() == Some(&execution.execution_id)
                && (execution.status != ExecutionStatus::Complete
                    || (!result.truncated && result.content.is_some()))
        });
    if !valid_result {
        return Err(VerificationError::InvalidResultEvidence {
            execution_id: execution.execution_id.clone(),
        });
    }
    Ok(())
}

fn append_execution_rejections(
    reasons: &mut Vec<VerificationRejection>,
    executions: &BTreeMap<ObjectId, &Execution>,
) {
    let incomplete = executions
        .values()
        .filter(|execution| {
            execution.required
                && execution.adapter_kind == AdapterKind::Provider
                && execution.status == ExecutionStatus::Incomplete
        })
        .map(|execution| execution.execution_id.clone())
        .collect::<Vec<_>>();
    if !incomplete.is_empty() {
        reasons.push(VerificationRejection::RequiredProviderIncomplete {
            execution_ids: incomplete,
        });
    }
    let unsupported = executions
        .values()
        .filter(|execution| {
            execution.required
                && execution.adapter_kind == AdapterKind::Provider
                && execution.status == ExecutionStatus::Unsupported
        })
        .map(|execution| execution.execution_id.clone())
        .collect::<Vec<_>>();
    if !unsupported.is_empty() {
        reasons.push(VerificationRejection::RequiredProviderUnsupported {
            execution_ids: unsupported,
        });
    }
}

fn build_verified_targets(
    candidate: &FixCandidate,
    targets: &BTreeSet<Fingerprint>,
    before: &BTreeMap<Fingerprint, Finding>,
    verification_ids: &BTreeMap<Fingerprint, Vec<ObjectId>>,
) -> Result<Vec<Finding>, VerificationError> {
    targets
        .iter()
        .map(|fingerprint| {
            let mut finding = before
                .get(fingerprint)
                .ok_or_else(|| VerificationError::UnknownTarget {
                    fingerprint: fingerprint.clone(),
                })?
                .clone();
            // LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.
            finding.state = FindingState::Verified;
            finding.fix_candidate_id = Some(candidate.fix_candidate_id.clone());
            finding.verification_execution_ids = Some(
                verification_ids
                    .get(fingerprint)
                    .ok_or_else(|| VerificationError::MissingTargetAttribution {
                        fingerprint: fingerprint.clone(),
                    })?
                    .clone(),
            );
            finding.validate()?;
            validate_finding_integrity(&finding).map_err(|source| {
                VerificationError::InvalidFinding {
                    phase: "verified",
                    source,
                }
            })?;
            Ok(finding)
        })
        .collect()
}

const fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
    }
}
