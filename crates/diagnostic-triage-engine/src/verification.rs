//! Deterministic before/after verification for safe fix candidates.

use std::collections::{BTreeMap, BTreeSet};

use diagnostic_triage_contracts::model::{
    AdapterKind, Applicability, Execution, ExecutionStatus, Finding, FixCandidate, Severity,
};
use diagnostic_triage_contracts::{AdapterId, Fingerprint, ObjectId};

use crate::finding::{finding_id_for_finding, validate_finding_integrity};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// The terminal state of a before/after safe-fix comparison.
///
/// After request validation, terminal-state precedence is strict: incomplete,
/// unsupported, regression, target remains, then verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationStatus {
    /// Every required execution completed and the fix satisfied the comparison.
    Verified,
    /// At least one target fingerprint was emitted after the fix.
    TargetRemains,
    /// A new finding was emitted at or above the target severity threshold.
    Regression,
    /// A named required provider or execution did not complete.
    IncompleteRequiredExecution,
    /// A named required provider or execution is unsupported.
    UnsupportedRequiredExecution,
    /// The request or one of its contract objects is not valid for verification.
    InvalidRequest,
}

/// The deterministic reason attached to an invalid request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidRequestReason {
    EmptyTargetSet,
    TargetNotPresentBeforeFix,
    TargetNotLinkedToFix,
    InvalidFixCandidate,
    MissingExecutionRequirement,
    InvalidFinding,
    InvalidExecution,
    ConflictingDuplicateExecution,
    ConflictingDuplicateFinding,
}

/// The result of a safe-fix comparison.
///
/// Every collection is sorted by the corresponding stable contract identity.
/// This makes the result independent of the order in which providers emit
/// findings or execution records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationResult {
    pub status: VerificationStatus,
    pub remaining_target_fingerprints: Vec<Fingerprint>,
    pub regression_fingerprints: Vec<Fingerprint>,
    pub incomplete_provider_ids: Vec<AdapterId>,
    pub incomplete_execution_ids: Vec<ObjectId>,
    pub unsupported_provider_ids: Vec<AdapterId>,
    pub unsupported_execution_ids: Vec<ObjectId>,
    pub invalid_reason: Option<InvalidRequestReason>,
}

/// Inputs to one pure before/after comparison.
pub struct VerificationRequest<'a> {
    pub fix_candidate: &'a FixCandidate,
    pub target_fingerprints: &'a [Fingerprint],
    pub before_findings: &'a [Finding],
    pub after_findings: &'a [Finding],
    pub executions: &'a [Execution],
    pub required_provider_ids: &'a [AdapterId],
    pub required_execution_ids: &'a [ObjectId],
}

/// Backwards-readable name for callers that refer to this as an outcome.
pub type VerificationOutcome = VerificationResult;

/// Compare findings before and after a proposed safe fix.
// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the explicit terminal-state precedence is kept in one auditable state machine"
)]
pub fn verify_safe_fix(request: &VerificationRequest<'_>) -> VerificationResult {
    if !matches!(request.fix_candidate.applicability, Applicability::Safe)
        || request.fix_candidate.validate().is_err()
    {
        return invalid(InvalidRequestReason::InvalidFixCandidate);
    }

    let targets = request
        .target_fingerprints
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if targets.is_empty() {
        return invalid(InvalidRequestReason::EmptyTargetSet);
    }
    if request.required_provider_ids.is_empty()
        && request.required_execution_ids.is_empty()
        && !request
            .executions
            .iter()
            .any(|execution| execution.required)
    {
        return invalid(InvalidRequestReason::MissingExecutionRequirement);
    }

    let before = match normalize_findings(request.before_findings) {
        Ok(findings) => findings,
        Err(reason) => return invalid(reason),
    };
    let after = match normalize_findings(request.after_findings) {
        Ok(findings) => findings,
        Err(reason) => return invalid(reason),
    };
    if targets
        .iter()
        .any(|fingerprint| !before.contains_key(fingerprint))
    {
        return invalid(InvalidRequestReason::TargetNotPresentBeforeFix);
    }
    let candidate_observations = request
        .fix_candidate
        .observation_ids
        .iter()
        .collect::<BTreeSet<_>>();
    if targets.iter().any(|fingerprint| {
        before.get(fingerprint).is_none_or(|finding| {
            !finding
                .observation_ids
                .iter()
                .any(|observation_id| candidate_observations.contains(observation_id))
        })
    }) {
        return invalid(InvalidRequestReason::TargetNotLinkedToFix);
    }

    let executions = match normalize_executions(request.executions) {
        Ok(executions) => executions,
        Err(reason) => return invalid(reason),
    };
    let failures = requirement_failures(
        &executions,
        request.required_provider_ids,
        request.required_execution_ids,
    );
    if !failures.incomplete_providers.is_empty() || !failures.incomplete_executions.is_empty() {
        return VerificationResult {
            status: VerificationStatus::IncompleteRequiredExecution,
            remaining_target_fingerprints: Vec::new(),
            regression_fingerprints: Vec::new(),
            incomplete_provider_ids: failures.incomplete_providers,
            incomplete_execution_ids: failures.incomplete_executions,
            unsupported_provider_ids: failures.unsupported_providers,
            unsupported_execution_ids: failures.unsupported_executions,
            invalid_reason: None,
        };
    }
    if !failures.unsupported_providers.is_empty() || !failures.unsupported_executions.is_empty() {
        return VerificationResult {
            status: VerificationStatus::UnsupportedRequiredExecution,
            remaining_target_fingerprints: Vec::new(),
            regression_fingerprints: Vec::new(),
            incomplete_provider_ids: Vec::new(),
            incomplete_execution_ids: Vec::new(),
            unsupported_provider_ids: failures.unsupported_providers,
            unsupported_execution_ids: failures.unsupported_executions,
            invalid_reason: None,
        };
    }

    let Some(target_severity_floor) = targets
        .iter()
        .filter_map(|fingerprint| before.get(fingerprint))
        .map(|finding| severity_rank(&finding.severity))
        .min()
    else {
        return invalid(InvalidRequestReason::TargetNotPresentBeforeFix);
    };
    let regression_fingerprints = after
        .iter()
        .filter(|(fingerprint, finding)| {
            let after_rank = severity_rank(&finding.severity);
            before.get(*fingerprint).map_or_else(
                || after_rank >= target_severity_floor,
                |previous| {
                    after_rank > severity_rank(&previous.severity)
                        && after_rank >= target_severity_floor
                },
            )
        })
        .map(|(fingerprint, _)| fingerprint.clone())
        .collect::<Vec<_>>();
    // Strict precedence: incomplete > unsupported > regression > target remains > verified.
    if !regression_fingerprints.is_empty() {
        return VerificationResult {
            status: VerificationStatus::Regression,
            remaining_target_fingerprints: Vec::new(),
            regression_fingerprints,
            incomplete_provider_ids: Vec::new(),
            incomplete_execution_ids: Vec::new(),
            unsupported_provider_ids: Vec::new(),
            unsupported_execution_ids: Vec::new(),
            invalid_reason: None,
        };
    }

    let remaining_target_fingerprints = targets
        .intersection(&after.keys().cloned().collect())
        .cloned()
        .collect::<Vec<_>>();
    if !remaining_target_fingerprints.is_empty() {
        return VerificationResult {
            status: VerificationStatus::TargetRemains,
            remaining_target_fingerprints,
            regression_fingerprints: Vec::new(),
            incomplete_provider_ids: Vec::new(),
            incomplete_execution_ids: Vec::new(),
            unsupported_provider_ids: Vec::new(),
            unsupported_execution_ids: Vec::new(),
            invalid_reason: None,
        };
    }

    VerificationResult {
        status: VerificationStatus::Verified,
        remaining_target_fingerprints: Vec::new(),
        regression_fingerprints: Vec::new(),
        incomplete_provider_ids: Vec::new(),
        incomplete_execution_ids: Vec::new(),
        unsupported_provider_ids: Vec::new(),
        unsupported_execution_ids: Vec::new(),
        invalid_reason: None,
    }
}

/// Alias for callers that prefer the comparison-oriented name.
#[must_use]
pub fn verify_before_after(request: &VerificationRequest<'_>) -> VerificationResult {
    verify_safe_fix(request)
}

fn invalid(reason: InvalidRequestReason) -> VerificationResult {
    VerificationResult {
        status: VerificationStatus::InvalidRequest,
        remaining_target_fingerprints: Vec::new(),
        regression_fingerprints: Vec::new(),
        incomplete_provider_ids: Vec::new(),
        incomplete_execution_ids: Vec::new(),
        unsupported_provider_ids: Vec::new(),
        unsupported_execution_ids: Vec::new(),
        invalid_reason: Some(reason),
    }
}

fn normalize_findings(
    findings: &[Finding],
) -> Result<BTreeMap<Fingerprint, Finding>, InvalidRequestReason> {
    let mut normalized = BTreeMap::<Fingerprint, Finding>::new();
    for finding in findings {
        finding
            .validate()
            .map_err(|_| InvalidRequestReason::InvalidFinding)?;
        validate_finding_integrity(finding).map_err(|_| InvalidRequestReason::InvalidFinding)?;
        if let Some(previous) = normalized.get_mut(&finding.fingerprint) {
            if !same_finding_identity(previous, finding) {
                return Err(InvalidRequestReason::ConflictingDuplicateFinding);
            }
            if severity_rank(&finding.severity) > severity_rank(&previous.severity) {
                previous.severity = finding.severity.clone();
            }
            previous.observation_ids = previous
                .observation_ids
                .iter()
                .chain(&finding.observation_ids)
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            previous.finding_id = finding_id_for_finding(previous)
                .map_err(|_| InvalidRequestReason::InvalidFinding)?;
        } else {
            normalized.insert(finding.fingerprint.clone(), finding.clone());
        }
    }
    Ok(normalized)
}

fn same_finding_identity(left: &Finding, right: &Finding) -> bool {
    left.tool.name == right.tool.name
        && left.tool.rule_id == right.tool.rule_id
        && left.language == right.language
        && left.classification == right.classification
        && left.location.as_ref().map(|location| &location.path)
            == right.location.as_ref().map(|location| &location.path)
        && left.symbol == right.symbol
        && left.message == right.message
        && left.expected == right.expected
        && left.observed == right.observed
}

fn normalize_executions(
    executions: &[Execution],
) -> Result<BTreeMap<ObjectId, Execution>, InvalidRequestReason> {
    let mut normalized = BTreeMap::new();
    for execution in executions {
        execution
            .validate()
            .map_err(|_| InvalidRequestReason::InvalidExecution)?;
        if let Some(previous) = normalized.insert(execution.execution_id.clone(), execution.clone())
            && previous != *execution
        {
            return Err(InvalidRequestReason::ConflictingDuplicateExecution);
        }
    }
    Ok(normalized)
}

#[derive(Default)]
struct RequirementFailures {
    incomplete_providers: Vec<AdapterId>,
    incomplete_executions: Vec<ObjectId>,
    unsupported_providers: Vec<AdapterId>,
    unsupported_executions: Vec<ObjectId>,
}

fn requirement_failures(
    executions: &BTreeMap<ObjectId, Execution>,
    required_provider_ids: &[AdapterId],
    required_execution_ids: &[ObjectId],
) -> RequirementFailures {
    let required_providers = required_provider_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let required_executions = required_execution_ids
        .iter()
        .cloned()
        .chain(
            executions
                .values()
                .filter(|execution| execution.required)
                .map(|execution| execution.execution_id.clone()),
        )
        .collect::<BTreeSet<_>>();
    let mut failures = RequirementFailures::default();

    for provider_id in required_providers {
        let statuses = executions
            .values()
            .filter(|execution| {
                execution.adapter_kind == AdapterKind::Provider
                    && execution.adapter_id == provider_id
            })
            .map(|execution| &execution.status)
            .collect::<Vec<_>>();
        if statuses.contains(&&ExecutionStatus::Complete) {
            continue;
        }
        if statuses.is_empty() || statuses.contains(&&ExecutionStatus::Incomplete) {
            failures.incomplete_providers.push(provider_id);
        } else {
            failures.unsupported_providers.push(provider_id);
        }
    }
    for execution_id in required_executions {
        match executions
            .get(&execution_id)
            .map(|execution| &execution.status)
        {
            None | Some(ExecutionStatus::Incomplete) => {
                failures.incomplete_executions.push(execution_id);
            }
            Some(ExecutionStatus::Unsupported) => {
                failures.unsupported_executions.push(execution_id);
            }
            Some(ExecutionStatus::Complete) => {}
        }
    }
    failures
}

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
    }
}
