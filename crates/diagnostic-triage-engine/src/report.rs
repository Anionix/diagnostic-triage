//! Deterministic construction of v1 session reports.

use diagnostic_triage_contracts::{
    model::{DecisionAction, ExecutionStatus, SessionReport, Verdict},
    validate_report,
};

use crate::{
    EngineError, finding::validate_finding_integrity, policy::validate_decision_integrity,
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// Canonicalize and finalize one v1 [`SessionReport`].
///
/// Contract validation runs before and after canonicalization. The incoming
/// verdict is deliberately ignored: the returned report always contains the
/// verdict derived from its required executions and decisions.
///
/// # Errors
///
/// Returns an error when the report violates a contract, Finding identity, or
/// Decision identity invariant.
pub fn canonicalize_session_report(
    mut report: SessionReport,
) -> Result<SessionReport, EngineError> {
    validate_report(&report)?;
    validate_report_engine_integrity(&report)?;
    canonicalize_collections(&mut report);
    report.verdict = compute_verdict(&report);
    validate_report(&report)?;
    Ok(report)
}

/// Recompute a report verdict after validating the complete report contract.
///
/// This function does not mutate the report. Use
/// [`canonicalize_session_report`] to return a finalized report.
///
/// # Errors
///
/// Returns an error when the report violates a contract, Finding identity, or
/// Decision identity invariant.
pub fn recompute_verdict(report: &SessionReport) -> Result<Verdict, EngineError> {
    validate_report(report)?;
    validate_report_engine_integrity(report)?;
    Ok(compute_verdict(report))
}

/// Compute the deterministic verdict for a contract-valid report.
///
/// Required execution status has precedence over policy: incomplete execution
/// first, unsupported execution second, blocking decision third, and pass last.
/// Callers accepting untrusted reports should use [`recompute_verdict`].
#[must_use]
pub fn compute_verdict(report: &SessionReport) -> Verdict {
    if report
        .executions
        .iter()
        .any(|execution| execution.required && execution.status == ExecutionStatus::Incomplete)
    {
        Verdict::Incomplete
    } else if report
        .executions
        .iter()
        .any(|execution| execution.required && execution.status == ExecutionStatus::Unsupported)
    {
        Verdict::Unsupported
    } else if report
        .decisions
        .iter()
        .any(|decision| decision.action == DecisionAction::Block)
    {
        Verdict::PolicyFail
    } else {
        Verdict::Pass
    }
}

fn validate_report_engine_integrity(report: &SessionReport) -> Result<(), EngineError> {
    for finding in &report.findings {
        validate_finding_integrity(finding)?;
    }
    for decision in &report.decisions {
        validate_decision_integrity(decision)?;
    }
    Ok(())
}

fn canonicalize_collections(report: &mut SessionReport) {
    report
        .observations
        .sort_unstable_by(|left, right| left.observation_id.cmp(&right.observation_id));
    report
        .findings
        .sort_unstable_by(|left, right| left.finding_id.cmp(&right.finding_id));
    report
        .decisions
        .sort_unstable_by(|left, right| left.decision_id.cmp(&right.decision_id));
    report
        .evidence
        .sort_unstable_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    report
        .fix_candidates
        .sort_unstable_by(|left, right| left.fix_candidate_id.cmp(&right.fix_candidate_id));
    report
        .executions
        .sort_unstable_by(|left, right| left.execution_id.cmp(&right.execution_id));

    for observation in &mut report.observations {
        sort_ids(&mut observation.evidence_ids);
    }
    for finding in &mut report.findings {
        sort_ids(&mut finding.observation_ids);
        sort_ids(&mut finding.evidence_ids);
        if let Some(execution_ids) = &mut finding.verification_execution_ids {
            sort_ids(execution_ids);
        }
    }
    for candidate in &mut report.fix_candidates {
        sort_ids(&mut candidate.observation_ids);
    }
}

fn sort_ids<T: Ord>(values: &mut [T]) {
    values.sort_unstable();
}
