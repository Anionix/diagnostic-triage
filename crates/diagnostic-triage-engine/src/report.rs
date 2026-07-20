//! Deterministic assembly of validated v1 session reports.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::str::FromStr;

use diagnostic_triage_contracts::model::{
    Decision, EngineIdentity, Evidence, Execution, Finding, FindingState, FixCandidate,
    Observation, SessionReport, SessionReportSchemaVersion,
};
use diagnostic_triage_contracts::{
    ContractError, Fingerprint, MAX_REPORT_BYTES, ObjectId, Sha256Digest, derive_session_verdict,
    validate_report,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::EngineError;
use crate::finding::validate_finding_integrity;
use crate::policy::{PolicyError, PolicySnapshot, validate_decision_integrity};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// Maximum number of items in each top-level v1 report collection.
pub const MAX_REPORT_COLLECTION_ITEMS: usize = 10_000;

/// Caller-owned facts required to assemble one report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportAssemblyInput {
    pub session_id: ObjectId,
    pub engine: EngineIdentity,
    pub observations: Vec<Observation>,
    pub findings: Vec<Finding>,
    pub evidence: Vec<Evidence>,
    pub fix_candidates: Vec<FixCandidate>,
    pub executions: Vec<Execution>,
    pub evaluation_time: Option<String>,
}

/// Typed failures from the pure report assembly boundary.
#[derive(Debug, Error)]
pub enum ReportAssemblyError {
    #[error("report collection {collection} contains {actual} items; maximum is {max}")]
    CollectionLimit {
        collection: &'static str,
        actual: usize,
        max: usize,
    },
    #[error("{phase} JSON exceeds the {max}-byte report limit")]
    ReportByteLimit { phase: &'static str, max: usize },
    #[error("{phase} JSON size preflight failed")]
    ReportEncoding {
        phase: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("evaluation_time is required when findings are present")]
    MissingEvaluationTime,
    #[error("evaluation_time is not allowed when findings are absent")]
    UnexpectedEvaluationTime,
    #[error("finding {finding_id} cannot be reported from state {state:?}")]
    InvalidFindingLifecycle {
        finding_id: String,
        state: FindingState,
    },
    #[error("finding integrity validation failed")]
    FindingIntegrity {
        #[source]
        source: EngineError,
    },
    #[error("decision integrity validation failed")]
    DecisionIntegrity {
        #[source]
        source: EngineError,
    },
    #[error("report reference preflight failed: {reason}")]
    ReferencePreflight { reason: &'static str },
    #[error("policy decision construction failed")]
    Policy {
        #[source]
        source: PolicyError,
    },
    #[error("report contract validation failed")]
    Contract {
        #[source]
        source: ContractError,
    },
    #[error("derived contract digest was not a valid SHA-256 value")]
    ContractDigest,
}

/// Assemble one canonical, fully validated v1 report without external I/O.
///
/// # Errors
///
/// Returns a typed error for aggregate bounds, timestamp presence, forged
/// Finding identity, invalid lifecycle, policy failure, or contract failure.
pub fn assemble_session_report(
    input: ReportAssemblyInput,
    policy: &PolicySnapshot,
) -> Result<SessionReport, ReportAssemblyError> {
    validate_collection_limits(&input)?;
    validate_json_size("input", &ReportInputPreflight::from(&input))?;
    let report = materialize_session_report(input, policy)?;
    validate_report(&report).map_err(|source| ReportAssemblyError::Contract { source })?;
    validate_json_size("assembled report", &report)?;
    Ok(report)
}

fn materialize_session_report(
    input: ReportAssemblyInput,
    policy: &PolicySnapshot,
) -> Result<SessionReport, ReportAssemblyError> {
    let ReportAssemblyInput {
        session_id,
        engine,
        mut observations,
        findings,
        mut evidence,
        mut fix_candidates,
        mut executions,
        evaluation_time,
    } = input;
    let evaluation_time = match (findings.is_empty(), evaluation_time) {
        (false, Some(value)) => Some(value),
        (false, None) => return Err(ReportAssemblyError::MissingEvaluationTime),
        (true, Some(_)) => return Err(ReportAssemblyError::UnexpectedEvaluationTime),
        (true, None) => None,
    };

    engine
        .validate()
        .map_err(|source| ReportAssemblyError::Contract { source })?;
    validate_input_objects(&observations, &evidence, &fix_candidates, &executions)?;
    let mut object_ids = validate_reference_preflight(
        &observations,
        &findings,
        &evidence,
        &fix_candidates,
        &executions,
    )?;

    let (mut reported_findings, mut decisions) = materialize_findings(
        findings,
        evaluation_time.as_deref(),
        policy,
        &mut object_ids,
    )?;

    for observation in &mut observations {
        observation.evidence_ids.sort();
    }
    for candidate in &mut fix_candidates {
        candidate.observation_ids.sort();
    }
    for execution in &mut executions {
        if let Some(verification) = &mut execution.verification {
            verification.target_fingerprints.sort();
        }
    }

    observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
    reported_findings.sort_by(|left, right| {
        left.fingerprint
            .cmp(&right.fingerprint)
            .then_with(|| left.finding_id.cmp(&right.finding_id))
    });
    decisions.sort_by(|left, right| {
        left.finding_id
            .cmp(&right.finding_id)
            .then_with(|| left.decision_id.cmp(&right.decision_id))
    });
    evidence.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    fix_candidates.sort_by(|left, right| left.fix_candidate_id.cmp(&right.fix_candidate_id));
    executions.sort_by(|left, right| left.execution_id.cmp(&right.execution_id));

    let contract_sha256 = contract_digest(&engine)?;
    let verdict = derive_session_verdict(&executions, &decisions);
    Ok(SessionReport {
        schema_version: SessionReportSchemaVersion::V1,
        session_id,
        engine,
        contract_sha256,
        policy_digest: policy.digest().clone(),
        verdict,
        observations,
        findings: reported_findings,
        decisions,
        evidence,
        fix_candidates,
        executions,
    })
}

fn materialize_findings(
    findings: Vec<Finding>,
    evaluation_time: Option<&str>,
    policy: &PolicySnapshot,
    object_ids: &mut BTreeSet<ObjectId>,
) -> Result<(Vec<Finding>, Vec<Decision>), ReportAssemblyError> {
    let mut reported_findings = Vec::with_capacity(findings.len());
    let mut decisions = Vec::with_capacity(findings.len());
    for finding in findings {
        validate_finding_integrity(&finding)
            .map_err(|source| ReportAssemblyError::FindingIntegrity { source })?;
        if !matches!(
            finding.state,
            FindingState::Classified | FindingState::FixProposed | FindingState::Verified
        ) {
            return Err(ReportAssemblyError::InvalidFindingLifecycle {
                finding_id: finding.finding_id.to_string(),
                state: finding.state,
            });
        }
        let decision = policy
            .build_decision(
                &finding,
                evaluation_time.ok_or(ReportAssemblyError::MissingEvaluationTime)?,
            )
            .map_err(|source| ReportAssemblyError::Policy { source })?;
        validate_decision_integrity(&decision)
            .map_err(|source| ReportAssemblyError::DecisionIntegrity { source })?;
        if !object_ids.insert(decision.decision_id.clone()) {
            return Err(ReportAssemblyError::ReferencePreflight {
                reason: "decision ID duplicates another report object ID",
            });
        }
        decisions.push(decision);
        let mut reported = finding
            .into_reported()
            .map_err(|source| ReportAssemblyError::Contract { source })?;
        canonicalize_finding_references(&mut reported);
        reported_findings.push(reported);
    }
    Ok((reported_findings, decisions))
}

#[derive(Serialize)]
struct ReportInputPreflight<'a> {
    session_id: &'a ObjectId,
    engine: &'a EngineIdentity,
    observations: &'a [Observation],
    findings: &'a [Finding],
    evidence: &'a [Evidence],
    fix_candidates: &'a [FixCandidate],
    executions: &'a [Execution],
    evaluation_time: Option<&'a str>,
}

impl<'a> From<&'a ReportAssemblyInput> for ReportInputPreflight<'a> {
    fn from(input: &'a ReportAssemblyInput) -> Self {
        Self {
            session_id: &input.session_id,
            engine: &input.engine,
            observations: &input.observations,
            findings: &input.findings,
            evidence: &input.evidence,
            fix_candidates: &input.fix_candidates,
            executions: &input.executions,
            evaluation_time: input.evaluation_time.as_deref(),
        }
    }
}

struct BoundedWriter {
    written: usize,
    limit: usize,
    exceeded: bool,
}

impl BoundedWriter {
    const fn new(limit: usize) -> Self {
        Self {
            written: 0,
            limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.written) {
            self.exceeded = true;
            return Err(io::Error::other("bounded JSON writer limit exceeded"));
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn validate_json_size<T: Serialize + ?Sized>(
    phase: &'static str,
    value: &T,
) -> Result<(), ReportAssemblyError> {
    validate_json_size_with_limit(phase, value, MAX_REPORT_BYTES)
}

fn validate_json_size_with_limit<T: Serialize + ?Sized>(
    phase: &'static str,
    value: &T,
    limit: usize,
) -> Result<(), ReportAssemblyError> {
    let mut writer = BoundedWriter::new(limit);
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(()),
        Err(_) if writer.exceeded => {
            Err(ReportAssemblyError::ReportByteLimit { phase, max: limit })
        }
        Err(source) => Err(ReportAssemblyError::ReportEncoding { phase, source }),
    }
}

fn validate_collection_limits(input: &ReportAssemblyInput) -> Result<(), ReportAssemblyError> {
    for (collection, actual) in [
        ("observations", input.observations.len()),
        ("findings", input.findings.len()),
        ("evidence", input.evidence.len()),
        ("fix_candidates", input.fix_candidates.len()),
        ("executions", input.executions.len()),
    ] {
        if actual > MAX_REPORT_COLLECTION_ITEMS {
            return Err(ReportAssemblyError::CollectionLimit {
                collection,
                actual,
                max: MAX_REPORT_COLLECTION_ITEMS,
            });
        }
    }
    Ok(())
}

fn validate_input_objects(
    observations: &[Observation],
    evidence: &[Evidence],
    fix_candidates: &[FixCandidate],
    executions: &[Execution],
) -> Result<(), ReportAssemblyError> {
    for observation in observations {
        observation
            .validate()
            .map_err(|source| ReportAssemblyError::Contract { source })?;
    }
    for item in evidence {
        item.validate()
            .map_err(|source| ReportAssemblyError::Contract { source })?;
    }
    for candidate in fix_candidates {
        candidate
            .validate()
            .map_err(|source| ReportAssemblyError::Contract { source })?;
    }
    for execution in executions {
        execution
            .validate()
            .map_err(|source| ReportAssemblyError::Contract { source })?;
    }
    Ok(())
}

fn validate_reference_preflight(
    observations: &[Observation],
    findings: &[Finding],
    evidence: &[Evidence],
    fix_candidates: &[FixCandidate],
    executions: &[Execution],
) -> Result<BTreeSet<ObjectId>, ReportAssemblyError> {
    let (index, object_ids) =
        ReferenceIndex::new(observations, findings, evidence, fix_candidates, executions)?;
    validate_observation_and_finding_references(&index, observations, findings)?;
    validate_evidence_and_fix_references(&index, evidence, fix_candidates)?;
    validate_verification_references(&index, executions)?;
    Ok(object_ids)
}

struct ReferenceIndex<'a> {
    observation_ids: BTreeSet<&'a ObjectId>,
    evidence_ids: BTreeSet<&'a ObjectId>,
    fix_candidate_ids: BTreeSet<&'a ObjectId>,
    execution_ids: BTreeSet<&'a ObjectId>,
    finding_fingerprints: BTreeSet<&'a Fingerprint>,
}

impl<'a> ReferenceIndex<'a> {
    fn new(
        observations: &'a [Observation],
        findings: &'a [Finding],
        evidence: &'a [Evidence],
        fix_candidates: &'a [FixCandidate],
        executions: &'a [Execution],
    ) -> Result<(Self, BTreeSet<ObjectId>), ReportAssemblyError> {
        let mut object_ids = BTreeSet::new();
        for identifier in observations
            .iter()
            .map(|item| &item.observation_id)
            .chain(findings.iter().map(|item| &item.finding_id))
            .chain(evidence.iter().map(|item| &item.evidence_id))
            .chain(fix_candidates.iter().map(|item| &item.fix_candidate_id))
            .chain(executions.iter().map(|item| &item.execution_id))
        {
            if object_ids.insert(identifier.clone()) {
                continue;
            }
            return Err(ReportAssemblyError::ReferencePreflight {
                reason: "report object IDs are not globally unique",
            });
        }
        let finding_fingerprints = findings
            .iter()
            .map(|item| &item.fingerprint)
            .collect::<BTreeSet<_>>();
        if finding_fingerprints.len() != findings.len() {
            return Err(ReportAssemblyError::ReferencePreflight {
                reason: "finding fingerprints are not unique",
            });
        }
        Ok((
            Self {
                observation_ids: observations
                    .iter()
                    .map(|item| &item.observation_id)
                    .collect(),
                evidence_ids: evidence.iter().map(|item| &item.evidence_id).collect(),
                fix_candidate_ids: fix_candidates
                    .iter()
                    .map(|item| &item.fix_candidate_id)
                    .collect(),
                execution_ids: executions.iter().map(|item| &item.execution_id).collect(),
                finding_fingerprints,
            },
            object_ids,
        ))
    }
}

fn validate_observation_and_finding_references(
    index: &ReferenceIndex<'_>,
    observations: &[Observation],
    findings: &[Finding],
) -> Result<(), ReportAssemblyError> {
    for observation in observations {
        if observation
            .evidence_ids
            .iter()
            .any(|identifier| !index.evidence_ids.contains(identifier))
        {
            return Err(ReportAssemblyError::ReferencePreflight {
                reason: "observation references unknown evidence",
            });
        }
    }
    for finding in findings {
        if finding
            .observation_ids
            .iter()
            .any(|identifier| !index.observation_ids.contains(identifier))
        {
            return Err(ReportAssemblyError::ReferencePreflight {
                reason: "finding references unknown observation",
            });
        }
        if finding
            .evidence_ids
            .iter()
            .any(|identifier| !index.evidence_ids.contains(identifier))
        {
            return Err(ReportAssemblyError::ReferencePreflight {
                reason: "finding references unknown evidence",
            });
        }
        if finding
            .fix_candidate_id
            .as_ref()
            .is_some_and(|identifier| !index.fix_candidate_ids.contains(identifier))
        {
            return Err(ReportAssemblyError::ReferencePreflight {
                reason: "finding references unknown fix candidate",
            });
        }
        if finding
            .verification_execution_ids
            .as_ref()
            .is_some_and(|ids| {
                ids.iter()
                    .any(|identifier| !index.execution_ids.contains(identifier))
            })
        {
            return Err(ReportAssemblyError::ReferencePreflight {
                reason: "finding references unknown verification execution",
            });
        }
    }
    Ok(())
}

fn validate_evidence_and_fix_references(
    index: &ReferenceIndex<'_>,
    evidence: &[Evidence],
    fix_candidates: &[FixCandidate],
) -> Result<(), ReportAssemblyError> {
    for item in evidence {
        if item
            .execution_id
            .as_ref()
            .is_some_and(|identifier| !index.execution_ids.contains(identifier))
        {
            return Err(ReportAssemblyError::ReferencePreflight {
                reason: "evidence references unknown execution",
            });
        }
    }
    for candidate in fix_candidates {
        if candidate
            .observation_ids
            .iter()
            .any(|identifier| !index.observation_ids.contains(identifier))
        {
            return Err(ReportAssemblyError::ReferencePreflight {
                reason: "fix candidate references unknown observation",
            });
        }
        if !index.evidence_ids.contains(&candidate.patch_evidence_id) {
            return Err(ReportAssemblyError::ReferencePreflight {
                reason: "fix candidate references unknown patch evidence",
            });
        }
    }
    Ok(())
}

fn validate_verification_references(
    index: &ReferenceIndex<'_>,
    executions: &[Execution],
) -> Result<(), ReportAssemblyError> {
    for execution in executions {
        let Some(verification) = execution.verification.as_ref() else {
            continue;
        };
        if !index
            .fix_candidate_ids
            .contains(&verification.fix_candidate_id)
        {
            return Err(ReportAssemblyError::ReferencePreflight {
                reason: "verification references unknown fix candidate",
            });
        }
        if !index
            .evidence_ids
            .contains(&verification.base_snapshot_evidence_id)
            || !index
                .evidence_ids
                .contains(&verification.result_evidence_id)
        {
            return Err(ReportAssemblyError::ReferencePreflight {
                reason: "verification references unknown evidence",
            });
        }
        if verification
            .target_fingerprints
            .iter()
            .any(|fingerprint| !index.finding_fingerprints.contains(fingerprint))
        {
            return Err(ReportAssemblyError::ReferencePreflight {
                reason: "verification references unknown target fingerprint",
            });
        }
    }
    Ok(())
}

fn canonicalize_finding_references(finding: &mut Finding) {
    finding.observation_ids.sort();
    finding.evidence_ids.sort();
    if let Some(ids) = &mut finding.verification_execution_ids {
        ids.sort();
    }
}

fn contract_digest(engine: &EngineIdentity) -> Result<Sha256Digest, ReportAssemblyError> {
    let digest = format!(
        "{:x}",
        Sha256::digest(engine.source_revision.as_str().as_bytes())
    );
    Sha256Digest::from_str(&digest).map_err(|_| ReportAssemblyError::ContractDigest)
}

#[cfg(test)]
mod tests {
    use super::{ReportAssemblyError, validate_json_size_with_limit};

    #[test]
    fn bounded_json_writer_accepts_exact_limit_and_rejects_overflow() {
        assert!(validate_json_size_with_limit("fixture", &"1234", 6).is_ok());
        assert!(matches!(
            validate_json_size_with_limit("fixture", &"1234", 5),
            Err(ReportAssemblyError::ReportByteLimit {
                phase: "fixture",
                max: 5,
            })
        ));
    }
}
