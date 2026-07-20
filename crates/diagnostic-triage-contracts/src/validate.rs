//! Cross-object validation for v1 transcripts and reports.

use std::collections::{HashMap, HashSet};

use crate::{
    ContractError, Fingerprint, ObjectId, Sha256Digest,
    jsonl::{decode_json_object, decode_jsonl, decode_line},
    model::{
        AdapterKind, Decision, Evidence, EvidenceSource, Execution, ExecutionStatus, Finding,
        FixCandidate, Observation, SessionReport,
    },
    protocol::{
        CompletionCounts, CompletionEnvelope, ManifestEnvelope, Operation, ProtocolEnvelope,
        RequestEnvelope,
    },
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

// 16 MiB provider stdout plus the maximum schema-valid request, rounded up.
const MAX_TRANSCRIPT_BYTES: usize = 32 * 1024 * 1024;
// Manifest, request, 10,000 payload events, and completion.
const MAX_TRANSCRIPT_LINES: usize = 10_003;
// Reports aggregate providers but remain bounded at the JSON wire boundary.
const MAX_REPORT_BYTES: usize = 64 * 1024 * 1024;

/// A fully decoded and semantically valid v1 Provider/Observer transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSession {
    pub manifest: ManifestEnvelope,
    pub request: RequestEnvelope,
    pub events: Vec<ProtocolEnvelope>,
    pub completion: CompletionEnvelope,
    pub provider_stdout_bytes: u64,
}

struct ReportIndex<'a> {
    observations: HashMap<ObjectId, &'a Observation>,
    findings: HashMap<ObjectId, &'a Finding>,
    decisions: HashMap<ObjectId, &'a Decision>,
    evidence: HashMap<ObjectId, &'a Evidence>,
    fixes: HashMap<ObjectId, &'a FixCandidate>,
    executions: HashMap<ObjectId, &'a Execution>,
}

impl<'a> ReportIndex<'a> {
    fn new(report: &'a SessionReport) -> Result<Self, ContractError> {
        let mut all_ids = HashSet::new();
        let findings = index_unique(
            &report.findings,
            |value| &value.finding_id,
            "finding",
            &mut all_ids,
        )?;
        let mut fingerprints = HashSet::new();
        for finding in findings.values() {
            if !fingerprints.insert(&finding.fingerprint) {
                return Err(model_error("duplicate finding fingerprint in report"));
            }
        }
        Ok(Self {
            observations: index_unique(
                &report.observations,
                |value| &value.observation_id,
                "observation",
                &mut all_ids,
            )?,
            findings,
            decisions: index_unique(
                &report.decisions,
                |value| &value.decision_id,
                "decision",
                &mut all_ids,
            )?,
            evidence: index_unique(
                &report.evidence,
                |value| &value.evidence_id,
                "evidence",
                &mut all_ids,
            )?,
            fixes: index_unique(
                &report.fix_candidates,
                |value| &value.fix_candidate_id,
                "fix candidate",
                &mut all_ids,
            )?,
            executions: index_unique(
                &report.executions,
                |value| &value.execution_id,
                "execution",
                &mut all_ids,
            )?,
        })
    }
}

/// Decode and validate one complete v1 JSON Lines transcript.
///
/// # Errors
///
/// Returns a typed contract error for malformed JSON, a local envelope/model
/// violation, or any cross-event ordering, capability, reference, or limit
/// violation.
pub fn validate_session_jsonl(input: &[u8]) -> Result<ValidatedSession, ContractError> {
    preflight_session_input(input, MAX_TRANSCRIPT_BYTES, MAX_TRANSCRIPT_LINES)?;
    let decoded = decode_jsonl(input)?;
    if decoded.len() < 3 {
        return Err(protocol_error(
            "session requires manifest, request, and completion",
        ));
    }
    let provider_stdout_bytes = decoded
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != 1)
        .try_fold(0_u64, |total, (_, line)| {
            total
                .checked_add(u64::try_from(line.raw_len).unwrap_or(u64::MAX))
                .ok_or_else(|| protocol_error("provider stdout byte count overflowed"))
        })?;
    let envelopes = decoded
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_value::<ProtocolEnvelope>(line.value)
                .map_err(|error| protocol_error(format!("line {}: {error}", index + 1)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut envelopes = envelopes.into_iter();
    let Some(ProtocolEnvelope::Manifest(manifest)) = envelopes.next() else {
        return Err(protocol_error("manifest must be first"));
    };
    let Some(ProtocolEnvelope::Request(request)) = envelopes.next() else {
        return Err(protocol_error("exactly one request must follow manifest"));
    };
    let mut tail = envelopes.collect::<Vec<_>>();
    let Some(ProtocolEnvelope::Completion(completion)) = tail.pop() else {
        return Err(protocol_error("completion must be final"));
    };
    let events = tail;

    validate_adapter_request(&manifest, &request)?;
    if events.len() > usize::try_from(request.limits.max_events).unwrap_or(usize::MAX) {
        return Err(protocol_error("event limit exceeded"));
    }
    if provider_stdout_bytes > request.limits.max_stdout_bytes {
        return Err(protocol_error("adapter stdout limit exceeded"));
    }
    if completion.tool_duration_ms > request.limits.timeout_ms {
        return Err(protocol_error("adapter exceeded the requested timeout"));
    }

    validate_sequences(&request, &events, &completion)?;
    validate_completion_counts(&events, &completion)?;
    validate_payloads(&manifest, &request, &events, &completion)?;

    Ok(ValidatedSession {
        manifest,
        request,
        events,
        completion,
        provider_stdout_bytes,
    })
}

fn preflight_session_input(
    input: &[u8],
    max_bytes: usize,
    max_lines: usize,
) -> Result<(), ContractError> {
    if input.len() > max_bytes {
        return Err(protocol_error(
            "session transcript exceeds the hard byte limit",
        ));
    }
    let line_count = input
        .split_inclusive(|byte| *byte == b'\n')
        .take(max_lines.saturating_add(1))
        .count();
    if line_count > max_lines {
        return Err(protocol_error(
            "session transcript exceeds the hard line limit",
        ));
    }

    let mut lines = input.split_inclusive(|byte| *byte == b'\n');
    if lines.next().is_none() {
        return Ok(());
    }
    let Some(raw_request) = lines.next() else {
        return Ok(());
    };
    let request_line = decode_line(2, raw_request)?;
    let ProtocolEnvelope::Request(request) =
        serde_json::from_value::<ProtocolEnvelope>(request_line.value)
            .map_err(|error| protocol_error(format!("line 2: {error}")))?
    else {
        return Err(protocol_error("exactly one request must follow manifest"));
    };
    let provider_bytes = input.len().saturating_sub(raw_request.len());
    if u64::try_from(provider_bytes).unwrap_or(u64::MAX) > request.limits.max_stdout_bytes {
        return Err(protocol_error("adapter stdout limit exceeded"));
    }
    let raw_final = input
        .split_inclusive(|byte| *byte == b'\n')
        .next_back()
        .ok_or_else(|| protocol_error("session transcript is empty"))?;
    let final_line = decode_line(line_count, raw_final)?;
    let final_envelope = serde_json::from_value::<ProtocolEnvelope>(final_line.value)
        .map_err(|error| protocol_error(format!("line {line_count}: {error}")))?;
    let structural_lines = if matches!(final_envelope, ProtocolEnvelope::Completion(_)) {
        3
    } else {
        2
    };
    let payload_lines = line_count.saturating_sub(structural_lines);
    if u64::try_from(payload_lines).unwrap_or(u64::MAX) > request.limits.max_events {
        return Err(protocol_error("event limit exceeded"));
    }
    Ok(())
}

/// Decode and validate one complete v1 `SessionReport` JSON object.
///
/// # Errors
///
/// Returns a typed contract error for malformed/duplicate-key JSON, local
/// model violations, duplicate object identifiers, or dangling/inconsistent
/// cross-object references.
pub fn validate_report_json(input: &[u8]) -> Result<SessionReport, ContractError> {
    preflight_report_input(input, MAX_REPORT_BYTES)?;
    let value = decode_json_object(input)?;
    let report = serde_json::from_value::<SessionReport>(value)
        .map_err(|error| ContractError::Model(error.to_string()))?;
    validate_report(&report)?;
    Ok(report)
}

fn preflight_report_input(input: &[u8], max_bytes: usize) -> Result<(), ContractError> {
    if input.len() > max_bytes {
        Err(model_error("session report exceeds the hard byte limit"))
    } else {
        Ok(())
    }
}

/// Validate an already decoded v1 `SessionReport`.
///
/// # Errors
///
/// Returns [`ContractError::Model`] when any local or referential invariant is
/// violated.
pub fn validate_report(report: &SessionReport) -> Result<(), ContractError> {
    report.validate()?;
    let index = ReportIndex::new(report)?;
    validate_report_references(report, &index)?;
    validate_report_decisions(report, &index)?;
    for candidate in index.fixes.values() {
        validate_fix_references(candidate, &index.observations, &index.evidence)?;
    }
    Ok(())
}

fn validate_report_references(
    report: &SessionReport,
    index: &ReportIndex<'_>,
) -> Result<(), ContractError> {
    for evidence in &report.evidence {
        if evidence
            .execution_id
            .as_ref()
            .is_some_and(|identifier| !index.executions.contains_key(identifier))
        {
            return Err(model_error("evidence references unknown execution"));
        }
    }
    validate_execution_verifications(report, index)?;
    for observation in &report.observations {
        require_all(
            &observation.evidence_ids,
            &index.evidence,
            "observation references unknown evidence",
        )?;
    }
    let finding_fingerprints_by_execution = validate_finding_references(report, index)?;
    validate_target_fingerprints(report, &finding_fingerprints_by_execution)
}

fn validate_execution_verifications(
    report: &SessionReport,
    index: &ReportIndex<'_>,
) -> Result<(), ContractError> {
    let mut base_snapshots_by_candidate: HashMap<ObjectId, Sha256Digest> = HashMap::new();
    for execution in &report.executions {
        let Some(verification) = execution.verification.as_ref() else {
            continue;
        };
        let Some(candidate) = index.fixes.get(&verification.fix_candidate_id) else {
            return Err(model_error(
                "execution verification references unknown fix candidate",
            ));
        };
        if candidate.applicability != crate::model::Applicability::Safe {
            return Err(model_error(
                "execution verification requires a SAFE fix candidate",
            ));
        }
        validate_verification_evidence(execution, verification, candidate, index)?;
        if let Some(previous) = base_snapshots_by_candidate.get(&verification.fix_candidate_id) {
            if previous != &verification.base_snapshot_sha256 {
                return Err(model_error(
                    "execution verification base snapshot differs for fix candidate",
                ));
            }
        }
        base_snapshots_by_candidate.insert(
            verification.fix_candidate_id.clone(),
            verification.base_snapshot_sha256.clone(),
        );
    }
    Ok(())
}

fn validate_verification_evidence(
    execution: &Execution,
    verification: &crate::model::VerificationAttribution,
    candidate: &FixCandidate,
    index: &ReportIndex<'_>,
) -> Result<(), ContractError> {
    let Some(patch) = index.evidence.get(&candidate.patch_evidence_id) else {
        return Err(model_error(
            "execution verification references unknown patch evidence",
        ));
    };
    if patch.source != EvidenceSource::Patch {
        return Err(model_error(
            "execution verification patch evidence is not a patch",
        ));
    }
    if patch.truncated {
        return Err(model_error(
            "execution verification patch evidence is truncated",
        ));
    }
    if patch.content.is_none() {
        return Err(model_error(
            "execution verification patch evidence must be inline",
        ));
    }
    if verification.patch_sha256 != patch.sha256 {
        return Err(model_error(
            "execution verification patch digest differs from patch evidence",
        ));
    }
    let Some(base_snapshot) = index.evidence.get(&verification.base_snapshot_evidence_id) else {
        return Err(model_error(
            "execution verification references unknown base snapshot evidence",
        ));
    };
    if base_snapshot.source != EvidenceSource::Artifact {
        return Err(model_error(
            "execution verification base snapshot evidence is not an artifact",
        ));
    }
    if base_snapshot.content.is_none() {
        return Err(model_error(
            "execution verification base snapshot evidence must be inline",
        ));
    }
    if base_snapshot.truncated {
        return Err(model_error(
            "execution verification base snapshot evidence is truncated",
        ));
    }
    if base_snapshot.media_type != "application/vnd.diagnostic-triage.snapshot+json" {
        return Err(model_error(
            "execution verification base snapshot evidence has an invalid media type",
        ));
    }
    if verification.base_snapshot_sha256 != base_snapshot.sha256 {
        return Err(model_error(
            "execution verification base snapshot digest differs from snapshot evidence",
        ));
    }
    if verification.base_snapshot_evidence_id == verification.result_evidence_id {
        return Err(model_error(
            "execution verification snapshot and result evidence must differ",
        ));
    }
    let Some(result) = index.evidence.get(&verification.result_evidence_id) else {
        return Err(model_error(
            "execution verification references unknown result evidence",
        ));
    };
    if !matches!(
        result.source,
        EvidenceSource::Stdout | EvidenceSource::Diagnostic | EvidenceSource::Artifact
    ) {
        return Err(model_error(
            "execution verification result evidence has an invalid source",
        ));
    }
    if result.media_type == "application/vnd.diagnostic-triage.snapshot+json" {
        return Err(model_error(
            "execution verification result evidence cannot be a base snapshot",
        ));
    }
    if execution.status == ExecutionStatus::Complete && result.truncated {
        return Err(model_error(
            "complete verification execution has truncated result evidence",
        ));
    }
    if execution.status == ExecutionStatus::Complete && result.content.is_none() {
        return Err(model_error(
            "complete verification result evidence must be inline",
        ));
    }
    if result.execution_id.as_ref() != Some(&execution.execution_id) {
        return Err(model_error(
            "execution verification result evidence belongs to a different execution",
        ));
    }
    Ok(())
}

fn validate_finding_references(
    report: &SessionReport,
    index: &ReportIndex<'_>,
) -> Result<HashMap<ObjectId, HashSet<Fingerprint>>, ContractError> {
    let mut finding_fingerprints_by_execution: HashMap<ObjectId, HashSet<Fingerprint>> =
        HashMap::new();
    for finding in &report.findings {
        require_all(
            &finding.observation_ids,
            &index.observations,
            "finding references unknown observation",
        )?;
        require_all(
            &finding.evidence_ids,
            &index.evidence,
            "finding references unknown evidence",
        )?;
        for identifier in &finding.observation_ids {
            let observation = index
                .observations
                .get(identifier)
                .expect("finding observation references were checked");
            if observation.tool != finding.tool {
                return Err(model_error(
                    "finding tool differs from source observation tool",
                ));
            }
        }
        if let Some(identifier) = &finding.fix_candidate_id {
            let Some(candidate) = index.fixes.get(identifier) else {
                return Err(model_error("finding references unknown fix candidate"));
            };
            let candidate_observations = candidate.observation_ids.iter().collect::<HashSet<_>>();
            if finding
                .observation_ids
                .iter()
                .any(|observation_id| !candidate_observations.contains(observation_id))
            {
                return Err(model_error(
                    "finding observations are outside the fix candidate scope",
                ));
            }
        }
        if let Some(identifiers) = &finding.verification_execution_ids {
            require_all(
                identifiers,
                &index.executions,
                "finding references unknown verification execution",
            )?;
            for identifier in identifiers {
                finding_fingerprints_by_execution
                    .entry(identifier.clone())
                    .or_default()
                    .insert(finding.fingerprint.clone());
            }
            validate_finding_verification(
                finding,
                identifiers,
                index,
                matches!(finding.state, crate::model::FindingState::Verified),
            )?;
        }
    }
    Ok(finding_fingerprints_by_execution)
}

fn validate_finding_verification(
    finding: &Finding,
    identifiers: &[ObjectId],
    index: &ReportIndex<'_>,
    is_verified: bool,
) -> Result<(), ContractError> {
    let Some(fix_candidate_id) = finding.fix_candidate_id.as_ref() else {
        return Err(model_error(
            "citing finding is missing its fix candidate reference",
        ));
    };
    let Some(candidate) = index.fixes.get(fix_candidate_id) else {
        return Err(model_error(
            "citing finding references unknown fix candidate",
        ));
    };
    if is_verified && candidate.applicability != crate::model::Applicability::Safe {
        return Err(model_error(
            "verified finding requires a SAFE fix candidate",
        ));
    }
    for identifier in identifiers {
        let Some(execution) = index.executions.get(identifier) else {
            return Err(model_error(
                "citing finding references unknown verification execution",
            ));
        };
        if execution.tool.name != finding.tool.name
            || execution.tool.version != finding.tool.version
        {
            return Err(model_error(
                "citing finding tool differs from execution tool",
            ));
        }
        let Some(verification) = execution.verification.as_ref() else {
            return Err(model_error(
                "citing finding cites execution without verification attribution",
            ));
        };
        if verification.fix_candidate_id != *fix_candidate_id {
            return Err(model_error(
                "citing finding execution attribution differs from fix candidate",
            ));
        }
        if is_verified {
            if execution.status != ExecutionStatus::Complete {
                return Err(model_error("verified finding cites incomplete execution"));
            }
            if execution.adapter_kind != AdapterKind::Provider {
                return Err(model_error("verified finding cites non-provider execution"));
            }
        }
    }
    Ok(())
}

fn validate_target_fingerprints(
    report: &SessionReport,
    finding_fingerprints_by_execution: &HashMap<ObjectId, HashSet<Fingerprint>>,
) -> Result<(), ContractError> {
    for execution in &report.executions {
        let Some(verification) = execution.verification.as_ref() else {
            continue;
        };
        let expected = finding_fingerprints_by_execution
            .get(&execution.execution_id)
            .cloned()
            .unwrap_or_default();
        let actual = verification
            .target_fingerprints
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        if actual != expected {
            return Err(model_error(
                "execution verification target fingerprints do not match citing findings",
            ));
        }
    }
    Ok(())
}

fn validate_report_decisions(
    report: &SessionReport,
    index: &ReportIndex<'_>,
) -> Result<(), ContractError> {
    let mut decided_findings = HashSet::new();
    for decision in index.decisions.values() {
        let Some(finding) = index.findings.get(&decision.finding_id) else {
            return Err(model_error("decision references unknown finding"));
        };
        if !decided_findings.insert(decision.finding_id.clone()) {
            return Err(model_error("finding has multiple policy decisions"));
        }
        if decision.policy_digest != report.policy_digest {
            return Err(model_error("decision policy digest differs from report"));
        }
        if decision
            .waiver
            .as_ref()
            .is_some_and(|waiver| waiver.fingerprint != finding.fingerprint)
        {
            return Err(model_error("waiver fingerprint differs from finding"));
        }
    }
    if decided_findings.len() != index.findings.len() {
        return Err(model_error("every finding requires one policy decision"));
    }
    Ok(())
}

fn validate_adapter_request(
    manifest: &ManifestEnvelope,
    request: &RequestEnvelope,
) -> Result<(), ContractError> {
    let operation_allowed = match manifest.adapter.kind {
        AdapterKind::Provider => matches!(
            request.operation,
            Operation::Check | Operation::Fix | Operation::Verify
        ),
        AdapterKind::Observer => matches!(request.operation, Operation::Observe),
        AdapterKind::Engine => false,
    };
    if !operation_allowed {
        return Err(protocol_error(
            "adapter role does not support the requested operation",
        ));
    }
    let capabilities = manifest
        .adapter
        .capabilities
        .iter()
        .map(AsRef::<str>::as_ref)
        .collect::<HashSet<_>>();
    if request
        .required_capabilities
        .iter()
        .any(|capability| !capabilities.contains(capability.as_str()))
    {
        return Err(protocol_error("required capability is unsupported"));
    }
    Ok(())
}

fn validate_sequences(
    request: &RequestEnvelope,
    events: &[ProtocolEnvelope],
    completion: &CompletionEnvelope,
) -> Result<(), ContractError> {
    for (expected, event) in events.iter().enumerate() {
        let Some((request_id, sequence)) = event_header(event) else {
            return Err(protocol_error(
                "manifest, request, or completion is out of order",
            ));
        };
        if request_id != &request.request_id {
            return Err(protocol_error("request_id mismatch"));
        }
        if sequence != u64::try_from(expected).unwrap_or(u64::MAX) {
            return Err(protocol_error("non-contiguous sequence"));
        }
    }
    if completion.request_id != request.request_id {
        return Err(protocol_error("request_id mismatch"));
    }
    if completion.sequence != u64::try_from(events.len()).unwrap_or(u64::MAX) {
        return Err(protocol_error("non-contiguous sequence"));
    }
    Ok(())
}

fn event_header(event: &ProtocolEnvelope) -> Option<(&ObjectId, u64)> {
    match event {
        ProtocolEnvelope::Observation(value) => Some((&value.request_id, value.sequence)),
        ProtocolEnvelope::Evidence(value) => Some((&value.request_id, value.sequence)),
        ProtocolEnvelope::FixCandidate(value) => Some((&value.request_id, value.sequence)),
        ProtocolEnvelope::Execution(value) => Some((&value.request_id, value.sequence)),
        ProtocolEnvelope::Manifest(_)
        | ProtocolEnvelope::Request(_)
        | ProtocolEnvelope::Completion(_) => None,
    }
}

fn validate_completion_counts(
    events: &[ProtocolEnvelope],
    completion: &CompletionEnvelope,
) -> Result<(), ContractError> {
    let mut actual = CompletionCounts {
        observations: 0,
        evidence: 0,
        fix_candidates: 0,
        executions: 0,
    };
    for event in events {
        match event {
            ProtocolEnvelope::Observation(_) => actual.observations += 1,
            ProtocolEnvelope::Evidence(_) => actual.evidence += 1,
            ProtocolEnvelope::FixCandidate(_) => actual.fix_candidates += 1,
            ProtocolEnvelope::Execution(_) => actual.executions += 1,
            ProtocolEnvelope::Manifest(_)
            | ProtocolEnvelope::Request(_)
            | ProtocolEnvelope::Completion(_) => {
                return Err(protocol_error("non-payload envelope appears after request"));
            }
        }
    }
    if actual != completion.counts {
        return Err(protocol_error("completion counts do not match events"));
    }
    Ok(())
}

fn validate_payloads(
    manifest: &ManifestEnvelope,
    request: &RequestEnvelope,
    events: &[ProtocolEnvelope],
    completion: &CompletionEnvelope,
) -> Result<(), ContractError> {
    let requested = request
        .required_capabilities
        .iter()
        .chain(&request.optional_capabilities)
        .map(AsRef::<str>::as_ref)
        .collect::<HashSet<_>>();
    let negotiated = manifest
        .adapter
        .capabilities
        .iter()
        .map(AsRef::<str>::as_ref)
        .filter(|capability| requested.contains(capability))
        .collect::<HashSet<_>>();
    let mut object_ids = HashSet::new();
    let mut evidence = HashMap::new();
    let mut observations = HashMap::new();
    let mut fixes = Vec::new();
    let mut executions = HashMap::new();
    let mut retained_bytes = 0_u64;

    for event in events {
        validate_adapter_event(manifest, event)?;
        if let Some(capability) = event_capability(event) {
            if !negotiated.contains(capability) {
                return Err(protocol_error(format!(
                    "event capability was not negotiated: {}",
                    event_name(event)
                )));
            }
        }
        let identifier = payload_identifier(event)
            .ok_or_else(|| protocol_error("non-payload envelope appears after request"))?;
        if !object_ids.insert(identifier.clone()) {
            return Err(protocol_error(format!("duplicate object id: {identifier}")));
        }
        match event {
            ProtocolEnvelope::Evidence(value) => {
                if value.evidence.retained_bytes > request.limits.max_evidence_bytes {
                    return Err(protocol_error("evidence limit exceeded"));
                }
                retained_bytes = retained_bytes
                    .checked_add(value.evidence.retained_bytes)
                    .ok_or_else(|| protocol_error("evidence byte count overflowed"))?;
                evidence.insert(value.evidence.evidence_id.clone(), &value.evidence);
            }
            ProtocolEnvelope::Observation(value) => {
                observations.insert(value.observation.observation_id.clone(), &value.observation);
            }
            ProtocolEnvelope::FixCandidate(value) => fixes.push(&value.fix_candidate),
            ProtocolEnvelope::Execution(value) => {
                validate_execution_attribution(manifest, &value.execution)?;
                executions.insert(value.execution.execution_id.clone(), &value.execution);
            }
            ProtocolEnvelope::Manifest(_)
            | ProtocolEnvelope::Request(_)
            | ProtocolEnvelope::Completion(_) => unreachable!("payload shape checked above"),
        }
    }
    if completion.evidence_bytes != retained_bytes {
        return Err(protocol_error("completion evidence byte count mismatch"));
    }
    for observation in observations.values() {
        require_all(
            &observation.evidence_ids,
            &evidence,
            "observation references unknown evidence",
        )?;
    }
    for item in evidence.values() {
        if item
            .execution_id
            .as_ref()
            .is_some_and(|identifier| !executions.contains_key(identifier))
        {
            return Err(protocol_error("evidence references unknown execution"));
        }
    }
    for candidate in fixes {
        validate_fix_references(candidate, &observations, &evidence)?;
    }
    Ok(())
}

fn validate_adapter_event(
    manifest: &ManifestEnvelope,
    event: &ProtocolEnvelope,
) -> Result<(), ContractError> {
    let allowed = match manifest.adapter.kind {
        AdapterKind::Provider => matches!(
            event,
            ProtocolEnvelope::Observation(_)
                | ProtocolEnvelope::Evidence(_)
                | ProtocolEnvelope::FixCandidate(_)
        ),
        AdapterKind::Observer => matches!(
            event,
            ProtocolEnvelope::Evidence(_) | ProtocolEnvelope::Execution(_)
        ),
        AdapterKind::Engine => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(protocol_error(format!(
            "{} cannot emit {}",
            match manifest.adapter.kind {
                AdapterKind::Provider => "provider",
                AdapterKind::Observer => "observer",
                AdapterKind::Engine => "engine",
            },
            event_name(event)
        )))
    }
}

fn event_capability(event: &ProtocolEnvelope) -> Option<&'static str> {
    match event {
        ProtocolEnvelope::Observation(_) => Some("diagnostic.check/v1"),
        ProtocolEnvelope::FixCandidate(_) => Some("fix.propose/v1"),
        ProtocolEnvelope::Execution(_) => Some("execution.observe/v1"),
        ProtocolEnvelope::Evidence(_)
        | ProtocolEnvelope::Manifest(_)
        | ProtocolEnvelope::Request(_)
        | ProtocolEnvelope::Completion(_) => None,
    }
}

fn event_name(event: &ProtocolEnvelope) -> &'static str {
    match event {
        ProtocolEnvelope::Manifest(_) => "manifest",
        ProtocolEnvelope::Request(_) => "request",
        ProtocolEnvelope::Observation(_) => "observation",
        ProtocolEnvelope::Evidence(_) => "evidence",
        ProtocolEnvelope::FixCandidate(_) => "fix_candidate",
        ProtocolEnvelope::Execution(_) => "execution",
        ProtocolEnvelope::Completion(_) => "completion",
    }
}

fn payload_identifier(event: &ProtocolEnvelope) -> Option<&ObjectId> {
    match event {
        ProtocolEnvelope::Observation(value) => Some(&value.observation.observation_id),
        ProtocolEnvelope::Evidence(value) => Some(&value.evidence.evidence_id),
        ProtocolEnvelope::FixCandidate(value) => Some(&value.fix_candidate.fix_candidate_id),
        ProtocolEnvelope::Execution(value) => Some(&value.execution.execution_id),
        ProtocolEnvelope::Manifest(_)
        | ProtocolEnvelope::Request(_)
        | ProtocolEnvelope::Completion(_) => None,
    }
}

fn validate_execution_attribution(
    manifest: &ManifestEnvelope,
    execution: &Execution,
) -> Result<(), ContractError> {
    if execution.adapter_id != manifest.adapter.id {
        return Err(protocol_error("execution adapter id differs from manifest"));
    }
    if execution.adapter_kind != manifest.adapter.kind {
        return Err(protocol_error(
            "execution adapter kind differs from manifest",
        ));
    }
    Ok(())
}

fn validate_fix_references(
    candidate: &FixCandidate,
    observations: &HashMap<ObjectId, &Observation>,
    evidence: &HashMap<ObjectId, &Evidence>,
) -> Result<(), ContractError> {
    require_all(
        &candidate.observation_ids,
        observations,
        "fix references unknown observation",
    )?;
    let mut candidate_tool = None;
    for identifier in &candidate.observation_ids {
        let observation = observations
            .get(identifier)
            .expect("fix observation references were checked");
        let tool_identity = (&observation.tool.name, &observation.tool.version);
        if candidate_tool.is_some_and(|expected| expected != tool_identity) {
            return Err(model_error("fix candidate spans multiple tool identities"));
        }
        candidate_tool = Some(tool_identity);
    }
    let Some(patch) = evidence.get(&candidate.patch_evidence_id) else {
        return Err(model_error("fix references unknown patch evidence"));
    };
    if patch.source != EvidenceSource::Patch {
        return Err(model_error("fix evidence is not a patch"));
    }
    Ok(())
}

fn index_unique<'a, T, F>(
    values: &'a [T],
    identifier: F,
    kind: &str,
    all_ids: &mut HashSet<ObjectId>,
) -> Result<HashMap<ObjectId, &'a T>, ContractError>
where
    F: Fn(&T) -> &ObjectId,
{
    let mut indexed = HashMap::with_capacity(values.len());
    for value in values {
        let identifier = identifier(value);
        if !all_ids.insert(identifier.clone()) {
            return Err(model_error(format!(
                "duplicate {kind} id in report: {identifier}"
            )));
        }
        indexed.insert(identifier.clone(), value);
    }
    Ok(indexed)
}

fn require_all<T>(
    identifiers: &[ObjectId],
    indexed: &HashMap<ObjectId, T>,
    message: &str,
) -> Result<(), ContractError> {
    if identifiers
        .iter()
        .all(|identifier| indexed.contains_key(identifier))
    {
        Ok(())
    } else {
        Err(model_error(message))
    }
}

fn protocol_error(message: impl Into<String>) -> ContractError {
    ContractError::Protocol(message.into())
}

fn model_error(message: impl Into<String>) -> ContractError {
    ContractError::Model(message.into())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{preflight_report_input, preflight_session_input};

    #[test]
    fn preflight_rejects_bytes_and_lines_before_json_materialization() {
        assert!(preflight_session_input(b"12345678901", 10, 3).is_err());
        assert!(preflight_session_input(b"{}\n{}\n{}\n{}", 64, 3).is_err());
        assert!(preflight_session_input(b"{}", 64, 3).is_ok());
    }

    #[test]
    fn report_preflight_rejects_bytes_before_json_materialization() {
        assert!(preflight_report_input(b"12345678901", 10).is_err());
        assert!(preflight_report_input(b"{}", 10).is_ok());
    }

    #[test]
    fn preflight_counts_a_noncompletion_final_line_as_payload() {
        let request = json!({
            "protocol_version": "diagnostic-triage.protocol/v1",
            "kind": "request",
            "request_id": "019f7e95-0000-7000-8000-000000000001",
            "operation": "CHECK",
            "workspace": ".",
            "targets": ["src/lib.rs"],
            "required_capabilities": [],
            "optional_capabilities": [],
            "limits": {
                "timeout_ms": 1,
                "max_stdout_bytes": 10_000,
                "max_stderr_bytes": 0,
                "max_evidence_bytes": 0,
                "max_events": 0
            }
        });
        let final_manifest = json!({
            "protocol_version": "diagnostic-triage.protocol/v1",
            "kind": "manifest",
            "adapter": {
                "id": "ruff",
                "version": "1",
                "kind": "PROVIDER",
                "capabilities": ["diagnostic.check/v1"],
                "languages": []
            }
        });
        let transcript = format!("{{}}\n{request}\n{final_manifest}");
        assert!(preflight_session_input(transcript.as_bytes(), 4096, 10).is_err());
    }
}
