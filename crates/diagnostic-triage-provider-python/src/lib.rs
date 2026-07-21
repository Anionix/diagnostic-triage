//! Ruff-backed Python provider protocol primitives.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

mod process;

use std::{
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

use diagnostic_triage_contracts::{
    Capability, Language, Nullable, ObjectId, RepoPath, Sha256Digest,
    model::{
        AdapterKind, Applicability, Evidence, EvidenceSchemaVersion, EvidenceSource,
        ExecutionStatus, FixCandidate, FixCandidateSchemaVersion, Location, Observation,
        ObservationSchemaVersion, Origin, Position, Severity, Tool,
    },
    protocol::{
        AdapterManifest, CompletionCounts, CompletionEnvelope, EnvelopeKind, EvidenceEnvelope,
        FixCandidateEnvelope, ManifestEnvelope, ObservationEnvelope, Operation, ProtocolEnvelope,
        ProtocolVersion, RequestEnvelope,
    },
    validate_session_jsonl,
};
use process::{
    BoundedOutput, ProcessLimits, ProcessOutcome, ProcessSpec, ProcessState, run_bounded,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
const CHECK_CAPABILITY: &str = "diagnostic.check/v1";
const FIX_CAPABILITY: &str = "fix.propose/v1";
const RUFF_FIX_MEDIA_TYPE: &str = "application/vnd.ruff.fix+json";

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("input exceeds the {limit}-byte bound")]
    InputLimit { limit: usize },
    #[error("expected exactly one RequestV1 envelope: {0}")]
    Request(String),
    #[error("unsupported request: {0}")]
    Unsupported(String),
    #[error("malformed Ruff JSON: {0}")]
    RuffJson(#[from] serde_json::Error),
    #[error("unsupported Ruff severity: {0}")]
    RuffSeverity(String),
    #[error("Ruff path escapes the repository: {0}")]
    PathEscape(String),
    #[error("event count exceeds the caller limit")]
    EventLimit,
    #[error(
        "canonical Ruff fix evidence exceeds the caller's {limit}-byte bound ({observed} bytes)"
    )]
    FixEvidenceLimit { observed: usize, limit: usize },
    #[error("generated envelope violates the v1 contract: {0}")]
    Contract(String),
    #[error("Ruff process failed: {0}")]
    Process(String),
    #[error("workspace is not a repository directory: {0}")]
    Workspace(String),
    #[error("failed to emit JSONL: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedRuff {
    pub events: Vec<ProtocolEnvelope>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSession {
    pub events: Vec<ProtocolEnvelope>,
    pub completion: CompletionEnvelope,
}

#[derive(Clone, Debug)]
pub struct CompletionBuilder {
    request_id: ObjectId,
    next_sequence: u64,
    max_events: u64,
    timeout_ms: u64,
    max_evidence_bytes: u32,
    counts: CompletionCounts,
    evidence_bytes: u64,
}

impl CompletionBuilder {
    #[must_use]
    pub fn new(request: &RequestEnvelope) -> Self {
        Self {
            request_id: request.request_id.clone(),
            next_sequence: 0,
            max_events: request.limits.max_events,
            timeout_ms: request.limits.timeout_ms,
            max_evidence_bytes: u32::try_from(request.limits.max_evidence_bytes)
                .unwrap_or(u32::MAX),
            counts: CompletionCounts {
                observations: 0,
                evidence: 0,
                fix_candidates: 0,
                executions: 0,
            },
            evidence_bytes: 0,
        }
    }

    fn observation(
        &mut self,
        observation: Observation,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if self.next_sequence >= self.max_events {
            return Err(ProviderError::EventLimit);
        }
        let envelope = ObservationEnvelope {
            protocol_version: ProtocolVersion::V1,
            kind: EnvelopeKind::Observation,
            request_id: self.request_id.clone(),
            sequence: self.next_sequence,
            observation,
        };
        ProtocolEnvelope::Observation(envelope.clone())
            .validate()
            .map_err(|error| ProviderError::Contract(error.to_string()))?;
        self.next_sequence += 1;
        self.counts.observations += 1;
        Ok(envelope)
    }

    fn evidence(
        &mut self,
        source: EvidenceSource,
        media_type: &str,
        output: &BoundedOutput,
    ) -> Result<EvidenceEnvelope, ProviderError> {
        if self.next_sequence >= self.max_events {
            return Err(ProviderError::EventLimit);
        }
        let retain_limit = usize::try_from(self.max_evidence_bytes).unwrap_or(usize::MAX);
        let retained = utf8_prefix(&output.bytes[..output.bytes.len().min(retain_limit)]);
        let retained_bytes = u64::try_from(retained.len()).unwrap_or(u64::MAX);
        let evidence = Evidence {
            schema_version: EvidenceSchemaVersion::V1,
            evidence_id: derive_event_id(&self.request_id, self.next_sequence)?,
            execution_id: None,
            source,
            media_type: media_type.to_owned(),
            retained_bytes,
            observed_bytes: output.observed_bytes,
            limit_bytes: self.max_evidence_bytes,
            truncated: output.observed_bytes > retained_bytes,
            sha256: Sha256Digest::compute(retained.as_bytes()),
            relative_path: None,
            content: Some(retained.to_owned()),
        };
        let envelope = EvidenceEnvelope {
            protocol_version: ProtocolVersion::V1,
            kind: EnvelopeKind::Evidence,
            request_id: self.request_id.clone(),
            sequence: self.next_sequence,
            evidence,
        };
        ProtocolEnvelope::Evidence(envelope.clone())
            .validate()
            .map_err(|error| ProviderError::Contract(error.to_string()))?;
        self.next_sequence += 1;
        self.counts.evidence += 1;
        self.evidence_bytes = self.evidence_bytes.saturating_add(retained_bytes);
        Ok(envelope)
    }

    fn patch_evidence(&mut self, content: String) -> Result<EvidenceEnvelope, ProviderError> {
        let limit = usize::try_from(self.max_evidence_bytes).unwrap_or(usize::MAX);
        if content.len() > limit {
            return Err(ProviderError::FixEvidenceLimit {
                observed: content.len(),
                limit,
            });
        }
        let observed_bytes = u64::try_from(content.len()).unwrap_or(u64::MAX);
        self.evidence(
            EvidenceSource::Patch,
            RUFF_FIX_MEDIA_TYPE,
            &BoundedOutput {
                bytes: content.into_bytes(),
                observed_bytes,
                truncated: false,
            },
        )
    }

    fn fix_candidate(
        &mut self,
        observation_id: ObjectId,
        applicability: Applicability,
        patch_evidence_id: ObjectId,
    ) -> Result<FixCandidateEnvelope, ProviderError> {
        if self.next_sequence >= self.max_events {
            return Err(ProviderError::EventLimit);
        }
        let envelope = FixCandidateEnvelope {
            protocol_version: ProtocolVersion::V1,
            kind: EnvelopeKind::FixCandidate,
            request_id: self.request_id.clone(),
            sequence: self.next_sequence,
            fix_candidate: FixCandidate {
                schema_version: FixCandidateSchemaVersion::V1,
                fix_candidate_id: derive_event_id(&self.request_id, self.next_sequence)?,
                observation_ids: vec![observation_id],
                applicability,
                tool_native: true,
                patch_evidence_id,
            },
        };
        ProtocolEnvelope::FixCandidate(envelope.clone())
            .validate()
            .map_err(|error| ProviderError::Contract(error.to_string()))?;
        self.next_sequence += 1;
        self.counts.fix_candidates += 1;
        Ok(envelope)
    }

    /// Build the final successful completion with the accumulated counts.
    ///
    /// # Errors
    ///
    /// Returns an error when duration or the generated envelope violates v1.
    pub fn complete(
        self,
        exit_code: u8,
        duration_ms: u64,
    ) -> Result<CompletionEnvelope, ProviderError> {
        self.finish(
            ExecutionStatus::Complete,
            Nullable(Some(exit_code)),
            duration_ms,
            None,
        )
    }

    /// Build the final incomplete completion with the accumulated counts.
    ///
    /// # Errors
    ///
    /// Returns an error when duration, message, or the envelope violates v1.
    pub fn incomplete(
        self,
        duration_ms: u64,
        message: impl Into<String>,
    ) -> Result<CompletionEnvelope, ProviderError> {
        self.finish(
            ExecutionStatus::Incomplete,
            Nullable(None),
            duration_ms,
            Some(message.into()),
        )
    }

    /// Build the final unsupported completion with the accumulated counts.
    ///
    /// # Errors
    ///
    /// Returns an error when duration, message, or the envelope violates v1.
    pub fn unsupported(
        self,
        duration_ms: u64,
        message: impl Into<String>,
    ) -> Result<CompletionEnvelope, ProviderError> {
        self.finish(
            ExecutionStatus::Unsupported,
            Nullable(None),
            duration_ms,
            Some(message.into()),
        )
    }

    fn finish(
        self,
        status: ExecutionStatus,
        tool_exit_code: Nullable<u8>,
        duration_ms: u64,
        message: Option<String>,
    ) -> Result<CompletionEnvelope, ProviderError> {
        if duration_ms > self.timeout_ms {
            return Err(ProviderError::Contract(
                "completion duration exceeds the request timeout".to_owned(),
            ));
        }
        let completion = CompletionEnvelope {
            protocol_version: ProtocolVersion::V1,
            kind: EnvelopeKind::Completion,
            request_id: self.request_id,
            sequence: self.next_sequence,
            status,
            tool_exit_code,
            tool_duration_ms: duration_ms,
            counts: self.counts,
            evidence_bytes: self.evidence_bytes,
            message,
        };
        ProtocolEnvelope::Completion(completion.clone())
            .validate()
            .map_err(|error| ProviderError::Contract(error.to_string()))?;
        Ok(completion)
    }
}

/// Build this slice's typed Provider manifest.
///
/// # Errors
///
/// Returns an error if a static v1 scalar no longer satisfies the contract.
pub fn manifest() -> Result<ManifestEnvelope, ProviderError> {
    Ok(ManifestEnvelope {
        protocol_version: ProtocolVersion::V1,
        kind: EnvelopeKind::Manifest,
        adapter: AdapterManifest {
            id: "ruff"
                .parse()
                .map_err(|error: &str| ProviderError::Contract(error.to_owned()))?,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            kind: AdapterKind::Provider,
            capabilities: vec![
                CHECK_CAPABILITY
                    .parse::<Capability>()
                    .map_err(|error| ProviderError::Contract(error.to_owned()))?,
                FIX_CAPABILITY
                    .parse::<Capability>()
                    .map_err(|error| ProviderError::Contract(error.to_owned()))?,
            ],
            languages: vec![
                "python"
                    .parse::<Language>()
                    .map_err(|error| ProviderError::Contract(error.to_owned()))?,
            ],
        },
    })
}

/// Emit exactly one validated manifest JSONL line.
///
/// # Errors
///
/// Returns an I/O, serialization, or contract validation error.
pub fn emit_manifest(writer: &mut impl Write) -> Result<(), ProviderError> {
    emit_envelope(writer, &ProtocolEnvelope::Manifest(manifest()?))
}

/// Emit one validated protocol envelope as one JSONL line.
///
/// # Errors
///
/// Returns an I/O, serialization, or contract validation error.
pub fn emit_envelope(
    writer: &mut impl Write,
    envelope: &ProtocolEnvelope,
) -> Result<(), ProviderError> {
    envelope
        .validate()
        .map_err(|error| ProviderError::Contract(error.to_string()))?;
    serde_json::to_writer(&mut *writer, envelope)?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// Decode exactly one bounded `RequestV1` JSONL line.
///
/// # Errors
///
/// Returns an error for overflow, malformed JSON, a non-request kind, or an
/// invalid v1 field.
pub fn decode_request(input: &[u8], max_bytes: usize) -> Result<RequestEnvelope, ProviderError> {
    if input.len() > max_bytes {
        return Err(ProviderError::InputLimit { limit: max_bytes });
    }
    let line = input
        .strip_suffix(b"\r\n")
        .or_else(|| input.strip_suffix(b"\n"))
        .unwrap_or(input);
    if line.contains(&b'\n') || line.contains(&b'\r') {
        return Err(ProviderError::Request(
            "request must occupy exactly one JSONL line".to_owned(),
        ));
    }
    let envelope = serde_json::from_slice::<ProtocolEnvelope>(line)
        .map_err(|error| ProviderError::Request(error.to_string()))?;
    envelope
        .validate()
        .map_err(|error| ProviderError::Request(error.to_string()))?;
    let ProtocolEnvelope::Request(request) = envelope else {
        return Err(ProviderError::Request(
            "input envelope kind is not request".to_owned(),
        ));
    };
    Ok(request)
}

/// Validate that a request can be honored by this bounded slice.
///
/// # Errors
///
/// Returns [`ProviderError::Unsupported`] for operations or required
/// capabilities that are not advertised.
pub fn validate_request(request: &RequestEnvelope) -> Result<(), ProviderError> {
    ProtocolEnvelope::Request(request.clone())
        .validate()
        .map_err(|error| ProviderError::Request(error.to_string()))?;
    if request.operation != Operation::Check {
        return Err(ProviderError::Unsupported(
            "this slice implements only CHECK".to_owned(),
        ));
    }
    if request
        .required_capabilities
        .iter()
        .any(|capability| !matches!(capability.as_str(), CHECK_CAPABILITY | FIX_CAPABILITY))
    {
        return Err(ProviderError::Unsupported(
            "required capability is not advertised".to_owned(),
        ));
    }
    if !request
        .required_capabilities
        .iter()
        .chain(&request.optional_capabilities)
        .any(|capability| capability.as_str() == CHECK_CAPABILITY)
    {
        return Err(ProviderError::Unsupported(
            "CHECK requires diagnostic.check/v1".to_owned(),
        ));
    }
    Ok(())
}

fn request_negotiates(request: &RequestEnvelope, capability: &str) -> bool {
    request
        .required_capabilities
        .iter()
        .chain(&request.optional_capabilities)
        .any(|requested| requested.as_str() == capability)
}

/// Purely normalize caller-bounded Ruff JSON while preserving Ruff's native
/// error/warning severity. Policy classification remains an Engine responsibility.
///
/// # Errors
///
/// Returns an error for malformed or over-limit output, path escapes, invalid
/// locations, or a completion builder from another request.
pub fn normalize_ruff_json(
    request: &RequestEnvelope,
    tool_version: &str,
    repository_root: &Path,
    input: &[u8],
    evidence_ids: &[ObjectId],
    completion: &mut CompletionBuilder,
) -> Result<NormalizedRuff, ProviderError> {
    if completion.request_id != request.request_id
        || completion.max_events != request.limits.max_events
        || completion.timeout_ms != request.limits.timeout_ms
        || u64::from(completion.max_evidence_bytes) != request.limits.max_evidence_bytes
    {
        return Err(ProviderError::Contract(
            "completion builder belongs to a different request".to_owned(),
        ));
    }
    if input.len() > usize::try_from(request.limits.max_stdout_bytes).unwrap_or(usize::MAX) {
        return Err(ProviderError::InputLimit {
            limit: usize::try_from(request.limits.max_stdout_bytes).unwrap_or(usize::MAX),
        });
    }
    let diagnostics = serde_json::from_slice::<Vec<RuffDiagnostic>>(input)?;
    if completion
        .next_sequence
        .checked_add(u64::try_from(diagnostics.len()).unwrap_or(u64::MAX))
        .is_none_or(|count| count > request.limits.max_events)
    {
        return Err(ProviderError::EventLimit);
    }

    let mut staged = completion.clone();
    let mut events = Vec::with_capacity(diagnostics.len());
    let emit_fixes = request_negotiates(request, FIX_CAPABILITY);
    for diagnostic in diagnostics {
        let normalized_path = normalize_path(&diagnostic.filename, repository_root)?;
        let severity = normalize_severity(&diagnostic.severity)?;
        let observation_id = derive_event_id(&request.request_id, staged.next_sequence)?;
        let patch = emit_fixes
            .then_some(diagnostic.fix.as_ref())
            .flatten()
            .map(|fix| {
                let fix_view = serde_json::from_value::<RuffFixView>(fix.clone())?;
                Ok::<_, ProviderError>((
                    serde_json::to_string(&RuffFixPatch {
                        version: tool_version,
                        filename: normalized_path.as_str(),
                        rule_id: diagnostic.code.as_deref(),
                        fix,
                    })?,
                    candidate_applicability(&fix_view),
                ))
            })
            .transpose()?;
        let observation = Observation {
            schema_version: ObservationSchemaVersion::V1,
            observation_id: observation_id.clone(),
            tool: Tool {
                name: "ruff".to_owned(),
                version: tool_version.to_owned(),
                rule_id: diagnostic.code,
            },
            language: "python"
                .parse::<Language>()
                .map_err(|error| ProviderError::Contract(error.to_owned()))?,
            severity,
            origin: Origin::Normal,
            message: diagnostic.message,
            location: Some(Location {
                path: normalized_path,
                // Ruff JSON reports one-based Unicode scalar-value columns
                // and an exclusive TextRange end, matching Location v1.
                start: diagnostic.location.into(),
                end: diagnostic.end_location.map(Into::into),
            }),
            symbol: None,
            expected: None,
            observed: None,
            evidence_ids: evidence_ids.to_vec(),
        };
        events.push(ProtocolEnvelope::Observation(
            staged.observation(observation)?,
        ));
        if let Some((content, applicability)) = patch {
            let patch_evidence = staged.patch_evidence(content)?;
            let patch_evidence_id = patch_evidence.evidence.evidence_id.clone();
            events.push(ProtocolEnvelope::Evidence(patch_evidence));
            events.push(ProtocolEnvelope::FixCandidate(staged.fix_candidate(
                observation_id,
                applicability,
                patch_evidence_id,
            )?));
        }
    }
    *completion = staged;
    Ok(NormalizedRuff { events })
}

/// Run Ruff through the provider-local shell-free bounded process transport.
///
/// Ruff exit codes zero and one are operationally complete when stdout is
/// valid structured JSON. All other process and normalization outcomes become
/// a typed `INCOMPLETE` session with any retainable bounded stream evidence.
///
/// # Errors
///
/// Returns an error only when the request or a generated protocol object
/// cannot satisfy the local v1 contract.
pub fn run_ruff_session(
    request: &RequestEnvelope,
    launch_root: &Path,
    ruff_program: &Path,
) -> Result<ProviderSession, ProviderError> {
    validate_request(request)?;
    let started = Instant::now();
    let mut builder = CompletionBuilder::new(request);
    let mut events = Vec::new();
    let workspace_root = match resolve_workspace(launch_root, &request.workspace) {
        Ok(path) => path,
        Err(error) => {
            return finish_incomplete(builder, events, started, error.to_string());
        }
    };
    let (tool_version, check_limits) =
        match probe_ruff(request, &workspace_root, ruff_program, started) {
            Ok(ready) => ready,
            Err(failure) => {
                if let Some(outcome) = &failure.outcome {
                    retain_process_evidence(&mut builder, &mut events, outcome, "text/plain")?;
                }
                return finish_incomplete(builder, events, started, failure.error.to_string());
            }
        };
    let check_spec = ProcessSpec::new(ruff_program)
        .args(["check", "--output-format", "json", "--"])
        .args(request.targets.iter().map(RepoPath::as_str))
        .current_dir(&workspace_root);
    let check_outcome = match run_bounded(&check_spec, check_limits) {
        Ok(outcome) => outcome,
        Err(error) => {
            return finish_incomplete(
                builder,
                events,
                started,
                ProviderError::Process(error.to_string()).to_string(),
            );
        }
    };
    let stdout_evidence_ids = retain_process_evidence(
        &mut builder,
        &mut events,
        &check_outcome,
        "application/json",
    )?;
    if check_outcome.state != ProcessState::Complete {
        return finish_incomplete(
            builder,
            events,
            started,
            ProviderError::Process(format!(
                "Ruff check was not complete: {:?}",
                check_outcome.state
            ))
            .to_string(),
        );
    }
    let Some(exit_code @ (0 | 1)) = check_outcome.exit_code else {
        return finish_incomplete(
            builder,
            events,
            started,
            ProviderError::Process(format!(
                "Ruff check failed with exit code {:?}",
                check_outcome.exit_code
            ))
            .to_string(),
        );
    };
    let normalized = match normalize_ruff_json(
        request,
        &tool_version,
        &workspace_root,
        &check_outcome.stdout.bytes,
        &stdout_evidence_ids,
        &mut builder,
    ) {
        Ok(value) => value,
        Err(error) => {
            return finish_incomplete(builder, events, started, error.to_string());
        }
    };
    events.extend(normalized.events);
    let completion = builder.complete(exit_code, elapsed_ms(started, request.limits.timeout_ms))?;
    Ok(ProviderSession { events, completion })
}

/// Validate all generated cross-envelope references, counts, capabilities,
/// sequences, durations, and byte limits as one protocol-v1 transcript.
///
/// # Errors
///
/// Returns an error when the generated session violates any v1 invariant.
pub fn validate_generated_session(
    request: &RequestEnvelope,
    session: &ProviderSession,
) -> Result<(), ProviderError> {
    validate_request(request)?;
    if session
        .events
        .iter()
        .any(|event| matches!(event, ProtocolEnvelope::FixCandidate(_)))
        && !request_negotiates(request, FIX_CAPABILITY)
    {
        return Err(ProviderError::Contract(
            "fix_candidate requires negotiated fix.propose/v1".to_owned(),
        ));
    }

    let actual_manifest = manifest()?;
    ProtocolEnvelope::Manifest(actual_manifest.clone())
        .validate()
        .map_err(|error| ProviderError::Contract(error.to_string()))?;
    ProtocolEnvelope::Request(request.clone())
        .validate()
        .map_err(|error| ProviderError::Contract(error.to_string()))?;
    for event in &session.events {
        event
            .validate()
            .map_err(|error| ProviderError::Contract(error.to_string()))?;
    }
    ProtocolEnvelope::Completion(session.completion.clone())
        .validate()
        .map_err(|error| ProviderError::Contract(error.to_string()))?;

    let mut transcript = Vec::new();
    emit_envelope(
        &mut transcript,
        &ProtocolEnvelope::Manifest(actual_manifest),
    )?;
    emit_envelope(&mut transcript, &ProtocolEnvelope::Request(request.clone()))?;
    for event in &session.events {
        emit_envelope(&mut transcript, event)?;
    }
    emit_envelope(
        &mut transcript,
        &ProtocolEnvelope::Completion(session.completion.clone()),
    )?;
    validate_session_jsonl(&transcript)
        .map(|_| ())
        .map_err(|error| ProviderError::Contract(error.to_string()))
}

/// Emit all post-request session events and the final completion.
///
/// # Errors
///
/// Returns an I/O, serialization, or local contract validation error.
pub fn emit_session_tail(
    writer: &mut impl Write,
    session: &ProviderSession,
) -> Result<(), ProviderError> {
    for event in &session.events {
        emit_envelope(writer, event)?;
    }
    emit_envelope(
        writer,
        &ProtocolEnvelope::Completion(session.completion.clone()),
    )
}

struct ProbeFailure {
    error: ProviderError,
    outcome: Option<Box<ProcessOutcome>>,
}

fn probe_ruff(
    request: &RequestEnvelope,
    workspace_root: &Path,
    ruff_program: &Path,
    started: Instant,
) -> Result<(String, ProcessLimits), ProbeFailure> {
    let limits = ProcessLimits::try_from(&request.limits).map_err(|error| ProbeFailure {
        error: ProviderError::Process(error.to_string()),
        outcome: None,
    })?;
    let outcome = run_bounded(
        &ProcessSpec::new(ruff_program)
            .arg("--version")
            .current_dir(workspace_root),
        limits,
    )
    .map_err(|error| ProbeFailure {
        error: ProviderError::Process(error.to_string()),
        outcome: None,
    })?;
    if outcome.state != ProcessState::Complete || outcome.exit_code != Some(0) {
        return Err(ProbeFailure {
            error: ProviderError::Process(format!(
                "Ruff version probe was not complete: {:?}",
                outcome.state
            )),
            outcome: Some(Box::new(outcome)),
        });
    }
    let version = parse_ruff_version(&outcome.stdout.bytes).map_err(|error| ProbeFailure {
        error,
        outcome: Some(Box::new(outcome.clone())),
    })?;
    let check_limits = remaining_process_limits(request, &outcome, started.elapsed())
        .map_err(|error| ProbeFailure {
            error,
            outcome: Some(Box::new(outcome.clone())),
        })?
        .ok_or_else(|| ProbeFailure {
            error: ProviderError::Process("Ruff version probe exhausted the timeout".to_owned()),
            outcome: Some(Box::new(outcome)),
        })?;
    Ok((version, check_limits))
}

fn finish_incomplete(
    builder: CompletionBuilder,
    events: Vec<ProtocolEnvelope>,
    started: Instant,
    message: String,
) -> Result<ProviderSession, ProviderError> {
    let timeout_ms = builder.timeout_ms;
    Ok(ProviderSession {
        events,
        completion: builder.incomplete(elapsed_ms(started, timeout_ms), message)?,
    })
}

fn retain_process_evidence(
    builder: &mut CompletionBuilder,
    events: &mut Vec<ProtocolEnvelope>,
    outcome: &ProcessOutcome,
    stdout_media_type: &str,
) -> Result<Vec<ObjectId>, ProviderError> {
    let mut stdout_ids = Vec::new();
    if outcome.stdout.observed_bytes > 0 && builder.next_sequence < builder.max_events {
        let evidence =
            builder.evidence(EvidenceSource::Stdout, stdout_media_type, &outcome.stdout)?;
        stdout_ids.push(evidence.evidence.evidence_id.clone());
        events.push(ProtocolEnvelope::Evidence(evidence));
    }
    if outcome.stderr.observed_bytes > 0 && builder.next_sequence < builder.max_events {
        let evidence = builder.evidence(EvidenceSource::Stderr, "text/plain", &outcome.stderr)?;
        events.push(ProtocolEnvelope::Evidence(evidence));
    }
    Ok(stdout_ids)
}

fn parse_ruff_version(bytes: &[u8]) -> Result<String, ProviderError> {
    let output = std::str::from_utf8(bytes)
        .map_err(|error| ProviderError::Process(format!("Ruff version is not UTF-8: {error}")))?;
    let version = output
        .trim()
        .strip_prefix("ruff ")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ProviderError::Process("Ruff version output is malformed".to_owned()))?;
    if version.chars().count() > 64 {
        return Err(ProviderError::Process(
            "Ruff version exceeds the v1 tool version bound".to_owned(),
        ));
    }
    Ok(version.to_owned())
}

fn remaining_process_limits(
    request: &RequestEnvelope,
    version: &ProcessOutcome,
    elapsed: Duration,
) -> Result<Option<ProcessLimits>, ProviderError> {
    let timeout = Duration::from_millis(request.limits.timeout_ms);
    let Some(remaining) = timeout.checked_sub(elapsed) else {
        return Ok(None);
    };
    let remaining_ms = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
    if remaining_ms == 0 {
        return Ok(None);
    }
    let stdout_used = usize::try_from(version.stdout.observed_bytes).unwrap_or(usize::MAX);
    let stderr_used = usize::try_from(version.stderr.observed_bytes).unwrap_or(usize::MAX);
    let stdout_limit = usize::try_from(request.limits.max_stdout_bytes)
        .unwrap_or(usize::MAX)
        .saturating_sub(stdout_used);
    let stderr_limit = usize::try_from(request.limits.max_stderr_bytes)
        .unwrap_or(usize::MAX)
        .saturating_sub(stderr_used);
    ProcessLimits {
        timeout: Duration::from_millis(remaining_ms),
        max_stdout_bytes: stdout_limit,
        max_stderr_bytes: stderr_limit,
    }
    .validate()
    .map(Some)
    .map_err(|error| ProviderError::Process(error.to_string()))
}

fn resolve_workspace(launch_root: &Path, workspace: &RepoPath) -> Result<PathBuf, ProviderError> {
    let root = fs::canonicalize(launch_root)
        .map_err(|error| ProviderError::Workspace(error.to_string()))?;
    let candidate = if workspace.as_str() == "." {
        root.clone()
    } else {
        root.join(workspace.as_str())
    };
    let resolved = fs::canonicalize(&candidate)
        .map_err(|error| ProviderError::Workspace(error.to_string()))?;
    if !resolved.starts_with(&root) || !resolved.is_dir() {
        return Err(ProviderError::Workspace(workspace.to_string()));
    }
    Ok(resolved)
}

fn elapsed_ms(started: Instant, timeout_ms: u64) -> u64 {
    u64::try_from(started.elapsed().as_millis())
        .unwrap_or(u64::MAX)
        .min(timeout_ms)
}

/// Build a typed zero-event `INCOMPLETE` completion for an invalid request.
///
/// # Errors
///
/// Returns an error when the supplied ID or message violates `CompletionV1`.
pub fn empty_incomplete(
    request_id: ObjectId,
    message: impl Into<String>,
) -> Result<CompletionEnvelope, ProviderError> {
    CompletionBuilder {
        request_id,
        next_sequence: 0,
        max_events: 0,
        timeout_ms: 0,
        max_evidence_bytes: 0,
        counts: CompletionCounts {
            observations: 0,
            evidence: 0,
            fix_candidates: 0,
            executions: 0,
        },
        evidence_bytes: 0,
    }
    .incomplete(0, message)
}

fn normalize_path(filename: &str, repository_root: &Path) -> Result<RepoPath, ProviderError> {
    let path = Path::new(filename);
    let relative = if path.is_absolute() {
        path.strip_prefix(repository_root)
            .map_err(|_| ProviderError::PathEscape(filename.to_owned()))?
    } else {
        path
    };
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => parts.push(
                value
                    .to_str()
                    .ok_or_else(|| ProviderError::PathEscape(filename.to_owned()))?,
            ),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ProviderError::PathEscape(filename.to_owned()));
            }
        }
    }
    let normalized = if parts.is_empty() {
        ".".to_owned()
    } else {
        parts.join("/")
    };
    normalized
        .parse::<RepoPath>()
        .map_err(|_| ProviderError::PathEscape(filename.to_owned()))
}

fn derive_event_id(request_id: &ObjectId, sequence: u64) -> Result<ObjectId, ProviderError> {
    let wire = request_id.as_str();
    let suffix = u64::from_str_radix(&wire[24..], 16)
        .map_err(|error| ProviderError::Contract(error.to_string()))?;
    let salt = sequence
        .checked_add(1)
        .ok_or_else(|| ProviderError::Contract("observation index overflowed".to_owned()))?;
    format!("{}{:012x}", &wire[..24], suffix ^ salt)
        .parse::<ObjectId>()
        .map_err(|error| ProviderError::Contract(error.to_owned()))
}

fn utf8_prefix(bytes: &[u8]) -> &str {
    match std::str::from_utf8(bytes) {
        Ok(value) => value,
        Err(error) => std::str::from_utf8(&bytes[..error.valid_up_to()]).unwrap_or(""),
    }
}

fn normalize_severity(value: &str) -> Result<Severity, ProviderError> {
    match value {
        "error" => Ok(Severity::Error),
        "warning" => Ok(Severity::Warning),
        _ => Err(ProviderError::RuffSeverity(value.to_owned())),
    }
}

fn candidate_applicability(fix: &RuffFixView) -> Applicability {
    if !fix_edits_are_complete_and_non_overlapping(fix.edits.as_deref()) {
        return Applicability::Manual;
    }
    match fix.applicability.as_deref() {
        Some("safe") => Applicability::Safe,
        Some("unsafe") => Applicability::Unsafe,
        _ => Applicability::Manual,
    }
}

fn fix_edits_are_complete_and_non_overlapping(edits: Option<&[RuffEditView]>) -> bool {
    let Some(edits) = edits.filter(|edits| !edits.is_empty()) else {
        return false;
    };
    let mut ranges = Vec::with_capacity(edits.len());
    for edit in edits {
        let (Some(_), Some(start), Some(end)) = (&edit.content, &edit.location, &edit.end_location)
        else {
            return false;
        };
        let start = (start.row, start.column);
        let end = (end.row, end.column);
        if start.0 == 0 || start.1 == 0 || end.0 == 0 || end.1 == 0 || start > end {
            return false;
        }
        ranges.push((start, end));
    }
    ranges.sort_unstable();
    ranges.windows(2).all(|pair| {
        let (previous_start, previous_end) = pair[0];
        let (next_start, _) = pair[1];
        previous_end <= next_start && previous_start != next_start
    })
}

#[derive(Debug, Deserialize)]
struct RuffDiagnostic {
    code: Option<String>,
    filename: String,
    location: RuffPosition,
    end_location: Option<RuffPosition>,
    message: String,
    severity: String,
    fix: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RuffPosition {
    row: u32,
    column: u32,
}

impl From<RuffPosition> for Position {
    fn from(value: RuffPosition) -> Self {
        Self {
            line: value.row,
            column: value.column,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RuffFixView {
    applicability: Option<String>,
    edits: Option<Vec<RuffEditView>>,
}

#[derive(Debug, Deserialize)]
struct RuffEditView {
    content: Option<String>,
    location: Option<RuffPosition>,
    end_location: Option<RuffPosition>,
}

#[derive(Serialize)]
struct RuffFixPatch<'a> {
    version: &'a str,
    filename: &'a str,
    rule_id: Option<&'a str>,
    fix: &'a serde_json::Value,
}
