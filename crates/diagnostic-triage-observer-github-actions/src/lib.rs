//! Offline GitHub Actions workflow-run Observer for Diagnostic Triage.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use diagnostic_triage_contracts::{
    Nullable, ObjectId, Sha256Digest,
    model::{
        AdapterKind, Cache, CacheStatus, Evidence, EvidenceSchemaVersion, EvidenceSource,
        Execution, ExecutionPhases, ExecutionSchemaVersion, ExecutionStatus, NotApplicable,
        Performance, PerformanceStatus, PhaseDuration, Retry, RetryStatus, Runner, RunnerStatus,
        Tool, ToolchainFingerprint, Unavailable,
    },
    protocol::{
        AdapterManifest, CompletionCounts, CompletionEnvelope, EnvelopeKind, EvidenceEnvelope,
        ExecutionEnvelope, ManifestEnvelope, Operation, ProtocolEnvelope, ProtocolVersion,
        RequestEnvelope,
    },
    validate_session_jsonl,
};
use jiff::Timestamp;
use serde::Deserialize;
use thiserror::Error;

const ADAPTER_ID: &str = "github-actions";
const OBSERVE_CAPABILITY: &str = "execution.observe/v1";
const SOURCE_FORMAT_VERSION: &str = "workflow-run-json/v1";
const SOURCE_MEDIA_TYPE: &str = "application/vnd.github.actions.workflow-run+json";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
const PERFORMANCE_BUDGET_MS: u32 = 60_000;
const MAX_MESSAGE_CHARS: usize = 8_192;
const FALLBACK_REQUEST_ID: &str = "00000000-0000-4000-8000-000000000000";

/// One Observer response after the manifest/request handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserverResponse {
    pub events: Vec<ProtocolEnvelope>,
    pub completion: CompletionEnvelope,
}

/// Offline source, normalization, and protocol failures.
#[derive(Debug, Error)]
pub enum ObserverError {
    #[error("invalid Observer request: {0}")]
    Request(String),
    #[error("invalid source path: {0}")]
    Path(String),
    #[error("source file exceeds the {MAX_INPUT_BYTES}-byte bound ({observed} bytes)")]
    InputLimit { observed: u64 },
    #[error("GitHub Actions source JSON is malformed: {0}")]
    SourceJson(#[from] serde_json::Error),
    #[error("GitHub Actions source is invalid: {0}")]
    Source(String),
    #[error("generated model violates the v1 contract: {0}")]
    Model(String),
    #[error(
        "max_stdout_bytes={limit} cannot encode the required manifest and completion ({minimum} bytes)"
    )]
    OutputLimit { limit: u64, minimum: u64 },
    #[error("Observer I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Clone, Debug, Deserialize)]
struct WorkflowRunInput {
    #[serde(rename = "id")]
    _id: u64,
    name: String,
    status: String,
    conclusion: Option<String>,
    created_at: Option<String>,
    run_started_at: Option<String>,
    updated_at: Option<String>,
    run_attempt: Option<u32>,
    #[serde(default)]
    diagnostic_triage: Option<InstrumentationInput>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct InstrumentationInput {
    phases_ms: Option<PhaseInput>,
    cache: Option<Cache>,
    retry: Option<Retry>,
    runner: Option<RunnerInput>,
    toolchain_fingerprint: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Deserialize)]
struct PhaseInput {
    queue: Option<u32>,
    setup: Option<u32>,
    run: Option<u32>,
    normalize: Option<u32>,
    total: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
struct RunnerInput {
    os: Option<String>,
    arch: Option<String>,
    image: Option<String>,
}

#[derive(Clone, Copy, Debug)]
struct DerivedDurations {
    queue: Option<u32>,
    run: Option<u32>,
    total: Option<u32>,
}

/// Construct the Observer manifest emitted before stdin is read.
#[must_use]
pub fn manifest() -> ManifestEnvelope {
    ManifestEnvelope {
        protocol_version: ProtocolVersion::V1,
        kind: EnvelopeKind::Manifest,
        adapter: AdapterManifest {
            id: scalar(ADAPTER_ID),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            kind: AdapterKind::Observer,
            capabilities: vec![scalar(OBSERVE_CAPABILITY)],
            languages: Vec::new(),
        },
    }
}

/// Run one manifest-first offline Observer session.
///
/// # Errors
///
/// Returns [`ObserverError`] when request framing, local file I/O, or protocol
/// emission cannot be completed safely.
pub fn run_stdio() -> Result<(), ObserverError> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_envelope(&mut output, &ProtocolEnvelope::Manifest(manifest()))?;
    output.flush()?;

    let stdin = io::stdin();
    let mut input = Vec::new();
    BufReader::new(stdin.lock())
        .take(u64::try_from(MAX_REQUEST_BYTES).unwrap_or(u64::MAX) + 1)
        .read_until(b'\n', &mut input)?;
    let (request, response) = match decode_request(&input) {
        Ok(request) => {
            let response = execute(&request)?;
            (Some(request), response)
        }
        Err(error) => (
            None,
            terminal_for_id(
                recover_request_id(&input),
                ExecutionStatus::Incomplete,
                &error.to_string(),
            ),
        ),
    };
    if let Some(request) = &request {
        validate_response(request, &response)?;
    }
    for event in &response.events {
        write_envelope(&mut output, event)?;
    }
    write_envelope(
        &mut output,
        &ProtocolEnvelope::Completion(response.completion),
    )?;
    output.flush()?;
    Ok(())
}

/// Decode exactly one bounded request line.
///
/// # Errors
///
/// Returns [`ObserverError::Request`] for oversized, multiline, malformed, or
/// non-request input.
pub fn read_request(input: impl Read) -> Result<RequestEnvelope, ObserverError> {
    let mut bytes = Vec::new();
    BufReader::new(input)
        .take(u64::try_from(MAX_REQUEST_BYTES).unwrap_or(u64::MAX) + 1)
        .read_until(b'\n', &mut bytes)?;
    decode_request(&bytes)
}

fn decode_request(input: &[u8]) -> Result<RequestEnvelope, ObserverError> {
    if input.len() > MAX_REQUEST_BYTES {
        return Err(ObserverError::Request(
            "request exceeds 65536 bytes".to_owned(),
        ));
    }
    let mut bytes = input.to_vec();
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.is_empty() || bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return Err(ObserverError::Request(
            "stdin must contain exactly one JSON object line".to_owned(),
        ));
    }
    let envelope = serde_json::from_slice::<ProtocolEnvelope>(&bytes)
        .map_err(|error| ObserverError::Request(error.to_string()))?;
    envelope
        .validate()
        .map_err(|error| ObserverError::Request(error.to_string()))?;
    match envelope {
        ProtocolEnvelope::Request(request) => Ok(request),
        _ => Err(ObserverError::Request(
            "request envelope kind mismatch".to_owned(),
        )),
    }
}

/// Observe one caller-provided local workflow-run JSON file without network I/O.
///
/// # Errors
///
/// Returns [`ObserverError`] when the repository cannot be inspected safely or
/// the negotiated stdout budget cannot encode a valid terminal response.
pub fn execute(request: &RequestEnvelope) -> Result<ObserverResponse, ObserverError> {
    let repository = match std::env::current_dir().and_then(std::fs::canonicalize) {
        Ok(repository) => repository,
        Err(error) => {
            return Ok(incomplete(
                request,
                Vec::new(),
                format!("repository is unavailable: {error}"),
            ));
        }
    };
    execute_in_repository(request, &repository)
}

fn execute_in_repository(
    request: &RequestEnvelope,
    repository: &Path,
) -> Result<ObserverResponse, ObserverError> {
    if let Err(error) = ProtocolEnvelope::Request(request.clone()).validate() {
        return Ok(incomplete(request, Vec::new(), error.to_string()));
    }
    if let Some(message) = unsupported_request(request) {
        return Ok(finish(
            request,
            Vec::new(),
            ExecutionStatus::Unsupported,
            None,
            Some(message),
        ));
    }
    let (run, mut events, mut ids) = match load_run(request, repository) {
        Ok(loaded) => loaded,
        // LLM contract: LOAD_FAILED -> BOUNDED -> INCOMPLETE -> REPORTED.
        Err(response) => return bound_response(request, *response),
    };
    if run.status != "completed" {
        return Ok(incomplete(
            request,
            events,
            format!("workflow run status is not completed: {}", run.status),
        ));
    }
    let execution = match normalize_run(&run, ids.next()) {
        Ok(execution) => execution,
        Err(error) => return Ok(incomplete(request, events, error.to_string())),
    };
    let envelope = ProtocolEnvelope::Execution(ExecutionEnvelope {
        protocol_version: ProtocolVersion::V1,
        kind: EnvelopeKind::Execution,
        request_id: request.request_id.clone(),
        sequence: u64::try_from(events.len()).unwrap_or(u64::MAX),
        execution,
    });
    if let Err(error) = envelope.validate() {
        return Ok(incomplete(
            request,
            events,
            ObserverError::Model(error.to_string()).to_string(),
        ));
    }
    events.push(envelope);
    let response = if u64::try_from(events.len()).unwrap_or(u64::MAX) > request.limits.max_events {
        incomplete(
            request,
            bounded_events(request, events),
            "normalized event count exceeds request limit".to_owned(),
        )
    } else {
        finish(request, events, ExecutionStatus::Complete, Some(0), None)
    };
    enforce_output_limit(request, response)
}

fn load_run(
    request: &RequestEnvelope,
    repository: &Path,
) -> Result<(WorkflowRunInput, Vec<ProtocolEnvelope>, IdFactory), Box<ObserverResponse>> {
    let source = resolve_source_path(request, repository)
        .map_err(|error| Box::new(incomplete(request, Vec::new(), error.to_string())))?;
    let bytes = match read_source(&source) {
        Ok(bytes) => bytes,
        Err(ObserverError::InputLimit { observed }) => {
            let evidence = evidence_from_bytes(
                request,
                &mut IdFactory::new(&request.request_id),
                &read_prefix(&source, request.limits.max_evidence_bytes),
                observed,
            );
            return Err(Box::new(incomplete(
                request,
                evidence.into_iter().collect(),
                ObserverError::InputLimit { observed }.to_string(),
            )));
        }
        Err(error) => {
            return Err(Box::new(incomplete(request, Vec::new(), error.to_string())));
        }
    };

    let mut ids = IdFactory::new(&request.request_id);
    let source_value = serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|error| {
        let evidence = evidence_from_bytes(
            request,
            &mut ids,
            &bytes,
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        );
        Box::new(incomplete(
            request,
            evidence.into_iter().collect(),
            ObserverError::SourceJson(error).to_string(),
        ))
    })?;
    let canonical = serde_json::to_vec(&source_value).map_err(|error| {
        Box::new(incomplete(
            request,
            Vec::new(),
            ObserverError::SourceJson(error).to_string(),
        ))
    })?;
    let evidence = evidence_from_bytes(
        request,
        &mut ids,
        &canonical,
        u64::try_from(canonical.len()).unwrap_or(u64::MAX),
    );
    let mut events = Vec::new();
    if let Some(evidence) = evidence {
        push_evidence(request, &mut events, evidence);
    }
    let run = serde_json::from_value::<WorkflowRunInput>(source_value).map_err(|error| {
        Box::new(incomplete(
            request,
            events.clone(),
            ObserverError::SourceJson(error).to_string(),
        ))
    })?;
    Ok((run, events, ids))
}

fn normalize_run(
    run: &WorkflowRunInput,
    execution_id: ObjectId,
) -> Result<Execution, ObserverError> {
    let conclusion = run
        .conclusion
        .as_deref()
        .ok_or_else(|| ObserverError::Source("completed run lacks conclusion".to_owned()))?;
    let status = execution_status(conclusion)?;
    let durations = derived_durations(run)?;
    let instrumentation = run.diagnostic_triage.as_ref();
    let phases = phases(
        instrumentation.and_then(|value| value.phases_ms.as_ref()),
        durations,
        conclusion,
    );
    let performance = performance(&phases.run);
    let cache = instrumentation
        .and_then(|value| value.cache.clone())
        .unwrap_or_else(|| default_cache(conclusion));
    let retry = retry(run, instrumentation.and_then(|value| value.retry.clone()))?;
    let runner = runner(instrumentation.and_then(|value| value.runner.as_ref()));
    let toolchain_fingerprint = instrumentation
        .and_then(|value| value.toolchain_fingerprint.clone())
        .map_or(
            ToolchainFingerprint::Unavailable(Unavailable::Value),
            ToolchainFingerprint::Digest,
        );
    let message = (conclusion != "success").then(|| {
        format!(
            "GitHub Actions workflow {} concluded {conclusion}",
            run.name
        )
    });

    let execution = Execution {
        schema_version: ExecutionSchemaVersion::V1,
        execution_id,
        adapter_id: scalar(ADAPTER_ID),
        adapter_kind: AdapterKind::Observer,
        tool: Tool {
            name: "github-actions".to_owned(),
            version: SOURCE_FORMAT_VERSION.to_owned(),
            rule_id: None,
        },
        toolchain_fingerprint,
        required: false,
        status,
        exit_code: Nullable(None),
        message,
        phases_ms: phases,
        performance,
        cache,
        retry,
        runner,
        verification: None,
    };
    execution
        .validate()
        .map_err(|error| ObserverError::Model(error.to_string()))?;
    Ok(execution)
}

fn execution_status(conclusion: &str) -> Result<ExecutionStatus, ObserverError> {
    match conclusion {
        "success" | "failure" | "neutral" | "skipped" => Ok(ExecutionStatus::Complete),
        "cancelled" | "timed_out" | "action_required" | "stale" | "startup_failure" => {
            Ok(ExecutionStatus::Incomplete)
        }
        _ => Err(ObserverError::Source(format!(
            "unsupported workflow conclusion: {conclusion}"
        ))),
    }
}

fn derived_durations(run: &WorkflowRunInput) -> Result<DerivedDurations, ObserverError> {
    let queue = duration_between(run.created_at.as_deref(), run.run_started_at.as_deref())?;
    let tool_run = duration_between(run.run_started_at.as_deref(), run.updated_at.as_deref())?;
    let total = duration_between(run.created_at.as_deref(), run.updated_at.as_deref())?;
    Ok(DerivedDurations {
        queue,
        run: tool_run,
        total,
    })
}

fn duration_between(start: Option<&str>, end: Option<&str>) -> Result<Option<u32>, ObserverError> {
    let (Some(start), Some(end)) = (start, end) else {
        return Ok(None);
    };
    let start = start
        .parse::<Timestamp>()
        .map_err(|error| ObserverError::Source(format!("invalid start timestamp: {error}")))?;
    let end = end
        .parse::<Timestamp>()
        .map_err(|error| ObserverError::Source(format!("invalid end timestamp: {error}")))?;
    let delta = end
        .as_millisecond()
        .checked_sub(start.as_millisecond())
        .ok_or_else(|| ObserverError::Source("timestamp duration overflow".to_owned()))?;
    if delta < 0 {
        return Err(ObserverError::Source(
            "workflow timestamps are not monotonic".to_owned(),
        ));
    }
    let milliseconds = u32::try_from(delta)
        .map_err(|_| ObserverError::Source("workflow duration exceeds u32".to_owned()))?;
    if milliseconds > 600_000 {
        return Err(ObserverError::Source(
            "workflow duration exceeds the v1 600000 ms bound".to_owned(),
        ));
    }
    Ok(Some(milliseconds))
}

fn phases(
    explicit: Option<&PhaseInput>,
    derived: DerivedDurations,
    conclusion: &str,
) -> ExecutionPhases {
    if conclusion == "skipped" && explicit.is_none() {
        let not_applicable = PhaseDuration::NotApplicable(NotApplicable::Value);
        return ExecutionPhases {
            queue: not_applicable.clone(),
            setup: not_applicable.clone(),
            run: not_applicable.clone(),
            normalize: not_applicable.clone(),
            total: not_applicable,
        };
    }
    if let Some(explicit) = explicit {
        return ExecutionPhases {
            queue: phase(explicit.queue),
            setup: phase(explicit.setup),
            run: phase(explicit.run),
            normalize: phase(explicit.normalize),
            total: phase(explicit.total),
        };
    }
    ExecutionPhases {
        queue: phase(derived.queue),
        setup: PhaseDuration::Unavailable(Unavailable::Value),
        run: phase(derived.run),
        normalize: PhaseDuration::Unavailable(Unavailable::Value),
        total: phase(derived.total),
    }
}

fn phase(value: Option<u32>) -> PhaseDuration {
    value.map_or(
        PhaseDuration::Unavailable(Unavailable::Value),
        PhaseDuration::Milliseconds,
    )
}

fn performance(run: &PhaseDuration) -> Performance {
    let status = match run {
        PhaseDuration::Milliseconds(value) if *value >= PERFORMANCE_BUDGET_MS => {
            PerformanceStatus::ImprovementCandidate
        }
        PhaseDuration::Milliseconds(_) => PerformanceStatus::WithinBudget,
        PhaseDuration::NotApplicable(_) | PhaseDuration::Unavailable(_) => {
            PerformanceStatus::NotEvaluated
        }
    };
    Performance {
        status,
        budget_ms: PERFORMANCE_BUDGET_MS,
    }
}

fn default_cache(conclusion: &str) -> Cache {
    Cache {
        status: if conclusion == "skipped" {
            CacheStatus::NotApplicable
        } else {
            CacheStatus::Unavailable
        },
        restore_ms: None,
        save_ms: None,
    }
}

fn retry(run: &WorkflowRunInput, explicit: Option<Retry>) -> Result<Retry, ObserverError> {
    if let Some(explicit) = explicit {
        if explicit.status == RetryStatus::Recorded
            && run
                .run_attempt
                .is_some_and(|attempt| explicit.attempt != Some(attempt))
        {
            return Err(ObserverError::Source(
                "retry attempt disagrees with run_attempt".to_owned(),
            ));
        }
        return Ok(explicit);
    }
    Ok(match run.run_attempt {
        Some(0) => {
            return Err(ObserverError::Source(
                "run_attempt must be positive".to_owned(),
            ));
        }
        Some(1) => Retry {
            status: RetryStatus::NotApplicable,
            attempt: None,
            same_revision: None,
            group_id: None,
        },
        Some(_) | None => Retry {
            status: RetryStatus::Unavailable,
            attempt: None,
            same_revision: None,
            group_id: None,
        },
    })
}

fn runner(input: Option<&RunnerInput>) -> Runner {
    let Some(input) = input else {
        return unavailable_runner();
    };
    let (Some(os), Some(arch)) = (&input.os, &input.arch) else {
        return unavailable_runner();
    };
    let identity = format!(
        "diagnostic-triage.runner/v1\0{os}\0{arch}\0{}",
        input.image.as_deref().unwrap_or("UNAVAILABLE")
    );
    Runner {
        status: RunnerStatus::Recorded,
        os: Some(os.clone()),
        arch: Some(arch.clone()),
        image: input.image.clone(),
        fingerprint: Some(Sha256Digest::compute(identity.as_bytes())),
    }
}

fn unavailable_runner() -> Runner {
    Runner {
        status: RunnerStatus::Unavailable,
        os: None,
        arch: None,
        image: None,
        fingerprint: None,
    }
}

fn resolve_source_path(
    request: &RequestEnvelope,
    repository: &Path,
) -> Result<PathBuf, ObserverError> {
    if request.targets.len() != 1 {
        return Err(ObserverError::Request(
            "GitHub Actions Observer requires exactly one input target".to_owned(),
        ));
    }
    let repository = std::fs::canonicalize(repository)?;
    let workspace = if request.workspace.as_str() == "." {
        repository.clone()
    } else {
        std::fs::canonicalize(repository.join(request.workspace.as_str()))?
    };
    if !workspace.is_dir() || !workspace.starts_with(&repository) {
        return Err(ObserverError::Path(request.workspace.to_string()));
    }
    let target = &request.targets[0];
    if request.workspace.as_str() != "."
        && target.as_str() != request.workspace.as_str()
        && !target
            .as_str()
            .strip_prefix(request.workspace.as_str())
            .is_some_and(|suffix| suffix.starts_with('/'))
    {
        return Err(ObserverError::Path(target.to_string()));
    }
    let source = std::fs::canonicalize(repository.join(target.as_str()))?;
    if !source.is_file() || !source.starts_with(&workspace) {
        return Err(ObserverError::Path(target.to_string()));
    }
    Ok(source)
}

fn read_source(path: &Path) -> Result<Vec<u8>, ObserverError> {
    let observed = path.metadata()?.len();
    if observed > u64::try_from(MAX_INPUT_BYTES).unwrap_or(u64::MAX) {
        return Err(ObserverError::InputLimit { observed });
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(u64::try_from(MAX_INPUT_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(ObserverError::InputLimit {
            observed: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        });
    }
    Ok(bytes)
}

fn read_prefix(path: &Path, limit: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Ok(file) = File::open(path) {
        let _ignored = file.take(limit).read_to_end(&mut bytes);
    }
    bytes
}

fn evidence_from_bytes(
    request: &RequestEnvelope,
    ids: &mut IdFactory,
    bytes: &[u8],
    observed_bytes: u64,
) -> Option<ProtocolEnvelope> {
    if bytes.is_empty() && observed_bytes == 0 {
        return None;
    }
    let limit = usize::try_from(request.limits.max_evidence_bytes).unwrap_or(usize::MAX);
    let retained_end = utf8_prefix_len(&bytes[..bytes.len().min(limit)]);
    let content = String::from_utf8_lossy(&bytes[..retained_end]).into_owned();
    let retained_bytes = u64::try_from(content.len()).unwrap_or(u64::MAX);
    let observed_bytes = observed_bytes.max(retained_bytes);
    let evidence = Evidence {
        schema_version: EvidenceSchemaVersion::V1,
        evidence_id: ids.next(),
        execution_id: None,
        source: EvidenceSource::Artifact,
        media_type: SOURCE_MEDIA_TYPE.to_owned(),
        retained_bytes,
        observed_bytes,
        limit_bytes: u32::try_from(request.limits.max_evidence_bytes).ok()?,
        truncated: observed_bytes > retained_bytes,
        sha256: Sha256Digest::compute(content.as_bytes()),
        relative_path: None,
        content: Some(content),
    };
    Some(ProtocolEnvelope::Evidence(EvidenceEnvelope {
        protocol_version: ProtocolVersion::V1,
        kind: EnvelopeKind::Evidence,
        request_id: request.request_id.clone(),
        sequence: 0,
        evidence,
    }))
}

fn utf8_prefix_len(bytes: &[u8]) -> usize {
    match std::str::from_utf8(bytes) {
        Ok(_) => bytes.len(),
        Err(error) => error.valid_up_to(),
    }
}

fn push_evidence(
    request: &RequestEnvelope,
    events: &mut Vec<ProtocolEnvelope>,
    event: ProtocolEnvelope,
) {
    if let ProtocolEnvelope::Evidence(mut evidence) = event {
        evidence.request_id = request.request_id.clone();
        evidence.sequence = u64::try_from(events.len()).unwrap_or(u64::MAX);
        events.push(ProtocolEnvelope::Evidence(evidence));
    }
}

fn unsupported_request(request: &RequestEnvelope) -> Option<String> {
    if request.operation != Operation::Observe {
        return Some("GitHub Actions Observer supports only OBSERVE".to_owned());
    }
    if !capability_requested(request, OBSERVE_CAPABILITY) {
        return Some("OBSERVE requires execution.observe/v1".to_owned());
    }
    request
        .required_capabilities
        .iter()
        .find(|capability| capability.as_str() != OBSERVE_CAPABILITY)
        .map(|capability| format!("required capability is unsupported: {capability}"))
}

fn capability_requested(request: &RequestEnvelope, expected: &str) -> bool {
    request
        .required_capabilities
        .iter()
        .chain(&request.optional_capabilities)
        .any(|capability| capability.as_str() == expected)
}

fn bounded_events(
    request: &RequestEnvelope,
    mut events: Vec<ProtocolEnvelope>,
) -> Vec<ProtocolEnvelope> {
    events.retain(|event| match event {
        ProtocolEnvelope::Evidence(value) => {
            value.evidence.retained_bytes <= request.limits.max_evidence_bytes
        }
        _ => true,
    });
    events.truncate(usize::try_from(request.limits.max_events).unwrap_or(usize::MAX));
    resequence_events(&mut events);
    events
}

fn resequence_events(events: &mut [ProtocolEnvelope]) {
    for (sequence, event) in events.iter_mut().enumerate() {
        match event {
            ProtocolEnvelope::Evidence(value) => {
                value.sequence = u64::try_from(sequence).unwrap_or(u64::MAX);
            }
            ProtocolEnvelope::Execution(value) => {
                value.sequence = u64::try_from(sequence).unwrap_or(u64::MAX);
            }
            ProtocolEnvelope::Observation(value) => {
                value.sequence = u64::try_from(sequence).unwrap_or(u64::MAX);
            }
            ProtocolEnvelope::FixCandidate(value) => {
                value.sequence = u64::try_from(sequence).unwrap_or(u64::MAX);
            }
            ProtocolEnvelope::Manifest(_)
            | ProtocolEnvelope::Request(_)
            | ProtocolEnvelope::Completion(_) => {}
        }
    }
}

fn incomplete(
    request: &RequestEnvelope,
    events: Vec<ProtocolEnvelope>,
    message: String,
) -> ObserverResponse {
    finish(
        request,
        events,
        ExecutionStatus::Incomplete,
        None,
        Some(message),
    )
}

fn bound_response(
    request: &RequestEnvelope,
    response: ObserverResponse,
) -> Result<ObserverResponse, ObserverError> {
    let ObserverResponse { events, completion } = response;
    let response = finish(
        request,
        bounded_events(request, events),
        completion.status,
        completion.tool_exit_code.0,
        completion.message,
    );
    enforce_output_limit(request, response)
}

fn finish(
    request: &RequestEnvelope,
    events: Vec<ProtocolEnvelope>,
    status: ExecutionStatus,
    exit_code: Option<u8>,
    message: Option<String>,
) -> ObserverResponse {
    let mut counts = CompletionCounts {
        observations: 0,
        evidence: 0,
        fix_candidates: 0,
        executions: 0,
    };
    let mut evidence_bytes = 0_u64;
    for event in &events {
        match event {
            ProtocolEnvelope::Evidence(value) => {
                counts.evidence += 1;
                evidence_bytes = evidence_bytes.saturating_add(value.evidence.retained_bytes);
            }
            ProtocolEnvelope::Execution(_) => counts.executions += 1,
            ProtocolEnvelope::Observation(_) => counts.observations += 1,
            ProtocolEnvelope::FixCandidate(_) => counts.fix_candidates += 1,
            ProtocolEnvelope::Manifest(_)
            | ProtocolEnvelope::Request(_)
            | ProtocolEnvelope::Completion(_) => {}
        }
    }
    ObserverResponse {
        completion: CompletionEnvelope {
            protocol_version: ProtocolVersion::V1,
            kind: EnvelopeKind::Completion,
            request_id: request.request_id.clone(),
            sequence: u64::try_from(events.len()).unwrap_or(u64::MAX),
            status,
            tool_exit_code: Nullable(exit_code),
            tool_duration_ms: 0,
            counts,
            evidence_bytes,
            message: message.map(|value| truncate_chars(&value, MAX_MESSAGE_CHARS)),
        },
        events,
    }
}

fn enforce_output_limit(
    request: &RequestEnvelope,
    response: ObserverResponse,
) -> Result<ObserverResponse, ObserverError> {
    if serialized_output_bytes(&response)? <= request.limits.max_stdout_bytes {
        return Ok(response);
    }

    let fallback = incomplete(
        request,
        Vec::new(),
        "Observer output exceeds max_stdout_bytes".to_owned(),
    );
    if serialized_output_bytes(&fallback)? <= request.limits.max_stdout_bytes {
        return Ok(fallback);
    }

    // INCOMPLETE requires a non-empty message; one ASCII byte is the smallest
    // valid terminal payload for an edge-sized output budget.
    let minimal = finish(
        request,
        Vec::new(),
        ExecutionStatus::Incomplete,
        None,
        Some("x".to_owned()),
    );
    let minimum = serialized_output_bytes(&minimal)?;
    if minimum <= request.limits.max_stdout_bytes {
        return Ok(minimal);
    }

    Err(ObserverError::OutputLimit {
        limit: request.limits.max_stdout_bytes,
        minimum,
    })
}

fn serialized_output_bytes(response: &ObserverResponse) -> Result<u64, ObserverError> {
    let mut bytes = Vec::new();
    std::iter::once(ProtocolEnvelope::Manifest(manifest()))
        .chain(response.events.iter().cloned())
        .chain(std::iter::once(ProtocolEnvelope::Completion(
            response.completion.clone(),
        )))
        .try_for_each(|event| write_envelope(&mut bytes, &event))?;
    Ok(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
}

fn terminal_for_id(
    request_id: ObjectId,
    status: ExecutionStatus,
    message: &str,
) -> ObserverResponse {
    let message = truncate_chars(message, MAX_MESSAGE_CHARS);
    ObserverResponse {
        events: Vec::new(),
        completion: CompletionEnvelope {
            protocol_version: ProtocolVersion::V1,
            kind: EnvelopeKind::Completion,
            request_id,
            sequence: 0,
            status,
            tool_exit_code: Nullable(None),
            tool_duration_ms: 0,
            counts: CompletionCounts {
                observations: 0,
                evidence: 0,
                fix_candidates: 0,
                executions: 0,
            },
            evidence_bytes: 0,
            message: Some(message),
        },
    }
}

fn recover_request_id(input: &[u8]) -> ObjectId {
    serde_json::from_slice::<serde_json::Value>(input)
        .ok()
        .and_then(|value| value.get("request_id")?.as_str()?.parse().ok())
        .unwrap_or_else(|| scalar(FALLBACK_REQUEST_ID))
}

fn validate_response(
    request: &RequestEnvelope,
    response: &ObserverResponse,
) -> Result<(), ObserverError> {
    for event in &response.events {
        event
            .validate()
            .map_err(|error| ObserverError::Model(error.to_string()))?;
    }
    ProtocolEnvelope::Completion(response.completion.clone())
        .validate()
        .map_err(|error| ObserverError::Model(error.to_string()))?;
    if unsupported_request(request).is_some() {
        return Ok(());
    }
    let mut transcript = Vec::new();
    write_envelope(&mut transcript, &ProtocolEnvelope::Manifest(manifest()))?;
    write_envelope(&mut transcript, &ProtocolEnvelope::Request(request.clone()))?;
    for event in &response.events {
        write_envelope(&mut transcript, event)?;
    }
    write_envelope(
        &mut transcript,
        &ProtocolEnvelope::Completion(response.completion.clone()),
    )?;
    validate_session_jsonl(&transcript)
        .map(|_| ())
        .map_err(|error| ObserverError::Model(error.to_string()))
}

fn write_envelope(
    output: &mut impl Write,
    envelope: &ProtocolEnvelope,
) -> Result<(), ObserverError> {
    envelope
        .validate()
        .map_err(|error| ObserverError::Model(error.to_string()))?;
    serde_json::to_writer(&mut *output, envelope)?;
    output.write_all(b"\n")?;
    Ok(())
}

fn truncate_chars(value: &str, maximum: usize) -> String {
    if value.chars().count() <= maximum {
        return value.to_owned();
    }
    value
        .chars()
        .take(maximum.saturating_sub(1))
        .chain(std::iter::once('…'))
        .collect()
}

fn scalar<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: std::fmt::Debug,
{
    value.parse().expect("Observer constants must be valid")
}

struct IdFactory {
    prefix: String,
    suffix: u64,
    next: u64,
}

impl IdFactory {
    fn new(request_id: &ObjectId) -> Self {
        Self {
            prefix: request_id.as_str()[..24].to_owned(),
            suffix: u64::from_str_radix(&request_id.as_str()[24..], 16)
                .expect("validated request IDs have a hexadecimal suffix"),
            next: 1,
        }
    }

    fn next(&mut self) -> ObjectId {
        let value = format!("{}{:012x}", self.prefix, self.suffix ^ self.next);
        self.next = self.next.saturating_add(1);
        scalar(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_INPUT_BYTES, OBSERVE_CAPABILITY, ObserverError,
        execute_in_repository as try_execute_in_repository, manifest, read_request,
        validate_response,
    };
    use diagnostic_triage_contracts::{
        model::{
            CacheStatus, Execution, ExecutionStatus, PerformanceStatus, PhaseDuration, RetryStatus,
            RunnerStatus, ToolchainFingerprint,
        },
        protocol::{ProtocolEnvelope, RequestEnvelope},
    };
    use std::{
        fs::{self, File},
        io::Cursor,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    const SUCCESS: &str = include_str!("../tests/golden/workflow-success.json");
    const OVER_BUDGET: &str = include_str!("../tests/golden/workflow-failure-over-budget.json");
    const CANCELLED: &str = include_str!("../tests/golden/workflow-cancelled.json");
    const ENRICHED: &str = include_str!("../tests/golden/workflow-enriched.json");
    const MISSING: &str = include_str!("../tests/golden/workflow-missing.json");
    const MALFORMED: &str = include_str!("../tests/golden/workflow-malformed.json");

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempRepo {
        root: PathBuf,
    }

    impl TempRepo {
        fn with_source(contents: &str) -> Self {
            let root = Self::new_root();
            fs::write(root.join("run.json"), contents).expect("fixture must be writable");
            Self { root }
        }

        fn new_root() -> PathBuf {
            let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "diagnostic-triage-github-observer-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("temporary repository must be creatable");
            root
        }
    }

    impl Drop for TempRepo {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }

    fn request() -> RequestEnvelope {
        let value = serde_json::json!({
            "protocol_version": "diagnostic-triage.protocol/v1",
            "kind": "request",
            "request_id": "019f7e95-0000-7000-8000-000000000065",
            "operation": "OBSERVE",
            "workspace": ".",
            "targets": ["run.json"],
            "required_capabilities": [OBSERVE_CAPABILITY],
            "optional_capabilities": [],
            "limits": {
                "timeout_ms": 1000,
                "max_stdout_bytes": 1_048_576,
                "max_stderr_bytes": 65_536,
                "max_evidence_bytes": 65_536,
                "max_events": 100
            }
        });
        match serde_json::from_value(value).expect("request fixture must be valid") {
            ProtocolEnvelope::Request(request) => request,
            _ => panic!("fixture must decode as request"),
        }
    }

    fn observe(contents: &str) -> super::ObserverResponse {
        let repository = TempRepo::with_source(contents);
        execute_in_repository(&request(), &repository.root)
    }

    fn execute_in_repository(
        request: &RequestEnvelope,
        repository: &Path,
    ) -> super::ObserverResponse {
        try_execute_in_repository(request, repository)
            .expect("representable request must produce a response")
    }

    fn observed_execution(response: &super::ObserverResponse) -> &Execution {
        response
            .events
            .iter()
            .find_map(|event| match event {
                ProtocolEnvelope::Execution(value) => Some(&value.execution),
                _ => None,
            })
            .expect("response must include an execution")
    }

    fn evidence_content(response: &super::ObserverResponse) -> &str {
        response
            .events
            .iter()
            .find_map(|event| match event {
                ProtocolEnvelope::Evidence(value) => value.evidence.content.as_deref(),
                _ => None,
            })
            .expect("response must include inline evidence")
    }

    fn assert_bounded_load_error(repository: &TempRepo) {
        let mut limited = request();
        limited.limits.max_events = 0;
        limited.limits.max_stdout_bytes = 1_024;

        let response = execute_in_repository(&limited, &repository.root);

        assert!(response.events.is_empty());
        assert_eq!(response.completion.sequence, 0);
        assert_eq!(response.completion.counts.evidence, 0);
        assert_eq!(response.completion.status, ExecutionStatus::Incomplete);
        validate_response(&limited, &response)
            .expect("bounded load error must retain a terminal completion");
    }

    #[test]
    fn manifest_advertises_only_offline_observation() {
        let actual = manifest();
        assert_eq!(
            actual.adapter.kind,
            diagnostic_triage_contracts::model::AdapterKind::Observer
        );
        assert_eq!(actual.adapter.capabilities.len(), 1);
        assert_eq!(actual.adapter.capabilities[0].as_str(), OBSERVE_CAPABILITY);
    }

    #[test]
    fn request_parser_rejects_non_request_input() {
        let manifest_line = serde_json::to_vec(&ProtocolEnvelope::Manifest(manifest()))
            .expect("manifest serializes");
        assert!(read_request(Cursor::new(manifest_line)).is_err());
    }

    #[test]
    fn successful_run_derives_only_available_rest_durations() {
        let response = observe(SUCCESS);
        let execution = observed_execution(&response);

        assert_eq!(response.completion.status, ExecutionStatus::Complete);
        assert_eq!(response.completion.tool_exit_code.0, Some(0));
        assert_eq!(response.completion.counts.evidence, 1);
        assert_eq!(response.completion.counts.executions, 1);
        assert_eq!(
            execution.phases_ms.queue,
            PhaseDuration::Milliseconds(2_000)
        );
        assert_eq!(execution.phases_ms.run, PhaseDuration::Milliseconds(40_000));
        assert_eq!(
            execution.phases_ms.total,
            PhaseDuration::Milliseconds(42_000)
        );
        assert!(matches!(
            execution.phases_ms.setup,
            PhaseDuration::Unavailable(_)
        ));
        assert!(matches!(
            execution.phases_ms.normalize,
            PhaseDuration::Unavailable(_)
        ));
        assert_eq!(
            execution.performance.status,
            PerformanceStatus::WithinBudget
        );
        assert_eq!(execution.cache.status, CacheStatus::Unavailable);
        assert_eq!(execution.retry.status, RetryStatus::NotApplicable);
        assert_eq!(execution.runner.status, RunnerStatus::Unavailable);
        assert!(matches!(
            execution.toolchain_fingerprint,
            ToolchainFingerprint::Unavailable(_)
        ));
    }

    #[test]
    fn classifies_the_sixty_second_budget_inclusively() {
        for (duration, expected) in [
            (59_999, PerformanceStatus::WithinBudget),
            (60_000, PerformanceStatus::ImprovementCandidate),
            (60_001, PerformanceStatus::ImprovementCandidate),
        ] {
            assert_eq!(
                crate::performance(&PhaseDuration::Milliseconds(duration)).status,
                expected
            );
        }
    }

    #[test]
    fn failed_run_over_sixty_seconds_is_only_an_improvement_candidate() {
        let response = observe(OVER_BUDGET);
        let execution = observed_execution(&response);

        assert_eq!(response.completion.status, ExecutionStatus::Complete);
        assert_eq!(execution.status, ExecutionStatus::Complete);
        assert_eq!(
            execution.performance.status,
            PerformanceStatus::ImprovementCandidate
        );
        assert_eq!(execution.phases_ms.run, PhaseDuration::Milliseconds(61_000));
        assert!(
            execution
                .message
                .as_deref()
                .is_some_and(|value| value.contains("failure"))
        );
    }

    #[test]
    fn cancellation_is_observed_without_failing_the_observer_session() {
        let response = observe(CANCELLED);

        assert_eq!(response.completion.status, ExecutionStatus::Complete);
        assert_eq!(
            observed_execution(&response).status,
            ExecutionStatus::Incomplete
        );
    }

    #[test]
    fn explicit_extension_preserves_phases_cache_retry_runner_and_toolchain() {
        let response = observe(ENRICHED);
        let execution = observed_execution(&response);

        assert_eq!(
            execution.phases_ms.setup,
            PhaseDuration::Milliseconds(7_000)
        );
        assert_eq!(execution.cache.status, CacheStatus::Hit);
        assert_eq!(execution.retry.status, RetryStatus::Recorded);
        assert_eq!(execution.retry.attempt, Some(2));
        assert_eq!(execution.retry.same_revision, Some(true));
        assert_eq!(execution.runner.status, RunnerStatus::Recorded);
        assert!(execution.runner.fingerprint.is_some());
        assert!(matches!(
            execution.toolchain_fingerprint,
            ToolchainFingerprint::Digest(_)
        ));

        let miss = ENRICHED.replace("\"HIT\"", "\"MISS\"");
        assert_eq!(
            observed_execution(&observe(&miss)).cache.status,
            CacheStatus::Miss
        );
    }

    #[test]
    fn missing_metrics_remain_unavailable_and_are_not_inferred() {
        let response = observe(MISSING);
        let execution = observed_execution(&response);

        assert!(matches!(
            execution.phases_ms.queue,
            PhaseDuration::Unavailable(_)
        ));
        assert!(matches!(
            execution.phases_ms.run,
            PhaseDuration::Unavailable(_)
        ));
        assert_eq!(
            execution.performance.status,
            PerformanceStatus::NotEvaluated
        );
        assert_eq!(execution.retry.status, RetryStatus::Unavailable);
    }

    #[test]
    fn malformed_source_is_incomplete_with_bounded_evidence() {
        let response = observe(MALFORMED);

        assert_eq!(response.completion.status, ExecutionStatus::Incomplete);
        assert_eq!(response.completion.counts.evidence, 1);
        assert_eq!(response.completion.counts.executions, 0);
        assert!(
            response
                .completion
                .message
                .as_deref()
                .is_some_and(|value| value.contains("malformed"))
        );
    }

    #[test]
    fn load_errors_obey_zero_event_and_tiny_stdout_limits() {
        assert_bounded_load_error(&TempRepo::with_source(MALFORMED));

        let root = TempRepo::new_root();
        let file = File::create(root.join("run.json")).expect("fixture file must be creatable");
        file.set_len(u64::try_from(MAX_INPUT_BYTES).unwrap_or(u64::MAX) + 1)
            .expect("sparse fixture must be sizable");
        assert_bounded_load_error(&TempRepo { root });

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let repository = TempRepo::with_source(SUCCESS);
            let path = repository.root.join("run.json");
            let original = path
                .metadata()
                .expect("fixture metadata exists")
                .permissions();
            let mut denied = original.clone();
            denied.set_mode(0o000);
            fs::set_permissions(&path, denied).expect("fixture must become unreadable");
            assert_bounded_load_error(&repository);
            fs::set_permissions(path, original).expect("fixture permissions must be restored");
        }
    }

    #[test]
    fn source_object_order_does_not_change_canonical_evidence() {
        let first = observe(
            r#"{"id":1,"name":"CI","status":"completed","conclusion":"success","run_attempt":1}"#,
        );
        let second = observe(
            r#"{"run_attempt":1,"conclusion":"success","status":"completed","name":"CI","id":1}"#,
        );

        assert_eq!(evidence_content(&first), evidence_content(&second));
        assert_eq!(observed_execution(&first), observed_execution(&second));
    }

    #[test]
    fn unsupported_capability_and_non_completed_source_are_terminal() {
        let repository = TempRepo::with_source(SUCCESS);
        let mut unsupported = request();
        unsupported.required_capabilities.push(
            "execution.unknown/v1"
                .parse()
                .expect("capability fixture must be valid"),
        );
        let response = execute_in_repository(&unsupported, &repository.root);
        assert_eq!(response.completion.status, ExecutionStatus::Unsupported);
        assert!(response.events.is_empty());

        let queued = SUCCESS.replace("\"completed\"", "\"queued\"");
        let response = observe(&queued);
        assert_eq!(response.completion.status, ExecutionStatus::Incomplete);
        assert_eq!(response.completion.counts.executions, 0);
    }

    #[test]
    fn event_and_source_overflow_are_incomplete() {
        let repository = TempRepo::with_source(SUCCESS);
        let mut limited = request();
        limited.limits.max_events = 1;
        let response = execute_in_repository(&limited, &repository.root);
        assert_eq!(response.completion.status, ExecutionStatus::Incomplete);
        assert_eq!(response.events.len(), 1);

        let root = TempRepo::new_root();
        let file = File::create(root.join("run.json")).expect("fixture file must be creatable");
        file.set_len(u64::try_from(MAX_INPUT_BYTES).unwrap_or(u64::MAX) + 1)
            .expect("sparse fixture must be sizable");
        let repository = TempRepo { root };
        let response = execute_in_repository(&request(), &repository.root);
        assert_eq!(response.completion.status, ExecutionStatus::Incomplete);
        assert!(
            response
                .completion
                .message
                .as_deref()
                .is_some_and(|value| value.contains("exceeds"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_rejected_before_source_read() {
        use std::os::unix::fs::symlink;

        let root = TempRepo::new_root();
        let outside = std::env::temp_dir().join(format!(
            "diagnostic-triage-github-outside-{}.json",
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&outside, SUCCESS).expect("outside fixture must be writable");
        symlink(&outside, root.join("run.json")).expect("symlink fixture must be creatable");
        let repository = TempRepo { root };

        let response = execute_in_repository(&request(), &repository.root);
        let _ignored = fs::remove_file(outside);
        assert_eq!(response.completion.status, ExecutionStatus::Incomplete);
        assert!(response.events.is_empty());
    }

    #[test]
    fn invalid_explicit_metrics_and_timestamp_order_are_incomplete() {
        let inconsistent = ENRICHED.replace("\"total\": 50000", "\"total\": 50001");
        assert_eq!(
            observe(&inconsistent).completion.status,
            ExecutionStatus::Incomplete
        );

        let reversed = SUCCESS.replace("00:00:42Z", "00:00:01Z");
        assert_eq!(
            observe(&reversed).completion.status,
            ExecutionStatus::Incomplete
        );

        let zero_attempt = SUCCESS.replace("\"run_attempt\": 1", "\"run_attempt\": 0");
        assert_eq!(
            observe(&zero_attempt).completion.status,
            ExecutionStatus::Incomplete
        );
    }

    #[test]
    fn output_limit_returns_only_an_incomplete_completion() {
        let repository = TempRepo::with_source(SUCCESS);
        let mut limited = request();
        limited.limits.max_stdout_bytes = 1_024;
        let response = execute_in_repository(&limited, &repository.root);

        assert_eq!(response.completion.status, ExecutionStatus::Incomplete);
        assert!(response.events.is_empty());
        assert!(
            response
                .completion
                .message
                .as_deref()
                .is_some_and(|value| value.contains("output"))
        );
        validate_response(&limited, &response)
            .expect("tiny output fallback must retain a terminal completion");
    }

    #[test]
    fn impossible_output_limit_is_explicitly_rejected() {
        let repository = TempRepo::with_source(SUCCESS);
        let mut limited = request();
        limited.limits.max_stdout_bytes = 1;

        let error = try_execute_in_repository(&limited, &repository.root)
            .expect_err("an impossible output limit must not emit an invalid fallback");
        assert!(
            matches!(error, ObserverError::OutputLimit { limit: 1, .. }),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn fixture_paths_are_repository_relative() {
        assert!(Path::new("run.json").is_relative());
    }
}
