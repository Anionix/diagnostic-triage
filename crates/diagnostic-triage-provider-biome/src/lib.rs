//! First-party Biome Provider for the Diagnostic Triage protocol.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

mod process;
mod sarif;

use std::{
    ffi::OsString,
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};

use camino::{Utf8Path, Utf8PathBuf};
use diagnostic_triage_contracts::{
    Language, Nullable, ObjectId, RepoPath, Sha256Digest,
    model::{
        AdapterKind, Evidence, EvidenceSchemaVersion, EvidenceSource, Observation,
        ObservationSchemaVersion, Origin, Position, Severity, Tool,
    },
    protocol::{
        AdapterManifest, CompletionCounts, CompletionEnvelope, EnvelopeKind, EvidenceEnvelope,
        ManifestEnvelope, ObservationEnvelope, Operation, ProtocolEnvelope, ProtocolVersion,
        RequestEnvelope,
    },
    validate_session_jsonl,
};
use thiserror::Error;

use process::{
    CapturedOutput, IncompleteReason, ProcessError, ProcessLimits, ProcessOutcome, ProcessState,
    run_direct,
};
use sarif::{SarifError, SarifLevel, SarifLog, SarifResult, parse_sarif};

const ADAPTER_ID: &str = "biome";
const CHECK_CAPABILITY: &str = "diagnostic.check/v1";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const FALLBACK_REQUEST_ID: &str = "00000000-0000-4000-8000-000000000000";

/// One provider response after the manifest/request handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderResponse {
    pub events: Vec<ProtocolEnvelope>,
    pub completion: CompletionEnvelope,
}

/// Failures that prevent the provider from producing a trustworthy response.
#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("invalid provider request: {0}")]
    Request(String),
    #[error(transparent)]
    Sarif(#[from] SarifError),
    #[error("invalid Biome diagnostic path: {0}")]
    Path(String),
    #[error("provider model construction failed: {0}")]
    Model(String),
    #[error("provider I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("provider JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Construct the manifest emitted before the provider reads stdin.
#[must_use]
pub fn manifest() -> ManifestEnvelope {
    // Biome SARIF has severity and locations but no authoritative edit payload;
    // RDJSON suggestions are prose. Advertising fix.propose would invent a patch.
    ManifestEnvelope {
        protocol_version: ProtocolVersion::V1,
        kind: EnvelopeKind::Manifest,
        adapter: AdapterManifest {
            id: scalar(ADAPTER_ID),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            kind: AdapterKind::Provider,
            capabilities: vec![scalar(CHECK_CAPABILITY)],
            languages: ["javascript", "typescript", "json", "css", "graphql"]
                .into_iter()
                .map(scalar)
                .collect(),
        },
    }
}

/// Run one manifest-first provider session over process stdin/stdout.
///
/// # Errors
///
/// Returns [`ProviderError`] when request framing, process execution, typed
/// normalization, or protocol output cannot be completed safely.
pub fn run_stdio() -> Result<(), ProviderError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_stdio_with(stdin.lock(), stdout.lock(), execute)
}

fn run_stdio_with<R, W, F>(
    reader: R,
    mut output: W,
    execute_request: F,
) -> Result<(), ProviderError>
where
    R: Read,
    W: Write,
    F: Fn(&RequestEnvelope) -> ProviderResponse,
{
    write_envelope(&mut output, &ProtocolEnvelope::Manifest(manifest()))?;
    output.flush()?;

    let mut input = Vec::new();
    BufReader::new(reader)
        .take(u64::try_from(MAX_REQUEST_BYTES).unwrap_or(u64::MAX) + 1)
        .read_until(b'\n', &mut input)?;
    let (request, response) = match decode_request(&input) {
        Ok(request) => {
            let response = execute_request(&request);
            (Some(request), response)
        }
        Err(error) => (
            None,
            terminal_for_id(
                recover_request_id(&input),
                diagnostic_triage_contracts::model::ExecutionStatus::Incomplete,
                error.to_string(),
            ),
        ),
    };
    let response = if let Some(request) = &request {
        if validate_response(request, &response).is_err() {
            // LLM contract: GENERATED -> VALIDATION_FAILED -> INCOMPLETE -> REPORTED.
            let fallback = terminal_for_id(
                request.request_id.clone(),
                diagnostic_triage_contracts::model::ExecutionStatus::Incomplete,
                "provider response exceeded negotiated limits".to_owned(),
            );
            validate_response(request, &fallback)?;
            fallback
        } else {
            response
        }
    } else {
        response
    };
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

/// Decode exactly one strict JSON Lines request envelope.
///
/// # Errors
///
/// Returns [`ProviderError::Request`] for oversized, multiline, malformed, or
/// non-request input.
pub fn read_request(input: impl Read) -> Result<RequestEnvelope, ProviderError> {
    let mut bytes = Vec::new();
    BufReader::new(input)
        .take(u64::try_from(MAX_REQUEST_BYTES).unwrap_or(u64::MAX) + 1)
        .read_until(b'\n', &mut bytes)?;
    decode_request(&bytes)
}

fn decode_request(input: &[u8]) -> Result<RequestEnvelope, ProviderError> {
    if input.len() > MAX_REQUEST_BYTES {
        return Err(ProviderError::Request(
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
        return Err(ProviderError::Request(
            "stdin must contain exactly one JSON object line".to_owned(),
        ));
    }
    let envelope = serde_json::from_slice::<ProtocolEnvelope>(&bytes)
        .map_err(|error| ProviderError::Request(error.to_string()))?;
    envelope
        .validate()
        .map_err(|error| ProviderError::Request(error.to_string()))?;
    match envelope {
        ProtocolEnvelope::Request(request) => Ok(request),
        _ => Err(ProviderError::Request(
            "request envelope kind mismatch".to_owned(),
        )),
    }
}

/// Execute a negotiated request using direct Biome argv and bounded streams.
#[must_use]
pub fn execute(request: &RequestEnvelope) -> ProviderResponse {
    let program =
        std::env::var_os("DIAGNOSTIC_TRIAGE_BIOME_BIN").unwrap_or_else(|| OsString::from("biome"));
    execute_with_program(request, Path::new(&program))
}

fn execute_with_program(request: &RequestEnvelope, program: &Path) -> ProviderResponse {
    if let Err(error) = ProtocolEnvelope::Request(request.clone()).validate() {
        return incomplete(request, Vec::new(), Duration::ZERO, error.to_string());
    }
    if let Some(message) = unsupported_request(request) {
        return finish(
            request,
            Vec::new(),
            diagnostic_triage_contracts::model::ExecutionStatus::Unsupported,
            None,
            Duration::ZERO,
            Some(message),
        );
    }

    let workspace = match resolve_workspace(request) {
        Ok(workspace) => workspace,
        Err(error) => return incomplete(request, Vec::new(), Duration::ZERO, error.to_string()),
    };
    let limits = ProcessLimits {
        timeout: Duration::from_millis(request.limits.timeout_ms),
        max_stdout_bytes: usize::try_from(request.limits.max_stdout_bytes).unwrap_or(usize::MAX),
        max_stderr_bytes: usize::try_from(request.limits.max_stderr_bytes).unwrap_or(usize::MAX),
    };
    let started = Instant::now();
    let (tool_version, check_limits) =
        match probe_biome(request, program, &workspace, limits, started) {
            Ok(ready) => ready,
            Err(response) => return *response,
        };
    let argv = match biome_argv(request) {
        Ok(argv) => argv,
        Err(error) => {
            return incomplete(
                request,
                Vec::new(),
                bounded_elapsed(started, request.limits.timeout_ms),
                error.to_string(),
            );
        }
    };
    match run_direct(program.as_os_str(), &argv, &workspace, check_limits) {
        Ok(outcome) => response_from_outcome(
            request,
            &workspace,
            &tool_version,
            &outcome,
            bounded_elapsed(started, request.limits.timeout_ms),
        ),
        Err(error) => incomplete(
            request,
            Vec::new(),
            bounded_elapsed(started, request.limits.timeout_ms),
            error.to_string(),
        ),
    }
}

fn probe_biome(
    request: &RequestEnvelope,
    program: &Path,
    workspace: &Path,
    limits: ProcessLimits,
    started: Instant,
) -> Result<(String, ProcessLimits), Box<ProviderResponse>> {
    let version_outcome = match run_direct(
        program.as_os_str(),
        &["--version".to_owned()],
        workspace,
        limits,
    ) {
        Ok(outcome) => outcome,
        Err(ProcessError::Spawn(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Err(Box::new(finish(
                request,
                Vec::new(),
                diagnostic_triage_contracts::model::ExecutionStatus::Unsupported,
                None,
                Duration::ZERO,
                Some("Biome executable was not found".to_owned()),
            )));
        }
        Err(error) => {
            return Err(Box::new(incomplete(
                request,
                Vec::new(),
                bounded_elapsed(started, request.limits.timeout_ms),
                error.to_string(),
            )));
        }
    };
    if version_outcome.state != ProcessState::Complete || version_outcome.exit_code != Some(0) {
        return Err(Box::new(incomplete_from_process(
            request,
            &version_outcome,
            "text/plain",
            bounded_elapsed(started, request.limits.timeout_ms),
            "Biome version probe did not complete successfully".to_owned(),
        )));
    }
    let tool_version = parse_biome_version(&version_outcome.stdout.bytes).map_err(|error| {
        Box::new(incomplete_from_process(
            request,
            &version_outcome,
            "text/plain",
            bounded_elapsed(started, request.limits.timeout_ms),
            error.to_string(),
        ))
    })?;
    let check_limits =
        remaining_limits(request, &version_outcome, started.elapsed()).ok_or_else(|| {
            Box::new(incomplete_from_process(
                request,
                &version_outcome,
                "text/plain",
                bounded_elapsed(started, request.limits.timeout_ms),
                "Biome version probe exhausted the request limits".to_owned(),
            ))
        })?;
    Ok((tool_version, check_limits))
}

fn response_from_outcome(
    request: &RequestEnvelope,
    workspace_root: &Path,
    tool_version: &str,
    outcome: &ProcessOutcome,
    total_duration: Duration,
) -> ProviderResponse {
    let mut ids = IdFactory::new(&request.request_id);
    let (evidence_events, stdout_evidence_id) =
        process_evidence(request, outcome, "application/sarif+json", &mut ids);

    let ProcessState::Complete = outcome.state else {
        return incomplete(
            request,
            bounded_events(request, evidence_events),
            total_duration,
            incomplete_message(outcome.state),
        );
    };
    let Some(exit_code @ (0 | 1)) = outcome.exit_code else {
        return incomplete(
            request,
            bounded_events(request, evidence_events),
            total_duration,
            format!("Biome check failed with exit code {:?}", outcome.exit_code),
        );
    };
    let report = match parse_sarif(&outcome.stdout.bytes, tool_version) {
        Ok(report) => report,
        Err(error @ SarifError::UnsupportedColumnKind) => {
            return finish(
                request,
                bounded_events(request, evidence_events),
                diagnostic_triage_contracts::model::ExecutionStatus::Unsupported,
                None,
                total_duration,
                Some(error.to_string()),
            );
        }
        Err(error) => {
            return incomplete(
                request,
                bounded_events(request, evidence_events),
                total_duration,
                error.to_string(),
            );
        }
    };
    let mut normalized_events = Vec::new();
    if let Err(error) = append_normalized_events(
        request,
        workspace_root,
        tool_version,
        &report,
        stdout_evidence_id.as_ref(),
        &mut ids,
        &mut normalized_events,
    ) {
        return incomplete(
            request,
            bounded_events(request, evidence_events),
            total_duration,
            error.to_string(),
        );
    }
    let mut events = evidence_events;
    events.extend(normalized_events);
    resequence_events(&mut events);
    if u64::try_from(events.len()).unwrap_or(u64::MAX) > request.limits.max_events {
        return incomplete(
            request,
            bounded_events(request, events),
            total_duration,
            "normalized event count exceeds request limit".to_owned(),
        );
    }
    finish(
        request,
        events,
        diagnostic_triage_contracts::model::ExecutionStatus::Complete,
        Some(exit_code),
        total_duration,
        None,
    )
}

fn append_normalized_events(
    request: &RequestEnvelope,
    workspace_root: &Path,
    tool_version: &str,
    report: &SarifLog,
    diagnostic_evidence_id: Option<&ObjectId>,
    ids: &mut IdFactory,
    events: &mut Vec<ProtocolEnvelope>,
) -> Result<(), ProviderError> {
    if !capability_requested(request, CHECK_CAPABILITY) {
        return Ok(());
    }
    for diagnostic in &report.runs[0].results {
        let path = diagnostic
            .locations
            .first()
            .map(|location| {
                normalize_path(
                    &location.physical_location.artifact_location.uri,
                    &request.workspace,
                    workspace_root,
                )
            })
            .transpose()?;
        let observation_id = ids.next();
        let observation = Observation {
            schema_version: ObservationSchemaVersion::V1,
            observation_id: observation_id.clone(),
            tool: Tool {
                name: "biome".to_owned(),
                version: tool_version.to_owned(),
                rule_id: Some(diagnostic.rule_id.clone()),
            },
            language: language_for(path.as_ref()),
            severity: severity(diagnostic.level),
            origin: Origin::Normal,
            message: diagnostic.message.text.clone(),
            location: location(diagnostic, path.clone())?,
            symbol: None,
            expected: None,
            observed: None,
            evidence_ids: diagnostic_evidence_id.into_iter().cloned().collect(),
        };
        push_observation(request, events, observation);
    }
    Ok(())
}

fn location(
    diagnostic: &SarifResult,
    path: Option<RepoPath>,
) -> Result<Option<diagnostic_triage_contracts::model::Location>, ProviderError> {
    let region = diagnostic
        .locations
        .first()
        .and_then(|location| location.physical_location.region.as_ref());
    let Some((path, range)) = path.zip(region) else {
        return Ok(None);
    };
    Ok(Some(diagnostic_triage_contracts::model::Location {
        path,
        // SARIF endColumn is exclusive. parse_sarif has already required
        // explicit Unicode points or Biome's source-backed native omission.
        start: Position {
            line: to_u32(range.start_line, "startLine")?,
            column: to_u32(range.start_column, "startColumn")?,
        },
        end: match (range.end_line, range.end_column) {
            (Some(line), Some(column)) => Some(Position {
                line: to_u32(line, "endLine")?,
                column: to_u32(column, "endColumn")?,
            }),
            (None, None) => None,
            _ => {
                return Err(ProviderError::Model(
                    "SARIF region has an incomplete end position".to_owned(),
                ));
            }
        },
    }))
}

fn to_u32(value: u64, field: &str) -> Result<u32, ProviderError> {
    u32::try_from(value).map_err(|_| ProviderError::Model(format!("{field} exceeds u32")))
}

fn process_evidence(
    request: &RequestEnvelope,
    outcome: &ProcessOutcome,
    stdout_media_type: &str,
    ids: &mut IdFactory,
) -> (Vec<ProtocolEnvelope>, Option<ObjectId>) {
    let mut events = Vec::new();
    let stdout = captured_evidence(
        ids,
        EvidenceSource::Stdout,
        stdout_media_type,
        &outcome.stdout,
        request.limits.max_evidence_bytes,
    );
    let stdout_id = stdout.as_ref().map(|evidence| evidence.evidence_id.clone());
    if let Some(evidence) = stdout {
        push_evidence(request, &mut events, evidence);
    }
    if let Some(evidence) = captured_evidence(
        ids,
        EvidenceSource::Stderr,
        "text/plain",
        &outcome.stderr,
        request.limits.max_evidence_bytes,
    ) {
        push_evidence(request, &mut events, evidence);
    }
    (events, stdout_id)
}

fn incomplete_from_process(
    request: &RequestEnvelope,
    outcome: &ProcessOutcome,
    stdout_media_type: &str,
    duration: Duration,
    message: String,
) -> ProviderResponse {
    let mut ids = IdFactory::new(&request.request_id);
    let (events, _) = process_evidence(request, outcome, stdout_media_type, &mut ids);
    incomplete(request, bounded_events(request, events), duration, message)
}

fn parse_biome_version(bytes: &[u8]) -> Result<String, ProviderError> {
    let output = std::str::from_utf8(bytes)
        .map_err(|error| ProviderError::Model(format!("Biome version is not UTF-8: {error}")))?;
    let version = output
        .trim()
        .strip_prefix("Version: ")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ProviderError::Model("Biome version output is malformed".to_owned()))?;
    if version.chars().count() > 64 {
        return Err(ProviderError::Model(
            "Biome version exceeds the v1 tool version bound".to_owned(),
        ));
    }
    Ok(version.to_owned())
}

fn remaining_limits(
    request: &RequestEnvelope,
    probe: &ProcessOutcome,
    elapsed: Duration,
) -> Option<ProcessLimits> {
    let timeout = Duration::from_millis(request.limits.timeout_ms).checked_sub(elapsed)?;
    if timeout < Duration::from_millis(1) {
        return None;
    }
    Some(ProcessLimits {
        timeout,
        max_stdout_bytes: usize::try_from(request.limits.max_stdout_bytes)
            .unwrap_or(usize::MAX)
            .saturating_sub(usize::try_from(probe.stdout.observed_bytes).unwrap_or(usize::MAX)),
        max_stderr_bytes: usize::try_from(request.limits.max_stderr_bytes)
            .unwrap_or(usize::MAX)
            .saturating_sub(usize::try_from(probe.stderr.observed_bytes).unwrap_or(usize::MAX)),
    })
}

fn bounded_elapsed(started: Instant, timeout_ms: u64) -> Duration {
    started.elapsed().min(Duration::from_millis(timeout_ms))
}

fn captured_evidence(
    ids: &mut IdFactory,
    source: EvidenceSource,
    media_type: &str,
    output: &CapturedOutput,
    limit: u64,
) -> Option<Evidence> {
    if output.observed_bytes == 0 {
        return None;
    }
    let maximum = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut retained = output.bytes.len().min(maximum);
    let content = match std::str::from_utf8(&output.bytes[..retained]) {
        Ok(content) => content.to_owned(),
        Err(error) => {
            retained = error.valid_up_to();
            std::str::from_utf8(&output.bytes[..retained])
                .unwrap_or("")
                .to_owned()
        }
    };
    let retained_bytes = u64::try_from(content.len()).unwrap_or(u64::MAX);
    let observed_bytes = output.observed_bytes.max(retained_bytes);
    Some(Evidence {
        schema_version: EvidenceSchemaVersion::V1,
        evidence_id: ids.next(),
        execution_id: None,
        source,
        media_type: media_type.to_owned(),
        retained_bytes,
        observed_bytes,
        limit_bytes: u32::try_from(limit).ok()?,
        truncated: observed_bytes > retained_bytes,
        sha256: Sha256Digest::compute(content.as_bytes()),
        relative_path: None,
        content: Some(content),
    })
}

fn normalize_path(
    raw: &str,
    workspace: &RepoPath,
    workspace_root: &Path,
) -> Result<RepoPath, ProviderError> {
    if raw.contains(['\\', '\0']) || raw.contains("://") {
        return Err(ProviderError::Path(raw.to_owned()));
    }
    let raw_path = Utf8Path::new(raw);
    let relative = if raw_path.is_absolute() {
        let canonical =
            std::fs::canonicalize(raw_path).map_err(|_| ProviderError::Path(raw.to_owned()))?;
        let stripped = canonical
            .strip_prefix(workspace_root)
            .map_err(|_| ProviderError::Path(raw.to_owned()))?;
        Utf8PathBuf::from_path_buf(stripped.to_path_buf())
            .map_err(|_| ProviderError::Path(raw.to_owned()))?
    } else {
        let mut normalized = raw;
        while let Some(stripped) = normalized.strip_prefix("./") {
            normalized = stripped;
        }
        Utf8PathBuf::from(normalized)
    };
    if relative.as_str().is_empty() || relative == Utf8Path::new(".") {
        return Err(ProviderError::Path(raw.to_owned()));
    }
    let repository_path = if workspace.as_str() == "." {
        relative
    } else {
        Utf8PathBuf::from(workspace.as_str()).join(relative)
    };
    let parsed = RepoPath::from_str(repository_path.as_str())
        .map_err(|_| ProviderError::Path(raw.to_owned()))?;
    let candidate = workspace_root.join(
        repository_path
            .strip_prefix(workspace.as_str())
            .unwrap_or(repository_path.as_path()),
    );
    if candidate.exists() {
        let canonical =
            std::fs::canonicalize(candidate).map_err(|_| ProviderError::Path(raw.to_owned()))?;
        if !canonical.starts_with(workspace_root) {
            return Err(ProviderError::Path(raw.to_owned()));
        }
    }
    Ok(parsed)
}

fn resolve_workspace(request: &RequestEnvelope) -> Result<PathBuf, ProviderError> {
    let repository = std::fs::canonicalize(std::env::current_dir()?)?;
    let candidate = if request.workspace.as_str() == "." {
        repository.clone()
    } else {
        repository.join(request.workspace.as_str())
    };
    let workspace = std::fs::canonicalize(candidate)?;
    if !workspace.is_dir() || !workspace.starts_with(&repository) {
        return Err(ProviderError::Path(request.workspace.to_string()));
    }
    Ok(workspace)
}

fn biome_argv(request: &RequestEnvelope) -> Result<Vec<String>, ProviderError> {
    let mut argv = vec![
        "check".to_owned(),
        "--reporter=sarif".to_owned(),
        "--max-diagnostics=none".to_owned(),
        "--no-errors-on-unmatched".to_owned(),
        "--".to_owned(),
    ];
    for target in &request.targets {
        let relative = if request.workspace.as_str() == "." {
            target.as_str()
        } else if target.as_str() == request.workspace.as_str() {
            "."
        } else {
            target
                .as_str()
                .strip_prefix(request.workspace.as_str())
                .and_then(|value| value.strip_prefix('/'))
                .ok_or_else(|| {
                    ProviderError::Path(format!(
                        "target {target} is outside workspace {}",
                        request.workspace
                    ))
                })?
        };
        argv.push(relative.to_owned());
    }
    Ok(argv)
}

fn unsupported_request(request: &RequestEnvelope) -> Option<String> {
    if request.operation != Operation::Check {
        return Some("Biome Provider supports only CHECK".to_owned());
    }
    if !capability_requested(request, CHECK_CAPABILITY) {
        return Some("CHECK requires diagnostic.check/v1".to_owned());
    }
    request
        .required_capabilities
        .iter()
        .find(|capability| capability.as_str() != CHECK_CAPABILITY)
        .map(|capability| format!("required capability is unsupported: {capability}"))
}

fn capability_requested(request: &RequestEnvelope, expected: &str) -> bool {
    request
        .required_capabilities
        .iter()
        .chain(&request.optional_capabilities)
        .any(|capability| capability.as_str() == expected)
}

fn severity(value: SarifLevel) -> Severity {
    match value {
        SarifLevel::Error => Severity::Error,
        SarifLevel::None | SarifLevel::Note => Severity::Info,
        SarifLevel::Warning => Severity::Warning,
    }
}

fn language_for(path: Option<&RepoPath>) -> Language {
    let language = path
        .and_then(|path| {
            path.as_str()
                .rsplit_once('.')
                .map(|(_, extension)| extension)
        })
        .map_or("unknown", |extension| match extension {
            "js" | "jsx" | "mjs" | "cjs" => "javascript",
            "ts" | "tsx" | "mts" | "cts" => "typescript",
            "json" | "jsonc" => "json",
            "css" => "css",
            "graphql" | "gql" => "graphql",
            _ => "unknown",
        });
    scalar(language)
}

fn push_observation(
    request: &RequestEnvelope,
    events: &mut Vec<ProtocolEnvelope>,
    observation: Observation,
) {
    events.push(ProtocolEnvelope::Observation(ObservationEnvelope {
        protocol_version: ProtocolVersion::V1,
        kind: EnvelopeKind::Observation,
        request_id: request.request_id.clone(),
        sequence: u64::try_from(events.len()).unwrap_or(u64::MAX),
        observation,
    }));
}

fn push_evidence(
    request: &RequestEnvelope,
    events: &mut Vec<ProtocolEnvelope>,
    evidence: Evidence,
) {
    events.push(ProtocolEnvelope::Evidence(EvidenceEnvelope {
        protocol_version: ProtocolVersion::V1,
        kind: EnvelopeKind::Evidence,
        request_id: request.request_id.clone(),
        sequence: u64::try_from(events.len()).unwrap_or(u64::MAX),
        evidence,
    }));
}

fn bounded_events(
    request: &RequestEnvelope,
    mut events: Vec<ProtocolEnvelope>,
) -> Vec<ProtocolEnvelope> {
    events.truncate(usize::try_from(request.limits.max_events).unwrap_or(usize::MAX));
    resequence_events(&mut events);
    events
}

fn resequence_events(events: &mut [ProtocolEnvelope]) {
    for (sequence, event) in events.iter_mut().enumerate() {
        match event {
            ProtocolEnvelope::Observation(value) => {
                value.sequence = u64::try_from(sequence).unwrap_or(u64::MAX);
            }
            ProtocolEnvelope::Evidence(value) => {
                value.sequence = u64::try_from(sequence).unwrap_or(u64::MAX);
            }
            ProtocolEnvelope::FixCandidate(value) => {
                value.sequence = u64::try_from(sequence).unwrap_or(u64::MAX);
            }
            ProtocolEnvelope::Execution(value) => {
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
    duration: Duration,
    message: String,
) -> ProviderResponse {
    finish(
        request,
        events,
        diagnostic_triage_contracts::model::ExecutionStatus::Incomplete,
        None,
        duration,
        Some(message),
    )
}

fn finish(
    request: &RequestEnvelope,
    events: Vec<ProtocolEnvelope>,
    status: diagnostic_triage_contracts::model::ExecutionStatus,
    exit_code: Option<u8>,
    duration: Duration,
    message: Option<String>,
) -> ProviderResponse {
    let mut counts = CompletionCounts {
        observations: 0,
        evidence: 0,
        fix_candidates: 0,
        executions: 0,
    };
    let mut evidence_bytes = 0_u64;
    for event in &events {
        match event {
            ProtocolEnvelope::Observation(_) => counts.observations += 1,
            ProtocolEnvelope::Evidence(value) => {
                counts.evidence += 1;
                evidence_bytes = evidence_bytes.saturating_add(value.evidence.retained_bytes);
            }
            ProtocolEnvelope::FixCandidate(_) => counts.fix_candidates += 1,
            ProtocolEnvelope::Execution(_) => counts.executions += 1,
            ProtocolEnvelope::Manifest(_)
            | ProtocolEnvelope::Request(_)
            | ProtocolEnvelope::Completion(_) => {}
        }
    }
    ProviderResponse {
        completion: CompletionEnvelope {
            protocol_version: ProtocolVersion::V1,
            kind: EnvelopeKind::Completion,
            request_id: request.request_id.clone(),
            sequence: u64::try_from(events.len()).unwrap_or(u64::MAX),
            status,
            tool_exit_code: Nullable(exit_code),
            tool_duration_ms: u64::try_from(duration.as_millis())
                .unwrap_or(u64::MAX)
                .min(request.limits.timeout_ms),
            counts,
            evidence_bytes,
            message,
        },
        events,
    }
}

fn terminal_for_id(
    request_id: ObjectId,
    status: diagnostic_triage_contracts::model::ExecutionStatus,
    message: String,
) -> ProviderResponse {
    ProviderResponse {
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
    response: &ProviderResponse,
) -> Result<(), ProviderError> {
    for event in &response.events {
        event
            .validate()
            .map_err(|error| ProviderError::Model(error.to_string()))?;
    }
    ProtocolEnvelope::Completion(response.completion.clone())
        .validate()
        .map_err(|error| ProviderError::Model(error.to_string()))?;
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
        .map_err(|error| ProviderError::Model(error.to_string()))
}

fn incomplete_message(state: ProcessState) -> String {
    match state {
        ProcessState::Complete => "Biome completed".to_owned(),
        ProcessState::Incomplete(IncompleteReason::Timeout) => "Biome timed out".to_owned(),
        ProcessState::Incomplete(IncompleteReason::StdoutOverflow) => {
            "Biome stdout exceeded the request limit".to_owned()
        }
        ProcessState::Incomplete(IncompleteReason::StderrOverflow) => {
            "Biome stderr exceeded the request limit".to_owned()
        }
        ProcessState::Incomplete(IncompleteReason::TerminatedWithoutCode) => {
            "Biome terminated without an exit code".to_owned()
        }
        ProcessState::Incomplete(IncompleteReason::UnrepresentableExitCode) => {
            "Biome exit code is outside the protocol range".to_owned()
        }
    }
}

fn write_envelope(
    output: &mut impl Write,
    envelope: &ProtocolEnvelope,
) -> Result<(), ProviderError> {
    envelope
        .validate()
        .map_err(|error| ProviderError::Model(error.to_string()))?;
    serde_json::to_writer(&mut *output, envelope)?;
    output.write_all(b"\n")?;
    Ok(())
}

fn scalar<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: std::fmt::Debug,
{
    value.parse().expect("provider constants must be valid")
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
        CHECK_CAPABILITY, ProviderError, biome_argv, decode_request, manifest, read_request,
        response_from_outcome, run_stdio_with, validate_response,
    };
    use crate::process::{CapturedOutput, ProcessOutcome, ProcessState};
    use diagnostic_triage_contracts::{
        model::{ExecutionStatus, Severity},
        protocol::{ProtocolEnvelope, RequestEnvelope},
        validate_session_jsonl,
    };
    use std::{
        fs,
        io::Cursor,
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    fn request() -> RequestEnvelope {
        let value = serde_json::json!({
            "protocol_version": "diagnostic-triage.protocol/v1",
            "kind": "request",
            "request_id": "019f7e95-0000-7000-8000-000000000063",
            "operation": "CHECK",
            "workspace": ".",
            "targets": ["src/main.ts"],
            "required_capabilities": [CHECK_CAPABILITY],
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

    fn complete_output(stdout: &str, exit_code: u8) -> ProcessOutcome {
        ProcessOutcome {
            state: ProcessState::Complete,
            exit_code: Some(exit_code),
            stdout: CapturedOutput {
                bytes: stdout.as_bytes().to_vec(),
                observed_bytes: u64::try_from(stdout.len()).expect("fixture length fits u64"),
                truncated: false,
            },
            stderr: CapturedOutput {
                bytes: Vec::new(),
                observed_bytes: 0,
                truncated: false,
            },
            duration: Duration::from_millis(12),
        }
    }

    #[test]
    fn manifest_advertises_only_the_typed_check_capability() {
        let manifest = manifest();
        let capabilities = manifest
            .adapter
            .capabilities
            .iter()
            .map(diagnostic_triage_contracts::Capability::as_str)
            .collect::<Vec<_>>();
        assert_eq!(capabilities, [CHECK_CAPABILITY]);
    }

    #[test]
    fn empty_report_completes_without_diagnostics() {
        let output = include_str!("../tests/golden/biome-clean.sarif.json");
        let response = response_from_outcome(
            &request(),
            Path::new("."),
            "2.4.15",
            &complete_output(output, 0),
            Duration::from_millis(14),
        );

        assert_eq!(response.completion.status, ExecutionStatus::Complete);
        assert_eq!(response.completion.tool_exit_code.0, Some(0));
        assert_eq!(response.completion.counts.observations, 0);
        assert_eq!(response.completion.counts.evidence, 1);
    }

    #[test]
    fn unsupported_required_capability_finishes_without_invoking_biome() {
        let mut unknown_request = request();
        unknown_request.required_capabilities = vec![
            "diagnostic.unknown/v1"
                .parse()
                .expect("capability fixture must be valid"),
        ];
        let response = super::execute(&unknown_request);

        assert_eq!(response.completion.status, ExecutionStatus::Unsupported);
        assert_eq!(response.completion.tool_exit_code.0, None);
        assert!(response.events.is_empty());

        let mut fix_request = request();
        fix_request
            .required_capabilities
            .push("fix.propose/v1".parse().unwrap());
        let response = super::execute(&fix_request);
        assert_eq!(response.completion.status, ExecutionStatus::Unsupported);
    }

    #[test]
    fn request_parser_rejects_kind_mismatch_and_multiline_documents() {
        let manifest_line = serde_json::to_vec(&ProtocolEnvelope::Manifest(manifest()))
            .expect("manifest serializes");
        assert!(matches!(
            read_request(Cursor::new(manifest_line)),
            Err(ProviderError::Request(_))
        ));
        assert!(matches!(
            decode_request(b"{}\n{}\n"),
            Err(ProviderError::Request(_))
        ));
    }

    #[test]
    fn direct_biome_argv_uses_a_terminator_and_no_shell_string() {
        assert_eq!(
            biome_argv(&request()).expect("request targets are inside workspace"),
            [
                "check",
                "--reporter=sarif",
                "--max-diagnostics=none",
                "--no-errors-on-unmatched",
                "--",
                "src/main.ts"
            ]
        );
    }

    #[test]
    fn typed_diagnostic_preserves_version_rule_severity_and_location() {
        let request = request();
        let response = response_from_outcome(
            &request,
            Path::new("."),
            "2.4.15",
            &complete_output(include_str!("../tests/golden/biome-findings.sarif.json"), 1),
            Duration::from_millis(14),
        );

        assert_eq!(response.completion.status, ExecutionStatus::Complete);
        assert_eq!(response.completion.tool_exit_code.0, Some(1));
        assert_eq!(response.completion.counts.observations, 2);
        assert_eq!(response.completion.counts.fix_candidates, 0);
        let observation = response.events.iter().find_map(|event| match event {
            ProtocolEnvelope::Observation(value)
                if value.observation.tool.rule_id.as_deref()
                    == Some("lint/suspicious/noDebugger") =>
            {
                Some(&value.observation)
            }
            _ => None,
        });
        let observation = observation.expect("the error observation must be emitted");
        assert_eq!(observation.severity, Severity::Error);
        assert_eq!(observation.tool.version, "2.4.15");
        assert_eq!(
            observation.tool.rule_id.as_deref(),
            Some("lint/suspicious/noDebugger")
        );
        assert_eq!(
            observation
                .location
                .as_ref()
                .map(|value| value.path.as_str()),
            Some("src/main.ts")
        );
    }

    #[test]
    fn whole_file_format_diagnostic_does_not_invent_a_position() {
        let response = response_from_outcome(
            &request(),
            Path::new("."),
            "2.4.15",
            &complete_output(include_str!("../tests/golden/biome-format.sarif.json"), 1),
            Duration::from_millis(14),
        );
        let observation = response.events.iter().find_map(|event| match event {
            ProtocolEnvelope::Observation(value) => Some(&value.observation),
            _ => None,
        });

        assert!(matches!(
            observation,
            Some(value)
                if value.tool.rule_id.as_deref() == Some("format")
                    && value.severity == Severity::Error
                    && value.location.is_none()
        ));
    }

    #[test]
    fn assist_diagnostic_preserves_its_native_rule_and_location() {
        let response = response_from_outcome(
            &request(),
            Path::new("."),
            "2.4.15",
            &complete_output(include_str!("../tests/golden/biome-assist.sarif.json"), 1),
            Duration::from_millis(14),
        );
        let observation = response.events.iter().find_map(|event| match event {
            ProtocolEnvelope::Observation(value) => Some(&value.observation),
            _ => None,
        });

        assert!(matches!(
            observation,
            Some(value)
                if value.tool.rule_id.as_deref() == Some("assist/source/organizeImports")
                    && value.location.as_ref().is_some_and(|location| location.end.is_some())
        ));
    }

    #[test]
    fn locations_preserve_half_open_unicode_points_insertions_and_next_line_end() {
        let response = response_from_outcome(
            &request(),
            Path::new("."),
            "2.4.15",
            &complete_output(
                include_str!("../tests/golden/biome-locations.sarif.json"),
                1,
            ),
            Duration::from_millis(14),
        );
        let locations = response
            .events
            .iter()
            .filter_map(|event| match event {
                ProtocolEnvelope::Observation(value) => value.observation.location.as_ref(),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(response.completion.status, ExecutionStatus::Complete);
        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].end.as_ref().unwrap().line, 1);
        assert_eq!(locations[0].end.as_ref().unwrap().column, 3);
        assert_eq!(locations[1].start, locations[1].end.clone().unwrap());
        assert_eq!(
            locations[2].start.line,
            locations[2].end.as_ref().unwrap().line
        );
        assert_eq!(locations[2].end.as_ref().unwrap().column, 4);
        assert_eq!(locations[3].end.as_ref().unwrap().line, 5);
        assert_eq!(locations[3].end.as_ref().unwrap().column, 1);
    }

    #[test]
    fn omitted_column_kind_preserves_source_backed_unicode_point_locations() {
        let sarif = include_str!("../tests/golden/biome-locations.sarif.json").replacen(
            ",\"columnKind\":\"unicodeCodePoints\"",
            "",
            1,
        );
        assert!(!sarif.contains("columnKind"));
        let request = request();
        let response = response_from_outcome(
            &request,
            Path::new("."),
            "2.4.15",
            &complete_output(&sarif, 1),
            Duration::from_millis(14),
        );
        let locations = response
            .events
            .iter()
            .filter_map(|event| match event {
                ProtocolEnvelope::Observation(value) => value.observation.location.as_ref(),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(response.completion.status, ExecutionStatus::Complete);
        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].start.column, 2);
        assert_eq!(locations[0].end.as_ref().unwrap().column, 3);
        assert_eq!(locations[1].start, locations[1].end.clone().unwrap());
        assert_eq!(locations[3].end.as_ref().unwrap().line, 5);
        assert_eq!(locations[3].end.as_ref().unwrap().column, 1);
        validate_response(&request, &response).expect("omitted Biome column kind remains valid");

        let unpinned = response_from_outcome(
            &request,
            Path::new("."),
            "2.4.14",
            &complete_output(&sarif, 1),
            Duration::from_millis(14),
        );
        assert_eq!(unpinned.completion.status, ExecutionStatus::Unsupported);
        assert_eq!(unpinned.completion.counts.observations, 0);
        validate_response(&request, &unpinned).expect("unpinned omission remains unsupported");
    }

    #[test]
    fn utf16_sarif_columns_finish_unsupported_without_observations() {
        let request = request();
        let response = response_from_outcome(
            &request,
            Path::new("."),
            "2.4.15",
            &complete_output(
                include_str!("../tests/golden/biome-utf16-columns.sarif.json"),
                1,
            ),
            Duration::from_millis(14),
        );

        assert_eq!(response.completion.status, ExecutionStatus::Unsupported);
        assert_eq!(response.completion.tool_exit_code.0, None);
        assert_eq!(response.completion.counts.observations, 0);
        assert_eq!(response.completion.counts.evidence, 1);
        validate_response(&request, &response).expect("UNSUPPORTED response satisfies protocol v1");
    }

    #[test]
    fn stdio_validation_overflows_emit_bounded_incomplete_completion() {
        let baseline_request = request();
        let invalid = response_from_outcome(
            &baseline_request,
            Path::new("."),
            "2.4.15",
            &complete_output(include_str!("../tests/golden/biome-findings.sarif.json"), 1),
            Duration::from_millis(14),
        );
        assert!(!invalid.events.is_empty());

        let mut event_overflow = baseline_request.clone();
        event_overflow.limits.max_events = 0;
        let mut evidence_overflow = baseline_request.clone();
        evidence_overflow.limits.max_evidence_bytes = 0;
        let mut stdout_overflow = baseline_request;
        stdout_overflow.limits.max_stdout_bytes = 1_024;

        for limited in [event_overflow, evidence_overflow, stdout_overflow] {
            let mut input = serde_json::to_vec(&ProtocolEnvelope::Request(limited.clone()))
                .expect("request serializes");
            input.push(b'\n');
            let mut output = Vec::new();
            run_stdio_with(Cursor::new(input), &mut output, |_| invalid.clone())
                .expect("validation overflow emits a fallback");
            let lines = output
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| serde_json::from_slice::<ProtocolEnvelope>(line).unwrap())
                .collect::<Vec<_>>();

            assert_eq!(lines.len(), 2);
            assert!(matches!(lines[0], ProtocolEnvelope::Manifest(_)));
            let ProtocolEnvelope::Completion(completion) = lines[1].clone() else {
                panic!("terminal line must be completion")
            };
            assert_eq!(completion.status, ExecutionStatus::Incomplete);
            let fallback = super::ProviderResponse {
                events: Vec::new(),
                completion,
            };
            validate_response(&limited, &fallback)
                .expect("fallback must fit the negotiated limits");
        }
    }

    #[test]
    fn malformed_partial_and_tool_error_sarif_are_incomplete_with_evidence() {
        for output in [
            "not-json",
            include_str!("../tests/golden/biome-partial.sarif.json"),
        ] {
            let response = response_from_outcome(
                &request(),
                Path::new("."),
                "2.4.15",
                &complete_output(output, 2),
                Duration::from_millis(14),
            );
            assert_eq!(response.completion.status, ExecutionStatus::Incomplete);
            assert_eq!(response.completion.tool_exit_code.0, None);
            assert_eq!(response.completion.counts.observations, 0);
            assert_eq!(response.completion.counts.evidence, 1);
        }
    }

    #[test]
    fn path_escape_is_incomplete_and_never_becomes_an_observation() {
        let response = response_from_outcome(
            &request(),
            Path::new("."),
            "2.4.15",
            &complete_output(
                include_str!("../tests/golden/biome-path-escape.sarif.json"),
                1,
            ),
            Duration::from_millis(14),
        );
        assert_eq!(response.completion.status, ExecutionStatus::Incomplete);
        assert_eq!(response.completion.counts.observations, 0);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_incomplete_and_never_becomes_an_observation() {
        use std::os::unix::fs::symlink;

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "diagnostic-triage-biome-path-{}-{nonce}",
            std::process::id()
        ));
        let outside = std::env::temp_dir().join(format!(
            "diagnostic-triage-biome-outside-{}-{nonce}.ts",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(&outside, "debugger;\n").unwrap();
        symlink(&outside, root.join("escape.ts")).unwrap();
        let sarif = include_str!("../tests/golden/biome-findings.sarif.json")
            .replace("src/main.ts", "escape.ts");

        let response = response_from_outcome(
            &request(),
            &root,
            "2.4.15",
            &complete_output(&sarif, 1),
            Duration::from_millis(14),
        );
        let _ignored = fs::remove_dir_all(&root);
        let _ignored = fs::remove_file(&outside);

        assert_eq!(response.completion.status, ExecutionStatus::Incomplete);
        assert_eq!(response.completion.counts.observations, 0);
    }

    #[test]
    fn nonzero_diagnostic_session_validates_end_to_end() {
        let request = request();
        let response = response_from_outcome(
            &request,
            Path::new("."),
            "2.4.15",
            &complete_output(include_str!("../tests/golden/biome-findings.sarif.json"), 1),
            Duration::from_millis(14),
        );
        let mut transcript = Vec::new();
        for envelope in std::iter::once(ProtocolEnvelope::Manifest(manifest()))
            .chain(std::iter::once(ProtocolEnvelope::Request(request)))
            .chain(response.events)
            .chain(std::iter::once(ProtocolEnvelope::Completion(
                response.completion,
            )))
        {
            serde_json::to_writer(&mut transcript, &envelope).expect("envelope serializes");
            transcript.push(b'\n');
        }

        validate_session_jsonl(&transcript).expect("provider transcript must satisfy protocol v1");
    }
}
