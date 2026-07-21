//! Cargo- and Clippy-backed Rust Provider for Diagnostic Triage.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

mod cargo_json;
mod process;

use std::{
    collections::HashSet,
    ffi::OsString,
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};

use camino::{Utf8Path, Utf8PathBuf};
use diagnostic_triage_contracts::{
    Nullable, ObjectId, RepoPath, Sha256Digest,
    model::{
        AdapterKind, Evidence, EvidenceSchemaVersion, EvidenceSource, ExecutionStatus, Location,
        Observation, ObservationSchemaVersion, Origin, Position, Severity, Tool,
    },
    protocol::{
        AdapterManifest, CompletionCounts, CompletionEnvelope, EnvelopeKind, EvidenceEnvelope,
        ManifestEnvelope, ObservationEnvelope, Operation, ProtocolEnvelope, ProtocolVersion,
        RequestEnvelope,
    },
    validate_session_jsonl,
};
use thiserror::Error;

use cargo_json::{CargoReport, RustcDiagnostic, RustcSpan, parse_cargo_jsonl};
use process::{
    CapturedOutput, IncompleteReason, ProcessError, ProcessLimits, ProcessOutcome, ProcessState,
    run_direct,
};

const ADAPTER_ID: &str = "rust";
const CHECK_CAPABILITY: &str = "diagnostic.check/v1";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_MESSAGE_CHARS: usize = 8_192;
const FALLBACK_REQUEST_ID: &str = "00000000-0000-4000-8000-000000000000";
const CARGO_CHECK_TOOL: &str = "cargo-check";
const CLIPPY_TOOL: &str = "clippy";

/// One Provider response after the manifest/request handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderResponse {
    pub events: Vec<ProtocolEnvelope>,
    pub completion: CompletionEnvelope,
}

/// Failures at the Rust Provider's typed process and normalization boundary.
#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("invalid Provider request: {0}")]
    Request(String),
    #[error("Cargo JSON boundary failed: {0}")]
    CargoJson(String),
    #[error("invalid Rust diagnostic path: {0}")]
    Path(String),
    #[error("Provider model construction failed: {0}")]
    Model(String),
    #[error("Provider I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("Provider JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Construct the manifest emitted before the Provider reads stdin.
#[must_use]
pub fn manifest() -> ManifestEnvelope {
    ManifestEnvelope {
        protocol_version: ProtocolVersion::V1,
        kind: EnvelopeKind::Manifest,
        adapter: AdapterManifest {
            id: scalar(ADAPTER_ID),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            kind: AdapterKind::Provider,
            capabilities: vec![scalar(CHECK_CAPABILITY)],
            languages: vec![scalar("rust")],
        },
    }
}

/// Run one manifest-first Provider session over process stdin/stdout.
///
/// # Errors
///
/// Returns [`ProviderError`] when framing, process execution, normalization,
/// or protocol emission cannot be completed safely.
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

    let mut request_bytes = Vec::new();
    BufReader::new(reader)
        .take(u64::try_from(MAX_REQUEST_BYTES).unwrap_or(u64::MAX) + 1)
        .read_until(b'\n', &mut request_bytes)?;
    let (request, response) = match decode_request(&request_bytes) {
        Ok(request) => {
            let response = execute_request(&request);
            (Some(request), response)
        }
        Err(error) => (
            None,
            terminal_for_id(
                recover_request_id(&request_bytes),
                ExecutionStatus::Incomplete,
                &error.to_string(),
            ),
        ),
    };
    let response = if let Some(request) = &request {
        match validate_response(request, &response) {
            Ok(()) => response,
            Err(error) => terminal_for_id(
                request.request_id.clone(),
                ExecutionStatus::Incomplete,
                &format!("provider response validation failed: {error}"),
            ),
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

/// Decode exactly one bounded JSON Lines request envelope.
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

/// Execute Cargo check and, after a successful build, Clippy.
#[must_use]
pub fn execute(request: &RequestEnvelope) -> ProviderResponse {
    let program =
        std::env::var_os("DIAGNOSTIC_TRIAGE_CARGO_BIN").unwrap_or_else(|| OsString::from("cargo"));
    execute_with_program(request, Path::new(&program))
}

#[allow(clippy::too_many_lines)]
fn execute_with_program(request: &RequestEnvelope, program: &Path) -> ProviderResponse {
    if let Err(error) = ProtocolEnvelope::Request(request.clone()).validate() {
        return incomplete(request, Vec::new(), Duration::ZERO, error.to_string());
    }
    if let Some(message) = unsupported_request(request) {
        return finish(
            request,
            Vec::new(),
            ExecutionStatus::Unsupported,
            None,
            Duration::ZERO,
            Some(message),
        );
    }
    let (repository_root, workspace_root) = match resolve_workspace(request) {
        Ok(roots) => roots,
        Err(error) => return incomplete(request, Vec::new(), Duration::ZERO, error.to_string()),
    };
    if let Err(error) = validate_targets(request, &repository_root, &workspace_root) {
        return incomplete(request, Vec::new(), Duration::ZERO, error.to_string());
    }

    let started = Instant::now();
    let mut usage = ProcessUsage::default();
    let mut events = Vec::new();
    let mut ids = IdFactory::new(&request.request_id);
    let mut seen = HashSet::new();

    let cargo_probe = match run_step(
        request,
        program,
        &["--version".to_owned()],
        &workspace_root,
        started,
        usage,
    ) {
        Ok(outcome) => outcome,
        Err(ProcessError::Spawn(error)) if error.kind() == io::ErrorKind::NotFound => {
            return finish(
                request,
                Vec::new(),
                ExecutionStatus::Unsupported,
                None,
                Duration::ZERO,
                Some("Cargo executable was not found".to_owned()),
            );
        }
        Err(error) => {
            return incomplete(
                request,
                Vec::new(),
                bounded_elapsed(started, request.limits.timeout_ms),
                error.to_string(),
            );
        }
    };
    usage.add(&cargo_probe);
    let cargo_version = match completed_probe(&cargo_probe, "cargo") {
        Ok(version) => version,
        Err(error) => {
            append_process_evidence(request, &cargo_probe, "text/plain", &mut ids, &mut events);
            return incomplete(
                request,
                bounded_events(request, events),
                bounded_elapsed(started, request.limits.timeout_ms),
                error,
            );
        }
    };

    let check_outcome = match run_step(
        request,
        program,
        &cargo_argv("check"),
        &workspace_root,
        started,
        usage,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            return incomplete(
                request,
                bounded_events(request, events),
                bounded_elapsed(started, request.limits.timeout_ms),
                error.to_string(),
            );
        }
    };
    usage.add(&check_outcome);
    let check_exit = match append_phase(
        request,
        &workspace_root,
        CARGO_CHECK_TOOL,
        &cargo_version,
        &check_outcome,
        &mut ids,
        &mut seen,
        &mut events,
    ) {
        Ok(result) if !result.success => {
            return complete_or_event_limit(request, events, result.exit_code, started);
        }
        Ok(result) => result.exit_code,
        Err(error) => {
            return incomplete(
                request,
                bounded_events(request, events),
                bounded_elapsed(started, request.limits.timeout_ms),
                error.to_string(),
            );
        }
    };
    debug_assert_eq!(check_exit, 0);

    let clippy_probe = match run_step(
        request,
        program,
        &["clippy".to_owned(), "--version".to_owned()],
        &workspace_root,
        started,
        usage,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            return incomplete(
                request,
                bounded_events(request, events),
                bounded_elapsed(started, request.limits.timeout_ms),
                error.to_string(),
            );
        }
    };
    usage.add(&clippy_probe);
    let clippy_version = match completed_probe(&clippy_probe, "clippy") {
        Ok(version) => version,
        Err(error) => {
            append_process_evidence(request, &clippy_probe, "text/plain", &mut ids, &mut events);
            return incomplete(
                request,
                bounded_events(request, events),
                bounded_elapsed(started, request.limits.timeout_ms),
                error,
            );
        }
    };

    let clippy_outcome = match run_step(
        request,
        program,
        &cargo_argv("clippy"),
        &workspace_root,
        started,
        usage,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            return incomplete(
                request,
                bounded_events(request, events),
                bounded_elapsed(started, request.limits.timeout_ms),
                error.to_string(),
            );
        }
    };
    let clippy = match append_phase(
        request,
        &workspace_root,
        CLIPPY_TOOL,
        &clippy_version,
        &clippy_outcome,
        &mut ids,
        &mut seen,
        &mut events,
    ) {
        Ok(result) => result,
        Err(error) => {
            return incomplete(
                request,
                bounded_events(request, events),
                bounded_elapsed(started, request.limits.timeout_ms),
                error.to_string(),
            );
        }
    };
    complete_or_event_limit(request, events, clippy.exit_code, started)
}

#[derive(Clone, Copy, Debug, Default)]
struct ProcessUsage {
    stdout: u64,
    stderr: u64,
}

impl ProcessUsage {
    fn add(&mut self, outcome: &ProcessOutcome) {
        self.stdout = self.stdout.saturating_add(outcome.stdout.observed_bytes);
        self.stderr = self.stderr.saturating_add(outcome.stderr.observed_bytes);
    }
}

#[derive(Clone, Copy, Debug)]
struct PhaseResult {
    success: bool,
    exit_code: u8,
}

fn run_step(
    request: &RequestEnvelope,
    program: &Path,
    argv: &[String],
    workspace: &Path,
    started: Instant,
    usage: ProcessUsage,
) -> Result<ProcessOutcome, ProcessError> {
    let limits = remaining_limits(request, started, usage).ok_or(ProcessError::BudgetExhausted)?;
    run_direct(program.as_os_str(), argv, workspace, limits)
}

fn remaining_limits(
    request: &RequestEnvelope,
    started: Instant,
    usage: ProcessUsage,
) -> Option<ProcessLimits> {
    let timeout =
        Duration::from_millis(request.limits.timeout_ms).checked_sub(started.elapsed())?;
    if timeout < Duration::from_millis(1) {
        return None;
    }
    Some(ProcessLimits {
        timeout,
        max_stdout_bytes: usize::try_from(
            request.limits.max_stdout_bytes.saturating_sub(usage.stdout),
        )
        .unwrap_or(usize::MAX),
        max_stderr_bytes: usize::try_from(
            request.limits.max_stderr_bytes.saturating_sub(usage.stderr),
        )
        .unwrap_or(usize::MAX),
    })
}

fn completed_probe(outcome: &ProcessOutcome, expected_name: &str) -> Result<String, String> {
    if outcome.state != ProcessState::Complete || outcome.exit_code != Some(0) {
        return Err(format!(
            "{expected_name} version probe did not complete successfully"
        ));
    }
    parse_version(&outcome.stdout.bytes, expected_name)
}

fn parse_version(bytes: &[u8], expected_name: &str) -> Result<String, String> {
    let output = std::str::from_utf8(bytes)
        .map_err(|error| format!("{expected_name} version is not UTF-8: {error}"))?;
    let mut fields = output.split_whitespace();
    let name = fields.next();
    let version = fields.next();
    if name != Some(expected_name)
        || version.is_none_or(str::is_empty)
        || version.is_some_and(|value| value.chars().count() > 64)
    {
        return Err(format!("{expected_name} version output is malformed"));
    }
    Ok(version.unwrap_or_default().to_owned())
}

fn cargo_argv(command: &str) -> Vec<String> {
    // Cargo owns package/target selection. Request targets constrain the
    // repository scope but are not converted into unsupported file arguments.
    [
        command,
        "--workspace",
        "--all-targets",
        "--locked",
        "--message-format=json",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[allow(clippy::too_many_arguments)]
fn append_phase(
    request: &RequestEnvelope,
    workspace_root: &Path,
    tool_name: &str,
    tool_version: &str,
    outcome: &ProcessOutcome,
    ids: &mut IdFactory,
    seen: &mut HashSet<String>,
    events: &mut Vec<ProtocolEnvelope>,
) -> Result<PhaseResult, ProviderError> {
    let stdout_evidence_id = append_process_evidence(
        request,
        outcome,
        "application/vnd.cargo.messages+json",
        ids,
        events,
    );
    let ProcessState::Complete = outcome.state else {
        return Err(ProviderError::Model(incomplete_message(outcome.state)));
    };
    let exit_code = outcome
        .exit_code
        .ok_or_else(|| ProviderError::Model("Cargo completed without an exit code".to_owned()))?;
    let report = parse_cargo_jsonl(&outcome.stdout.bytes)
        .map_err(|error| ProviderError::CargoJson(error.to_string()))?;
    validate_phase_result(&report, exit_code)?;
    append_observations(
        request,
        workspace_root,
        tool_name,
        tool_version,
        &report,
        stdout_evidence_id.as_ref(),
        ids,
        seen,
        events,
    )?;
    Ok(PhaseResult {
        success: report.success,
        exit_code,
    })
}

fn validate_phase_result(report: &CargoReport, exit_code: u8) -> Result<(), ProviderError> {
    if report.success != (exit_code == 0) {
        return Err(ProviderError::Model(
            "Cargo build-finished status disagrees with the process exit code".to_owned(),
        ));
    }
    if !report.success
        && !report
            .diagnostics
            .iter()
            .any(|diagnostic| matches!(diagnostic.level.as_str(), "error" | "ice"))
    {
        return Err(ProviderError::Model(
            "Cargo failed without a structured error diagnostic".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_observations(
    request: &RequestEnvelope,
    workspace_root: &Path,
    tool_name: &str,
    tool_version: &str,
    report: &CargoReport,
    diagnostic_evidence_id: Option<&ObjectId>,
    ids: &mut IdFactory,
    seen: &mut HashSet<String>,
    events: &mut Vec<ProtocolEnvelope>,
) -> Result<(), ProviderError> {
    for diagnostic in &report.diagnostics {
        let severity = severity(&diagnostic.level)?;
        let primary = diagnostic.spans.iter().find(|span| span.is_primary);
        if diagnostic.code.is_none()
            && primary.is_none()
            && !matches!(diagnostic.level.as_str(), "error" | "warning" | "ice")
        {
            continue;
        }
        let location = primary
            .map(|span| location(span, &request.workspace, workspace_root))
            .transpose()?;
        let message = diagnostic_message(diagnostic);
        let rule_id = diagnostic.code.as_ref().map(|code| code.code.clone());
        let key = observation_key(&severity, rule_id.as_deref(), &message, location.as_ref());
        if !seen.insert(key) {
            continue;
        }
        let observation = Observation {
            schema_version: ObservationSchemaVersion::V1,
            observation_id: ids.next(),
            tool: Tool {
                name: tool_name.to_owned(),
                version: tool_version.to_owned(),
                rule_id,
            },
            language: scalar("rust"),
            severity,
            origin: Origin::Normal,
            message,
            location,
            symbol: None,
            expected: None,
            observed: None,
            evidence_ids: diagnostic_evidence_id.into_iter().cloned().collect(),
        };
        push_observation(request, events, observation);
    }
    Ok(())
}

fn severity(level: &str) -> Result<Severity, ProviderError> {
    match level {
        "error" | "ice" => Ok(Severity::Error),
        "warning" => Ok(Severity::Warning),
        "note" | "help" | "failure-note" => Ok(Severity::Info),
        _ => Err(ProviderError::Model(format!(
            "unsupported rustc diagnostic level: {level}"
        ))),
    }
}

fn diagnostic_message(diagnostic: &RustcDiagnostic) -> String {
    let rendered = diagnostic
        .rendered
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let fallback;
    let value = if let Some(rendered) = rendered {
        rendered
    } else {
        fallback =
            diagnostic
                .children
                .iter()
                .fold(diagnostic.message.clone(), |mut text, child| {
                    text.push('\n');
                    text.push_str(&child.level);
                    text.push_str(": ");
                    text.push_str(&child.message);
                    text
                });
        fallback.trim()
    };
    truncate_chars(value, MAX_MESSAGE_CHARS)
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

fn location(
    span: &RustcSpan,
    workspace: &RepoPath,
    workspace_root: &Path,
) -> Result<Location, ProviderError> {
    validate_rustc_span(span)?;
    let location = Location {
        path: normalize_path(&span.file_name, workspace, workspace_root)?,
        // rustc JSON exposes one-based character offsets with an exclusive
        // span end, so its Unicode code-point coordinates match Location v1.
        start: Position {
            line: to_u32(span.line_start, "line_start")?,
            column: to_u32(span.column_start, "column_start")?,
        },
        end: Some(Position {
            line: to_u32(span.line_end, "line_end")?,
            column: to_u32(span.column_end, "column_end")?,
        }),
    };
    location
        .validate()
        .map_err(|error| ProviderError::Model(error.to_string()))?;
    Ok(location)
}

fn validate_rustc_span(span: &RustcSpan) -> Result<(), ProviderError> {
    if span.line_start == 0
        || span.line_end == 0
        || span.column_start == 0
        || span.column_end == 0
        || (span.line_end, span.column_end) < (span.line_start, span.column_start)
    {
        return Err(ProviderError::Model(
            "rustc span position must be positive and end must not precede start".to_owned(),
        ));
    }
    for (value, field) in [
        (span.line_start, "line_start"),
        (span.line_end, "line_end"),
        (span.column_start, "column_start"),
        (span.column_end, "column_end"),
    ] {
        to_u32(value, field)?;
    }
    Ok(())
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

fn observation_key(
    severity: &Severity,
    rule_id: Option<&str>,
    message: &str,
    location: Option<&Location>,
) -> String {
    let position = location.map_or_else(String::new, |location| {
        format!(
            "{}:{}:{}:{:?}",
            location.path, location.start.line, location.start.column, location.end
        )
    });
    format!(
        "{severity:?}\0{}\0{message}\0{position}",
        rule_id.unwrap_or_default()
    )
}

fn to_u32(value: u64, field: &str) -> Result<u32, ProviderError> {
    u32::try_from(value).map_err(|_| ProviderError::Model(format!("{field} exceeds u32")))
}

fn resolve_workspace(request: &RequestEnvelope) -> Result<(PathBuf, PathBuf), ProviderError> {
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
    Ok((repository, workspace))
}

fn validate_targets(
    request: &RequestEnvelope,
    repository_root: &Path,
    workspace_root: &Path,
) -> Result<(), ProviderError> {
    for target in &request.targets {
        if request.workspace.as_str() != "."
            && target.as_str() != request.workspace.as_str()
            && !target
                .as_str()
                .strip_prefix(request.workspace.as_str())
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return Err(ProviderError::Path(target.to_string()));
        }
        let candidate = repository_root.join(target.as_str());
        if candidate.exists() {
            let canonical = std::fs::canonicalize(candidate)?;
            if !canonical.starts_with(workspace_root) {
                return Err(ProviderError::Path(target.to_string()));
            }
        }
    }
    Ok(())
}

fn unsupported_request(request: &RequestEnvelope) -> Option<String> {
    if request.operation != Operation::Check {
        return Some("Rust Provider supports only CHECK".to_owned());
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

fn append_process_evidence(
    request: &RequestEnvelope,
    outcome: &ProcessOutcome,
    stdout_media_type: &str,
    ids: &mut IdFactory,
    events: &mut Vec<ProtocolEnvelope>,
) -> Option<ObjectId> {
    let stdout = captured_evidence(
        ids,
        EvidenceSource::Stdout,
        stdout_media_type,
        &outcome.stdout,
        request.limits.max_evidence_bytes,
    );
    let stdout_id = stdout.as_ref().map(|evidence| evidence.evidence_id.clone());
    if let Some(evidence) = stdout {
        push_evidence(request, events, evidence);
    }
    if let Some(evidence) = captured_evidence(
        ids,
        EvidenceSource::Stderr,
        "text/plain",
        &outcome.stderr,
        request.limits.max_evidence_bytes,
    ) {
        push_evidence(request, events, evidence);
    }
    stdout_id
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

fn complete_or_event_limit(
    request: &RequestEnvelope,
    events: Vec<ProtocolEnvelope>,
    exit_code: u8,
    started: Instant,
) -> ProviderResponse {
    let duration = bounded_elapsed(started, request.limits.timeout_ms);
    if u64::try_from(events.len()).unwrap_or(u64::MAX) > request.limits.max_events {
        return incomplete(
            request,
            bounded_events(request, events),
            duration,
            "normalized event count exceeds request limit".to_owned(),
        );
    }
    finish(
        request,
        events,
        ExecutionStatus::Complete,
        Some(exit_code),
        duration,
        None,
    )
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
        ExecutionStatus::Incomplete,
        None,
        duration,
        Some(message),
    )
}

fn finish(
    request: &RequestEnvelope,
    events: Vec<ProtocolEnvelope>,
    status: ExecutionStatus,
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
            message: message.map(|value| truncate_chars(&value, MAX_MESSAGE_CHARS)),
        },
        events,
    }
}

fn terminal_for_id(
    request_id: ObjectId,
    status: ExecutionStatus,
    message: &str,
) -> ProviderResponse {
    let message = truncate_chars(message, MAX_MESSAGE_CHARS);
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
        ProcessState::Complete => "Cargo completed".to_owned(),
        ProcessState::Incomplete(IncompleteReason::Timeout) => "Cargo timed out".to_owned(),
        ProcessState::Incomplete(IncompleteReason::StdoutOverflow) => {
            "Cargo stdout exceeded the request limit".to_owned()
        }
        ProcessState::Incomplete(IncompleteReason::StderrOverflow) => {
            "Cargo stderr exceeded the request limit".to_owned()
        }
        ProcessState::Incomplete(IncompleteReason::TerminatedWithoutCode) => {
            "Cargo terminated without an exit code".to_owned()
        }
        ProcessState::Incomplete(IncompleteReason::UnrepresentableExitCode) => {
            "Cargo exit code is outside the protocol range".to_owned()
        }
    }
}

fn bounded_elapsed(started: Instant, timeout_ms: u64) -> Duration {
    started.elapsed().min(Duration::from_millis(timeout_ms))
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
    value.parse().expect("Provider constants must be valid")
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
        CHECK_CAPABILITY, MAX_MESSAGE_CHARS, ProviderError, cargo_argv, decode_request,
        diagnostic_message, execute_with_program, location, manifest, normalize_path, read_request,
        run_stdio_with, severity, terminal_for_id, validate_response,
    };
    use crate::cargo_json::{RustcChild, RustcDiagnostic, RustcSpan};
    use diagnostic_triage_contracts::{
        Sha256Digest,
        model::{
            ExecutionStatus, Location, Observation, ObservationSchemaVersion, Origin, Position,
            Severity, Tool,
        },
        protocol::{
            EnvelopeKind, ObservationEnvelope, ProtocolEnvelope, ProtocolVersion, RequestEnvelope,
        },
    };
    use std::{
        fs,
        io::Cursor,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(unix)]
    struct FakeCargo {
        root: PathBuf,
        program: PathBuf,
    }

    #[cfg(unix)]
    impl FakeCargo {
        fn new(check: &str, check_exit: u8, clippy: &str, clippy_exit: u8) -> Self {
            use std::os::unix::fs::PermissionsExt;

            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "diagnostic-triage-rust-provider-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let program = root.join("cargo");
            let body = format!(
                concat!(
                    "#!/bin/sh\n",
                    "if [ \"$1\" = \"--version\" ]; then printf 'cargo 1.93.1 (fixture)\\n'; exit 0; fi\n",
                    "if [ \"$1\" = \"check\" ]; then printf '%s' '{check}'; exit {check_exit}; fi\n",
                    "if [ \"$1\" = \"clippy\" ] && [ \"$2\" = \"--version\" ]; then printf 'clippy 0.1.93 (fixture)\\n'; exit 0; fi\n",
                    "if [ \"$1\" = \"clippy\" ]; then printf '%s' '{clippy}'; exit {clippy_exit}; fi\n",
                    "exit 91\n"
                ),
                check = check,
                check_exit = check_exit,
                clippy = clippy,
                clippy_exit = clippy_exit,
            );
            fs::write(&program, body).unwrap();
            fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
            Self { root, program }
        }

        fn from_body(body: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;

            static NEXT: AtomicU64 = AtomicU64::new(10_000);
            let root = std::env::temp_dir().join(format!(
                "diagnostic-triage-rust-provider-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let program = root.join("cargo");
            fs::write(&program, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
            Self { root, program }
        }
    }

    #[cfg(unix)]
    impl Drop for FakeCargo {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }

    fn request() -> RequestEnvelope {
        match serde_json::from_slice::<ProtocolEnvelope>(include_bytes!(
            "../tests/golden/request.jsonl"
        ))
        .expect("request fixture is valid")
        {
            ProtocolEnvelope::Request(request) => request,
            _ => panic!("fixture must contain a request"),
        }
    }

    #[test]
    fn manifest_is_a_rust_check_provider() {
        let value = manifest();
        assert_eq!(value.adapter.id.as_str(), "rust");
        assert_eq!(value.adapter.languages[0].as_str(), "rust");
        assert_eq!(value.adapter.capabilities[0].as_str(), CHECK_CAPABILITY);
    }

    #[test]
    fn direct_argv_is_locked_workspace_wide_and_structured() {
        assert_eq!(
            cargo_argv("check"),
            [
                "check",
                "--workspace",
                "--all-targets",
                "--locked",
                "--message-format=json"
            ]
        );
    }

    #[test]
    fn request_parser_rejects_kind_mismatch_and_multiple_lines() {
        let manifest_line = serde_json::to_vec(&ProtocolEnvelope::Manifest(manifest()))
            .expect("manifest serializes");
        assert!(matches!(
            read_request(Cursor::new(manifest_line)),
            Err(ProviderError::Request(_))
        ));
        assert!(decode_request(b"{}\n{}\n").is_err());
    }

    #[test]
    fn run_stdio_turns_invalid_observation_into_terminal_completion() {
        let request = request();
        let mut response = terminal_for_id(
            request.request_id.clone(),
            ExecutionStatus::Complete,
            "test response",
        );
        response
            .events
            .push(ProtocolEnvelope::Observation(ObservationEnvelope {
                protocol_version: ProtocolVersion::V1,
                kind: EnvelopeKind::Observation,
                request_id: request.request_id.clone(),
                sequence: 0,
                observation: Observation {
                    schema_version: ObservationSchemaVersion::V1,
                    observation_id: request.request_id.clone(),
                    tool: Tool {
                        name: "rustc".to_owned(),
                        version: "1.85.1".to_owned(),
                        rule_id: None,
                    },
                    language: "rust".parse().unwrap(),
                    severity: Severity::Error,
                    origin: Origin::Normal,
                    message: "invalid location".to_owned(),
                    location: Some(Location {
                        path: "src/lib.rs".parse().unwrap(),
                        start: Position { line: 0, column: 1 },
                        end: None,
                    }),
                    symbol: None,
                    expected: None,
                    observed: None,
                    evidence_ids: Vec::new(),
                },
            }));
        let mut input =
            serde_json::to_vec(&ProtocolEnvelope::Request(request)).expect("request serializes");
        input.push(b'\n');
        let mut output = Vec::new();

        run_stdio_with(Cursor::new(input), &mut output, |_| response.clone())
            .expect("invalid response is converted to a terminal completion");

        let events = String::from_utf8(output)
            .expect("protocol output is UTF-8")
            .lines()
            .map(|line| serde_json::from_str::<ProtocolEnvelope>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            events.as_slice(),
            [ProtocolEnvelope::Manifest(_), ProtocolEnvelope::Completion(value)]
                if value.status == ExecutionStatus::Incomplete
                    && value.tool_exit_code.0.is_none()
                    && value.message.as_deref().is_some_and(|message| message.len() <= MAX_MESSAGE_CHARS)
        ));
    }

    #[test]
    fn unsupported_required_capability_finishes_without_running_cargo() {
        let mut request = request();
        request.required_capabilities = vec!["rust.future/v1".parse().unwrap()];
        let response = execute_with_program(&request, Path::new("missing-cargo-must-not-run"));
        assert_eq!(response.completion.status, ExecutionStatus::Unsupported);
        assert_eq!(response.completion.tool_exit_code.0, None);
        assert!(response.events.is_empty());
    }

    #[test]
    fn rendered_message_preserves_children_and_has_a_bounded_fallback() {
        let diagnostic = RustcDiagnostic {
            message: "primary".to_owned(),
            code: None,
            level: "warning".to_owned(),
            spans: Vec::new(),
            children: vec![RustcChild {
                message: "child".to_owned(),
                level: "help".to_owned(),
            }],
            rendered: None,
        };
        assert_eq!(diagnostic_message(&diagnostic), "primary\nhelp: child");
        assert_eq!(severity("ice").unwrap(), Severity::Error);
    }

    #[test]
    fn subworkspace_diagnostic_paths_remain_repository_relative() {
        let workspace = "crates/member".parse().unwrap();
        let path = normalize_path("src/lib.rs", &workspace, Path::new("crates/member")).unwrap();
        assert_eq!(path.as_str(), "crates/member/src/lib.rs");
    }

    #[test]
    fn rustc_locations_preserve_insertions_and_half_open_code_point_ranges() {
        let workspace = ".".parse().unwrap();
        let spans = [
            RustcSpan {
                file_name: "src/unicode.rs".to_owned(),
                line_start: 1,
                line_end: 1,
                column_start: 2,
                column_end: 2,
                is_primary: true,
            },
            RustcSpan {
                file_name: "src/unicode.rs".to_owned(),
                line_start: 2,
                line_end: 2,
                column_start: 2,
                column_end: 4,
                is_primary: true,
            },
            RustcSpan {
                file_name: "src/unicode.rs".to_owned(),
                line_start: 3,
                line_end: 4,
                column_start: 1,
                column_end: 1,
                is_primary: true,
            },
        ];
        let locations = spans
            .iter()
            .map(|span| location(span, &workspace, Path::new(".")))
            .collect::<Result<Vec<_>, _>>()
            .expect("rustc coordinates match Location v1");

        assert_eq!(locations[0].start, locations[0].end.clone().unwrap());
        assert_eq!(locations[1].end.as_ref().unwrap().column, 4);
        assert_eq!(locations[2].end.as_ref().unwrap().line, 4);
        assert_eq!(locations[2].end.as_ref().unwrap().column, 1);
    }

    #[test]
    fn rustc_location_boundary_rejects_non_positive_and_reversed_spans() {
        let workspace = ".".parse().unwrap();
        for (line_start, line_end, column_start, column_end) in
            [(0, 1, 1, 1), (1, 1, 0, 1), (2, 1, 1, 1), (1, 1, 3, 2)]
        {
            let span = RustcSpan {
                file_name: "src/lib.rs".to_owned(),
                line_start,
                line_end,
                column_start,
                column_end,
                is_primary: true,
            };
            assert!(location(&span, &workspace, Path::new(".")).is_err());
        }
    }

    #[test]
    fn rustc_non_bmp_fixture_proves_scalar_not_utf16_or_utf8_columns() {
        let provenance: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../tests/golden/rustc-unicode.provenance.json"
        ))
        .expect("rustc fixture provenance is JSON");
        assert_eq!(provenance["tool"], "rustc");
        assert_eq!(
            provenance["tool_version"],
            "rustc 1.85.1 (4eb161250 2025-03-15)"
        );
        assert_eq!(
            provenance["commit_hash"],
            "4eb161250e340c8f48f66e2b929ef4a5bed7c181"
        );
        assert_eq!(
            provenance["coordinate_probe"]["unicode_scalar_start_column"],
            26
        );
        assert_eq!(provenance["coordinate_probe"]["utf16_start_column"], 27);
        assert_eq!(provenance["coordinate_probe"]["utf8_byte_start_column"], 29);
        assert_eq!(
            provenance["source_sha256"],
            Sha256Digest::compute(include_bytes!("../tests/golden/rustc-unicode.rs")).as_str()
        );
        assert_eq!(
            provenance["output_sha256"],
            Sha256Digest::compute(include_bytes!("../tests/golden/rustc-unicode.jsonl")).as_str()
        );

        let first_line = std::str::from_utf8(include_bytes!("../tests/golden/rustc-unicode.jsonl"))
            .expect("rustc fixture is UTF-8")
            .lines()
            .next()
            .expect("rustc fixture has a diagnostic");
        let diagnostic = serde_json::from_str::<RustcDiagnostic>(first_line)
            .expect("pinned rustc JSON fixture parses");
        let span = diagnostic.spans[0].clone();
        let location = location(&span, &".".parse().unwrap(), Path::new("."))
            .expect("rustc fixture span normalizes");
        assert_eq!(location.start.column, 26);
        assert_eq!(location.end.as_ref().expect("rustc span end").column, 33);
    }

    #[cfg(unix)]
    #[test]
    fn successful_check_then_clippy_deduplicates_rustc_diagnostics() {
        let fake = FakeCargo::new(
            include_str!("../tests/golden/cargo-check-warning.jsonl"),
            0,
            include_str!("../tests/golden/clippy-findings.jsonl"),
            0,
        );
        let request = request();
        let response = execute_with_program(&request, &fake.program);

        assert_eq!(response.completion.status, ExecutionStatus::Complete);
        assert_eq!(response.completion.tool_exit_code.0, Some(0));
        assert_eq!(response.completion.counts.observations, 2);
        assert_eq!(response.completion.counts.evidence, 2);
        let tools = response
            .events
            .iter()
            .filter_map(|event| match event {
                ProtocolEnvelope::Observation(value) => Some((
                    value.observation.tool.name.as_str(),
                    value.observation.tool.rule_id.as_deref(),
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            tools,
            [
                ("cargo-check", Some("unused_variables")),
                ("clippy", Some("clippy::useless_vec"))
            ]
        );
        validate_response(&request, &response).expect("complete session satisfies protocol v1");
    }

    #[cfg(unix)]
    #[test]
    fn compiler_failure_is_complete_and_skips_clippy() {
        let fake = FakeCargo::new(
            include_str!("../tests/golden/cargo-check-error.jsonl"),
            101,
            "this branch must not run\n",
            91,
        );
        let request = request();
        let response = execute_with_program(&request, &fake.program);

        assert_eq!(response.completion.status, ExecutionStatus::Complete);
        assert_eq!(response.completion.tool_exit_code.0, Some(101));
        assert_eq!(response.completion.counts.observations, 1);
        assert!(response.events.iter().any(|event| matches!(
            event,
            ProtocolEnvelope::Observation(value)
                if value.observation.tool.rule_id.as_deref() == Some("E0308")
                    && value.observation.message.contains("expected String")
        )));
        validate_response(&request, &response).expect("diagnostic failure is a complete run");
    }

    #[cfg(unix)]
    #[test]
    fn malformed_partial_and_path_escape_are_incomplete_with_evidence() {
        for output in [
            include_str!("../tests/golden/cargo-malformed.jsonl"),
            include_str!("../tests/golden/cargo-partial.jsonl").trim_end(),
            include_str!("../tests/golden/cargo-path-escape.jsonl"),
        ] {
            let fake = FakeCargo::new(output, 101, "", 0);
            let request = request();
            let response = execute_with_program(&request, &fake.program);
            assert_eq!(response.completion.status, ExecutionStatus::Incomplete);
            assert_eq!(response.completion.tool_exit_code.0, None);
            assert!(response.completion.counts.evidence >= 1);
            validate_response(&request, &response)
                .expect("incomplete session still satisfies protocol v1");
        }
    }

    #[cfg(unix)]
    #[test]
    fn timeout_and_aggregate_output_overflow_are_incomplete() {
        let sleepy = FakeCargo::from_body("sleep 1");
        let mut timeout_request = request();
        timeout_request.limits.timeout_ms = 30;
        let response = execute_with_program(&timeout_request, &sleepy.program);
        assert_eq!(response.completion.status, ExecutionStatus::Incomplete);

        let verbose = FakeCargo::from_body("printf 'cargo 1.93.1 (fixture)\\n'");
        let mut output_request = request();
        output_request.limits.max_stdout_bytes = 4;
        let response = execute_with_program(&output_request, &verbose.program);
        assert_eq!(response.completion.status, ExecutionStatus::Incomplete);
        assert!(response.completion.counts.evidence >= 1);
    }
}
