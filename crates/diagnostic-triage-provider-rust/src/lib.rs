//! Cargo- and Clippy-backed Rust Provider for Diagnostic Triage.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

mod cargo_json;
mod process;

use std::{
    collections::HashSet,
    ffi::OsString,
    fmt::Write as _,
    io::{self, BufRead, BufReader, Read, Write},
    path::{Component, Path, PathBuf},
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
    #[error("invalid Rust diagnostic path")]
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
    let scope = match select_cargo_scope(request, &repository_root, &workspace_root) {
        Ok(scope) => scope,
        Err(error) => return incomplete(request, Vec::new(), Duration::ZERO, error.to_string()),
    };
    let verification_target = if request.operation == Operation::Verify {
        match VerificationTargetDir::new(&repository_root, &request.request_id) {
            Ok(target) => target,
            Err(error) => {
                return incomplete(request, Vec::new(), Duration::ZERO, error.to_string());
            }
        }
    } else {
        VerificationTargetDir::disabled()
    };
    let response = execute_in_workspace(
        request,
        program,
        &repository_root,
        &workspace_root,
        &scope,
        verification_target.path(),
    );
    finalize_verification_target(verification_target, request, response)
}

#[allow(clippy::too_many_lines)]
fn execute_in_workspace(
    request: &RequestEnvelope,
    program: &Path,
    repository_root: &Path,
    workspace_root: &Path,
    scope: &CargoScope,
    target_dir: Option<&Path>,
) -> ProviderResponse {
    let diagnostic_scope = DiagnosticScope {
        cargo: scope,
        repository_root,
        workspace_root,
        verification_target: target_dir,
    };

    let started = Instant::now();
    let mut usage = ProcessUsage::default();
    let mut events = Vec::new();
    let mut ids = IdFactory::new(&request.request_id);
    let mut seen = HashSet::new();

    let cargo_probe = match run_step(
        request,
        program,
        &["--version".to_owned()],
        workspace_root,
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
            append_process_evidence(
                request,
                &cargo_probe,
                "text/plain",
                target_dir,
                &mut ids,
                &mut events,
            );
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
        &cargo_argv("check", scope, target_dir),
        workspace_root,
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
        &diagnostic_scope,
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
        workspace_root,
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
            append_process_evidence(
                request,
                &clippy_probe,
                "text/plain",
                target_dir,
                &mut ids,
                &mut events,
            );
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
        &cargo_argv("clippy", scope, target_dir),
        workspace_root,
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
        &diagnostic_scope,
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
        || version.is_none_or(|value| {
            value.is_empty()
                || value.chars().count() > 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
        })
    {
        return Err(format!("{expected_name} version output is malformed"));
    }
    Ok(version.unwrap_or_default().to_owned())
}

#[derive(Debug)]
struct VerificationTargetDir {
    path: Option<PathBuf>,
}

impl VerificationTargetDir {
    const fn disabled() -> Self {
        Self { path: None }
    }

    fn new(repository_root: &Path, request_id: &ObjectId) -> io::Result<Self> {
        let root = std::fs::canonicalize(std::env::temp_dir())?;
        if root.starts_with(repository_root) {
            return Err(io::Error::other("temporary directory is inside repository"));
        }
        for attempt in 0..64 {
            let path = root.join(format!(
                "diagnostic-triage-cargo-{}-{request_id}-{attempt}",
                std::process::id()
            ));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self { path: Some(path) }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::ErrorKind::AlreadyExists.into())
    }

    fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    fn close(mut self) -> io::Result<()> {
        let Some(path) = self.path.take() else {
            return Ok(());
        };
        match std::fs::remove_dir_all(&path) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.path = Some(path);
                Err(error)
            }
        }
    }
}

fn finalize_verification_target(
    target: VerificationTargetDir,
    request: &RequestEnvelope,
    response: ProviderResponse,
) -> ProviderResponse {
    match target.close() {
        Ok(()) => response,
        Err(error) => incomplete(
            request,
            Vec::new(),
            std::time::Duration::ZERO,
            format!("cleanup Cargo verification target: {error}"),
        ),
    }
}

impl Drop for VerificationTargetDir {
    fn drop(&mut self) {
        if let Some(Err(error)) = self.path.take().map(std::fs::remove_dir_all) {
            eprintln!("Cargo verification target cleanup retry failed: {error}");
        }
    }
}

// Cargo scope state is selected before execution so observations stay within the requested
// workspace or manifest; invalid or unsupported scope terminates as INCOMPLETE | UNSUPPORTED.
#[derive(Clone, Debug, Eq, PartialEq)]
enum CargoScope {
    Workspace,
    Manifest {
        manifest: PathBuf,
        repository_path: RepoPath,
    },
}

struct DiagnosticScope<'a> {
    cargo: &'a CargoScope,
    repository_root: &'a Path,
    workspace_root: &'a Path,
    verification_target: Option<&'a Path>,
}

fn cargo_argv(command: &str, scope: &CargoScope, target_dir: Option<&Path>) -> Vec<String> {
    let mut argv = vec![command.to_owned()];
    if let Some(target_dir) = target_dir {
        argv.extend(["--target-dir".to_owned(), target_dir.display().to_string()]);
    }
    match scope {
        CargoScope::Workspace => argv.push("--workspace".to_owned()),
        CargoScope::Manifest { manifest, .. } => {
            argv.extend(["--manifest-path".to_owned(), manifest.display().to_string()]);
        }
    }
    argv.extend([
        "--all-targets".to_owned(),
        "--locked".to_owned(),
        "--message-format=json".to_owned(),
    ]);
    argv
}

#[allow(clippy::too_many_arguments)]
fn append_phase(
    request: &RequestEnvelope,
    scope: &DiagnosticScope<'_>,
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
        scope.verification_target,
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
        scope,
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
    scope: &DiagnosticScope<'_>,
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
        let unredacted_message = diagnostic_message(diagnostic);
        let generated = diagnostic_is_generated(diagnostic, scope);
        let location = if generated {
            None
        } else {
            primary
                .map(|span| scoped_location(span, scope))
                .transpose()?
                .flatten()
        };
        if primary.is_some() && location.is_none() && !generated {
            continue;
        }
        let identity = diagnostic_identity(diagnostic, scope);
        let message = if generated {
            identity.clone()
        } else {
            redact_verification_target(&unredacted_message, scope)
        };
        let rule_id = diagnostic
            .code
            .as_ref()
            .map(|code| redact_verification_target(&code.code, scope));
        let key = observation_key(&severity, rule_id.as_deref(), &identity, location.as_ref());
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
        _ => Err(ProviderError::Model(
            "unsupported rustc diagnostic level".to_owned(),
        )),
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

fn location(span: &RustcSpan, scope: &DiagnosticScope<'_>) -> Result<Location, ProviderError> {
    validate_rustc_span(span)?;
    let location = Location {
        path: normalize_path(&span.file_name, scope)?,
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

fn scoped_location(
    span: &RustcSpan,
    scope: &DiagnosticScope<'_>,
) -> Result<Option<Location>, ProviderError> {
    match location(span, scope) {
        Ok(location) => Ok(Some(location)),
        Err(error)
            if matches!(error, ProviderError::Path(_))
                && is_existing_repository_sibling(&span.file_name, scope)? =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn verification_target_path(raw: &str, scope: &DiagnosticScope<'_>) -> bool {
    let Some(root) = scope.verification_target else {
        return false;
    };
    let path = Path::new(raw);
    !raw.contains(['\\', '\0'])
        && path.is_absolute()
        && path.starts_with(root)
        && !path.components().any(|part| part == Component::ParentDir)
}

fn diagnostic_is_generated(diagnostic: &RustcDiagnostic, scope: &DiagnosticScope<'_>) -> bool {
    diagnostic
        .spans
        .iter()
        .any(|span| verification_target_path(&span.file_name, scope))
        || std::iter::once(diagnostic.message.as_str())
            .chain(diagnostic.rendered.as_deref())
            .chain(
                diagnostic
                    .children
                    .iter()
                    .map(|child| child.message.as_str()),
            )
            .any(|text| verification_target_mentioned(text, scope))
}

fn verification_target_mentioned(text: &str, scope: &DiagnosticScope<'_>) -> bool {
    scope.verification_target.is_some_and(|root| {
        let root = root.to_string_lossy();
        !root.is_empty()
            && text.match_indices(root.as_ref()).any(|(start, _)| {
                let before = text[..start].chars().next_back();
                let after = text[start + root.len()..].chars().next();
                before.is_none_or(path_text_boundary)
                    && after.is_none_or(|value| {
                        matches!(value, '/' | '\\') || path_text_boundary(value)
                    })
            })
    })
}

fn path_text_boundary(value: char) -> bool {
    value.is_whitespace() || !value.is_alphanumeric() && !matches!(value, '_' | '-' | '.')
}

fn redact_verification_target(message: &str, scope: &DiagnosticScope<'_>) -> String {
    scope.verification_target.map_or_else(
        || message.to_owned(),
        |root| message.replace(root.to_string_lossy().as_ref(), "<verification-target>"),
    )
}

fn diagnostic_identity(diagnostic: &RustcDiagnostic, scope: &DiagnosticScope<'_>) -> String {
    let root = scope
        .verification_target
        .map(|path| path.to_string_lossy())
        .unwrap_or_default();
    let escaped_root = format!("{root:?}");
    let root = &escaped_root[1..escaped_root.len().saturating_sub(1)];
    let identity =
        format!("{diagnostic:?}")
            .split(root)
            .fold(String::new(), |mut identity, segment| {
                write!(&mut identity, "{}:{segment}", segment.len())
                    .expect("writing to String cannot fail");
                identity
            });
    format!(
        "generated Rust diagnostic {}",
        Sha256Digest::compute(identity.as_bytes()).as_str()
    )
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

fn normalize_path(raw: &str, scope: &DiagnosticScope<'_>) -> Result<RepoPath, ProviderError> {
    if raw.contains(['\\', '\0']) || raw.contains("://") {
        return Err(ProviderError::Path(raw.to_owned()));
    }
    let scope_root = canonical_scope_root(scope.cargo, scope.repository_root)?;
    let raw_path = Utf8Path::new(raw);
    if raw_path.is_absolute() {
        let canonical =
            std::fs::canonicalize(raw_path).map_err(|_| ProviderError::Path(raw.to_owned()))?;
        let stripped = canonical
            .strip_prefix(scope.repository_root)
            .map_err(|_| ProviderError::Path(raw.to_owned()))?;
        if !canonical.starts_with(&scope_root) {
            return Err(ProviderError::Path(raw.to_owned()));
        }
        return RepoPath::from_str(
            Utf8PathBuf::from_path_buf(stripped.to_path_buf())
                .map_err(|_| ProviderError::Path(raw.to_owned()))?
                .as_str(),
        )
        .map_err(|_| ProviderError::Path(raw.to_owned()));
    }

    let mut normalized = raw;
    while let Some(stripped) = normalized.strip_prefix("./") {
        normalized = stripped;
    }
    let relative = Utf8PathBuf::from(normalized);
    RepoPath::from_str(relative.as_str()).map_err(|_| ProviderError::Path(raw.to_owned()))?;

    let repository_path = if path_is_in_scope(&relative, scope.cargo) {
        relative
    } else {
        let workspace_prefix = scope
            .workspace_root
            .strip_prefix(scope.repository_root)
            .map_err(|_| ProviderError::Path(raw.to_owned()))?;
        let workspace_prefix = Utf8PathBuf::from_path_buf(workspace_prefix.to_path_buf())
            .map_err(|_| ProviderError::Path(raw.to_owned()))?;
        let from_workspace = workspace_prefix.join(&relative);
        let workspace_candidate = scope.workspace_root.join(relative.as_str());
        if !path_is_in_scope(&from_workspace, scope.cargo) || !workspace_candidate.exists() {
            return Err(ProviderError::Path(raw.to_owned()));
        }
        from_workspace
    };
    let candidate = scope.repository_root.join(repository_path.as_str());
    if candidate.exists() {
        let canonical =
            std::fs::canonicalize(candidate).map_err(|_| ProviderError::Path(raw.to_owned()))?;
        if !canonical.starts_with(scope_root) {
            return Err(ProviderError::Path(raw.to_owned()));
        }
    }
    RepoPath::from_str(repository_path.as_str()).map_err(|_| ProviderError::Path(raw.to_owned()))
}

fn path_is_in_scope(path: &Utf8Path, scope: &CargoScope) -> bool {
    match scope {
        CargoScope::Workspace => true,
        CargoScope::Manifest {
            repository_path, ..
        } => path.starts_with(Utf8Path::new(repository_path.as_str())),
    }
}

fn canonical_scope_root(
    scope: &CargoScope,
    repository_root: &Path,
) -> Result<PathBuf, ProviderError> {
    let path = match scope {
        CargoScope::Workspace => repository_root.to_path_buf(),
        CargoScope::Manifest {
            repository_path, ..
        } => repository_root.join(repository_path.as_str()),
    };
    std::fs::canonicalize(path).map_err(ProviderError::Io)
}

fn is_existing_repository_sibling(
    raw: &str,
    scope: &DiagnosticScope<'_>,
) -> Result<bool, ProviderError> {
    if raw.contains(['\\', '\0']) || raw.contains("://") {
        return Ok(false);
    }
    let raw_path = Utf8Path::new(raw);
    let candidate = if raw_path.is_absolute() {
        raw_path.as_std_path().to_path_buf()
    } else {
        let normalized = raw.trim_start_matches("./");
        if RepoPath::from_str(normalized).is_err() {
            return Ok(false);
        }
        scope.repository_root.join(normalized)
    };
    if !candidate.exists() {
        return Ok(false);
    }
    let canonical = std::fs::canonicalize(candidate)?;
    Ok(canonical.starts_with(scope.repository_root)
        && !canonical.starts_with(canonical_scope_root(scope.cargo, scope.repository_root)?))
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

fn select_cargo_scope(
    request: &RequestEnvelope,
    repository_root: &Path,
    workspace_root: &Path,
) -> Result<CargoScope, ProviderError> {
    let [target] = request.targets.as_slice() else {
        return Err(ProviderError::Request(
            "Rust Provider requires exactly one target scope".to_owned(),
        ));
    };
    if target.as_str() == "." {
        return (request.workspace.as_str() == ".")
            .then_some(CargoScope::Workspace)
            .ok_or_else(|| ProviderError::Path(target.to_string()));
    }
    if request.workspace.as_str() != "."
        && !Utf8Path::new(target.as_str()).starts_with(Utf8Path::new(request.workspace.as_str()))
    {
        return Err(ProviderError::Path(target.to_string()));
    }
    let candidate = repository_root.join(target.as_str());
    let canonical =
        std::fs::canonicalize(&candidate).map_err(|_| ProviderError::Path(target.to_string()))?;
    if !canonical.is_dir() || !canonical.starts_with(workspace_root) {
        return Err(ProviderError::Path(target.to_string()));
    }
    let manifest = canonical.join("Cargo.toml");
    if !manifest.is_file()
        || !std::fs::canonicalize(&manifest)
            .map(|path| path.starts_with(&canonical))
            .unwrap_or(false)
    {
        return Err(ProviderError::Request(format!(
            "target {target} is not a unique Cargo package directory"
        )));
    }
    let relative_manifest = manifest
        .strip_prefix(workspace_root)
        .map_err(|_| ProviderError::Path(target.to_string()))?
        .to_path_buf();
    let repository_path = canonical
        .strip_prefix(repository_root)
        .map_err(|_| ProviderError::Path(target.to_string()))?;
    let repository_path = Utf8PathBuf::from_path_buf(repository_path.to_path_buf())
        .map_err(|_| ProviderError::Path(target.to_string()))?
        .as_str()
        .parse()
        .map_err(|_| ProviderError::Path(target.to_string()))?;
    Ok(CargoScope::Manifest {
        manifest: relative_manifest,
        repository_path,
    })
}

fn unsupported_request(request: &RequestEnvelope) -> Option<String> {
    if !matches!(request.operation, Operation::Check | Operation::Verify) {
        return Some("Rust Provider supports only CHECK and VERIFY".to_owned());
    }
    if !capability_requested(request, CHECK_CAPABILITY) {
        return Some("diagnostic operation requires diagnostic.check/v1".to_owned());
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
    verification_target: Option<&Path>,
    ids: &mut IdFactory,
    events: &mut Vec<ProtocolEnvelope>,
) -> Option<ObjectId> {
    if verification_target.is_some() {
        return None;
    }
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
        CHECK_CAPABILITY, CargoScope, DiagnosticScope, MAX_MESSAGE_CHARS, ProviderError,
        cargo_argv, decode_request, diagnostic_message, execute_with_program, location, manifest,
        normalize_path, read_request, run_stdio_with, scoped_location, select_cargo_scope,
        severity, terminal_for_id, validate_response,
    };
    use crate::cargo_json::{RustcChild, RustcDiagnostic, RustcSpan};
    use diagnostic_triage_contracts::{
        Sha256Digest,
        model::{
            ExecutionStatus, Location, Observation, ObservationSchemaVersion, Origin, Position,
            Severity, Tool,
        },
        protocol::{
            EnvelopeKind, ObservationEnvelope, Operation, ProtocolEnvelope, ProtocolVersion,
            RequestEnvelope,
        },
    };
    use std::{
        fs,
        io::Cursor,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::Instant,
    };

    const MEMBER_SCOPE: &str = "crates/diagnostic-triage-provider-rust";

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

    fn scoped_request(workspace: &str, targets: &[&str]) -> RequestEnvelope {
        let mut request = request();
        request.workspace = workspace.parse().unwrap();
        request.targets = targets
            .iter()
            .map(|target| target.parse().unwrap())
            .collect();
        request
    }

    fn repository_root() -> PathBuf {
        std::fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap()
    }

    fn root_location(span: &RustcSpan) -> Result<Location, ProviderError> {
        location(
            span,
            &DiagnosticScope {
                cargo: &CargoScope::Workspace,
                repository_root: Path::new("."),
                workspace_root: Path::new("."),
                verification_target: None,
            },
        )
    }

    #[test]
    fn manifest_is_a_rust_check_provider() {
        let value = manifest();
        assert_eq!(value.adapter.id.as_str(), "rust");
        assert_eq!(value.adapter.languages[0].as_str(), "rust");
        assert_eq!(value.adapter.capabilities[0].as_str(), CHECK_CAPABILITY);
    }

    #[test]
    fn llm_contract_markers_use_the_canonical_lifecycle() {
        let marker = ["// LLM", " contract:"].concat();
        let expected_suffix = "DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.";
        let suffixes = include_str!("lib.rs")
            .lines()
            .filter_map(|line| line.split_once(&marker).map(|(_, suffix)| suffix.trim()))
            .collect::<Vec<_>>();

        assert!(!suffixes.is_empty(), "lifecycle marker must remain present");
        for suffix in suffixes {
            assert_eq!(suffix, expected_suffix, "noncanonical lifecycle marker");
        }
    }

    #[test]
    fn root_target_selects_workspace_and_check_clippy_share_scope_argv() {
        let root = repository_root();
        let scope = select_cargo_scope(&request(), &root, &root).unwrap();
        assert_eq!(scope, CargoScope::Workspace);
        let check = cargo_argv("check", &scope, None);
        let clippy = cargo_argv("clippy", &scope, None);
        assert_eq!(
            check,
            [
                "check",
                "--workspace",
                "--all-targets",
                "--locked",
                "--message-format=json"
            ]
        );
        assert_eq!(&check[1..], &clippy[1..]);
    }

    #[cfg(unix)]
    #[test]
    fn verify_uses_and_removes_an_external_cargo_target() {
        let fake = FakeCargo::from_body(
            r#"
if [ "$1" = "--version" ]; then printf 'cargo 1.93.1 (fixture)\n'; exit 0; fi
if [ "$1" = "clippy" ] && [ "$2" = "--version" ]; then printf 'clippy 0.1.93 (fixture)\n'; exit 0; fi
if [ "$1" = "check" ] || [ "$1" = "clippy" ]; then
  if [ "$2" != "--target-dir" ]; then exit 92; fi
  printf '%s\n' "$3" > "$0.target"
  mkdir -p "$3/out" && printf source > "$3/out/generated.rs"
  printf '{"reason":"compiler-message","message":{"message":"generated failure at %s","code":{"code":"%s","explanation":null},"level":"error","spans":[{"file_name":"src/lib.rs","line_start":1,"line_end":1,"column_start":1,"column_end":2,"is_primary":true},{"file_name":"%s","line_start":1,"line_end":1,"column_start":1,"column_end":2,"is_primary":true}],"children":[{"message":"consider writing the generated file at %s/out/generated.rs","level":"help"}],"rendered":"error at %s"}}\n' "$3" "$3" "$3/out/generated.rs" "$3" "$3/out/generated.rs"
  printf '{"reason":"compiler-message","message":{"message":"generated failure at %s","code":{"code":"%s","explanation":null},"level":"error","spans":[{"file_name":"%s","line_start":2,"line_end":2,"column_start":1,"column_end":2,"is_primary":true}],"children":[],"rendered":null}}\n' "$3" "$3" "$3/out/other.rs"
  printf '{"reason":"compiler-message","message":{"message":"generated failure at <verification-target>","code":{"code":"%s","explanation":null},"level":"error","spans":[{"file_name":"%s","line_start":2,"line_end":2,"column_start":1,"column_end":2,"is_primary":true}],"children":[],"rendered":null}}\n' "$3" "$3/out/other.rs"
  printf '{"reason":"compiler-message","message":{"message":"repository failure at %s-backup","code":{"code":"E0001","explanation":null},"level":"error","spans":[{"file_name":"src/lib.rs","line_start":3,"line_end":3,"column_start":1,"column_end":2,"is_primary":true}],"children":[{"message":"keep context","level":"help"}],"rendered":null}}\n' "$3"
  printf '%s\n' '{"reason":"compiler-message","message":{"message":"repository failure at <verification-target>-backup","code":{"code":"E0001","explanation":null},"level":"error","spans":[{"file_name":"src/lib.rs","line_start":3,"line_end":3,"column_start":1,"column_end":2,"is_primary":true}],"children":[{"message":"keep context","level":"help"}],"rendered":null}}'
  printf '{"reason":"compiler-message","message":{"message":"hidden target %s","code":{"code":"E0002","explanation":null},"level":"error","spans":[{"file_name":"src/lib.rs","line_start":4,"line_end":4,"column_start":1,"column_end":2,"is_primary":true}],"children":[{"message":"hidden child %s","level":"help"}],"rendered":"safe rendered"}}\n' "$3" "$3"
  printf '%s\n' '{"reason":"build-finished","success":false}'
  exit 1
fi
exit 91
"#,
        );
        let mut request = request();
        request.operation = Operation::Verify;
        let id = &request.request_id;
        let collision = std::env::temp_dir().join(format!(
            "diagnostic-triage-cargo-{}-{id}-0",
            std::process::id()
        ));
        let _ignored = fs::remove_dir_all(&collision);
        fs::create_dir(&collision).unwrap();

        let response = execute_with_program(&request, &fake.program);
        let target = fs::read_to_string(fake.program.with_extension("target")).unwrap();
        let observations = response
            .events
            .iter()
            .filter_map(|event| match event {
                ProtocolEnvelope::Observation(event) => Some(&event.observation),
                _ => None,
            })
            .collect::<Vec<_>>();
        let generated = observations
            .iter()
            .filter(|observation| observation.location.is_none())
            .collect::<Vec<_>>();
        assert_eq!(generated.len(), 4);
        let serialized = serde_json::to_string(&observations).unwrap();
        assert!(!serialized.contains(target.trim()));
        assert_eq!(
            observations
                .iter()
                .filter(|item| item.location.is_some())
                .count(),
            2
        );
        assert!(!Path::new(target.trim()).exists());
        fs::remove_dir(collision).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn verify_probe_failures_do_not_publish_the_external_target() {
        let cases = [
            r#"if [ "$1" = "--version" ]; then printf 'cargo /tmp/private\n'; exit 0; fi; exit 91"#,
            r#"if [ "$1" = "--version" ]; then printf 'cargo 1.93.1 (fixture)\n'; exit 0; fi; if [ "$1" = "check" ]; then printf '%s\n' '{"reason":"build-finished","success":true}'; exit 0; fi; if [ "$1" = "clippy" ] && [ "$2" = "--version" ]; then printf 'broken '; cat "$0.expected"; exit 1; fi; exit 91"#,
            r#"if [ "$1" = "--version" ]; then printf 'cargo 1.93.1 (fixture)\n'; exit 0; fi; if [ "$1" = "check" ]; then target=$(cat "$0.expected"); printf '{"reason":"compiler-message","message":{"message":"traversal","code":{"code":"E0001"},"level":"error","spans":[{"file_name":"%s/../outside.rs","line_start":1,"line_end":1,"column_start":1,"column_end":2,"is_primary":true}],"children":[],"rendered":null}}\n' "$target"; printf '%s\n' '{"reason":"build-finished","success":false}'; exit 1; fi; exit 91"#,
            r#"if [ "$1" = "--version" ]; then printf 'cargo 1.93.1 (fixture)\n'; exit 0; fi; if [ "$1" = "check" ]; then target=$(cat "$0.expected"); printf '{"reason":"compiler-message","message":{"message":"bad level","code":{"code":"E0001"},"level":"%s","spans":[],"children":[],"rendered":null}}\n' "$target"; printf '%s\n' '{"reason":"build-finished","success":false}'; exit 1; fi; exit 91"#,
        ];

        for body in cases {
            let fake = FakeCargo::from_body(body);
            let mut request = request();
            request.operation = Operation::Verify;
            request.request_id = "019f7e95-0000-7000-8000-000000000067".parse().unwrap();
            let target = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "diagnostic-triage-cargo-{}-{}-0",
                    std::process::id(),
                    request.request_id
                ));
            let _ignored = fs::remove_dir_all(&target);
            fs::write(
                fake.program.with_extension("expected"),
                target.to_string_lossy().as_bytes(),
            )
            .unwrap();

            let response = execute_with_program(&request, &fake.program);

            assert_eq!(response.completion.status, ExecutionStatus::Incomplete);
            assert_eq!(response.completion.counts.evidence, 0);
            let message = response.completion.message.unwrap_or_default();
            assert!(!message.contains(target.to_string_lossy().as_ref()));
            assert!(!target.exists());
        }
    }

    #[test]
    fn verify_cleanup_failure_is_incomplete() {
        let request = request();
        let complete = super::complete_or_event_limit(&request, Vec::new(), 0, Instant::now());
        let target = super::VerificationTargetDir {
            path: Some(repository_root().join("missing-verification-target")),
        };

        let response = super::finalize_verification_target(target, &request, complete);

        assert_eq!(response.completion.status, ExecutionStatus::Incomplete);
    }

    #[test]
    fn nested_workspace_target_selects_relative_manifest_without_workspace() {
        let root = repository_root();
        let workspace = std::fs::canonicalize(root.join(MEMBER_SCOPE)).unwrap();
        let request = scoped_request(MEMBER_SCOPE, &[MEMBER_SCOPE]);
        let scope = select_cargo_scope(&request, &root, &workspace).unwrap();
        assert_eq!(
            scope,
            CargoScope::Manifest {
                manifest: PathBuf::from("Cargo.toml"),
                repository_path: MEMBER_SCOPE.parse().unwrap(),
            }
        );
        let check = cargo_argv("check", &scope, None);
        let clippy = cargo_argv("clippy", &scope, None);
        assert!(!check.contains(&"--workspace".to_owned()));
        assert_eq!(&check[1..], &clippy[1..]);
    }

    #[test]
    fn root_workspace_member_target_selects_member_manifest() {
        let root = repository_root();
        let request = scoped_request(".", &[MEMBER_SCOPE]);
        assert_eq!(
            select_cargo_scope(&request, &root, &root).unwrap(),
            CargoScope::Manifest {
                manifest: PathBuf::from(MEMBER_SCOPE).join("Cargo.toml"),
                repository_path: MEMBER_SCOPE.parse().unwrap(),
            }
        );
    }

    #[test]
    fn unsupported_target_shapes_are_typed_before_cargo_execution() {
        let root = repository_root();
        let cases = [
            scoped_request(".", &[MEMBER_SCOPE, "crates/diagnostic-triage-contracts"]),
            scoped_request(".", &["crates/diagnostic-triage-provider-rust/src/lib.rs"]),
            scoped_request(".", &["crates/diagnostic-triage-provider-rust/src"]),
            scoped_request(".", &["crates/diagnostic-triage-provider-rust/missing"]),
            scoped_request(MEMBER_SCOPE, &["crates/diagnostic-triage-contracts"]),
        ];
        let response = execute_with_program(&cases[0], Path::new("cargo-must-not-run"));
        assert_eq!(response.completion.status, ExecutionStatus::Incomplete);
        assert_eq!(response.completion.tool_exit_code.0, None);
        assert!(response.events.is_empty());
        for request in cases {
            let workspace = if request.workspace.as_str() == "." {
                root.clone()
            } else {
                std::fs::canonicalize(root.join(request.workspace.as_str())).unwrap()
            };
            assert!(matches!(
                select_cargo_scope(&request, &root, &workspace),
                Err(ProviderError::Request(_) | ProviderError::Path(_))
            ));
        }
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
    fn nested_scope_paths_are_relative_and_siblings_are_rejected() {
        let root = repository_root();
        let workspace_root = std::fs::canonicalize(root.join(MEMBER_SCOPE)).unwrap();
        let request = scoped_request(MEMBER_SCOPE, &[MEMBER_SCOPE]);
        let cargo = select_cargo_scope(&request, &root, &workspace_root).unwrap();
        let scope = DiagnosticScope {
            cargo: &cargo,
            repository_root: &root,
            workspace_root: &workspace_root,
            verification_target: None,
        };
        assert_eq!(
            normalize_path("src/lib.rs", &scope).unwrap().as_str(),
            format!("{MEMBER_SCOPE}/src/lib.rs")
        );
        let repository_relative = format!("{MEMBER_SCOPE}/src/lib.rs");
        assert_eq!(
            normalize_path(&repository_relative, &scope)
                .unwrap()
                .as_str(),
            format!("{MEMBER_SCOPE}/src/lib.rs")
        );
        assert!(normalize_path("crates/diagnostic-triage-contracts/src/lib.rs", &scope).is_err());
        assert!(normalize_path("docs/contracts/protocol-v1.md", &scope).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn nested_scope_prefers_cargo_cwd_when_root_has_the_same_relative_file() {
        let fixture = FakeCargo::from_body("exit 0");
        let workspace_root = fixture.root.join("member");
        fs::create_dir_all(fixture.root.join("src")).unwrap();
        fs::create_dir_all(workspace_root.join("src")).unwrap();
        fs::write(fixture.root.join("src/lib.rs"), "// repository root").unwrap();
        fs::write(workspace_root.join("src/lib.rs"), "// selected member").unwrap();
        let cargo = CargoScope::Manifest {
            manifest: PathBuf::from("member/Cargo.toml"),
            repository_path: "member".parse().unwrap(),
        };
        let scope = DiagnosticScope {
            cargo: &cargo,
            repository_root: &fixture.root,
            workspace_root: &workspace_root,
            verification_target: None,
        };

        assert_eq!(
            normalize_path("src/lib.rs", &scope).unwrap().as_str(),
            "member/src/lib.rs"
        );
    }

    #[cfg(unix)]
    #[test]
    fn selected_package_excludes_sibling_diagnostic_locations() {
        let root = repository_root();
        let request = scoped_request(".", &[MEMBER_SCOPE]);
        let cargo = select_cargo_scope(&request, &root, &root).unwrap();
        let scope = DiagnosticScope {
            cargo: &cargo,
            repository_root: &root,
            workspace_root: &root,
            verification_target: None,
        };
        let span = RustcSpan {
            file_name: "crates/diagnostic-triage-contracts/src/lib.rs".to_owned(),
            line_start: 1,
            line_end: 1,
            column_start: 1,
            column_end: 2,
            is_primary: true,
        };

        assert_eq!(scoped_location(&span, &scope).unwrap(), None);
    }

    #[test]
    fn rustc_locations_preserve_insertions_and_half_open_code_point_ranges() {
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
            .map(root_location)
            .collect::<Result<Vec<_>, _>>()
            .expect("rustc coordinates match Location v1");

        assert_eq!(locations[0].start, locations[0].end.clone().unwrap());
        assert_eq!(locations[1].end.as_ref().unwrap().column, 4);
        assert_eq!(locations[2].end.as_ref().unwrap().line, 4);
        assert_eq!(locations[2].end.as_ref().unwrap().column, 1);
    }

    #[test]
    fn rustc_location_boundary_rejects_non_positive_and_reversed_spans() {
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
            assert!(root_location(&span).is_err());
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
        let location = root_location(&span).expect("rustc fixture span normalizes");
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
