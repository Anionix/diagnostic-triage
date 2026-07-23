//! Narrow command facade used by the unpublished CLI crate.

use std::{
    fmt::Write as _,
    fs,
    path::{Component, Path},
    str::FromStr,
    time::Duration,
};

use diagnostic_triage_contracts::{
    AdapterId, Capability, RepoPath, Sha256Digest,
    model::{SessionReport, Verdict},
    protocol::{
        EnvelopeKind, Operation, ProtocolEnvelope, ProtocolVersion, RequestEnvelope, RequestLimits,
    },
};
use diagnostic_triage_engine::deterministic_object_id;
use similar::TextDiff;
use thiserror::Error;

use crate::orchestration::{
    PreparedRuffFix, ReadOnlyMode, assemble_read_only_report, assemble_verified_report,
    authorize_canonical_ruff_verification, execute_current_read_only_plan, execute_fix_plan,
    execute_patch_verification, prepare_single_canonical_ruff_fix, project_executed_read_only_plan,
};
use crate::{
    MAX_RUFF_FIX_FILE_BYTES, RuntimeConfig, ScratchChange, ScratchLimits, ScratchPatch,
    ScratchWorkspace,
    config::{
        DEFAULT_MAX_EVENTS, DEFAULT_MAX_EVIDENCE_BYTES, DEFAULT_MAX_STDERR_BYTES,
        DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_MS,
    },
    process::{ProcessLimits, ProcessSpec, ProcessState, run_bounded},
    session::{ProviderSessionError, ProviderSessionState, run_provider_session},
};

// LLM contract: CONFIGURED -> EXECUTED -> NORMALIZED -> REPORTED; operational failure -> exit 2.

/// Read-only command selected by the CLI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOnlyCommandMode {
    Check,
    Ci,
}

/// Opaque failure from the internal runtime command pipeline.
#[derive(Debug, Error)]
pub enum RuntimeCommandError {
    #[error("read-only execution failed: {0}")]
    Execution(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("runtime projection failed: {0}")]
    Projection(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("report assembly failed: {0}")]
    Report(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// One deterministic patch proposal and its stable pre-fix status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixCommandResult {
    pub patch: Vec<u8>,
    pub exit_code: u8,
}

/// Failures before a scratch-only fix or verification result can be trusted.
#[derive(Debug, Error)]
pub enum FixCommandError {
    #[error("repository snapshot discovery failed: {0}")]
    Snapshot(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("scratch workspace failed: {0}")]
    Scratch(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("fix Provider execution failed: {0}")]
    Execution(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("runtime projection failed: {0}")]
    Projection(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("fix candidate preparation failed: {0}")]
    Preparation(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("canonical patch cannot be represented as a v1 unified diff")]
    PatchFormat,
    #[error("patch input exceeds the {MAX_PATCH_INPUT_BYTES}-byte limit")]
    PatchInputLimit,
    #[error("patch process failed: {0}")]
    PatchProcess(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("patch was rejected: state={state:?}, exit_code={exit_code:?}")]
    PatchRejected {
        state: ProcessState,
        exit_code: Option<u8>,
    },
    #[error("patch result differs from the authoritative tool-native candidate")]
    PatchMismatch,
    #[error("safe-fix verification failed: {0}")]
    Verification(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("report assembly failed: {0}")]
    Report(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("no authoritative SAFE fix candidate was produced")]
    NoSafeCandidate,
}

/// Successful offline Observer transcript plus its stable terminal status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserverCommandResult {
    pub transcript: Vec<u8>,
    pub exit_code: u8,
}

/// Failures before a trustworthy offline Observer transcript is available.
#[derive(Debug, Error)]
pub enum ObserverCommandError {
    #[error("Observer request identity could not be derived: {0}")]
    Identity(String),
    #[error("Observer request contains an invalid scalar: {0}")]
    Request(String),
    #[error("Observer input snapshot could not be staged: {0}")]
    Snapshot(#[source] std::io::Error),
    #[error(transparent)]
    Session(#[from] ProviderSessionError),
    #[error("Observer did not produce a complete validated session: {0}")]
    Terminal(String),
    #[error("Observer transcript could not be encoded: {0}")]
    Encoding(#[from] serde_json::Error),
}

const MAX_PATCH_INPUT_BYTES: usize = 64 * 1024 * 1024;
const INTERNAL_TOOL_TIMEOUT: Duration = Duration::from_secs(10);

/// Execute one complete read-only command and assemble its v1 report.
///
/// The repository identity is derived from the exact state snapshot checked
/// again after the Provider group exits. No caller-selected digest can enter
/// the command path.
///
/// # Errors
///
/// Returns a typed command-boundary error when execution, normalization, or
/// report assembly fails.
pub fn run_read_only_command(
    config: &RuntimeConfig,
    repository_root: &Path,
    mode: ReadOnlyCommandMode,
    evaluation_time: impl FnOnce() -> Option<String>,
) -> Result<SessionReport, RuntimeCommandError> {
    let mode = match mode {
        ReadOnlyCommandMode::Check => ReadOnlyMode::Check,
        ReadOnlyCommandMode::Ci => ReadOnlyMode::Ci,
    };
    let executed = execute_current_read_only_plan(config, repository_root, mode)
        .map_err(|error| RuntimeCommandError::Execution(Box::new(error)))?;
    let projection = project_executed_read_only_plan(executed)
        .map_err(|error| RuntimeCommandError::Projection(Box::new(error)))?;
    let evaluation_time = projection
        .requires_evaluation_time()
        .then(evaluation_time)
        .flatten();
    assemble_read_only_report(projection, evaluation_time)
        .map_err(|error| RuntimeCommandError::Report(Box::new(error)))
}

/// Propose at most one authoritative SAFE Ruff patch without mutating the source repository.
///
/// # Errors
///
/// Returns a typed operational failure when snapshot staging, Provider execution,
/// candidate selection, canonicalization, or scratch cleanup cannot complete.
pub fn run_fix_command(
    config: &RuntimeConfig,
    repository_root: &Path,
    evaluation_time: impl FnOnce() -> Option<String>,
) -> Result<FixCommandResult, FixCommandError> {
    // LLM contract: MATERIALIZED -> STAGED -> FIX_EXECUTED -> CANONICALIZED -> PATCH_REPORTED;
    // source mutation, ambiguity, or cleanup failure -> INCOMPLETE.
    let paths = materialized_repository_paths(config, repository_root)?;
    let scratch = stage_snapshot(config, repository_root, &paths)?;
    let result = (|| {
        let executed = execute_fix_plan(config, repository_root, &scratch)
            .map_err(|error| FixCommandError::Execution(Box::new(error)))?;
        let projection = project_executed_read_only_plan(executed)
            .map_err(|error| FixCommandError::Projection(Box::new(error)))?;
        let report_time = projection
            .requires_evaluation_time()
            .then(evaluation_time)
            .flatten();
        let report = assemble_read_only_report(projection.clone(), report_time)
            .map_err(|error| FixCommandError::Report(Box::new(error)))?;
        let patch = prepare_single_canonical_ruff_fix(&scratch, projection)
            .map_err(|error| FixCommandError::Preparation(Box::new(error)))?
            .map(|prepared| render_unified_patch(&scratch, &prepared.canonical.patch))
            .transpose()?
            .unwrap_or_default();
        Ok(FixCommandResult {
            patch,
            exit_code: verdict_exit_code(&report.verdict),
        })
    })();
    let cleanup = scratch
        .cleanup()
        .map_err(|error| FixCommandError::Scratch(Box::new(error)));
    result.and_then(|value| cleanup.map(|()| value))
}

/// Verify that an arbitrary unified diff has the exact result of one authoritative SAFE Ruff fix.
///
/// Both the imported patch and the canonical candidate are applied only to private scratch
/// workspaces. The source repository remains read-only.
///
/// # Errors
///
/// Returns a typed failure for malformed, ambiguous, non-canonical, incomplete, or regressive
/// patch verification.
pub fn run_verify_patch_command(
    config: &RuntimeConfig,
    repository_root: &Path,
    patch_bytes: &[u8],
    evaluation_time: impl FnOnce() -> Option<String>,
) -> Result<SessionReport, FixCommandError> {
    // LLM contract: PATCH_READ -> SOURCE_STAGED -> IMPORTED -> RESULT_MATCHED -> VERIFIED ->
    // REPORTED; source mutation, mismatch, regression, or cleanup failure -> INCOMPLETE.
    if patch_bytes.len() > MAX_PATCH_INPUT_BYTES {
        return Err(FixCommandError::PatchInputLimit);
    }
    let paths = materialized_repository_paths(config, repository_root)?;
    let mut canonical_scratch = stage_snapshot(config, repository_root, &paths)?;
    let imported_scratch = stage_snapshot(config, repository_root, &paths)?;
    let result = (|| {
        if canonical_scratch.base_evidence().sha256 != imported_scratch.base_evidence().sha256 {
            return Err(FixCommandError::PatchMismatch);
        }
        let executed = execute_fix_plan(config, repository_root, &canonical_scratch)
            .map_err(|error| FixCommandError::Execution(Box::new(error)))?;
        let before = project_executed_read_only_plan(executed)
            .map_err(|error| FixCommandError::Projection(Box::new(error)))?;
        let PreparedRuffFix {
            projection: before,
            candidate,
            canonical,
        } = prepare_single_canonical_ruff_fix(&canonical_scratch, before)
            .map_err(|error| FixCommandError::Preparation(Box::new(error)))?
            .ok_or(FixCommandError::NoSafeCandidate)?;
        let _ = render_unified_patch(&canonical_scratch, &canonical.patch)?;

        apply_unified_patch(imported_scratch.path(), patch_bytes)?;
        let empty = ScratchPatch::new(Vec::new())
            .map_err(|error| FixCommandError::Scratch(Box::new(error)))?;
        let imported_result = imported_scratch
            .capture(&empty, None)
            .map_err(|error| FixCommandError::Scratch(Box::new(error)))?
            .result
            .sha256;
        let application = canonical_scratch
            .apply_for_verification(&canonical.patch)
            .map_err(|error| FixCommandError::Scratch(Box::new(error)))?;
        let canonical_result = canonical_scratch
            .capture(&canonical.patch, None)
            .map_err(|error| FixCommandError::Scratch(Box::new(error)))?
            .result
            .sha256;
        if imported_result != canonical_result {
            return Err(FixCommandError::PatchMismatch);
        }

        let executed = execute_patch_verification(
            config,
            repository_root,
            &canonical_scratch,
            &canonical.patch,
        )
        .map_err(|error| FixCommandError::Execution(Box::new(error)))?;
        let after = project_executed_read_only_plan(executed)
            .map_err(|error| FixCommandError::Projection(Box::new(error)))?;
        let authorized = authorize_canonical_ruff_verification(
            &canonical_scratch,
            &canonical,
            &candidate,
            &application,
            before,
            after,
        )
        .map_err(|error| FixCommandError::Verification(Box::new(error)))?;
        assemble_verified_report(authorized, evaluation_time())
            .map_err(|error| FixCommandError::Report(Box::new(error)))
    })();
    let imported_cleanup = imported_scratch
        .cleanup()
        .map_err(|error| FixCommandError::Scratch(Box::new(error)));
    let canonical_cleanup = canonical_scratch
        .cleanup()
        .map_err(|error| FixCommandError::Scratch(Box::new(error)));
    result.and_then(|report| imported_cleanup.and(canonical_cleanup).map(|()| report))
}

fn stage_snapshot(
    config: &RuntimeConfig,
    repository_root: &Path,
    paths: &[String],
) -> Result<ScratchWorkspace, FixCommandError> {
    let limits = config
        .request_limits()
        .map_err(|error| FixCommandError::Preparation(Box::new(error)))?;
    ScratchWorkspace::stage(
        repository_root,
        paths,
        ScratchLimits {
            max_evidence_bytes: u32::try_from(limits.max_evidence_bytes)
                .map_err(|error| FixCommandError::Preparation(Box::new(error)))?,
            ..ScratchLimits::default()
        },
    )
    .map_err(|error| FixCommandError::Scratch(Box::new(error)))
}

fn materialized_repository_paths(
    config: &RuntimeConfig,
    repository_root: &Path,
) -> Result<Vec<String>, FixCommandError> {
    let outcome = run_bounded(
        &ProcessSpec::new("git")
            .args([
                "--literal-pathspecs",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ])
            .current_dir(repository_root),
        internal_tool_limits(),
    )
    .map_err(|error| FixCommandError::Snapshot(Box::new(error)))?;
    if outcome.state != ProcessState::Complete || outcome.exit_code != Some(0) {
        return Err(FixCommandError::Snapshot(Box::new(std::io::Error::other(
            format!(
                "git ls-files failed: state={:?}, exit_code={:?}",
                outcome.state, outcome.exit_code
            ),
        ))));
    }
    if !outcome.stdout.bytes.is_empty() && !outcome.stdout.bytes.ends_with(&[0]) {
        return Err(FixCommandError::Snapshot(Box::new(std::io::Error::other(
            "git ls-files returned a truncated path record",
        ))));
    }
    let mut paths = outcome
        .stdout
        .bytes
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| {
            std::str::from_utf8(path)
                .map(str::to_owned)
                .map_err(|error| FixCommandError::Snapshot(Box::new(error)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if config.repository.workspace.as_str() != "." {
        paths.push(config.repository.workspace.as_str().to_owned());
    }
    paths.extend(
        config
            .repository
            .targets
            .iter()
            .filter(|target| target.as_str() != ".")
            .map(|target| target.as_str().to_owned()),
    );
    paths.extend(config.providers.iter().filter_map(|provider| {
        let path = Path::new(&provider.program);
        (!path.is_absolute()
            && path.components().count() > 1
            && !path
                .components()
                .any(|component| matches!(component, Component::ParentDir)))
        .then(|| provider.program.clone())
    }));
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn render_unified_patch(
    scratch: &ScratchWorkspace,
    patch: &ScratchPatch,
) -> Result<Vec<u8>, FixCommandError> {
    let [ScratchChange::Write { path, contents }] = patch.changes() else {
        return Err(FixCommandError::PatchFormat);
    };
    let original = scratch
        .read_immutable_base_file(path, MAX_RUFF_FIX_FILE_BYTES)
        .map_err(|error| FixCommandError::Scratch(Box::new(error)))?;
    let original = std::str::from_utf8(&original).map_err(|_| FixCommandError::PatchFormat)?;
    let replacement = std::str::from_utf8(contents).map_err(|_| FixCommandError::PatchFormat)?;
    let old_path = git_quote_path("a/", path);
    let new_path = git_quote_path("b/", path);
    let output = TextDiff::from_lines(original, replacement)
        .unified_diff()
        .context_radius(3)
        .header(&old_path, &new_path)
        .to_string();
    if output.is_empty() {
        return Err(FixCommandError::PatchFormat);
    }
    Ok(output.into_bytes())
}

fn git_quote_path(prefix: &str, path: &str) -> String {
    // Git's primary diff specification uses double-quoted C-style byte escapes for unusual paths:
    // https://git-scm.com/docs/git-diff
    let mut quoted = String::from("\"");
    for byte in prefix.bytes().chain(path.bytes()) {
        match byte {
            b'\\' => quoted.push_str("\\\\"),
            b'"' => quoted.push_str("\\\""),
            0x20..=0x7e => quoted.push(char::from(byte)),
            value => write!(&mut quoted, "\\{value:03o}").expect("writing to String cannot fail"),
        }
    }
    quoted.push('"');
    quoted
}

fn apply_unified_patch(workspace: &Path, patch: &[u8]) -> Result<(), FixCommandError> {
    // `git apply` is atomic by default and rejects paths outside the current working directory:
    // https://git-scm.com/docs/git-apply
    let outcome = run_bounded(
        &ProcessSpec::new("git")
            .args(["apply", "--whitespace=nowarn", "--"])
            .current_dir(workspace)
            .stdin(patch.to_vec()),
        internal_tool_limits(),
    )
    .map_err(|error| FixCommandError::PatchProcess(Box::new(error)))?;
    if outcome.state != ProcessState::Complete || outcome.exit_code != Some(0) {
        return Err(FixCommandError::PatchRejected {
            state: outcome.state,
            exit_code: outcome.exit_code,
        });
    }
    Ok(())
}

fn internal_tool_limits() -> ProcessLimits {
    ProcessLimits {
        timeout: INTERNAL_TOOL_TIMEOUT,
        ..ProcessLimits::default()
    }
}

/// Run the first-party GitHub Actions Observer through the public JSONL protocol.
///
/// # Errors
///
/// Returns a typed request, process, protocol, or encoding failure.
pub fn run_github_actions_observer(
    program: &Path,
    input: &str,
    input_bytes: &[u8],
) -> Result<ObserverCommandResult, ObserverCommandError> {
    let request = github_actions_observer_request(input, input_bytes)?;
    let snapshot = tempfile::Builder::new()
        .prefix("diagnostic-triage-observe-")
        .tempdir()
        .map_err(ObserverCommandError::Snapshot)?;
    let source = snapshot.path().join(request.targets[0].as_str());
    if let Some(parent) = source.parent() {
        fs::create_dir_all(parent).map_err(ObserverCommandError::Snapshot)?;
    }
    fs::write(&source, input_bytes).map_err(ObserverCommandError::Snapshot)?;
    let outcome = run_provider_session(
        ProcessSpec::new(program).current_dir(snapshot.path()),
        &AdapterId::from_str("github-actions")
            .map_err(|reason| ObserverCommandError::Request(reason.to_string()))?,
        env!("CARGO_PKG_VERSION"),
        &request,
    )?;
    encode_observer_outcome(outcome)
}

fn github_actions_observer_request(
    input: &str,
    input_bytes: &[u8],
) -> Result<RequestEnvelope, ObserverCommandError> {
    let target = RepoPath::from_str(input)
        .map_err(|reason| ObserverCommandError::Request(reason.to_string()))?;
    let digest = Sha256Digest::compute(input_bytes).to_string();
    let request_id = deterministic_object_id(
        "diagnostic-triage.cli-observe-request/v1",
        ["github-actions", target.as_str(), digest.as_str()],
    )
    .map_err(|error| ObserverCommandError::Identity(error.to_string()))?;
    Ok(RequestEnvelope {
        protocol_version: ProtocolVersion::V1,
        kind: EnvelopeKind::Request,
        request_id,
        operation: Operation::Observe,
        workspace: RepoPath::from_str(".")
            .map_err(|reason| ObserverCommandError::Request(reason.to_string()))?,
        targets: vec![target],
        required_capabilities: vec![
            Capability::from_str("execution.observe/v1")
                .map_err(|reason| ObserverCommandError::Request(reason.to_string()))?,
        ],
        optional_capabilities: Vec::new(),
        limits: RequestLimits {
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_stdout_bytes: DEFAULT_MAX_STDOUT_BYTES,
            max_stderr_bytes: DEFAULT_MAX_STDERR_BYTES,
            max_evidence_bytes: DEFAULT_MAX_EVIDENCE_BYTES,
            max_events: DEFAULT_MAX_EVENTS,
        },
    })
}

fn encode_observer_outcome(
    outcome: crate::session::ProviderSessionOutcome,
) -> Result<ObserverCommandResult, ObserverCommandError> {
    let (session, exit_code) = match outcome.state {
        ProviderSessionState::Complete(session) => (session, 0),
        ProviderSessionState::Incomplete {
            validated_session: Some(session),
            ..
        }
        | ProviderSessionState::Unsupported {
            validated_session: Some(session),
            ..
        } => (session, 2),
        ProviderSessionState::Incomplete { reason, .. }
        | ProviderSessionState::Unsupported { reason, .. } => {
            return Err(ObserverCommandError::Terminal(reason));
        }
    };
    let mut transcript = Vec::new();
    for envelope in std::iter::once(ProtocolEnvelope::Manifest(session.manifest.clone()))
        .chain(std::iter::once(ProtocolEnvelope::Request(
            session.request.clone(),
        )))
        .chain(session.events.iter().cloned())
        .chain(std::iter::once(ProtocolEnvelope::Completion(
            session.completion.clone(),
        )))
    {
        serde_json::to_writer(&mut transcript, &envelope)?;
        transcript.push(b'\n');
    }
    Ok(ObserverCommandResult {
        transcript,
        exit_code,
    })
}

/// Map a validated v1 verdict to its stable process exit code.
#[must_use]
pub const fn verdict_exit_code(verdict: &Verdict) -> u8 {
    match verdict {
        Verdict::Pass => 0,
        Verdict::PolicyFail => 1,
        Verdict::Incomplete | Verdict::Unsupported => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn github_actions_request_binds_operation_capability_target_and_bytes() {
        let request =
            github_actions_observer_request("runs/completed.json", b"{\"id\":1}").expect("request");
        let changed =
            github_actions_observer_request("runs/completed.json", b"{\"id\":2}").expect("changed");

        assert_eq!(request.operation, Operation::Observe);
        assert_eq!(request.targets[0].as_str(), "runs/completed.json");
        assert_eq!(
            request.required_capabilities[0].as_str(),
            "execution.observe/v1"
        );
        assert_ne!(request.request_id, changed.request_id);
    }

    #[cfg(unix)]
    #[test]
    fn quoted_unified_diff_round_trips_only_inside_scratch() {
        let repository = tempdir().expect("repository");
        fs::create_dir(repository.path().join("src")).expect("source directory");
        let relative = "src/café file.py";
        fs::write(repository.path().join(relative), b"import os\nvalue = 1\n").expect("source");
        let mut canonical =
            ScratchWorkspace::stage(repository.path(), &["src"], ScratchLimits::default())
                .expect("canonical scratch");
        let imported =
            ScratchWorkspace::stage(repository.path(), &["src"], ScratchLimits::default())
                .expect("import scratch");
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: relative.to_owned(),
            contents: b"value = 1\n".to_vec(),
        }])
        .expect("patch");

        let unified = render_unified_patch(&canonical, &patch).expect("unified diff");
        assert!(
            std::str::from_utf8(&unified)
                .expect("UTF-8 diff")
                .starts_with("--- \"a/src/caf\\303\\251 file.py\"\n")
        );
        apply_unified_patch(imported.path(), &unified).expect("import");
        canonical
            .apply_for_verification(&patch)
            .expect("canonical apply");
        let empty = ScratchPatch::new(Vec::new()).expect("empty patch");
        assert_eq!(
            imported
                .capture(&empty, None)
                .expect("imported")
                .result
                .sha256,
            canonical
                .capture(&patch, None)
                .expect("canonical")
                .result
                .sha256
        );
        assert_eq!(
            fs::read(repository.path().join(relative)).expect("original"),
            b"import os\nvalue = 1\n"
        );
        imported.cleanup().expect("import cleanup");
        canonical.cleanup().expect("canonical cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn git_apply_rejects_a_patch_path_escape() {
        let repository = tempdir().expect("repository");
        let scratch =
            ScratchWorkspace::stage(repository.path(), &[] as &[&str], ScratchLimits::default())
                .expect("scratch");
        let patch = b"--- /dev/null\n+++ b/../escape\n@@ -0,0 +1 @@\n+escaped\n";

        assert!(matches!(
            apply_unified_patch(scratch.path(), patch),
            Err(FixCommandError::PatchRejected { .. })
        ));
        assert!(!repository.path().join("escape").exists());
        scratch.cleanup().expect("cleanup");
    }
}
