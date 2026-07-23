//! Narrow command facade used by the unpublished CLI crate.

use std::{
    collections::BTreeSet,
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
    AuthorizedPatchVerification, PreparedRuffFix, ReadOnlyMode, RepositoryState,
    assemble_read_only_report, assemble_verified_report, authorize_canonical_ruff_verification,
    capture_repository_state, execute_current_read_only_plan, execute_fix_plan,
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
    #[error("required repository path is missing: {path}")]
    MissingRequiredPath { path: String },
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
    #[error("repository changed while the verified patch was being prepared")]
    RepositoryChanged,
    #[error("verified patch output failed before source publication: {0}")]
    PatchOutput(#[source] std::io::Error),
    #[error("fix --apply-safe source publication is supported only on Linux and Apple platforms")]
    ApplySafePlatformUnsupported,
    #[error("safe patch was applied, but the final repository no longer matches verification")]
    AppliedRepositoryConflict,
    #[error("report assembly failed: {0}")]
    Report(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("no authoritative SAFE fix candidate was produced")]
    NoSafeCandidate,
    #[error("operation failed ({operation}); scratch cleanup also failed ({cleanup})")]
    OperationAndCleanup {
        #[source]
        operation: Box<FixCommandError>,
        cleanup: Box<FixCommandError>,
    },
    #[error("safe patch was applied, but scratch cleanup failed ({cleanup})")]
    AppliedAndCleanup {
        #[source]
        cleanup: Box<FixCommandError>,
    },
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
    finish_with_cleanup(result, cleanup)
}

/// Verify and explicitly apply one authoritative SAFE Ruff fix to the source repository.
///
/// The tool-native candidate is canonicalized and verified in private workspaces first. The
/// runtime emits the verified patch, consumes the exact authorization, revalidates the source
/// snapshot, and atomically exchanges the single-file result. No output failure or
/// pre-publication safety failure writes to the source repository. The output callback must return
/// success only after its destination accepted and flushed the complete patch.
///
/// # Errors
///
/// Returns a typed operational failure when any safety gate, source binding, publication, or
/// cleanup step fails.
pub fn run_apply_safe_command(
    config: &RuntimeConfig,
    repository_root: &Path,
    evaluation_time: impl FnOnce() -> Option<String>,
    emit_patch: impl FnOnce(&[u8]) -> std::io::Result<()>,
) -> Result<FixCommandResult, FixCommandError> {
    run_apply_safe_command_for_platform(
        config,
        repository_root,
        evaluation_time,
        source_publication_supported(),
        emit_patch,
    )
}

fn run_apply_safe_command_for_platform(
    config: &RuntimeConfig,
    repository_root: &Path,
    evaluation_time: impl FnOnce() -> Option<String>,
    publication_supported: bool,
    emit_patch: impl FnOnce(&[u8]) -> std::io::Result<()>,
) -> Result<FixCommandResult, FixCommandError> {
    // LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED ->
    // REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.
    // LLM contract: EXPLICIT_REQUEST -> SAFE_SELECTED -> TOOL_NATIVE -> SCRATCH_APPLIED ->
    // PROVIDERS_COMPLETE -> REGRESSION_FREE -> SOURCE_REVALIDATED -> AUTH_CONSUMED -> PUBLISHED;
    // any failed gate before PUBLISHED leaves the source repository unchanged.
    let source_state = capture_source_state(repository_root)?;
    let paths = materialized_repository_paths(config, repository_root)?;
    let mut scratch = stage_snapshot(config, repository_root, &paths)?;
    let result = (|| {
        require_source_state(repository_root, &source_state)?;
        let executed = execute_fix_plan(config, repository_root, &scratch)
            .map_err(|error| FixCommandError::Execution(Box::new(error)))?;
        let before = project_executed_read_only_plan(executed)
            .map_err(|error| FixCommandError::Projection(Box::new(error)))?;
        let report_time = before
            .requires_evaluation_time()
            .then(evaluation_time)
            .flatten();
        let Some(PreparedRuffFix {
            projection: before,
            candidate,
            canonical,
        }) = prepare_single_canonical_ruff_fix(&scratch, before.clone())
            .map_err(|error| FixCommandError::Preparation(Box::new(error)))?
        else {
            require_source_state(repository_root, &source_state)?;
            let report = assemble_read_only_report(before, report_time)
                .map_err(|error| FixCommandError::Report(Box::new(error)))?;
            return Ok((
                FixCommandResult {
                    patch: Vec::new(),
                    exit_code: verdict_exit_code(&report.verdict),
                },
                false,
            ));
        };
        require_source_publication_support(publication_supported)?;
        let unified = render_unified_patch(&scratch, &canonical.patch)?;

        let application = scratch
            .apply_for_verification(&canonical.patch)
            .map_err(|error| FixCommandError::Scratch(Box::new(error)))?;
        let canonical_result = scratch
            .capture(&canonical.patch, None)
            .map_err(|error| FixCommandError::Scratch(Box::new(error)))?
            .result
            .sha256;
        verify_unified_patch_result(
            config,
            repository_root,
            &paths,
            &scratch.base_evidence().sha256,
            &canonical_result,
            &unified,
        )?;

        let executed =
            execute_patch_verification(config, repository_root, &scratch, &canonical.patch)
                .map_err(|error| FixCommandError::Execution(Box::new(error)))?;
        let after = project_executed_read_only_plan(executed)
            .map_err(|error| FixCommandError::Projection(Box::new(error)))?;
        let AuthorizedPatchVerification {
            projection,
            authorization,
        } = authorize_canonical_ruff_verification(
            &scratch,
            &canonical,
            &candidate,
            &application,
            before,
            after,
        )
        .map_err(|error| FixCommandError::Verification(Box::new(error)))?;
        let verified_candidate = projection.candidate.clone();
        let report =
            assemble_verified_report(projection, authorization.verified_fix(), report_time)
                .map_err(|error| FixCommandError::Report(Box::new(error)))?;

        require_source_state(repository_root, &source_state)?;
        emit_patch(&unified).map_err(FixCommandError::PatchOutput)?;
        require_source_state(repository_root, &source_state)?;
        scratch
            .publish_verified_to_source(
                &verified_candidate,
                &canonical.patch,
                &canonical.patch_evidence,
                authorization,
            )
            .map_err(|error| FixCommandError::Scratch(Box::new(error)))?;
        verify_published_repository(
            config,
            repository_root,
            &paths,
            &source_state,
            &canonical_result,
        )?;
        Ok((
            FixCommandResult {
                patch: unified,
                exit_code: verdict_exit_code(&report.verdict),
            },
            true,
        ))
    })();
    let cleanup = scratch
        .cleanup()
        .map_err(|error| FixCommandError::Scratch(Box::new(error)));
    finish_apply_with_cleanup(result, cleanup)
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
    let imported_scratch = stage_snapshot(config, repository_root, &paths)?;
    let imported = (|| {
        apply_unified_patch(imported_scratch.path(), patch_bytes)?;
        let empty = ScratchPatch::new(Vec::new())
            .map_err(|error| FixCommandError::Scratch(Box::new(error)))?;
        let result = imported_scratch
            .capture(&empty, None)
            .map_err(|error| FixCommandError::Scratch(Box::new(error)))?
            .result
            .sha256;
        Ok((imported_scratch.base_evidence().sha256.clone(), result))
    })();
    let imported_cleanup = imported_scratch
        .cleanup()
        .map_err(|error| FixCommandError::Scratch(Box::new(error)));
    let (imported_base, imported_result) = finish_with_cleanup(imported, imported_cleanup)?;

    let mut canonical_scratch = stage_snapshot(config, repository_root, &paths)?;
    let result = (|| {
        if canonical_scratch.base_evidence().sha256 != imported_base {
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
        let AuthorizedPatchVerification {
            projection,
            authorization,
        } = authorize_canonical_ruff_verification(
            &canonical_scratch,
            &canonical,
            &candidate,
            &application,
            before,
            after,
        )
        .map_err(|error| FixCommandError::Verification(Box::new(error)))?;
        assemble_verified_report(projection, authorization.verified_fix(), evaluation_time())
            .map_err(|error| FixCommandError::Report(Box::new(error)))
    })();
    let canonical_cleanup = canonical_scratch
        .cleanup()
        .map_err(|error| FixCommandError::Scratch(Box::new(error)));
    finish_with_cleanup(result, canonical_cleanup)
}

fn verify_unified_patch_result(
    config: &RuntimeConfig,
    repository_root: &Path,
    paths: &[String],
    expected_base: &Sha256Digest,
    expected_result: &Sha256Digest,
    unified: &[u8],
) -> Result<(), FixCommandError> {
    let imported = stage_snapshot(config, repository_root, paths)?;
    let result = (|| {
        if &imported.base_evidence().sha256 != expected_base {
            return Err(FixCommandError::PatchMismatch);
        }
        apply_unified_patch(imported.path(), unified)?;
        let empty = ScratchPatch::new(Vec::new())
            .map_err(|error| FixCommandError::Scratch(Box::new(error)))?;
        let result = imported
            .capture(&empty, None)
            .map_err(|error| FixCommandError::Scratch(Box::new(error)))?
            .result
            .sha256;
        if &result != expected_result {
            return Err(FixCommandError::PatchMismatch);
        }
        Ok(())
    })();
    let cleanup = imported
        .cleanup()
        .map_err(|error| FixCommandError::Scratch(Box::new(error)));
    finish_with_cleanup(result, cleanup)
}

fn capture_source_state(repository_root: &Path) -> Result<RepositoryState, FixCommandError> {
    capture_repository_state(repository_root)
        .map_err(|error| FixCommandError::Snapshot(Box::new(error)))
}

const fn source_publication_supported() -> bool {
    cfg!(any(target_os = "linux", target_vendor = "apple"))
}

fn require_source_publication_support(publication_supported: bool) -> Result<(), FixCommandError> {
    // LLM contract: SAFE_CANDIDATE -> PLATFORM_VERIFIED -> PUBLICATION_ALLOWED;
    // unsupported publication -> UNSUPPORTED. NO_CANDIDATE returns before this boundary.
    if !publication_supported {
        return Err(FixCommandError::ApplySafePlatformUnsupported);
    }
    Ok(())
}

fn require_source_state(
    repository_root: &Path,
    expected: &RepositoryState,
) -> Result<(), FixCommandError> {
    if &capture_source_state(repository_root)? != expected {
        return Err(FixCommandError::RepositoryChanged);
    }
    Ok(())
}

fn verify_published_repository(
    config: &RuntimeConfig,
    repository_root: &Path,
    expected_paths: &[String],
    source_state: &RepositoryState,
    expected_result: &Sha256Digest,
) -> Result<(), FixCommandError> {
    let current_state = capture_repository_state(repository_root)
        .map_err(|_| FixCommandError::AppliedRepositoryConflict)?;
    if !published_repository_identity_matches(&current_state, source_state) {
        return Err(FixCommandError::AppliedRepositoryConflict);
    }
    let current_paths = materialized_repository_paths(config, repository_root)
        .map_err(|_| FixCommandError::AppliedRepositoryConflict)?;
    if current_paths != expected_paths {
        return Err(FixCommandError::AppliedRepositoryConflict);
    }
    let comparison = stage_snapshot(config, repository_root, &current_paths)
        .map_err(|_| FixCommandError::AppliedRepositoryConflict)?;
    let matches = comparison.base_evidence().sha256 == *expected_result;
    comparison
        .cleanup()
        .map_err(|error| FixCommandError::AppliedAndCleanup {
            cleanup: Box::new(FixCommandError::Scratch(Box::new(error))),
        })?;
    if !matches {
        return Err(FixCommandError::AppliedRepositoryConflict);
    }
    Ok(())
}

fn published_repository_identity_matches(
    current: &RepositoryState,
    source: &RepositoryState,
) -> bool {
    current[0] == source[0] && current[1] == source[1] && current[3] == source[3]
}

fn finish_with_cleanup<T>(
    operation: Result<T, FixCommandError>,
    cleanup: Result<(), FixCommandError>,
) -> Result<T, FixCommandError> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(operation), Ok(())) => Err(operation),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(operation), Err(cleanup)) => Err(FixCommandError::OperationAndCleanup {
            operation: Box::new(operation),
            cleanup: Box::new(cleanup),
        }),
    }
}

fn finish_apply_with_cleanup<T>(
    operation: Result<(T, bool), FixCommandError>,
    cleanup: Result<(), FixCommandError>,
) -> Result<T, FixCommandError> {
    match (operation, cleanup) {
        (Ok((value, _)), Ok(())) => Ok(value),
        (Err(operation), Ok(())) => Err(operation),
        (Ok((_, true)), Err(cleanup)) => Err(FixCommandError::AppliedAndCleanup {
            cleanup: Box::new(cleanup),
        }),
        (Ok((_, false)), Err(cleanup)) => Err(cleanup),
        (Err(operation), Err(cleanup)) => Err(FixCommandError::OperationAndCleanup {
            operation: Box::new(operation),
            cleanup: Box::new(cleanup),
        }),
    }
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
    // LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED ->
    // REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.
    // Git documents that --cached lists index entries, not only materialized worktree paths:
    // https://git-scm.com/docs/git-ls-files
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

    let required_paths = configured_materialized_paths(config);
    let required_paths = required_paths.into_iter().collect::<BTreeSet<_>>();
    let mut materialized = Vec::with_capacity(paths.len() + required_paths.len());
    for path in paths.drain(..) {
        match fs::symlink_metadata(repository_root.join(&path)) {
            Ok(_) => materialized.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if required_paths.contains(&path) {
                    return Err(FixCommandError::MissingRequiredPath { path });
                }
                // `git ls-files --cached` includes tracked files deleted from the
                // worktree. They are unrelated unless explicitly selected below.
            }
            Err(source) => {
                return Err(FixCommandError::Snapshot(Box::new(std::io::Error::other(
                    format!("cannot inspect repository path {path}: {source}"),
                ))));
            }
        }
    }

    for path in required_paths {
        match fs::symlink_metadata(repository_root.join(&path)) {
            Ok(_) => materialized.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(FixCommandError::MissingRequiredPath { path });
            }
            Err(source) => {
                return Err(FixCommandError::Snapshot(Box::new(std::io::Error::other(
                    format!("cannot inspect required repository path {path}: {source}"),
                ))));
            }
        }
    }

    materialized.sort();
    materialized.dedup();
    Ok(materialized)
}

fn configured_materialized_paths(config: &RuntimeConfig) -> Vec<String> {
    let mut paths = Vec::new();
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
    paths
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
    use std::process::Command;
    use tempfile::tempdir;

    fn git_repository() -> tempfile::TempDir {
        let repository = tempdir().expect("repository");
        fs::create_dir(repository.path().join("src")).expect("source directory");
        fs::write(
            repository.path().join("src/lib.rs"),
            b"pub fn value() -> u8 { 1 }\n",
        )
        .expect("source");
        fs::write(repository.path().join("unrelated.txt"), b"unrelated\n").expect("unrelated");
        for arguments in [
            &["init", "-q"][..],
            &["config", "user.name", "test"][..],
            &["config", "user.email", "test@example.invalid"][..],
            &["config", "commit.gpgsign", "false"][..],
            &["add", "-A"][..],
            &["commit", "-qm", "baseline"][..],
        ] {
            assert!(
                Command::new("git")
                    .args(arguments)
                    .current_dir(repository.path())
                    .status()
                    .expect("git")
                    .success()
            );
        }
        repository
    }

    fn repository_config(target: &str) -> RuntimeConfig {
        RuntimeConfig::from_toml(&format!(
            "[engine]\nversion=\"0.1.0\"\nsource_revision=\"a12b34c56d78e90f1234567890abcdef12345678\"\n[repository]\nworkspace=\".\"\ntargets=[\"{target}\"]\n"
        ))
        .expect("valid configuration")
    }

    #[test]
    fn operation_and_cleanup_failures_are_both_retained() {
        let error = finish_with_cleanup::<()>(
            Err(FixCommandError::NoSafeCandidate),
            Err(FixCommandError::PatchFormat),
        )
        .expect_err("both failures remain visible");

        assert!(matches!(
            error,
            FixCommandError::OperationAndCleanup {
                operation,
                cleanup,
            } if matches!(*operation, FixCommandError::NoSafeCandidate)
                && matches!(*cleanup, FixCommandError::PatchFormat)
        ));
    }

    #[test]
    fn materialized_paths_ignore_unrelated_deleted_tracked_files() {
        let repository = git_repository();
        fs::remove_file(repository.path().join("unrelated.txt")).expect("delete unrelated");

        let config = repository_config("src");
        let paths = materialized_repository_paths(&config, repository.path()).expect("paths");
        assert!(paths.iter().any(|path| path == "src/lib.rs"));
        assert!(!paths.iter().any(|path| path == "unrelated.txt"));

        let scratch = stage_snapshot(&config, repository.path(), &paths).expect("scratch stage");
        scratch.cleanup().expect("scratch cleanup");
    }

    #[test]
    fn source_state_rejects_a_skipped_tracked_deletion_that_reappears() {
        let repository = git_repository();
        fs::remove_file(repository.path().join("unrelated.txt")).expect("delete unrelated");
        let source_state = capture_source_state(repository.path()).expect("source state");
        let config = repository_config("src");
        let paths = materialized_repository_paths(&config, repository.path()).expect("paths");
        assert!(!paths.iter().any(|path| path == "unrelated.txt"));

        fs::write(repository.path().join("unrelated.txt"), b"restored\n").expect("restore tracked");

        assert!(matches!(
            require_source_state(repository.path(), &source_state),
            Err(FixCommandError::RepositoryChanged)
        ));
    }

    #[test]
    fn unsupported_publication_platform_preserves_a_no_candidate_noop() {
        let repository = git_repository();
        let config = repository_config("src");
        let original = fs::read(repository.path().join("src/lib.rs")).expect("source");
        let mut emitted = false;

        let result = run_apply_safe_command_for_platform(
            &config,
            repository.path(),
            || None,
            false,
            |_| {
                emitted = true;
                Ok(())
            },
        )
        .expect("read-only no-op");

        assert!(result.patch.is_empty());
        assert!(!emitted);
        assert_eq!(
            fs::read(repository.path().join("src/lib.rs")).expect("unchanged source"),
            original
        );
    }

    #[test]
    fn publication_platform_gate_reports_unsupported_publication() {
        assert!(matches!(
            require_source_publication_support(false),
            Err(FixCommandError::ApplySafePlatformUnsupported)
        ));
        assert!(require_source_publication_support(true).is_ok());
    }

    #[test]
    fn published_identity_rejects_ignored_or_untracked_drift() {
        let source = [
            b"head".to_vec(),
            b"index".to_vec(),
            b"tracked-before".to_vec(),
            b"untracked-before".to_vec(),
        ];
        let mut current = source.clone();
        current[2] = b"tracked-after".to_vec();
        assert!(published_repository_identity_matches(&current, &source));

        current[3] = b"untracked-after".to_vec();
        assert!(!published_repository_identity_matches(&current, &source));
    }

    #[test]
    fn materialized_paths_reject_missing_required_target_explicitly() {
        let repository = git_repository();
        fs::remove_file(repository.path().join("src/lib.rs")).expect("delete target");

        let config = repository_config("src/lib.rs");
        let error = materialized_repository_paths(&config, repository.path())
            .expect_err("missing target must fail");
        assert!(matches!(
            error,
            FixCommandError::MissingRequiredPath { path } if path == "src/lib.rs"
        ));
    }

    #[test]
    fn applied_cleanup_failure_remains_explicitly_committed() {
        let error = finish_apply_with_cleanup(Ok(((), true)), Err(FixCommandError::PatchFormat))
            .expect_err("published cleanup failure");

        assert!(matches!(
            error,
            FixCommandError::AppliedAndCleanup { cleanup }
                if matches!(*cleanup, FixCommandError::PatchFormat)
        ));
    }

    #[test]
    fn noop_cleanup_failure_is_not_reported_as_applied() {
        assert!(matches!(
            finish_apply_with_cleanup(Ok(((), false)), Err(FixCommandError::PatchFormat)),
            Err(FixCommandError::PatchFormat)
        ));
    }

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
