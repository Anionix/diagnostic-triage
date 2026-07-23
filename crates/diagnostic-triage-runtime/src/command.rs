//! Narrow command facade used by the unpublished CLI crate.

use std::{fs, path::Path, str::FromStr};

use diagnostic_triage_contracts::{
    AdapterId, Capability, RepoPath, Sha256Digest,
    model::{SessionReport, Verdict},
    protocol::{
        EnvelopeKind, Operation, ProtocolEnvelope, ProtocolVersion, RequestEnvelope, RequestLimits,
    },
};
use diagnostic_triage_engine::deterministic_object_id;
use thiserror::Error;

use crate::orchestration::{
    ReadOnlyMode, assemble_read_only_report, execute_current_read_only_plan,
    project_executed_read_only_plan,
};
use crate::{
    RuntimeConfig,
    config::{
        DEFAULT_MAX_EVENTS, DEFAULT_MAX_EVIDENCE_BYTES, DEFAULT_MAX_STDERR_BYTES,
        DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_MS,
    },
    process::ProcessSpec,
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
}
