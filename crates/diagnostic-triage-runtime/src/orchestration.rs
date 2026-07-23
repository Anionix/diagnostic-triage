//! Pure, deterministic planning for read-only runtime sessions.

use std::{
    collections::BTreeSet,
    fs, io,
    path::{Component, Path, PathBuf},
};

use diagnostic_triage_contracts::protocol::{
    EnvelopeKind, Operation, ProtocolEnvelope, ProtocolVersion, RequestEnvelope, RequestLimits,
};
use diagnostic_triage_contracts::{
    AdapterId, ContractError, Nullable, ObjectId, RepoPath, Sha256Digest,
    model::{AdapterKind, Evidence, Execution, ExecutionStatus, FixCandidate, Observation, Tool},
};
use diagnostic_triage_engine::{EngineError, deterministic_object_id};
use serde::Serialize;
use thiserror::Error;

use crate::{
    config::{ConfigError, ProviderConfig, RuntimeConfig},
    execution::{ProviderExecutionInput, validated_provider_execution},
    execution_identity as identity,
    process::ProcessSpec,
    session::{
        ProviderSessionError, ProviderSessionOutcome, ProviderSessionState, run_provider_session,
    },
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

const PLAN_ID_DOMAIN: &str = "diagnostic-triage.runtime-plan/v1";
const REQUEST_ID_DOMAIN: &str = "diagnostic-triage.runtime-request/v1";
const EXECUTION_ID_DOMAIN: &str = "diagnostic-triage.runtime-execution/v1";
const MAX_EXECUTION_MESSAGE_CHARS: usize = 8_192;
const EMPTY_EXECUTION_MESSAGE: &str = "provider session ended without a reason";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadOnlyMode {
    Check,
    Ci,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlannedProvider {
    config: ProviderConfig,
    request: RequestEnvelope,
    execution_id: ObjectId,
}

impl PlannedProvider {
    fn run(
        self,
        workspace: &ResolvedWorkspace,
        program: PathBuf,
    ) -> Result<ExecutedProvider, ReadOnlyRunError> {
        let spec = ProcessSpec::new(program)
            .args(self.config.argv.clone())
            .current_dir(workspace.repository_root());
        let outcome = run_provider_session(
            spec,
            &self.config.adapter_id,
            &self.config.adapter_version,
            &self.request,
        )
        .map_err(|source| ReadOnlyRunError::Provider {
            adapter_id: self.config.adapter_id.clone(),
            source,
        })?;
        Ok(ExecutedProvider {
            planned: self,
            outcome,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadOnlyPlan {
    plan_id: ObjectId,
    targets: Vec<RepoPath>,
    providers: Vec<PlannedProvider>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecutedProvider {
    planned: PlannedProvider,
    outcome: ProviderSessionOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecutedReadOnlyPlan {
    plan_id: ObjectId,
    providers: Vec<ExecutedProvider>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ReadOnlyRuntimeProjection {
    plan_id: ObjectId,
    observations: Vec<Observation>,
    evidence: Vec<Evidence>,
    fix_candidates: Vec<FixCandidate>,
    executions: Vec<Execution>,
}
struct ResolvedWorkspace {
    repository_root: PathBuf,
    workspace_root: PathBuf,
}

impl ResolvedWorkspace {
    fn repository_root(&self) -> &Path {
        &self.repository_root
    }
}

#[derive(Debug, Error)]
pub(crate) enum ReadOnlyPlanError {
    #[error("runtime configuration is invalid")]
    Config(#[from] ConfigError),
    #[error("plan identity could not be encoded")]
    Encoding(#[from] serde_json::Error),
    #[error("plan identity could not be derived")]
    Identity(#[from] EngineError),
    #[error("planned request is invalid")]
    Contract(#[from] ContractError),
    #[error("planned object identifiers collided")]
    IdentityCollision,
}

#[derive(Debug, Error)]
pub(crate) enum ReadOnlyRunError {
    #[error(transparent)]
    Plan(#[from] ReadOnlyPlanError),
    #[error("failed to {operation} at {path}")]
    WorkspaceIo {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("workspace is not a directory: {path}")]
    WorkspaceNotDirectory { path: PathBuf },
    #[error("workspace {workspace} escapes trusted repository root {repository_root}")]
    WorkspaceEscape {
        workspace: PathBuf,
        repository_root: PathBuf,
    },
    #[error("failed to resolve provider program {program}")]
    ProviderProgramIo {
        program: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("provider program {program} escapes trusted repository root {repository_root}")]
    ProviderProgramEscape {
        program: PathBuf,
        repository_root: PathBuf,
    },
    #[error("provider program path form is unsupported: {program}")]
    ProviderProgramUnsupported { program: PathBuf },
    #[error("failed to resolve provider target {target}")]
    ProviderTargetIo {
        target: RepoPath,
        #[source]
        source: io::Error,
    },
    #[error("provider target {target} escapes trusted workspace {workspace}")]
    ProviderTargetEscape {
        target: RepoPath,
        workspace: PathBuf,
    },
    #[error("provider session failed for {adapter_id}")]
    Provider {
        adapter_id: AdapterId,
        #[source]
        source: ProviderSessionError,
    },
}

#[derive(Debug, Error)]
pub(crate) enum ProviderExecutionError {
    #[error("provider {0} projection identity mismatch: {1:?}")]
    Mismatch(AdapterId, identity::ProviderIdentityMismatch),
    #[error("provider tool duration is out of range")]
    Duration,
    #[error(transparent)]
    Contract(#[from] ContractError),
}

#[derive(Debug, Error)]
pub(crate) enum RuntimeProjectionError {
    #[error(transparent)]
    Provider(#[from] ProviderExecutionError),
    #[error("runtime projection object ID collided: {0}")]
    ObjectIdCollision(ObjectId),
}
pub(crate) fn build_read_only_plan(
    config: &RuntimeConfig,
    repository_digest: &Sha256Digest,
    mode: ReadOnlyMode,
) -> Result<ReadOnlyPlan, ReadOnlyPlanError> {
    let config = config.normalized()?;
    let limits = RequestLimits::try_from(&config.limits)?;
    let config_json = serde_json::to_string(&config)?;
    let mode = match mode {
        ReadOnlyMode::Check => "check",
        ReadOnlyMode::Ci => "ci",
    };
    let plan_id = deterministic_object_id(
        PLAN_ID_DOMAIN,
        [mode, config_json.as_str(), repository_digest.as_str()],
    )?;
    // RFC 9562 section 5.8: UUIDv8 uniqueness is implementation-specific; reject duplicates.
    let mut object_ids = BTreeSet::from([plan_id.clone()]);
    let targets = config.repository.targets;
    let mut providers = Vec::with_capacity(config.providers.len());
    for provider in config.providers {
        let request_id = deterministic_object_id(
            REQUEST_ID_DOMAIN,
            [plan_id.as_str(), provider.adapter_id.as_str()],
        )?;
        let execution_id = deterministic_object_id(
            EXECUTION_ID_DOMAIN,
            [plan_id.as_str(), provider.adapter_id.as_str()],
        )?;
        if !object_ids.insert(request_id.clone()) || !object_ids.insert(execution_id.clone()) {
            return Err(ReadOnlyPlanError::IdentityCollision);
        }
        let request = RequestEnvelope {
            protocol_version: ProtocolVersion::V1,
            kind: EnvelopeKind::Request,
            request_id,
            operation: Operation::Check,
            workspace: config.repository.workspace.clone(),
            targets: targets.clone(),
            required_capabilities: provider.required_capabilities.clone(),
            optional_capabilities: provider.optional_capabilities.clone(),
            limits: limits.clone(),
        };
        ProtocolEnvelope::Request(request.clone()).validate()?;
        providers.push(PlannedProvider {
            config: provider,
            request,
            execution_id,
        });
    }
    Ok(ReadOnlyPlan {
        plan_id,
        targets,
        providers,
    })
}

pub(crate) fn execute_read_only_plan(
    config: &RuntimeConfig,
    repository_root: &Path,
    repository_digest: &Sha256Digest,
    mode: ReadOnlyMode,
) -> Result<ExecutedReadOnlyPlan, ReadOnlyRunError> {
    let plan = build_read_only_plan(config, repository_digest, mode)?;
    let workspace = resolve_workspace(repository_root, &config.repository.workspace)?;
    let ReadOnlyPlan {
        plan_id,
        targets,
        providers,
    } = plan;
    // LLM contract: PLANNED -> TARGETS_PREFLIGHTED -> PROGRAMS_PREFLIGHTED -> PROVIDER_STARTED; target rejection -> zero Provider launches.
    validate_provider_targets(&workspace, &targets)?;
    let programs = providers
        .iter()
        .map(|provider| {
            resolve_provider_program(workspace.repository_root(), &provider.config.program)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut executed = Vec::with_capacity(providers.len());
    for (planned, program) in providers.into_iter().zip(programs) {
        executed.push(planned.run(&workspace, program)?);
    }
    Ok(ExecutedReadOnlyPlan {
        plan_id,
        providers: executed,
    })
}

fn validate_provider_targets(
    workspace: &ResolvedWorkspace,
    targets: &[RepoPath],
) -> Result<(), ReadOnlyRunError> {
    // All planned Providers receive this same normalized target list. Validate the
    // complete list before resolving or launching the first Provider process.
    for target in targets {
        let candidate = workspace.repository_root.join(target.as_str());
        let resolved = canonical_existing_ancestor(&candidate, target, &workspace.workspace_root)?;
        if !resolved.starts_with(&workspace.workspace_root) {
            return Err(ReadOnlyRunError::ProviderTargetEscape {
                target: target.clone(),
                workspace: workspace.workspace_root.clone(),
            });
        }
    }
    Ok(())
}

fn canonical_existing_ancestor(
    candidate: &Path,
    target: &RepoPath,
    workspace_root: &Path,
) -> Result<PathBuf, ReadOnlyRunError> {
    let mut current = candidate;
    loop {
        match fs::symlink_metadata(current) {
            Ok(_) => {
                return fs::canonicalize(current).map_err(|source| {
                    ReadOnlyRunError::ProviderTargetIo {
                        target: target.clone(),
                        source,
                    }
                });
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                current =
                    current
                        .parent()
                        .ok_or_else(|| ReadOnlyRunError::ProviderTargetEscape {
                            target: target.clone(),
                            workspace: workspace_root.to_path_buf(),
                        })?;
            }
            Err(source) => {
                return Err(ReadOnlyRunError::ProviderTargetIo {
                    target: target.clone(),
                    source,
                });
            }
        }
    }
}

fn synthesize_execution(
    planned: &PlannedProvider,
    state: &ProviderSessionState,
) -> Result<Execution, ProviderExecutionError> {
    use ProviderSessionState as State;
    use identity::ExpectedCompletion as Completion;

    let (status, session, completion, exit_code) = match state {
        State::Complete(session) => (
            ExecutionStatus::Complete,
            Some(session.as_ref()),
            Completion::Complete,
            session.completion.tool_exit_code.clone(),
        ),
        State::Incomplete {
            reason,
            validated_session,
        } => (
            ExecutionStatus::Incomplete,
            validated_session.as_deref(),
            Completion::Incomplete(reason),
            Nullable(None),
        ),
        State::Unsupported {
            reason,
            validated_session,
            ..
        } => (
            ExecutionStatus::Unsupported,
            validated_session.as_deref(),
            Completion::Unsupported(reason),
            Nullable(None),
        ),
    };
    if let Some(session) = session {
        identity::validate_provider_execution_identity(
            &identity::ProviderExecutionIdentity {
                request: &planned.request,
                adapter_id: &planned.config.adapter_id,
                adapter_version: &planned.config.adapter_version,
                adapter_kind: AdapterKind::Provider,
                tool_name: &planned.config.tool_name,
                tool_version: &planned.config.tool_version,
                completion,
            },
            session,
        )
        .map_err(|mismatch| {
            ProviderExecutionError::Mismatch(planned.config.adapter_id.clone(), mismatch)
        })?;
    }
    let run_ms = session
        .map(|value| {
            u32::try_from(value.completion.tool_duration_ms)
                .map_err(|_| ProviderExecutionError::Duration)
        })
        .transpose()?;
    let message = match completion {
        Completion::Complete => session.and_then(|value| value.completion.message.clone()),
        Completion::Incomplete(reason) | Completion::Unsupported(reason) => {
            Some(bounded_message(reason))
        }
    };
    validated_provider_execution(ProviderExecutionInput {
        execution_id: planned.execution_id.clone(),
        adapter_id: planned.config.adapter_id.clone(),
        tool: Tool {
            name: planned.config.tool_name.clone(),
            version: planned.config.tool_version.clone(),
            rule_id: None,
        },
        required: planned.config.required,
        status,
        exit_code,
        message,
        run_duration_ms: run_ms,
    })
    .map_err(ProviderExecutionError::from)
}

pub(crate) fn project_executed_read_only_plan(
    executed: ExecutedReadOnlyPlan,
) -> Result<ReadOnlyRuntimeProjection, RuntimeProjectionError> {
    let ExecutedReadOnlyPlan { plan_id, providers } = executed;
    project_provider_states(
        plan_id,
        providers
            .into_iter()
            .map(|provider| (provider.planned, provider.outcome.state))
            .collect(),
    )
}

fn project_provider_states(
    plan_id: ObjectId,
    mut providers: Vec<(PlannedProvider, ProviderSessionState)>,
) -> Result<ReadOnlyRuntimeProjection, RuntimeProjectionError> {
    providers.sort_by(|left, right| left.0.config.adapter_id.cmp(&right.0.config.adapter_id));
    // LLM contract: EXECUTED -> IDENTITIES_VALIDATED -> COMPLETE_PAYLOAD_PROJECTED -> CANONICALIZED; any mismatch or collision -> REJECTED atomically.
    let mut executions = providers
        .iter()
        .map(|(planned, state)| {
            synthesize_execution(planned, state).map_err(RuntimeProjectionError::Provider)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut object_ids = vec![plan_id.clone()];
    for (planned, _) in &providers {
        object_ids.push(planned.request.request_id.clone());
        object_ids.push(planned.execution_id.clone());
    }
    let (mut observations, mut evidence, mut fix_candidates) = (Vec::new(), Vec::new(), Vec::new());
    for (_, state) in providers {
        let ProviderSessionState::Complete(session) = state else {
            continue;
        };
        for event in session.events {
            match event {
                ProtocolEnvelope::Observation(mut envelope) => {
                    envelope.observation.evidence_ids.sort();
                    object_ids.push(envelope.observation.observation_id.clone());
                    observations.push(envelope.observation);
                }
                ProtocolEnvelope::Evidence(envelope) => {
                    object_ids.push(envelope.evidence.evidence_id.clone());
                    evidence.push(envelope.evidence);
                }
                ProtocolEnvelope::FixCandidate(mut envelope) => {
                    envelope.fix_candidate.observation_ids.sort();
                    object_ids.push(envelope.fix_candidate.fix_candidate_id.clone());
                    fix_candidates.push(envelope.fix_candidate);
                }
                ProtocolEnvelope::Manifest(_)
                | ProtocolEnvelope::Request(_)
                | ProtocolEnvelope::Execution(_)
                | ProtocolEnvelope::Completion(_) => {}
            }
        }
    }
    object_ids.sort();
    if let Some(collision) = object_ids
        .windows(2)
        .find(|pair| pair[0] == pair[1])
        .map(|pair| pair[0].clone())
    {
        return Err(RuntimeProjectionError::ObjectIdCollision(collision));
    }
    observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
    evidence.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    fix_candidates.sort_by(|left, right| left.fix_candidate_id.cmp(&right.fix_candidate_id));
    executions.sort_by(|left, right| left.execution_id.cmp(&right.execution_id));
    Ok(ReadOnlyRuntimeProjection {
        plan_id,
        observations,
        evidence,
        fix_candidates,
        executions,
    })
}

fn bounded_message(message: &str) -> String {
    match message {
        "" => EMPTY_EXECUTION_MESSAGE.to_owned(),
        value => value.chars().take(MAX_EXECUTION_MESSAGE_CHARS).collect(),
    }
}

fn resolve_workspace(
    repository_root: &Path,
    workspace: &diagnostic_triage_contracts::RepoPath,
) -> Result<ResolvedWorkspace, ReadOnlyRunError> {
    let repository_root =
        fs::canonicalize(repository_root).map_err(|source| ReadOnlyRunError::WorkspaceIo {
            operation: "canonicalize repository root",
            path: repository_root.to_path_buf(),
            source,
        })?;
    let candidate = repository_root.join(workspace.as_str());
    let resolved =
        fs::canonicalize(&candidate).map_err(|source| ReadOnlyRunError::WorkspaceIo {
            operation: "canonicalize workspace",
            path: candidate,
            source,
        })?;
    if !resolved.starts_with(&repository_root) {
        return Err(ReadOnlyRunError::WorkspaceEscape {
            workspace: resolved,
            repository_root,
        });
    }
    if !resolved.is_dir() {
        return Err(ReadOnlyRunError::WorkspaceNotDirectory { path: resolved });
    }
    Ok(ResolvedWorkspace {
        repository_root,
        workspace_root: resolved,
    })
}

fn resolve_provider_program(
    repository_root: &Path,
    configured: &str,
) -> Result<PathBuf, ReadOnlyRunError> {
    let program = Path::new(configured);
    if program.is_absolute() || is_bare_program_name(program) {
        return Ok(program.to_path_buf());
    }
    if program.has_root()
        || matches!(program.components().next(), Some(Component::Prefix(_)))
        || !configured.chars().any(std::path::is_separator)
    {
        return Err(ReadOnlyRunError::ProviderProgramUnsupported {
            program: program.to_path_buf(),
        });
    }

    let candidate = repository_root.join(program);
    let resolved =
        fs::canonicalize(&candidate).map_err(|source| ReadOnlyRunError::ProviderProgramIo {
            program: candidate,
            source,
        })?;
    if !resolved.starts_with(repository_root) {
        return Err(ReadOnlyRunError::ProviderProgramEscape {
            program: resolved,
            repository_root: repository_root.to_path_buf(),
        });
    }
    Ok(resolved)
}

fn is_bare_program_name(program: &Path) -> bool {
    let mut components = program.components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

#[cfg(test)]
mod tests {
    use std::{env, fs};

    use super::{
        PlannedProvider, ReadOnlyMode, RuntimeProjectionError, build_read_only_plan,
        execute_read_only_plan, project_provider_states, resolve_provider_program,
        resolve_workspace, synthesize_execution,
    };
    use crate::{RuntimeConfig, session::ProviderSessionState};
    use diagnostic_triage_contracts::{
        ObjectId, Sha256Digest, ValidatedSession,
        model::{Execution, ExecutionStatus, PhaseDuration},
        protocol::Operation,
        validate_session_jsonl,
    };
    use tempfile::tempdir;

    const REVISION: &str = "a12b34c56d78e90f1234567890abcdef12345678";
    const SESSION_JSONL: &str = include_str!("../../../tests/fixtures/v1/valid-session.jsonl");
    const FIX_SESSION_JSONL: &str =
        include_str!("../../../tests/fixtures/v1/invalid-fix-nonpatch-evidence.jsonl");
    const ALPHA: &str = "[[providers]]\nadapter_id=\"alpha\"\nadapter_version=\"1\"\ntool_name=\"ruff\"\ntool_version=\"0.12\"\nprogram=\"provider\"\nargv=[\"--stdio\"]\nrequired=true\nrequired_capabilities=[\"diagnostic.fix/v1\",\"diagnostic.check/v1\"]\noptional_capabilities=[\"diagnostic.metadata/v1\"]";
    const ZETA: &str = "[[providers]]\nadapter_id=\"zeta\"\nadapter_version=\"1\"\ntool_name=\"ruff\"\ntool_version=\"0.12\"\nprogram=\"provider\"\nargv=[\"--stdio\"]\nrequired=true\nrequired_capabilities=[\"diagnostic.fix/v1\",\"diagnostic.check/v1\"]\noptional_capabilities=[\"diagnostic.metadata/v1\"]";

    fn config(target: &str) -> RuntimeConfig {
        RuntimeConfig::from_toml(&format!(
            "[engine]\nversion=\"0.1.0\"\nsource_revision=\"{REVISION}\"\n\
             [repository]\nworkspace=\".\"\ntargets=[\"shared\",\"{target}\"]\n{ALPHA}\n{ZETA}\n\
             [limits]\ntimeout_ms=1234\nmax_stdout_bytes=321\nmax_stderr_bytes=654\nmax_evidence_bytes=777\nmax_events=8"
        ))
        .expect("valid plan config")
    }

    fn execution_fixture() -> (PlannedProvider, ValidatedSession) {
        let session = validate_session_jsonl(SESSION_JSONL.as_bytes()).unwrap();
        let mut config = config("src").providers.remove(0);
        config.adapter_id = session.manifest.adapter.id.clone();
        config.adapter_version = session.manifest.adapter.version.clone();
        config.tool_name = "ruff".to_owned();
        config.tool_version = "0.12.4".to_owned();
        let planned = PlannedProvider {
            config,
            request: session.request.clone(),
            execution_id: "019f7e95-0000-7000-8000-000000000009".parse().unwrap(),
        };
        (planned, session)
    }

    fn fixture_terminal(status: &str) -> ValidatedSession {
        let input = SESSION_JSONL.replace(
            "\"status\":\"COMPLETE\",\"tool_exit_code\":1",
            &format!("\"status\":\"{status}\",\"tool_exit_code\":null,\"message\":\"terminal\""),
        );
        validate_session_jsonl(input.as_bytes()).unwrap()
    }

    fn project(planned: &PlannedProvider, state: &ProviderSessionState) -> Execution {
        synthesize_execution(planned, state).unwrap()
    }

    fn aggregate_fixture(
        adapter_id: &str,
        request_suffix: u16,
        required: bool,
    ) -> (PlannedProvider, ValidatedSession) {
        let request_id = format!("019f7e95-0000-7000-8000-{request_suffix:012}");
        let input = FIX_SESSION_JSONL
            .replace("\"source\":\"STDOUT\"", "\"source\":\"PATCH\"")
            .replace("\"id\":\"ruff\"", &format!("\"id\":\"{adapter_id}\""))
            .replace("019f7e95-0000-7000-8000-000000000271", &request_id);
        let session = validate_session_jsonl(input.as_bytes()).unwrap();
        let mut provider = config("src").providers.remove(0);
        provider.adapter_id = session.manifest.adapter.id.clone();
        provider.adapter_version = session.manifest.adapter.version.clone();
        provider.tool_name = "ruff".to_owned();
        provider.tool_version = "0.12.4".to_owned();
        provider.required = required;
        let planned = PlannedProvider {
            config: provider,
            request: session.request.clone(),
            execution_id: format!("019f7e95-0000-7000-8000-{:012}", request_suffix + 1)
                .parse()
                .unwrap(),
        };
        (planned, session)
    }

    #[test]
    fn synthesizes_execution_only_from_planned_identity_and_session_state() {
        let (planned, session) = execution_fixture();
        let complete = project(
            &planned,
            &ProviderSessionState::Complete(Box::new(session.clone())),
        );
        assert_eq!(complete.execution_id, planned.execution_id);
        assert_eq!(complete.adapter_id, planned.config.adapter_id);
        assert_eq!(complete.tool.name, planned.config.tool_name);
        assert!(complete.required);
        assert_eq!(complete.status, ExecutionStatus::Complete);
        assert_eq!(complete.exit_code.0, Some(1));
        assert_eq!(complete.phases_ms.run, PhaseDuration::Milliseconds(184));

        let terminal = fixture_terminal("INCOMPLETE");
        let incomplete = project(
            &planned,
            &ProviderSessionState::Incomplete {
                reason: "terminal".to_owned(),
                validated_session: Some(Box::new(terminal)),
            },
        );
        assert_eq!(incomplete.status, ExecutionStatus::Incomplete);
        assert_eq!(incomplete.exit_code.0, None);
        assert_eq!(incomplete.phases_ms.run, PhaseDuration::Milliseconds(184));

        let unsupported = project(
            &planned,
            &ProviderSessionState::Unsupported {
                missing_required: Vec::new(),
                reason: "x".repeat(9_000),
                validated_session: None,
            },
        );
        assert_eq!(unsupported.message.unwrap().chars().count(), 8_192);
        assert_eq!(
            unsupported.phases_ms.run,
            PhaseDuration::Unavailable(diagnostic_triage_contracts::model::Unavailable::Value)
        );

        assert_eq!(super::bounded_message(""), super::EMPTY_EXECUTION_MESSAGE);
        let mut overflow = session;
        overflow.completion.tool_duration_ms = u64::MAX;
        let state = ProviderSessionState::Complete(Box::new(overflow));
        assert!(matches!(
            synthesize_execution(&planned, &state),
            Err(super::ProviderExecutionError::Duration)
        ));
    }

    #[test]
    fn aggregate_projection_is_canonical_complete_only_and_collision_safe() {
        let (first, first_session) = aggregate_fixture("alpha", 281, true);
        let (second, second_session) = aggregate_fixture("zeta", 283, false);
        let plan_id: ObjectId = "019f7e95-0000-7000-8000-000000000280".parse().unwrap();
        let complete = ProviderSessionState::Complete(Box::new(first_session.clone()));
        let terminal = ProviderSessionState::Unsupported {
            missing_required: Vec::new(),
            reason: "terminal".to_owned(),
            validated_session: None,
        };
        let mut states = vec![
            (first.clone(), complete.clone()),
            (second.clone(), terminal),
        ];
        let forward = project_provider_states(plan_id.clone(), states.clone()).unwrap();
        states.reverse();
        let reverse = project_provider_states(plan_id.clone(), states).unwrap();
        assert_eq!(
            serde_json::to_vec(&forward).unwrap(),
            serde_json::to_vec(&reverse).unwrap()
        );
        assert_eq!(forward.observations.len(), 1);
        assert_eq!(forward.evidence.len(), 1);
        assert_eq!(forward.fix_candidates.len(), 1);
        assert_eq!(forward.executions.len(), 2);
        assert!(forward.executions[0].required);
        assert!(!forward.executions[1].required);

        let collision = project_provider_states(
            plan_id,
            vec![
                (first.clone(), complete.clone()),
                (
                    second,
                    ProviderSessionState::Complete(Box::new(second_session)),
                ),
            ],
        );
        assert!(matches!(
            collision,
            Err(RuntimeProjectionError::ObjectIdCollision(_))
        ));

        let reserved = project_provider_states(
            "019f7e95-0000-7000-8000-000000000272".parse().unwrap(),
            vec![(first.clone(), complete.clone())],
        );
        assert!(matches!(
            reserved,
            Err(RuntimeProjectionError::ObjectIdCollision(_))
        ));

        let mut mismatch = first;
        mismatch.config.tool_version = "wrong".to_owned();
        let error = project_provider_states(
            "019f7e95-0000-7000-8000-000000000280".parse().unwrap(),
            vec![(mismatch, complete)],
        );
        assert!(matches!(error, Err(RuntimeProjectionError::Provider(..))));
    }

    #[test]
    fn executes_absolute_provider_under_trusted_repository_root() {
        let repository = tempdir().unwrap();
        let mut config = config("src");
        fs::create_dir(repository.path().join("workspace")).unwrap();
        config.repository.workspace = "workspace".parse().unwrap();
        config.repository.targets = vec!["workspace".parse().unwrap()];
        config.providers.truncate(1);
        config.providers[0].program = env::current_exe().unwrap().to_str().unwrap().to_owned();
        config.providers[0].argv = vec!["--exact".to_owned(), "__no_such_test__".to_owned()];
        let executed = execute_read_only_plan(
            &config,
            repository.path(),
            &Sha256Digest::compute(b"repository"),
            ReadOnlyMode::Check,
        )
        .unwrap();

        let resolved = resolve_workspace(repository.path(), &config.repository.workspace).unwrap();
        assert_eq!(
            resolved.repository_root,
            fs::canonicalize(repository.path()).unwrap()
        );
        assert_eq!(
            resolved.workspace_root,
            fs::canonicalize(repository.path().join("workspace")).unwrap()
        );
        let state = &executed.providers[0].outcome.state;
        assert!(matches!(state, ProviderSessionState::Incomplete { .. }));
    }

    #[test]
    fn resolves_only_explicit_relative_programs_against_repository_root() {
        let repository = tempdir().unwrap();
        let repository_root = fs::canonicalize(repository.path()).unwrap();
        fs::create_dir(repository.path().join("bin")).unwrap();
        let provider = repository.path().join("bin/provider");
        fs::write(&provider, b"provider").unwrap();

        assert_eq!(
            resolve_provider_program(&repository_root, "./bin/provider").unwrap(),
            fs::canonicalize(&provider).unwrap()
        );
        assert_eq!(
            resolve_provider_program(&repository_root, "provider").unwrap(),
            std::path::PathBuf::from("provider")
        );
        let absolute = env::current_exe().unwrap();
        assert_eq!(
            resolve_provider_program(&repository_root, absolute.to_str().unwrap()).unwrap(),
            absolute
        );
    }

    #[test]
    fn launches_repo_relative_provider_from_outside_repository() {
        let repository = tempdir().unwrap();
        fs::create_dir(repository.path().join("bin")).unwrap();
        let program = format!("provider{}", env::consts::EXE_SUFFIX);
        fs::copy(
            env::current_exe().unwrap(),
            repository.path().join("bin").join(&program),
        )
        .unwrap();
        assert!(!env::current_dir().unwrap().starts_with(repository.path()));

        let mut config = config("src");
        config.providers.truncate(1);
        config.providers[0].program = format!("./bin/{program}");
        config.providers[0].argv = vec!["--exact".to_owned(), "__no_such_test__".to_owned()];
        let executed = execute_read_only_plan(
            &config,
            repository.path(),
            &Sha256Digest::compute(b"repository"),
            ReadOnlyMode::Check,
        )
        .unwrap();

        assert!(matches!(
            executed.providers[0].outcome.state,
            ProviderSessionState::Incomplete { .. }
        ));
    }

    #[test]
    fn preflights_every_provider_program_before_first_launch() {
        let root = tempdir().unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        fs::write(root.path().join("outside-provider"), b"outside").unwrap();
        let mut config = config("src");
        config.providers[0].program = repository
            .join("missing-first-provider")
            .to_str()
            .unwrap()
            .to_owned();
        config.providers[1].program = "../outside-provider".to_owned();

        let error = execute_read_only_plan(
            &config,
            &repository,
            &Sha256Digest::compute(b"repository"),
            ReadOnlyMode::Check,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            super::ReadOnlyRunError::ProviderProgramEscape { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_target_symlink_escape_before_provider_launch() {
        use std::os::unix::fs::symlink;

        let repository = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::create_dir(repository.path().join("workspace")).unwrap();
        fs::write(repository.path().join("enable-launch-probe"), b"").unwrap();
        symlink(outside.path(), repository.path().join("workspace/link")).unwrap();
        let mut config = config("workspace/link/missing.py");
        config.repository.workspace = "workspace".parse().unwrap();
        config.repository.targets = vec!["workspace/missing.py".parse().unwrap()];
        config.providers.truncate(1);
        config.providers[0].program = env::current_exe().unwrap().to_str().unwrap().to_owned();
        config.providers[0].argv = vec![
            "--ignored".to_owned(),
            "--exact".to_owned(),
            "orchestration::tests::provider_launch_probe".to_owned(),
        ];

        execute_read_only_plan(
            &config,
            repository.path(),
            &Sha256Digest::compute(b"repository"),
            ReadOnlyMode::Check,
        )
        .unwrap();
        assert!(repository.path().join("provider-launched").is_file());
        fs::remove_file(repository.path().join("provider-launched")).unwrap();

        config.repository.targets = vec!["workspace/link/missing.py".parse().unwrap()];
        let error = execute_read_only_plan(
            &config,
            repository.path(),
            &Sha256Digest::compute(b"repository"),
            ReadOnlyMode::Check,
        )
        .unwrap_err();

        assert!(!repository.path().join("provider-launched").exists());
        assert!(matches!(
            error,
            super::ReadOnlyRunError::ProviderTargetEscape { .. }
        ));
    }

    #[test]
    #[ignore = "invoked only as an isolated child-process launch probe"]
    fn provider_launch_probe() {
        if std::path::Path::new("enable-launch-probe").is_file() {
            fs::write("provider-launched", b"launched").unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_provider_program_symlink_escape_before_launch() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let repository = root.path().join("repository");
        let outside = root.path().join("outside-provider");
        fs::create_dir(&repository).unwrap();
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, repository.join("provider")).unwrap();
        let repository_root = fs::canonicalize(&repository).unwrap();

        let error = resolve_provider_program(&repository_root, "./provider").unwrap_err();

        assert!(matches!(
            error,
            super::ReadOnlyRunError::ProviderProgramEscape { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_workspace_symlink_escape_before_provider_execution() {
        use std::os::unix::fs::symlink;

        let repository = tempdir().unwrap();
        let outside = tempdir().unwrap();
        symlink(outside.path(), repository.path().join("escape")).unwrap();
        let mut config = config("src");
        config.repository.workspace = "escape".parse().unwrap();

        let error = execute_read_only_plan(
            &config,
            repository.path(),
            &Sha256Digest::compute(b"repository"),
            ReadOnlyMode::Check,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            super::ReadOnlyRunError::WorkspaceEscape { .. }
        ));
    }

    #[test]
    fn plans_are_canonical_domain_separated_and_input_sensitive() {
        let digest = Sha256Digest::compute(b"repository");
        let runtime_config = config("src");
        let forward = build_read_only_plan(&runtime_config, &digest, ReadOnlyMode::Check).unwrap();
        let repeated = build_read_only_plan(&runtime_config, &digest, ReadOnlyMode::Check).unwrap();
        let mut reversed = runtime_config.clone();
        reversed.providers.reverse();
        reversed.repository.targets.reverse();
        for provider in &mut reversed.providers {
            provider.required_capabilities.reverse();
        }
        let reverse = build_read_only_plan(&reversed, &digest, ReadOnlyMode::Check).unwrap();
        assert_eq!(forward, repeated);
        assert_eq!(forward, reverse);
        assert_eq!(forward.providers.len(), 2);
        let (first, second) = (&forward.providers[0], &forward.providers[1]);
        let (request, provider) = (&first.request, &first.config);
        assert_eq!(provider, &runtime_config.providers[0]);
        assert_eq!(request.workspace, runtime_config.repository.workspace);
        assert_eq!(request.targets, runtime_config.repository.targets);
        assert_eq!(request.limits, runtime_config.request_limits().unwrap());
        assert_eq!(request.operation, Operation::Check);
        assert_eq!(
            request.required_capabilities,
            provider.required_capabilities
        );
        assert_eq!(
            request.optional_capabilities,
            provider.optional_capabilities
        );
        assert_ne!(request.request_id, first.execution_id);
        assert_ne!(request.request_id, second.request.request_id);
        assert_ne!(first.execution_id, second.execution_id);
        assert_eq!(
            serde_json::to_vec(request).unwrap(),
            serde_json::to_vec(&repeated.providers[0].request).unwrap()
        );

        let ci = build_read_only_plan(&runtime_config, &digest, ReadOnlyMode::Ci).unwrap();
        let changed_digest = build_read_only_plan(
            &runtime_config,
            &Sha256Digest::compute(b"other repository"),
            ReadOnlyMode::Check,
        )
        .unwrap();
        let changed_target =
            build_read_only_plan(&config("tests"), &digest, ReadOnlyMode::Check).unwrap();
        let mut changed_provider = runtime_config.clone();
        changed_provider.providers[0].tool_version.push_str(".1");
        let changed_provider =
            build_read_only_plan(&changed_provider, &digest, ReadOnlyMode::Check).unwrap();
        for changed in [&ci, &changed_digest, &changed_target, &changed_provider] {
            assert_ne!(forward.plan_id, changed.plan_id);
            assert_ne!(
                first.request.request_id,
                changed.providers[0].request.request_id
            );
            assert_ne!(first.execution_id, changed.providers[0].execution_id);
        }
        assert_eq!(ci.providers[0].request.operation, Operation::Check);

        let mut one = runtime_config.clone();
        one.providers.truncate(1);
        let one = build_read_only_plan(&one, &digest, ReadOnlyMode::Check).unwrap();
        assert_eq!(one.providers.len(), 1);
        let mut no_providers = runtime_config;
        no_providers.providers.clear();
        let empty = build_read_only_plan(&no_providers, &digest, ReadOnlyMode::Check).unwrap();
        assert!(empty.providers.is_empty());
    }
}
