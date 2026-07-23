//! Pure, deterministic planning for read-only runtime sessions.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::BTreeSet,
    fs, io,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use diagnostic_triage_contracts::protocol::{
    EnvelopeKind, Operation, ProtocolEnvelope, ProtocolVersion, RequestEnvelope, RequestLimits,
};
use diagnostic_triage_contracts::{
    AdapterId, ContractError, Nullable, ObjectId, RepoPath, Sha256Digest,
    model::{
        AdapterKind, EngineIdentity, Evidence, Execution, ExecutionStatus, FixCandidate,
        Observation, SessionReport, Tool,
    },
};
use diagnostic_triage_engine::{
    EngineError,
    dedup::deduplicate_findings,
    deterministic_object_id,
    finding::build_finding,
    report::{
        ReportAssemblyError, ReportAssemblyInput, assemble_session_report,
        validate_report_collection_count,
    },
};
use serde::Serialize;
use thiserror::Error;

use crate::{
    config::{ConfigError, ProviderConfig, RuntimeConfig},
    execution::{ProviderExecutionInput, validated_provider_execution},
    execution_identity as identity,
    process::{ProcessError, ProcessLimits, ProcessSpec, ProcessState, run_bounded},
    scratch::{ScratchError, ScratchPatch, ScratchWorkspace},
    session::{
        ProviderSessionError, ProviderSessionOutcome, ProviderSessionState, run_provider_session,
    },
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

const PLAN_ID_DOMAIN: &str = "diagnostic-triage.runtime-plan/v1";
const REQUEST_ID_DOMAIN: &str = "diagnostic-triage.runtime-request/v1";
const EXECUTION_ID_DOMAIN: &str = "diagnostic-triage.runtime-execution/v1";
const FIX_PROPOSE_CAPABILITY: &str = "fix.propose/v1";
const MAX_EXECUTION_MESSAGE_CHARS: usize = 8_192;
const EMPTY_EXECUTION_MESSAGE: &str = "provider session ended without a reason";
const REPOSITORY_STATE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadOnlyMode {
    Check,
    Ci,
    Fix,
    Verify,
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
    config: RuntimeConfig,
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
    config: RuntimeConfig,
    plan_id: ObjectId,
    providers: Vec<ExecutedProvider>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ReadOnlyRuntimeProjection {
    #[serde(skip)]
    config: RuntimeConfig,
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
    #[error("repository state command could not run")]
    RepositoryStateProcess(#[source] ProcessError),
    #[error("repository state command failed: state={0:?}, exit_code={1:?}")]
    RepositoryStateCommand(ProcessState, Option<u8>),
    #[error("tracked repository entry cannot be checked safely")]
    RepositoryTrackedEntry,
    #[error("configured Provider mutated tracked repository state")]
    RepositoryMutation,
    #[error("scratch verification boundary failed")]
    Scratch(#[from] ScratchError),
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
    #[error(transparent)]
    Report(#[from] ReportAssemblyError),
    #[error("runtime projection object ID collided: {0}")]
    ObjectIdCollision(ObjectId),
}

#[derive(Debug, Error)]
pub(crate) enum ReadOnlyReportError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("runtime classification or deduplication failed")]
    Engine(#[from] EngineError),
    #[error(transparent)]
    Report(#[from] ReportAssemblyError),
}
pub(crate) fn build_read_only_plan(
    config: &RuntimeConfig,
    repository_digest: &Sha256Digest,
    mode: ReadOnlyMode,
) -> Result<ReadOnlyPlan, ReadOnlyPlanError> {
    let mut config = config.normalized()?;
    let (mode, operation) = match mode {
        ReadOnlyMode::Check => ("check", Operation::Check),
        ReadOnlyMode::Ci => ("ci", Operation::Check),
        ReadOnlyMode::Fix => ("fix", Operation::Fix),
        ReadOnlyMode::Verify => ("verify", Operation::Verify),
    };
    if operation == Operation::Fix {
        // LLM contract: CONFIGURED -> CAPABILITY_AND_ROLE_PROMOTED -> PLANNED; incapable FIX Provider -> FILTERED.
        config.providers.retain_mut(|provider| {
            let fix_capability = provider
                .required_capabilities
                .iter()
                .chain(&provider.optional_capabilities)
                .find(|capability| capability.as_str() == FIX_PROPOSE_CAPABILITY)
                .cloned();
            let Some(fix_capability) = fix_capability else {
                return false;
            };
            provider
                .optional_capabilities
                .retain(|capability| capability.as_str() != FIX_PROPOSE_CAPABILITY);
            if !provider.required_capabilities.contains(&fix_capability) {
                provider.required_capabilities.push(fix_capability);
                provider.required_capabilities.sort();
            }
            provider.required = true;
            true
        });
    }
    let report_config = config.clone();
    let limits = RequestLimits::try_from(&config.limits)?;
    let config_json = serde_json::to_string(&config)?;
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
            operation,
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
        config: report_config,
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
        config,
        plan_id,
        targets,
        providers,
    } = plan;
    // LLM contract: PLANNED -> PREFLIGHTED -> REPOSITORY_SNAPSHOTTED -> PROVIDER_GROUPS_REAPED -> MUTATION_VERIFIED; external writers excluded.
    validate_provider_targets(&workspace, &targets)?;
    let programs = providers
        .iter()
        .map(|provider| {
            resolve_provider_program(workspace.repository_root(), &provider.config.program)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let before = capture_repository_state(workspace.repository_root())?;
    let run_result: Result<ExecutedReadOnlyPlan, ReadOnlyRunError> = (|| {
        let mut executed = Vec::with_capacity(providers.len());
        for (planned, program) in providers.into_iter().zip(programs) {
            executed.push(planned.run(&workspace, program)?);
        }
        Ok(ExecutedReadOnlyPlan {
            config,
            plan_id,
            providers: executed,
        })
    })();
    let after = capture_repository_state(workspace.repository_root())?;
    if before != after {
        return Err(ReadOnlyRunError::RepositoryMutation);
    }
    run_result
}

pub(crate) fn execute_patch_verification(
    config: &RuntimeConfig,
    repository_root: &Path,
    scratch: &ScratchWorkspace,
    patch: &ScratchPatch,
) -> Result<ExecutedReadOnlyPlan, ReadOnlyRunError> {
    let before = scratch.capture_applied(patch, None)?;
    let plan = build_read_only_plan(config, &before.result.sha256, ReadOnlyMode::Verify)?;
    let original = resolve_workspace(repository_root, &config.repository.workspace)?;
    let workspace = resolve_workspace(scratch.path(), &config.repository.workspace)?;
    let ReadOnlyPlan {
        config,
        plan_id,
        targets,
        providers,
    } = plan;
    // LLM contract: PATCH_APPLIED -> VERIFY_PLANNED -> PROVIDERS_REAPED -> RESULT_RECAPTURED;
    // missing apply or any post-apply mutation -> INCOMPLETE.
    validate_provider_targets(&workspace, &targets)?;
    let programs = providers
        .iter()
        .map(|provider| {
            resolve_provider_program(original.repository_root(), &provider.config.program)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let original_before = capture_repository_state(original.repository_root())?;
    let run_result: Result<ExecutedReadOnlyPlan, ReadOnlyRunError> = (|| {
        let mut executed = Vec::with_capacity(providers.len());
        for (planned, program) in providers.into_iter().zip(programs) {
            executed.push(planned.run(&workspace, program)?);
        }
        Ok(ExecutedReadOnlyPlan {
            config,
            plan_id,
            providers: executed,
        })
    })();
    let scratch_after = scratch.capture_applied(patch, None);
    let original_after = capture_repository_state(original.repository_root())?;
    if original_before != original_after {
        return Err(ReadOnlyRunError::RepositoryMutation);
    }
    scratch_after?;
    let executed = run_result?;
    Ok(executed)
}

type RepositoryState = [Vec<u8>; 3];

fn capture_repository_state(repository_root: &Path) -> Result<RepositoryState, ReadOnlyRunError> {
    Ok([
        run_git(repository_root, &["rev-parse", "--verify", "HEAD"])?,
        run_git(repository_root, &["ls-files", "--stage", "-v", "-z"])?,
        raw_tracked_state(repository_root)?,
    ])
}

fn run_git(repository_root: &Path, argv: &[&str]) -> Result<Vec<u8>, ReadOnlyRunError> {
    run_git_input(repository_root, argv, Vec::new())
}

fn raw_tracked_state(repository_root: &Path) -> Result<Vec<u8>, ReadOnlyRunError> {
    let paths = run_git(repository_root, &["ls-files", "-z"])?;
    let mut input = Vec::new();
    let mut state = Vec::new();
    for raw in paths
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let relative =
            std::str::from_utf8(raw).map_err(|_| ReadOnlyRunError::RepositoryTrackedEntry)?;
        if relative.contains('\n') {
            return Err(ReadOnlyRunError::RepositoryTrackedEntry);
        }
        let path = repository_root.join(relative);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => {
                state.push(1);
                #[cfg(unix)]
                state.extend_from_slice(&metadata.permissions().mode().to_le_bytes());
                state.extend_from_slice(raw);
                state.push(0);
                input.extend_from_slice(raw);
                input.push(b'\n');
            }
            Ok(metadata) if metadata.file_type().is_symlink() => {
                state.push(2);
                state.extend_from_slice(raw);
                state.push(0);
                let target =
                    fs::read_link(&path).map_err(|source| ReadOnlyRunError::WorkspaceIo {
                        operation: "read tracked symbolic link",
                        path,
                        source,
                    })?;
                state.extend_from_slice(
                    target
                        .to_str()
                        .ok_or(ReadOnlyRunError::RepositoryTrackedEntry)?
                        .as_bytes(),
                );
                state.push(0);
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                state.push(0);
                state.extend_from_slice(raw);
                state.push(0);
            }
            Err(source) => {
                return Err(ReadOnlyRunError::WorkspaceIo {
                    operation: "inspect tracked repository state",
                    path,
                    source,
                });
            }
            Ok(_) => return Err(ReadOnlyRunError::RepositoryTrackedEntry),
        }
    }
    state.extend(run_git_input(
        repository_root,
        &["hash-object", "--no-filters", "--stdin-paths"],
        input,
    )?);
    Ok(state)
}

fn run_git_input(
    repository_root: &Path,
    argv: &[&str],
    stdin: Vec<u8>,
) -> Result<Vec<u8>, ReadOnlyRunError> {
    let outcome = run_bounded(
        &ProcessSpec::new("git")
            .args(argv.iter().copied())
            .current_dir(repository_root)
            .stdin(stdin),
        ProcessLimits {
            timeout: REPOSITORY_STATE_TIMEOUT,
            max_stdout_bytes: ProcessLimits::DEFAULT_STDOUT_BYTES,
            max_stderr_bytes: ProcessLimits::DEFAULT_STDERR_BYTES,
        },
    )
    .map_err(ReadOnlyRunError::RepositoryStateProcess)?;
    if outcome.state != ProcessState::Complete || outcome.exit_code != Some(0) {
        return Err(ReadOnlyRunError::RepositoryStateCommand(
            outcome.state,
            outcome.exit_code,
        ));
    }
    Ok(outcome.stdout.bytes)
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
    let ExecutedReadOnlyPlan {
        config,
        plan_id,
        providers,
    } = executed;
    project_provider_states(
        config,
        plan_id,
        providers
            .into_iter()
            .map(|provider| (provider.planned, provider.outcome.state))
            .collect(),
    )
}

fn project_provider_states(
    config: RuntimeConfig,
    plan_id: ObjectId,
    mut providers: Vec<(PlannedProvider, ProviderSessionState)>,
) -> Result<ReadOnlyRuntimeProjection, RuntimeProjectionError> {
    // LLM contract: EXECUTED -> BOUNDED -> IDENTITIES_VALIDATED -> COMPLETE_PAYLOAD_PROJECTED -> CANONICALIZED; overflow, mismatch, or collision -> REJECTED atomically.
    preflight_provider_projection_collections(&providers)?;
    providers.sort_by(|left, right| left.0.config.adapter_id.cmp(&right.0.config.adapter_id));
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
        config,
        plan_id,
        observations,
        evidence,
        fix_candidates,
        executions,
    })
}

fn preflight_provider_projection_collections(
    providers: &[(PlannedProvider, ProviderSessionState)],
) -> Result<(), ReportAssemblyError> {
    let (mut observations, mut evidence, mut fix_candidates) = (0usize, 0usize, 0usize);
    for (_, state) in providers {
        let ProviderSessionState::Complete(session) = state else {
            continue;
        };
        // ValidatedSession guarantees these completion counts equal the retained event stream.
        observations = observations.saturating_add(
            usize::try_from(session.completion.counts.observations).unwrap_or(usize::MAX),
        );
        evidence = evidence.saturating_add(
            usize::try_from(session.completion.counts.evidence).unwrap_or(usize::MAX),
        );
        fix_candidates = fix_candidates.saturating_add(
            usize::try_from(session.completion.counts.fix_candidates).unwrap_or(usize::MAX),
        );
    }
    preflight_projection_collections(observations, evidence, fix_candidates, providers.len())
}

pub(crate) fn assemble_read_only_report(
    projection: ReadOnlyRuntimeProjection,
    evaluation_time: Option<String>,
) -> Result<SessionReport, ReadOnlyReportError> {
    let ReadOnlyRuntimeProjection {
        config,
        plan_id,
        observations,
        evidence,
        fix_candidates,
        executions,
    } = projection;
    // LLM contract: NORMALIZED -> BOUNDED -> CLASSIFIED; aggregate overflow -> REJECTED before classification.
    preflight_projection_collections(
        observations.len(),
        evidence.len(),
        fix_candidates.len(),
        executions.len(),
    )?;
    let rules = config.classification_rules()?;
    let policy = config.policy_snapshot()?;
    // LLM contract: NORMALIZED -> CLASSIFIED -> REPORTED; invalid classification, policy, or reference -> REJECTED atomically.
    let findings = observations
        .iter()
        .map(|observation| build_finding(observation, &rules).map(|value| value.finding))
        .collect::<Result<Vec<_>, _>>()?;
    let findings = deduplicate_findings(findings)?;
    Ok(assemble_session_report(
        ReportAssemblyInput {
            session_id: plan_id,
            engine: EngineIdentity {
                version: config.engine.version.clone(),
                source_revision: config.engine.source_revision.clone(),
            },
            observations,
            findings,
            evidence,
            fix_candidates,
            executions,
            evaluation_time,
        },
        &policy,
    )?)
}

fn preflight_projection_collections(
    observations: usize,
    evidence: usize,
    fix_candidates: usize,
    executions: usize,
) -> Result<(), ReportAssemblyError> {
    for (collection, actual) in [
        ("observations", observations),
        ("evidence", evidence),
        ("fix_candidates", fix_candidates),
        ("executions", executions),
    ] {
        validate_report_collection_count(collection, actual)?;
    }
    Ok(())
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
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{env, fs, path::Path};

    use super::{
        PlannedProvider, ReadOnlyMode, ReadOnlyReportError, RuntimeProjectionError,
        assemble_read_only_report, build_read_only_plan, execute_patch_verification,
        execute_read_only_plan, preflight_projection_collections, project_provider_states,
        resolve_provider_program, resolve_workspace, synthesize_execution,
    };
    use crate::{
        RuntimeConfig, ScratchChange, ScratchError, ScratchLimits, ScratchPatch, ScratchWorkspace,
        session::ProviderSessionState,
    };
    use diagnostic_triage_contracts::{
        ObjectId, Sha256Digest, ValidatedSession,
        model::{Category, Execution, ExecutionStatus, MicroCategory, PhaseDuration, Verdict},
        protocol::{Operation, ProtocolEnvelope},
        validate_session_jsonl,
    };
    use diagnostic_triage_engine::report::{MAX_REPORT_COLLECTION_ITEMS, ReportAssemblyError};
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

    fn init_git(repository: &Path) {
        fs::write(repository.join(".baseline"), b"baseline").unwrap();
        super::run_git(repository, &["init", "-q"]).unwrap();
        super::run_git(repository, &["config", "user.name", "t"]).unwrap();
        super::run_git(repository, &["config", "user.email", "t@e"]).unwrap();
        super::run_git(repository, &["config", "commit.gpgsign", "false"]).unwrap();
        super::run_git(repository, &["add", "-A"]).unwrap();
        super::run_git(repository, &["commit", "-qm", "baseline"]).unwrap();
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
        let forward =
            project_provider_states(config("src"), plan_id.clone(), states.clone()).unwrap();
        states.reverse();
        let reverse = project_provider_states(config("src"), plan_id.clone(), states).unwrap();
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
        let evaluated_at = Some("2026-07-23T00:00:00Z".to_owned());
        let forward_report = assemble_read_only_report(forward, evaluated_at.clone()).unwrap();
        let reverse_report = assemble_read_only_report(reverse, evaluated_at).unwrap();
        assert_eq!(forward_report.verdict, Verdict::Pass);
        assert_eq!(
            forward_report.findings[0].classification.category,
            Category::Unknown
        );
        assert_eq!(
            forward_report.findings[0].classification.micro_category,
            MicroCategory::Unknown
        );
        assert_eq!(
            serde_json::to_vec(&forward_report).unwrap(),
            serde_json::to_vec(&reverse_report).unwrap()
        );

        let collision = project_provider_states(
            config("src"),
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
            config("src"),
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
            config("src"),
            "019f7e95-0000-7000-8000-000000000280".parse().unwrap(),
            vec![(mismatch, complete)],
        );
        assert!(matches!(error, Err(RuntimeProjectionError::Provider(..))));
    }

    #[test]
    fn empty_runtime_projection_is_a_valid_pass_without_evaluation_time() {
        let projection = project_provider_states(
            config("src"),
            "019f7e95-0000-7000-8000-000000000280".parse().unwrap(),
            Vec::new(),
        )
        .unwrap();
        let report = assemble_read_only_report(projection, None).unwrap();
        assert_eq!(report.verdict, Verdict::Pass);
        assert!(report.findings.is_empty());
        assert!(report.executions.is_empty());
    }

    #[test]
    fn projection_collection_preflight_is_exact_and_covers_every_collection() {
        preflight_projection_collections(
            MAX_REPORT_COLLECTION_ITEMS,
            MAX_REPORT_COLLECTION_ITEMS,
            MAX_REPORT_COLLECTION_ITEMS,
            MAX_REPORT_COLLECTION_ITEMS,
        )
        .unwrap();

        for (collection, counts) in [
            ("observations", [MAX_REPORT_COLLECTION_ITEMS + 1, 0, 0, 0]),
            ("evidence", [0, MAX_REPORT_COLLECTION_ITEMS + 1, 0, 0]),
            ("fix_candidates", [0, 0, MAX_REPORT_COLLECTION_ITEMS + 1, 0]),
            ("executions", [0, 0, 0, MAX_REPORT_COLLECTION_ITEMS + 1]),
        ] {
            let error =
                preflight_projection_collections(counts[0], counts[1], counts[2], counts[3])
                    .unwrap_err();
            assert!(matches!(
                error,
                ReportAssemblyError::CollectionLimit { collection: actual, .. }
                    if actual == collection
            ));
        }
    }

    #[test]
    fn projection_overflow_precedes_observation_classification() {
        let (planned, session) = aggregate_fixture("alpha", 291, true);
        let mut projection = project_provider_states(
            config("src"),
            "019f7e95-0000-7000-8000-000000000290".parse().unwrap(),
            vec![(planned, ProviderSessionState::Complete(Box::new(session)))],
        )
        .unwrap();
        let mut invalid = projection.observations[0].clone();
        invalid.message.clear();
        projection.observations = vec![invalid; MAX_REPORT_COLLECTION_ITEMS + 1];

        assert!(matches!(
            assemble_read_only_report(projection, Some("2026-07-23T00:00:00Z".to_owned())),
            Err(ReadOnlyReportError::Report(ReportAssemblyError::CollectionLimit {
                collection: "observations",
                actual,
                max,
            })) if actual == MAX_REPORT_COLLECTION_ITEMS + 1 && max == MAX_REPORT_COLLECTION_ITEMS
        ));
    }

    #[test]
    fn provider_projection_overflow_precedes_aggregate_materialization() {
        let (first, mut first_session) = aggregate_fixture("alpha", 301, true);
        let (second, mut second_session) = aggregate_fixture("zeta", 303, true);
        let first_observation = first_session
            .events
            .iter()
            .find(|event| matches!(event, ProtocolEnvelope::Observation(_)))
            .unwrap()
            .clone();
        let second_observation = second_session
            .events
            .iter()
            .find(|event| matches!(event, ProtocolEnvelope::Observation(_)))
            .unwrap()
            .clone();
        let per_provider = MAX_REPORT_COLLECTION_ITEMS / 2 + 1;
        first_session.events = vec![first_observation; per_provider];
        second_session.events = vec![second_observation; per_provider];
        for session in [&mut first_session, &mut second_session] {
            session.completion.counts.observations = u64::try_from(per_provider).unwrap();
            session.completion.counts.evidence = 0;
            session.completion.counts.fix_candidates = 0;
        }

        assert!(matches!(
            project_provider_states(
                config("src"),
                "019f7e95-0000-7000-8000-000000000300".parse().unwrap(),
                vec![
                    (first, ProviderSessionState::Complete(Box::new(first_session))),
                    (second, ProviderSessionState::Complete(Box::new(second_session))),
                ],
            ),
            Err(RuntimeProjectionError::Report(ReportAssemblyError::CollectionLimit {
                collection: "observations",
                actual,
                max,
            })) if actual == per_provider * 2 && max == MAX_REPORT_COLLECTION_ITEMS
        ));
    }

    #[cfg(unix)]
    #[test]
    fn tracked_provider_mutation_is_rejected_before_projection() {
        let repository = tempdir().unwrap();
        let tracked = repository.path().join("tracked.txt");
        fs::write(&tracked, b"original").unwrap();
        init_git(repository.path());
        fs::set_permissions(&tracked, fs::Permissions::from_mode(0o644)).unwrap();
        let mut config = config("tracked.txt");
        config.providers.truncate(1);
        let chmod = env::split_paths(&env::var_os("PATH").unwrap())
            .map(|directory| directory.join("chmod"))
            .find(|candidate| candidate.is_file())
            .unwrap();
        config.providers[0].program = chmod.to_str().unwrap().to_owned();
        config.providers[0].argv = vec!["0600".into(), "tracked.txt".into()];
        let error = execute_read_only_plan(
            &config,
            repository.path(),
            &Sha256Digest::compute(b"repository"),
            ReadOnlyMode::Check,
        )
        .unwrap_err();
        assert!(matches!(error, super::ReadOnlyRunError::RepositoryMutation));
    }

    #[test]
    fn patch_verification_requires_apply_and_runs_against_the_bound_result() {
        let repository = tempdir().unwrap();
        fs::write(repository.path().join("tracked.txt"), b"before").unwrap();
        init_git(repository.path());
        let mut config = config("tracked.txt");
        config.providers.truncate(1);
        config.providers[0].program = env::current_exe().unwrap().to_str().unwrap().to_owned();
        config.providers[0].argv = vec!["--exact".to_owned(), "__no_such_test__".to_owned()];
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "tracked.txt".to_owned(),
            contents: b"after".to_vec(),
        }])
        .unwrap();
        let mut scratch = ScratchWorkspace::stage(
            repository.path(),
            &["tracked.txt"],
            ScratchLimits::default(),
        )
        .unwrap();

        let error =
            execute_patch_verification(&config, repository.path(), &scratch, &patch).unwrap_err();
        assert!(matches!(
            error,
            super::ReadOnlyRunError::Scratch(ScratchError::PatchNotApplied)
        ));

        scratch.apply_for_verification(&patch).unwrap();
        let verified =
            execute_patch_verification(&config, repository.path(), &scratch, &patch).unwrap();
        assert_eq!(
            verified.providers[0].planned.request.operation,
            Operation::Verify
        );
        let evidence = scratch
            .capture_applied(
                &patch,
                Some(verified.providers[0].planned.execution_id.clone()),
            )
            .unwrap();
        assert_ne!(evidence.base.sha256, evidence.result.sha256);
        assert_eq!(
            fs::read(repository.path().join("tracked.txt")).unwrap(),
            b"before"
        );
        scratch.cleanup().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn patch_verification_detects_original_repository_mutation() {
        let repository = tempdir().unwrap();
        let tracked = repository.path().join("tracked.txt");
        fs::write(&tracked, b"before").unwrap();
        init_git(repository.path());
        fs::set_permissions(&tracked, fs::Permissions::from_mode(0o644)).unwrap();
        let mut config = config("tracked.txt");
        config.providers.truncate(1);
        let chmod = env::split_paths(&env::var_os("PATH").unwrap())
            .map(|directory| directory.join("chmod"))
            .find(|candidate| candidate.is_file())
            .unwrap();
        config.providers[0].program = chmod.to_str().unwrap().to_owned();
        config.providers[0].argv = vec!["0600".to_owned(), tracked.to_str().unwrap().to_owned()];
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "tracked.txt".to_owned(),
            contents: b"after".to_vec(),
        }])
        .unwrap();
        let mut scratch = ScratchWorkspace::stage(
            repository.path(),
            &["tracked.txt"],
            ScratchLimits::default(),
        )
        .unwrap();
        scratch.apply_for_verification(&patch).unwrap();

        let error =
            execute_patch_verification(&config, repository.path(), &scratch, &patch).unwrap_err();

        assert!(matches!(error, super::ReadOnlyRunError::RepositoryMutation));
        assert_eq!(
            fs::read(scratch.path().join("tracked.txt")).unwrap(),
            b"after"
        );
        scratch.cleanup().unwrap();
    }

    #[test]
    fn executes_absolute_provider_under_trusted_repository_root() {
        let repository = tempdir().unwrap();
        let mut config = config("src");
        fs::create_dir(repository.path().join("workspace")).unwrap();
        init_git(repository.path());
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
        init_git(repository.path());
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
        init_git(repository.path());
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
    fn fix_plan_promotes_optional_capability_to_required() {
        let mut runtime_config = config("src");
        runtime_config.providers[0]
            .optional_capabilities
            .push("fix.propose/v1".parse().unwrap());
        runtime_config.providers[0].required = false;

        let plan = build_read_only_plan(
            &runtime_config,
            &Sha256Digest::compute(b"repository"),
            ReadOnlyMode::Fix,
        )
        .unwrap();
        assert_eq!(plan.providers.len(), 1);
        let provider = &plan.providers[0];

        assert!(
            provider
                .request
                .required_capabilities
                .contains(&super::FIX_PROPOSE_CAPABILITY.parse().unwrap())
        );
        assert!(
            provider
                .request
                .optional_capabilities
                .iter()
                .all(|capability| capability.as_str() != super::FIX_PROPOSE_CAPABILITY)
        );
        assert_eq!(
            provider.request.required_capabilities,
            provider.config.required_capabilities
        );
        assert!(provider.config.required);
        assert_eq!(provider.config, plan.config.providers[0]);
        plan.config.validate().unwrap();
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
        let mut fix_config = runtime_config.clone();
        fix_config.providers[0]
            .optional_capabilities
            .push("fix.propose/v1".parse().unwrap());
        let fix = build_read_only_plan(&fix_config, &digest, ReadOnlyMode::Fix).unwrap();
        let verify = build_read_only_plan(&runtime_config, &digest, ReadOnlyMode::Verify).unwrap();
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
        for changed in [
            &ci,
            &fix,
            &verify,
            &changed_digest,
            &changed_target,
            &changed_provider,
        ] {
            assert_ne!(forward.plan_id, changed.plan_id);
            assert_ne!(
                first.request.request_id,
                changed.providers[0].request.request_id
            );
            assert_ne!(first.execution_id, changed.providers[0].execution_id);
        }
        assert_eq!(ci.providers[0].request.operation, Operation::Check);
        assert_eq!(fix.providers.len(), 1);
        assert_eq!(fix.providers[0].config.adapter_id.as_str(), "alpha");
        assert_eq!(fix.providers[0].request.operation, Operation::Fix);
        assert_eq!(verify.providers[0].request.operation, Operation::Verify);

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
