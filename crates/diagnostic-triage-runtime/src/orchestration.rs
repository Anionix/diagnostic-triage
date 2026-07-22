//! Pure, deterministic planning for read-only runtime sessions.

use std::collections::BTreeSet;

use diagnostic_triage_contracts::protocol::{
    EnvelopeKind, Operation, ProtocolEnvelope, ProtocolVersion, RequestEnvelope, RequestLimits,
};
use diagnostic_triage_contracts::{ContractError, ObjectId, Sha256Digest};
use diagnostic_triage_engine::{EngineError, deterministic_object_id};
use thiserror::Error;

use crate::config::{ConfigError, ProviderConfig, RuntimeConfig};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

const PLAN_ID_DOMAIN: &str = "diagnostic-triage.runtime-plan/v1";
const REQUEST_ID_DOMAIN: &str = "diagnostic-triage.runtime-request/v1";
const EXECUTION_ID_DOMAIN: &str = "diagnostic-triage.runtime-execution/v1";

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadOnlyPlan {
    plan_id: ObjectId,
    providers: Vec<PlannedProvider>,
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
            targets: config.repository.targets.clone(),
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
    Ok(ReadOnlyPlan { plan_id, providers })
}

#[cfg(test)]
mod tests {
    use super::{ReadOnlyMode, build_read_only_plan};
    use crate::RuntimeConfig;
    use diagnostic_triage_contracts::{Sha256Digest, protocol::Operation};

    const REVISION: &str = "a12b34c56d78e90f1234567890abcdef12345678";
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
