//! Validated construction of runtime-owned Provider execution records.

use diagnostic_triage_contracts::{
    AdapterId, ContractError, Nullable, ObjectId,
    model::{
        AdapterKind, Cache, CacheStatus, Execution, ExecutionPhases, ExecutionSchemaVersion,
        ExecutionStatus, Performance, PerformanceStatus, PhaseDuration, Retry, RetryStatus, Runner,
        RunnerStatus, Tool, ToolchainFingerprint, Unavailable,
    },
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

const PERFORMANCE_BUDGET_MS: u32 = 60_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderExecutionInput {
    pub execution_id: ObjectId,
    pub adapter_id: AdapterId,
    pub tool: Tool,
    pub required: bool,
    pub status: ExecutionStatus,
    pub exit_code: Nullable<u8>,
    pub message: Option<String>,
    pub run_duration_ms: Option<u32>,
}

pub(crate) fn validated_provider_execution(
    input: ProviderExecutionInput,
) -> Result<Execution, ContractError> {
    let unavailable = PhaseDuration::Unavailable(Unavailable::Value);
    let performance_status =
        input
            .run_duration_ms
            .map_or(PerformanceStatus::NotEvaluated, |duration| {
                if duration > PERFORMANCE_BUDGET_MS {
                    PerformanceStatus::ImprovementCandidate
                } else {
                    PerformanceStatus::WithinBudget
                }
            });
    let execution = Execution {
        schema_version: ExecutionSchemaVersion::V1,
        execution_id: input.execution_id,
        adapter_id: input.adapter_id,
        adapter_kind: AdapterKind::Provider,
        tool: input.tool,
        toolchain_fingerprint: ToolchainFingerprint::Unavailable(Unavailable::Value),
        required: input.required,
        status: input.status,
        exit_code: input.exit_code,
        message: input.message,
        phases_ms: ExecutionPhases {
            queue: unavailable.clone(),
            setup: unavailable.clone(),
            run: input
                .run_duration_ms
                .map_or_else(|| unavailable.clone(), PhaseDuration::Milliseconds),
            normalize: unavailable.clone(),
            total: unavailable,
        },
        performance: Performance {
            status: performance_status,
            budget_ms: PERFORMANCE_BUDGET_MS,
        },
        cache: Cache {
            status: CacheStatus::Unavailable,
            restore_ms: None,
            save_ms: None,
        },
        retry: Retry {
            status: RetryStatus::NotApplicable,
            attempt: None,
            same_revision: None,
            group_id: None,
        },
        runner: Runner {
            status: RunnerStatus::Unavailable,
            os: None,
            arch: None,
            image: None,
            fingerprint: None,
        },
        verification: None,
    };
    execution.validate()?;
    Ok(execution)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(status: ExecutionStatus, exit_code: Option<u8>) -> ProviderExecutionInput {
        ProviderExecutionInput {
            execution_id: "019f7e95-0000-7000-8000-000000000009".parse().unwrap(),
            adapter_id: "ruff".parse().unwrap(),
            tool: Tool {
                name: "ruff".to_owned(),
                version: "0.12.4".to_owned(),
                rule_id: None,
            },
            required: true,
            message: (status != ExecutionStatus::Complete).then(|| "terminal".to_owned()),
            status,
            exit_code: Nullable(exit_code),
            run_duration_ms: None,
        }
    }

    #[test]
    fn constructs_valid_complete_and_terminal_records() {
        let complete = validated_provider_execution(input(ExecutionStatus::Complete, Some(0)))
            .expect("complete execution");
        assert_eq!(complete.adapter_kind, AdapterKind::Provider);
        assert_eq!(
            complete.toolchain_fingerprint,
            ToolchainFingerprint::Unavailable(Unavailable::Value)
        );
        for phase in [
            &complete.phases_ms.queue,
            &complete.phases_ms.setup,
            &complete.phases_ms.normalize,
            &complete.phases_ms.total,
        ] {
            assert_eq!(phase, &PhaseDuration::Unavailable(Unavailable::Value));
        }
        assert_eq!(complete.cache.status, CacheStatus::Unavailable);
        assert_eq!(complete.retry.status, RetryStatus::NotApplicable);
        assert_eq!(complete.runner.status, RunnerStatus::Unavailable);
        assert!(complete.verification.is_none());

        for value in [
            input(ExecutionStatus::Incomplete, None),
            input(ExecutionStatus::Unsupported, None),
        ] {
            validated_provider_execution(value)
                .unwrap()
                .validate()
                .unwrap();
        }
    }

    #[test]
    fn evaluates_only_the_run_duration_against_budget() {
        for (duration, expected) in [
            (Some(60_000), PerformanceStatus::WithinBudget),
            (Some(60_001), PerformanceStatus::ImprovementCandidate),
            (None, PerformanceStatus::NotEvaluated),
        ] {
            let mut value = input(ExecutionStatus::Complete, Some(0));
            value.run_duration_ms = duration;
            let execution = validated_provider_execution(value).unwrap();
            assert_eq!(execution.performance.status, expected);
            assert_eq!(
                execution.phases_ms.run,
                duration.map_or(
                    PhaseDuration::Unavailable(Unavailable::Value),
                    PhaseDuration::Milliseconds,
                )
            );
        }
    }

    #[test]
    fn rejects_invalid_status_exit_combinations() {
        assert!(validated_provider_execution(input(ExecutionStatus::Complete, None)).is_err());
        assert!(validated_provider_execution(input(ExecutionStatus::Incomplete, Some(1))).is_err());
    }
}
