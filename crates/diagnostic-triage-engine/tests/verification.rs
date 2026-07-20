use diagnostic_triage_contracts::model::{
    AdapterKind, Applicability, Cache, CacheStatus, Execution, ExecutionPhases,
    ExecutionSchemaVersion, ExecutionStatus, Finding, FindingSchemaVersion, FindingState,
    FixCandidate, FixCandidateSchemaVersion, Performance, PerformanceStatus, PhaseDuration, Retry,
    RetryStatus, Runner, RunnerStatus, Severity, Taxonomy, Tool, ToolchainFingerprint, Unavailable,
};
use diagnostic_triage_contracts::{AdapterId, Fingerprint, Nullable, ObjectId};
use diagnostic_triage_engine::finding::{finding_id_for_finding, fingerprint_for_finding};
use diagnostic_triage_engine::verification::{
    InvalidRequestReason, VerificationRequest, VerificationStatus, verify_safe_fix,
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

fn id(value: u128) -> ObjectId {
    format!("019f7e95-0000-7000-8000-{value:012x}")
        .parse()
        .expect("fixture ID is canonical")
}

fn fingerprint(value: char) -> Fingerprint {
    finding(999, value, Severity::Info).fingerprint
}

fn provider_id(value: &str) -> AdapterId {
    value.parse().expect("fixture provider ID is canonical")
}

fn finding(finding_id: u128, value: char, severity: Severity) -> Finding {
    let mut finding = Finding {
        schema_version: FindingSchemaVersion::V1,
        finding_id: id(finding_id),
        fingerprint: format!("dtfp1:{}", "0".repeat(64))
            .parse()
            .expect("placeholder fingerprint is canonical"),
        observation_ids: vec![id(600)],
        tool: Tool {
            name: "fixture-tool".to_owned(),
            version: "1.0.0".to_owned(),
            rule_id: Some("fixture-rule".to_owned()),
        },
        language: "rust".parse().expect("fixture language is canonical"),
        severity,
        classification: Taxonomy {
            category: diagnostic_triage_contracts::model::Category::Correctness,
            micro_category: diagnostic_triage_contracts::model::MicroCategory::WrongResult,
        },
        message: format!("fixture finding {value}"),
        location: None,
        symbol: None,
        expected: None,
        observed: None,
        state: FindingState::Classified,
        evidence_ids: Vec::new(),
        fix_candidate_id: None,
        verification_execution_ids: None,
    };
    finding.fingerprint = fingerprint_for_finding(&finding).unwrap();
    finding.finding_id = finding_id_for_finding(&finding).unwrap();
    finding
}

fn candidate(applicability: Applicability) -> FixCandidate {
    FixCandidate {
        schema_version: FixCandidateSchemaVersion::V1,
        fix_candidate_id: id(500),
        observation_ids: vec![id(600)],
        applicability,
        tool_native: !matches!(applicability, Applicability::Manual),
        patch_evidence_id: id(700),
    }
}

fn execution(execution_id: u128, provider: &str, status: ExecutionStatus) -> Execution {
    let complete = status == ExecutionStatus::Complete;
    Execution {
        schema_version: ExecutionSchemaVersion::V1,
        execution_id: id(execution_id),
        adapter_id: provider_id(provider),
        adapter_kind: AdapterKind::Provider,
        tool: Tool {
            name: "fixture-tool".to_owned(),
            version: "1.0.0".to_owned(),
            rule_id: None,
        },
        toolchain_fingerprint: ToolchainFingerprint::Unavailable(Unavailable::Value),
        required: true,
        status,
        exit_code: Nullable(if complete { Some(0) } else { None }),
        message: (!complete).then(|| "fixture execution incomplete".to_owned()),
        phases_ms: ExecutionPhases {
            queue: PhaseDuration::Milliseconds(1),
            setup: PhaseDuration::Milliseconds(1),
            run: PhaseDuration::Milliseconds(1),
            normalize: PhaseDuration::Milliseconds(1),
            total: PhaseDuration::Milliseconds(4),
        },
        performance: Performance {
            status: PerformanceStatus::WithinBudget,
            budget_ms: 1,
        },
        cache: Cache {
            status: CacheStatus::NotApplicable,
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
    }
}

fn request<'a>(
    fix_candidate: &'a FixCandidate,
    target_fingerprints: &'a [Fingerprint],
    before_findings: &'a [Finding],
    after_findings: &'a [Finding],
    executions: &'a [Execution],
    required_provider_ids: &'a [AdapterId],
    required_execution_ids: &'a [ObjectId],
) -> VerificationRequest<'a> {
    VerificationRequest {
        fix_candidate,
        target_fingerprints,
        before_findings,
        after_findings,
        executions,
        required_provider_ids,
        required_execution_ids,
    }
}

#[test]
fn verifies_when_targets_disappear() {
    let fix = candidate(Applicability::Safe);
    let target = fingerprint('a');
    let before = vec![finding(1, 'a', Severity::Error)];
    let after = Vec::new();
    let executions = vec![execution(10, "rust-provider", ExecutionStatus::Complete)];
    let providers = vec![provider_id("rust-provider")];
    let execution_ids = vec![id(10)];

    let result = verify_safe_fix(&request(
        &fix,
        &[target],
        &before,
        &after,
        &executions,
        &providers,
        &execution_ids,
    ));

    assert_eq!(result.status, VerificationStatus::Verified);
}

#[test]
fn empty_execution_requirements_cannot_verify() {
    let fix = candidate(Applicability::Safe);
    let target = fingerprint('a');
    let before = vec![finding(1, 'a', Severity::Error)];

    let result = verify_safe_fix(&request(&fix, &[target], &before, &[], &[], &[], &[]));

    assert_eq!(result.status, VerificationStatus::InvalidRequest);
    assert_eq!(
        result.invalid_reason,
        Some(InvalidRequestReason::MissingExecutionRequirement)
    );
}

#[test]
fn reports_a_retained_target_fingerprint() {
    let fix = candidate(Applicability::Safe);
    let target = fingerprint('a');
    let before = vec![finding(1, 'a', Severity::Error)];
    let after = vec![finding(2, 'a', Severity::Info)];
    let executions = vec![execution(10, "rust-provider", ExecutionStatus::Complete)];
    let providers = vec![provider_id("rust-provider")];
    let execution_ids = vec![id(10)];

    let result = verify_safe_fix(&request(
        &fix,
        std::slice::from_ref(&target),
        &before,
        &after,
        &executions,
        &providers,
        &execution_ids,
    ));

    assert_eq!(result.status, VerificationStatus::TargetRemains);
    assert_eq!(result.remaining_target_fingerprints, vec![target]);
}

#[test]
fn rejects_a_new_equal_or_higher_severity_finding() {
    let fix = candidate(Applicability::Safe);
    let target = fingerprint('a');
    let regression = fingerprint('b');
    let before = vec![finding(1, 'a', Severity::Warning)];
    let after = vec![finding(2, 'b', Severity::Error)];
    let executions = vec![execution(10, "rust-provider", ExecutionStatus::Complete)];
    let providers = vec![provider_id("rust-provider")];
    let execution_ids = vec![id(10)];

    let result = verify_safe_fix(&request(
        &fix,
        &[target],
        &before,
        &after,
        &executions,
        &providers,
        &execution_ids,
    ));

    assert_eq!(result.status, VerificationStatus::Regression);
    assert_eq!(result.regression_fingerprints, vec![regression]);
}

#[test]
fn regression_precedes_a_remaining_target_and_keeps_its_fingerprint() {
    let fix = candidate(Applicability::Safe);
    let target = fingerprint('a');
    let regression = fingerprint('b');
    let before = vec![finding(1, 'a', Severity::Warning)];
    let after = vec![
        finding(2, 'a', Severity::Warning),
        finding(3, 'b', Severity::Warning),
    ];
    let executions = vec![execution(10, "rust-provider", ExecutionStatus::Complete)];

    let result = verify_safe_fix(&request(
        &fix,
        &[target],
        &before,
        &after,
        &executions,
        &[provider_id("rust-provider")],
        &[id(10)],
    ));

    assert_eq!(result.status, VerificationStatus::Regression);
    assert!(result.remaining_target_fingerprints.is_empty());
    assert_eq!(result.regression_fingerprints, vec![regression]);
}

#[test]
fn allows_a_new_lower_severity_finding() {
    let fix = candidate(Applicability::Safe);
    let target = fingerprint('a');
    let new_finding = fingerprint('b');
    let before = vec![finding(1, 'a', Severity::Error)];
    let after = vec![finding(2, 'b', Severity::Warning)];
    let executions = vec![execution(10, "rust-provider", ExecutionStatus::Complete)];
    let providers = vec![provider_id("rust-provider")];
    let execution_ids = vec![id(10)];

    let result = verify_safe_fix(&request(
        &fix,
        &[target],
        &before,
        &after,
        &executions,
        &providers,
        &execution_ids,
    ));

    assert_eq!(result.status, VerificationStatus::Verified);
    assert!(result.regression_fingerprints.is_empty());
    assert!(!new_finding.as_str().is_empty());
}

#[test]
fn reports_incomplete_required_provider_and_execution() {
    let fix = candidate(Applicability::Safe);
    let target = fingerprint('a');
    let before = vec![finding(1, 'a', Severity::Error)];
    let after = Vec::new();
    let executions = vec![execution(10, "rust-provider", ExecutionStatus::Incomplete)];
    let providers = vec![provider_id("rust-provider")];
    let execution_ids = vec![id(10)];

    let result = verify_safe_fix(&request(
        &fix,
        &[target],
        &before,
        &after,
        &executions,
        &providers,
        &execution_ids,
    ));

    assert_eq!(
        result.status,
        VerificationStatus::IncompleteRequiredExecution
    );
    assert_eq!(result.incomplete_provider_ids, providers);
    assert_eq!(result.incomplete_execution_ids, execution_ids);
}

#[test]
fn reports_unsupported_required_provider_and_execution() {
    let fix = candidate(Applicability::Safe);
    let target = fingerprint('a');
    let before = vec![finding(1, 'a', Severity::Error)];
    let executions = vec![execution(10, "rust-provider", ExecutionStatus::Unsupported)];
    let providers = vec![provider_id("rust-provider")];
    let execution_ids = vec![id(10)];

    let result = verify_safe_fix(&request(
        &fix,
        &[target],
        &before,
        &[],
        &executions,
        &providers,
        &execution_ids,
    ));

    assert_eq!(
        result.status,
        VerificationStatus::UnsupportedRequiredExecution
    );
    assert_eq!(result.unsupported_provider_ids, providers);
    assert_eq!(result.unsupported_execution_ids, execution_ids);
}

#[test]
fn incomplete_precedes_unsupported_and_both_are_retained() {
    let fix = candidate(Applicability::Safe);
    let target = fingerprint('a');
    let before = vec![finding(1, 'a', Severity::Error)];
    let executions = vec![
        execution(10, "rust-provider", ExecutionStatus::Incomplete),
        execution(11, "biome-provider", ExecutionStatus::Unsupported),
    ];

    let result = verify_safe_fix(&request(
        &fix,
        &[target],
        &before,
        &[],
        &executions,
        &[provider_id("rust-provider"), provider_id("biome-provider")],
        &[id(10), id(11)],
    ));

    assert_eq!(
        result.status,
        VerificationStatus::IncompleteRequiredExecution
    );
    assert_eq!(
        result.incomplete_provider_ids,
        vec![provider_id("rust-provider")]
    );
    assert_eq!(result.incomplete_execution_ids, vec![id(10)]);
    assert_eq!(
        result.unsupported_provider_ids,
        vec![provider_id("biome-provider")]
    );
    assert_eq!(result.unsupported_execution_ids, vec![id(11)]);
}

#[test]
fn every_required_execution_is_checked_even_when_not_named() {
    let fix = candidate(Applicability::Safe);
    let target = fingerprint('a');
    let before = vec![finding(1, 'a', Severity::Error)];
    let after = Vec::new();
    let executions = vec![execution(10, "rust-provider", ExecutionStatus::Incomplete)];
    let providers = Vec::new();
    let execution_ids = Vec::new();

    let result = verify_safe_fix(&request(
        &fix,
        &[target],
        &before,
        &after,
        &executions,
        &providers,
        &execution_ids,
    ));

    assert_eq!(
        result.status,
        VerificationStatus::IncompleteRequiredExecution
    );
    assert_eq!(result.incomplete_execution_ids, vec![id(10)]);
}

#[test]
fn named_required_provider_detects_a_missing_execution() {
    let fix = candidate(Applicability::Safe);
    let target = fingerprint('a');
    let before = vec![finding(1, 'a', Severity::Error)];
    let after = Vec::new();
    let executions = Vec::new();
    let providers = vec![provider_id("rust-provider")];
    let execution_ids = Vec::new();

    let result = verify_safe_fix(&request(
        &fix,
        &[target],
        &before,
        &after,
        &executions,
        &providers,
        &execution_ids,
    ));

    assert_eq!(
        result.status,
        VerificationStatus::IncompleteRequiredExecution
    );
    assert_eq!(result.incomplete_provider_ids, providers);
}

#[test]
fn duplicate_and_unordered_inputs_have_the_same_result() {
    let fix = candidate(Applicability::Safe);
    let target = fingerprint('a');
    let before = vec![
        finding(2, 'b', Severity::Info),
        finding(1, 'a', Severity::Error),
        finding(3, 'a', Severity::Error),
    ];
    let after = vec![finding(4, 'b', Severity::Info)];
    let executions = vec![
        execution(11, "other-provider", ExecutionStatus::Complete),
        execution(10, "rust-provider", ExecutionStatus::Complete),
        execution(10, "rust-provider", ExecutionStatus::Complete),
    ];
    let providers = vec![
        provider_id("other-provider"),
        provider_id("rust-provider"),
        provider_id("rust-provider"),
    ];
    let execution_ids = vec![id(11), id(10), id(10)];

    let result = verify_safe_fix(&request(
        &fix,
        &[target.clone(), target],
        &before,
        &after,
        &executions,
        &providers,
        &execution_ids,
    ));

    let canonical_executions = vec![execution(10, "rust-provider", ExecutionStatus::Complete)];
    let canonical_providers = vec![provider_id("rust-provider")];
    let canonical_execution_ids = vec![id(10)];
    let canonical_result = verify_safe_fix(&request(
        &fix,
        &[fingerprint('a')],
        &[
            finding(1, 'a', Severity::Error),
            finding(2, 'b', Severity::Info),
        ],
        &after,
        &canonical_executions,
        &canonical_providers,
        &canonical_execution_ids,
    ));

    assert_eq!(result, canonical_result);
    assert_eq!(result.status, VerificationStatus::Verified);
}

#[test]
fn conflicting_duplicate_finding_identity_is_invalid() {
    let fix = candidate(Applicability::Safe);
    let target = fingerprint('a');
    let before = vec![finding(1, 'a', Severity::Error), {
        let mut conflict = finding(2, 'a', Severity::Error);
        conflict.classification = Taxonomy {
            category: diagnostic_triage_contracts::model::Category::Type,
            micro_category: diagnostic_triage_contracts::model::MicroCategory::IncompatibleType,
        };
        conflict.finding_id = finding_id_for_finding(&conflict).unwrap();
        conflict
    }];
    let after = Vec::new();
    let executions = vec![execution(10, "rust-provider", ExecutionStatus::Complete)];
    let providers = vec![provider_id("rust-provider")];
    let execution_ids = vec![id(10)];

    let result = verify_safe_fix(&request(
        &fix,
        &[target],
        &before,
        &after,
        &executions,
        &providers,
        &execution_ids,
    ));

    assert_eq!(result.status, VerificationStatus::InvalidRequest);
    assert_eq!(
        result.invalid_reason,
        Some(InvalidRequestReason::ConflictingDuplicateFinding)
    );
}

#[test]
fn target_must_be_linked_to_the_fix_candidate() {
    let mut fix = candidate(Applicability::Safe);
    fix.observation_ids = vec![id(999)];
    let target = fingerprint('a');
    let before = vec![finding(1, 'a', Severity::Error)];
    let executions = vec![execution(10, "rust-provider", ExecutionStatus::Complete)];

    let result = verify_safe_fix(&request(
        &fix,
        &[target],
        &before,
        &[],
        &executions,
        &[provider_id("rust-provider")],
        &[id(10)],
    ));

    assert_eq!(result.status, VerificationStatus::InvalidRequest);
    assert_eq!(
        result.invalid_reason,
        Some(InvalidRequestReason::TargetNotLinkedToFix)
    );
}

#[test]
fn severity_increase_of_an_existing_finding_is_a_regression() {
    let fix = candidate(Applicability::Safe);
    let target = fingerprint('a');
    let escalated = fingerprint('b');
    let before = vec![
        finding(1, 'a', Severity::Warning),
        finding(2, 'b', Severity::Info),
    ];
    let after = vec![finding(3, 'b', Severity::Warning)];
    let executions = vec![execution(10, "rust-provider", ExecutionStatus::Complete)];

    let result = verify_safe_fix(&request(
        &fix,
        &[target],
        &before,
        &after,
        &executions,
        &[provider_id("rust-provider")],
        &[id(10)],
    ));

    assert_eq!(result.status, VerificationStatus::Regression);
    assert_eq!(result.regression_fingerprints, vec![escalated]);
}

#[test]
fn conflicting_duplicate_execution_is_invalid_with_specific_reason() {
    let fix = candidate(Applicability::Safe);
    let target = fingerprint('a');
    let before = vec![finding(1, 'a', Severity::Error)];
    let after = Vec::new();
    let mut conflict = execution(10, "rust-provider", ExecutionStatus::Complete);
    conflict.tool.version = "2.0.0".to_owned();
    let executions = vec![
        execution(10, "rust-provider", ExecutionStatus::Complete),
        conflict,
    ];
    let providers = vec![provider_id("rust-provider")];
    let execution_ids = vec![id(10)];

    let result = verify_safe_fix(&request(
        &fix,
        &[target],
        &before,
        &after,
        &executions,
        &providers,
        &execution_ids,
    ));

    assert_eq!(result.status, VerificationStatus::InvalidRequest);
    assert_eq!(
        result.invalid_reason,
        Some(InvalidRequestReason::ConflictingDuplicateExecution)
    );
}

#[test]
fn manual_and_unsafe_candidates_are_invalid_requests() {
    let target = fingerprint('a');
    let before = vec![finding(1, 'a', Severity::Error)];
    let after = Vec::new();
    let executions = vec![execution(10, "rust-provider", ExecutionStatus::Complete)];
    let providers = vec![provider_id("rust-provider")];
    let execution_ids = vec![id(10)];

    for applicability in [Applicability::Manual, Applicability::Unsafe] {
        let fix = candidate(applicability);
        let result = verify_safe_fix(&request(
            &fix,
            std::slice::from_ref(&target),
            &before,
            &after,
            &executions,
            &providers,
            &execution_ids,
        ));
        assert_eq!(result.status, VerificationStatus::InvalidRequest);
        assert_eq!(
            result.invalid_reason,
            Some(InvalidRequestReason::InvalidFixCandidate)
        );
    }
}
