// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use std::str::FromStr;

use diagnostic_triage_contracts::{
    AdapterId, Language, Nullable, ObjectId, RepoPath, Sha256Digest, SourceRevision,
    model::{
        AdapterKind, Applicability, Cache, CacheStatus, Category, EngineIdentity, Evidence,
        EvidenceSchemaVersion, EvidenceSource, Execution, ExecutionPhases, ExecutionSchemaVersion,
        ExecutionStatus, Finding, FindingState, FixCandidate, FixCandidateSchemaVersion,
        MicroCategory, NotApplicable, Observation, ObservationSchemaVersion, Performance,
        PerformanceStatus, PreReportState, Retry, RetryStatus, Runner, RunnerStatus, Severity,
        Taxonomy, Tool, ToolchainFingerprint, Unavailable, Verdict, VerificationAttribution,
    },
};
use diagnostic_triage_engine::{
    deterministic_object_id,
    finding::build_finding_with_taxonomy,
    policy::PolicySnapshot,
    report::{
        MAX_REPORT_COLLECTION_ITEMS, ReportAssemblyError, ReportAssemblyInput,
        assemble_session_report,
    },
};
use sha2::{Digest, Sha256};

const EVALUATION_TIME: &str = "2026-07-21T00:00:00Z";

fn id(kind: &str, key: &str) -> ObjectId {
    deterministic_object_id("diagnostic-triage.report-test/v1", [kind, key]).unwrap()
}

fn engine() -> EngineIdentity {
    EngineIdentity {
        version: "0.1.0".into(),
        source_revision: SourceRevision::from_str(&"a".repeat(40)).unwrap(),
    }
}

fn observation(key: &str, severity: Severity) -> Observation {
    Observation {
        schema_version: ObservationSchemaVersion::V1,
        observation_id: id("observation", key),
        tool: Tool {
            name: "fixture-tool".into(),
            version: "1.0.0".into(),
            rule_id: Some("fixture.rule".into()),
        },
        language: Language::from_str("rust").unwrap(),
        severity,
        origin: diagnostic_triage_contracts::model::Origin::Normal,
        message: format!("fixture diagnostic {key}"),
        location: None,
        symbol: None,
        expected: None,
        observed: None,
        evidence_ids: Vec::new(),
    }
}

fn finding(observation: &Observation) -> Finding {
    build_finding_with_taxonomy(
        observation,
        &Taxonomy {
            category: Category::Type,
            micro_category: MicroCategory::IncompatibleType,
        },
    )
    .unwrap()
}

fn policy() -> PolicySnapshot {
    PolicySnapshot::new(&[], &[]).unwrap()
}

fn input(
    observations: Vec<Observation>,
    findings: Vec<Finding>,
    executions: Vec<Execution>,
    evaluation_time: Option<&str>,
) -> ReportAssemblyInput {
    ReportAssemblyInput {
        session_id: id("session", "fixture"),
        engine: engine(),
        observations,
        findings,
        evidence: Vec::new(),
        fix_candidates: Vec::new(),
        executions,
        evaluation_time: evaluation_time.map(str::to_owned),
    }
}

fn rejected(input: ReportAssemblyInput) -> ReportAssemblyError {
    match assemble_session_report(input, &policy()) {
        Ok(_) => panic!("report assembly unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn execution(key: &str, status: ExecutionStatus) -> Execution {
    Execution {
        schema_version: ExecutionSchemaVersion::V1,
        execution_id: id("execution", key),
        adapter_id: AdapterId::from_str("fixture.engine").unwrap(),
        adapter_kind: AdapterKind::Engine,
        tool: Tool {
            name: "fixture-tool".into(),
            version: "1.0.0".into(),
            rule_id: None,
        },
        toolchain_fingerprint: ToolchainFingerprint::Unavailable(Unavailable::Value),
        required: true,
        status,
        exit_code: Nullable(None),
        message: Some("fixture execution outcome".into()),
        phases_ms: ExecutionPhases {
            queue: diagnostic_triage_contracts::model::PhaseDuration::NotApplicable(
                NotApplicable::Value,
            ),
            setup: diagnostic_triage_contracts::model::PhaseDuration::NotApplicable(
                NotApplicable::Value,
            ),
            run: diagnostic_triage_contracts::model::PhaseDuration::NotApplicable(
                NotApplicable::Value,
            ),
            normalize: diagnostic_triage_contracts::model::PhaseDuration::NotApplicable(
                NotApplicable::Value,
            ),
            total: diagnostic_triage_contracts::model::PhaseDuration::NotApplicable(
                NotApplicable::Value,
            ),
        },
        performance: Performance {
            status: PerformanceStatus::NotEvaluated,
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
        verification: None,
    }
}

fn evidence_for(key: &str) -> Evidence {
    Evidence {
        schema_version: EvidenceSchemaVersion::V1,
        evidence_id: id("evidence", key),
        execution_id: None,
        source: EvidenceSource::Stdout,
        media_type: "text/plain".into(),
        retained_bytes: 0,
        observed_bytes: 0,
        limit_bytes: 1,
        truncated: false,
        sha256: Sha256Digest::from_str(&"0".repeat(64)).unwrap(),
        relative_path: Some(RepoPath::from_str(&format!("{key}.txt")).unwrap()),
        content: None,
    }
}

fn evidence() -> Evidence {
    evidence_for("fixture")
}

fn fix_candidate() -> FixCandidate {
    FixCandidate {
        schema_version: FixCandidateSchemaVersion::V1,
        fix_candidate_id: id("fix-candidate", "fixture"),
        observation_ids: vec![id("observation", "fixture")],
        applicability: Applicability::Manual,
        tool_native: false,
        patch_evidence_id: id("evidence", "fixture"),
    }
}

fn inline_evidence(
    key: &str,
    source: EvidenceSource,
    media_type: &str,
    content: &str,
    execution_id: Option<ObjectId>,
) -> Evidence {
    Evidence {
        schema_version: EvidenceSchemaVersion::V1,
        evidence_id: id("evidence", key),
        execution_id,
        source,
        media_type: media_type.to_owned(),
        retained_bytes: content.len().try_into().unwrap(),
        observed_bytes: content.len().try_into().unwrap(),
        limit_bytes: 1_048_576,
        truncated: false,
        sha256: Sha256Digest::from_str(&format!("{:x}", Sha256::digest(content.as_bytes())))
            .unwrap(),
        relative_path: None,
        content: Some(content.to_owned()),
    }
}

fn candidate_for(
    key: &str,
    observation_id: ObjectId,
    patch_evidence_id: ObjectId,
    applicability: Applicability,
) -> FixCandidate {
    FixCandidate {
        schema_version: FixCandidateSchemaVersion::V1,
        fix_candidate_id: id("fix-candidate", key),
        observation_ids: vec![observation_id],
        applicability,
        tool_native: true,
        patch_evidence_id,
    }
}

#[test]
fn empty_input_is_a_valid_pass_report() {
    let policy = policy();
    let report =
        assemble_session_report(input(Vec::new(), Vec::new(), Vec::new(), None), &policy).unwrap();

    assert_eq!(report.session_id, id("session", "fixture"));
    assert_eq!(report.verdict, Verdict::Pass);
    assert!(report.observations.is_empty());
    assert!(report.findings.is_empty());
    assert!(report.decisions.is_empty());
    assert!(report.evidence.is_empty());
    assert!(report.fix_candidates.is_empty());
    assert!(report.executions.is_empty());
    assert_eq!(&report.policy_digest, policy.digest());
    assert_eq!(
        report.contract_sha256,
        Sha256Digest::from_str(&format!(
            "{:x}",
            Sha256::digest(report.engine.source_revision.as_str().as_bytes())
        ))
        .unwrap()
    );
}

#[test]
fn blocking_finding_gets_decision_and_reported_transition() {
    let observation = observation("blocking", Severity::Error);
    let finding = finding(&observation);
    let finding_id = finding.finding_id.clone();

    let report = assemble_session_report(
        input(
            vec![observation],
            vec![finding],
            Vec::new(),
            Some(EVALUATION_TIME),
        ),
        &policy(),
    )
    .unwrap();

    assert_eq!(report.verdict, Verdict::PolicyFail);
    assert_eq!(report.decisions.len(), 1);
    assert_eq!(report.decisions[0].finding_id, finding_id);
    assert_eq!(
        report.decisions[0].action,
        diagnostic_triage_contracts::model::DecisionAction::Block
    );
    assert_eq!(report.findings[0].state, FindingState::Reported);
    assert_eq!(
        report.findings[0].pre_report_state,
        Some(diagnostic_triage_contracts::model::PreReportState::Classified)
    );
}

#[test]
fn report_transition_preserves_fix_proposed_and_verified_provenance() {
    let fix_observation = observation("fix-proposed", Severity::Warning);
    let patch = inline_evidence(
        "fix-proposed-patch",
        EvidenceSource::Patch,
        "text/x-diff",
        "--- a/file\n+++ b/file\n",
        None,
    );
    let candidate = candidate_for(
        "fix-proposed",
        fix_observation.observation_id.clone(),
        patch.evidence_id.clone(),
        Applicability::Manual,
    );
    let mut fix_finding = finding(&fix_observation);
    fix_finding.state = FindingState::FixProposed;
    fix_finding.fix_candidate_id = Some(candidate.fix_candidate_id.clone());
    let mut fix_input = input(
        vec![fix_observation],
        vec![fix_finding],
        Vec::new(),
        Some(EVALUATION_TIME),
    );
    fix_input.evidence = vec![patch];
    fix_input.fix_candidates = vec![candidate];
    let fix_report = assemble_session_report(fix_input, &policy()).unwrap();
    assert_eq!(
        fix_report.findings[0].pre_report_state,
        Some(PreReportState::FixProposed)
    );

    let verified_observation = observation("verified", Severity::Warning);
    let patch = inline_evidence(
        "verified-patch",
        EvidenceSource::Patch,
        "text/x-diff",
        "--- a/file\n+++ b/file\n",
        None,
    );
    let snapshot = inline_evidence(
        "verified-snapshot",
        EvidenceSource::Artifact,
        "application/vnd.diagnostic-triage.snapshot+json",
        "{\"findings\":[]}",
        None,
    );
    let candidate = candidate_for(
        "verified",
        verified_observation.observation_id.clone(),
        patch.evidence_id.clone(),
        Applicability::Safe,
    );
    let mut verified_finding = finding(&verified_observation);
    let execution_id = id("execution", "verified");
    let result = inline_evidence(
        "verified-result",
        EvidenceSource::Diagnostic,
        "application/json",
        "{\"findings\":[]}",
        Some(execution_id.clone()),
    );
    let mut verification = execution("verified", ExecutionStatus::Complete);
    verification.adapter_kind = AdapterKind::Provider;
    verification.exit_code = Nullable(Some(0));
    verification.message = None;
    verification.verification = Some(Box::new(VerificationAttribution {
        fix_candidate_id: candidate.fix_candidate_id.clone(),
        patch_sha256: patch.sha256.clone(),
        base_snapshot_sha256: snapshot.sha256.clone(),
        base_snapshot_evidence_id: snapshot.evidence_id.clone(),
        target_fingerprints: vec![verified_finding.fingerprint.clone()],
        result_evidence_id: result.evidence_id.clone(),
    }));
    verified_finding.state = FindingState::Verified;
    verified_finding.fix_candidate_id = Some(candidate.fix_candidate_id.clone());
    verified_finding.verification_execution_ids = Some(vec![execution_id]);
    let mut verified_input = input(
        vec![verified_observation],
        vec![verified_finding],
        vec![verification],
        Some(EVALUATION_TIME),
    );
    verified_input.evidence = vec![result, snapshot, patch];
    verified_input.fix_candidates = vec![candidate];
    let verified_report = assemble_session_report(verified_input, &policy()).unwrap();
    assert_eq!(
        verified_report.findings[0].pre_report_state,
        Some(PreReportState::Verified)
    );
}

#[test]
fn preclassified_and_already_reported_findings_are_rejected() {
    let observation = observation("lifecycle", Severity::Warning);
    let mut discovered = finding(&observation);
    discovered.state = FindingState::Discovered;
    assert!(matches!(
        rejected(input(
            vec![observation.clone()],
            vec![discovered],
            Vec::new(),
            Some(EVALUATION_TIME),
        )),
        ReportAssemblyError::InvalidFindingLifecycle {
            state: FindingState::Discovered,
            ..
        }
    ));

    let reported = finding(&observation).into_reported().unwrap();
    assert!(matches!(
        rejected(input(
            vec![observation],
            vec![reported],
            Vec::new(),
            Some(EVALUATION_TIME),
        )),
        ReportAssemblyError::InvalidFindingLifecycle {
            state: FindingState::Reported,
            ..
        }
    ));
}

#[test]
fn input_and_reference_permutations_are_byte_identical_and_canonical() {
    let first_evidence = evidence_for("alpha");
    let second_evidence = evidence_for("beta");
    let mut first_observation = observation("alpha", Severity::Warning);
    first_observation.evidence_ids = vec![
        second_evidence.evidence_id.clone(),
        first_evidence.evidence_id.clone(),
    ];
    let second_observation = observation("beta", Severity::Warning);
    let mut first_finding = finding(&first_observation);
    let second_finding = finding(&second_observation);
    first_finding.observation_ids = vec![
        second_observation.observation_id.clone(),
        first_observation.observation_id.clone(),
    ];

    let mut forward_input = input(
        vec![first_observation.clone(), second_observation.clone()],
        vec![first_finding.clone(), second_finding.clone()],
        Vec::new(),
        Some(EVALUATION_TIME),
    );
    forward_input.evidence = vec![first_evidence.clone(), second_evidence.clone()];
    let forward = assemble_session_report(forward_input, &policy()).unwrap();
    let mut reverse_input = input(
        vec![second_observation, first_observation],
        vec![second_finding, first_finding],
        Vec::new(),
        Some(EVALUATION_TIME),
    );
    reverse_input.evidence = vec![second_evidence, first_evidence];
    let reverse = assemble_session_report(reverse_input, &policy()).unwrap();

    assert_eq!(
        serde_json::to_vec(&forward).unwrap(),
        serde_json::to_vec(&reverse).unwrap()
    );
    assert!(
        forward
            .observations
            .windows(2)
            .all(|pair| pair[0].observation_id < pair[1].observation_id)
    );
    assert!(forward.findings.windows(2).all(|pair| {
        (&pair[0].fingerprint, &pair[0].finding_id) < (&pair[1].fingerprint, &pair[1].finding_id)
    }));
    assert!(
        forward
            .evidence
            .windows(2)
            .all(|pair| pair[0].evidence_id < pair[1].evidence_id)
    );
    let merged = forward
        .findings
        .iter()
        .find(|candidate| candidate.observation_ids.len() == 2)
        .unwrap();
    assert!(
        merged
            .observation_ids
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert!(merged.evidence_ids.windows(2).all(|pair| pair[0] < pair[1]));
    let observation_with_evidence = forward
        .observations
        .iter()
        .find(|candidate| candidate.evidence_ids.len() == 2)
        .unwrap();
    assert!(
        observation_with_evidence
            .evidence_ids
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
}

#[test]
fn evaluation_time_is_required_iff_findings_are_present() {
    let observation = observation("timestamp", Severity::Warning);
    let finding = finding(&observation);

    let missing_for_finding = input(
        vec![observation.clone()],
        vec![finding.clone()],
        Vec::new(),
        None,
    );
    let present_without_finding = input(Vec::new(), Vec::new(), Vec::new(), Some(EVALUATION_TIME));

    assert!(matches!(
        rejected(missing_for_finding),
        ReportAssemblyError::MissingEvaluationTime
    ));
    assert!(matches!(
        rejected(present_without_finding),
        ReportAssemblyError::UnexpectedEvaluationTime
    ));
}

#[test]
fn verdict_precedence_is_incomplete_then_unsupported_then_policy_fail_then_pass() {
    let cases = [
        ("pass", None, false, Verdict::Pass),
        ("policy-fail", None, true, Verdict::PolicyFail),
        (
            "unsupported",
            Some(ExecutionStatus::Unsupported),
            true,
            Verdict::Unsupported,
        ),
        (
            "incomplete",
            Some(ExecutionStatus::Incomplete),
            true,
            Verdict::Incomplete,
        ),
    ];

    for (key, execution_status, has_finding, expected_verdict) in cases {
        let (observations, findings, evaluation_time) = if has_finding {
            let observation = observation(key, Severity::Error);
            let finding = finding(&observation);
            (vec![observation], vec![finding], Some(EVALUATION_TIME))
        } else {
            (Vec::new(), Vec::new(), None)
        };
        let executions = execution_status
            .map(|status| vec![execution(key, status)])
            .unwrap_or_default();

        let report = assemble_session_report(
            input(observations, findings, executions, evaluation_time),
            &policy(),
        )
        .unwrap();

        assert_eq!(report.verdict, expected_verdict, "case {key}");
    }
}

#[test]
fn forged_finding_identity_is_rejected() {
    let observation = observation("forged", Severity::Warning);
    let mut finding = finding(&observation);
    finding.finding_id = id("forged-finding", "replacement");

    let error = rejected(input(
        vec![observation],
        vec![finding],
        Vec::new(),
        Some(EVALUATION_TIME),
    ));
    assert!(matches!(
        error,
        ReportAssemblyError::FindingIntegrity { .. }
    ));
}

#[test]
fn every_report_collection_rejects_max_plus_one_before_assembly() {
    let observation = observation("bound", Severity::Warning);
    let finding = finding(&observation);
    let execution = execution("bound", ExecutionStatus::Unsupported);
    let evidence = evidence();
    let fix_candidate = fix_candidate();
    let count = MAX_REPORT_COLLECTION_ITEMS + 1;

    let mut observations_input = input(Vec::new(), Vec::new(), Vec::new(), None);
    observations_input.observations = vec![observation; count];
    let mut findings_input = input(Vec::new(), Vec::new(), Vec::new(), Some(EVALUATION_TIME));
    findings_input.findings = vec![finding; count];
    let mut evidence_input = input(Vec::new(), Vec::new(), Vec::new(), None);
    evidence_input.evidence = vec![evidence; count];
    let mut fixes_input = input(Vec::new(), Vec::new(), Vec::new(), None);
    fixes_input.fix_candidates = vec![fix_candidate; count];
    let mut executions_input = input(Vec::new(), Vec::new(), Vec::new(), None);
    executions_input.executions = vec![execution; count];

    for (collection, input) in [
        ("observations", observations_input),
        ("findings", findings_input),
        ("evidence", evidence_input),
        ("fix_candidates", fixes_input),
        ("executions", executions_input),
    ] {
        assert!(matches!(
            rejected(input),
            ReportAssemblyError::CollectionLimit {
                collection: actual_collection,
                actual,
                max: MAX_REPORT_COLLECTION_ITEMS,
            } if actual_collection == collection && actual == count
        ));
    }
}

#[test]
fn maximum_report_collection_is_accepted() {
    let observations = (0..MAX_REPORT_COLLECTION_ITEMS)
        .map(|index| observation(&format!("maximum-{index}"), Severity::Info))
        .collect::<Vec<_>>();
    let report =
        assemble_session_report(input(observations, Vec::new(), Vec::new(), None), &policy())
            .unwrap();
    assert_eq!(report.observations.len(), MAX_REPORT_COLLECTION_ITEMS);
}

#[test]
fn nested_reference_bounds_are_validated_before_canonicalization() {
    let mut observation = observation("nested-bound", Severity::Info);
    observation.evidence_ids = (0..65)
        .map(|index| id("nested-evidence", &index.to_string()))
        .collect();
    assert!(matches!(
        rejected(input(vec![observation], Vec::new(), Vec::new(), None)),
        ReportAssemblyError::Contract { .. }
    ));
}

#[test]
fn duplicate_and_dangling_references_fail_before_decision_materialization() {
    let observation = observation("dangling", Severity::Warning);
    let finding = finding(&observation);
    assert!(matches!(
        rejected(input(
            Vec::new(),
            vec![finding],
            Vec::new(),
            Some(EVALUATION_TIME),
        )),
        ReportAssemblyError::ReferencePreflight {
            reason: "finding references unknown observation",
        }
    ));

    let mut duplicate_evidence = evidence_for("duplicate");
    duplicate_evidence.evidence_id = observation.observation_id.clone();
    let mut duplicate_input = input(vec![observation], Vec::new(), Vec::new(), None);
    duplicate_input.evidence = vec![duplicate_evidence];
    assert!(matches!(
        rejected(duplicate_input),
        ReportAssemblyError::ReferencePreflight {
            reason: "report object IDs are not globally unique",
        }
    ));
}
