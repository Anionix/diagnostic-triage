use std::str::FromStr;

use diagnostic_triage_contracts::{
    AdapterId, Nullable, ObjectId, RepoPath, Sha256Digest, SourceRevision,
    model::{
        AdapterKind, Applicability, Cache, CacheStatus, Category, Evidence, EvidenceSchemaVersion,
        EvidenceSource, Execution, ExecutionPhases, ExecutionSchemaVersion, ExecutionStatus,
        Finding, FindingState, FixCandidate, FixCandidateSchemaVersion, MicroCategory,
        NotApplicable, Observation, ObservationSchemaVersion, Origin, Performance,
        PerformanceStatus, PhaseDuration, PreReportState, Retry, RetryStatus, Runner, RunnerStatus,
        Severity, Taxonomy, Tool, ToolchainFingerprint, Unavailable, VerificationAttribution,
    },
};
use diagnostic_triage_engine::{
    deterministic_object_id,
    finding::build_finding_with_taxonomy,
    policy::PolicySnapshot,
    report::{ReportAssemblyInput, assemble_session_report},
    verification::{
        MAX_VERIFICATION_TARGETS, PatchApplication, SafeFixComparisonInput, SafeFixVerification,
        VerificationError, VerificationRejection, compare_safe_fix,
    },
};
use sha2::{Digest, Sha256};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

fn id(kind: &str, key: &str) -> ObjectId {
    deterministic_object_id("diagnostic-triage.verification-test/v1", [kind, key]).unwrap()
}

fn tool() -> Tool {
    Tool {
        name: "fixture-tool".into(),
        version: "1.0.0".into(),
        rule_id: Some("fixture.rule".into()),
    }
}

fn observation(key: &str, severity: Severity) -> Observation {
    Observation {
        schema_version: ObservationSchemaVersion::V1,
        observation_id: id("observation", key),
        tool: tool(),
        language: "rust".parse().unwrap(),
        severity,
        origin: Origin::Normal,
        message: format!("fixture diagnostic {key}"),
        location: None,
        symbol: None,
        expected: None,
        observed: None,
        evidence_ids: Vec::new(),
    }
}

fn classified(key: &str, severity: Severity) -> Finding {
    build_finding_with_taxonomy(
        &observation(key, severity),
        &Taxonomy {
            category: Category::Type,
            micro_category: MicroCategory::IncompatibleType,
        },
    )
    .unwrap()
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
        media_type: media_type.into(),
        retained_bytes: content.len().try_into().unwrap(),
        observed_bytes: content.len().try_into().unwrap(),
        limit_bytes: 1_048_576,
        truncated: false,
        sha256: Sha256Digest::from_str(&format!("{:x}", Sha256::digest(content.as_bytes())))
            .unwrap(),
        relative_path: None,
        content: Some(content.into()),
    }
}

fn phases() -> ExecutionPhases {
    ExecutionPhases {
        queue: PhaseDuration::NotApplicable(NotApplicable::Value),
        setup: PhaseDuration::NotApplicable(NotApplicable::Value),
        run: PhaseDuration::NotApplicable(NotApplicable::Value),
        normalize: PhaseDuration::NotApplicable(NotApplicable::Value),
        total: PhaseDuration::NotApplicable(NotApplicable::Value),
    }
}

fn execution(
    execution_id: ObjectId,
    candidate: &FixCandidate,
    patch: &Evidence,
    snapshot: &Evidence,
    result: &Evidence,
    targets: Vec<diagnostic_triage_contracts::Fingerprint>,
) -> Execution {
    Execution {
        schema_version: ExecutionSchemaVersion::V1,
        execution_id,
        adapter_id: AdapterId::from_str("fixture.provider").unwrap(),
        adapter_kind: AdapterKind::Provider,
        tool: tool(),
        toolchain_fingerprint: ToolchainFingerprint::Unavailable(Unavailable::Value),
        required: true,
        status: ExecutionStatus::Complete,
        exit_code: Nullable(Some(0)),
        message: None,
        phases_ms: phases(),
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
        verification: Some(Box::new(VerificationAttribution {
            fix_candidate_id: candidate.fix_candidate_id.clone(),
            patch_sha256: patch.sha256.clone(),
            base_snapshot_sha256: snapshot.sha256.clone(),
            base_snapshot_evidence_id: snapshot.evidence_id.clone(),
            target_fingerprints: targets,
            result_evidence_id: result.evidence_id.clone(),
        })),
    }
}

#[derive(Clone)]
struct Fixture {
    candidate: FixCandidate,
    targets: Vec<diagnostic_triage_contracts::Fingerprint>,
    evidence: Vec<Evidence>,
    executions: Vec<Execution>,
    patch_application: PatchApplication,
    before: Vec<Finding>,
    after: Vec<Finding>,
}

impl Fixture {
    fn new(targets: &[(&str, Severity)]) -> Self {
        let mut before = targets
            .iter()
            .map(|(key, severity)| classified(key, severity.clone()))
            .collect::<Vec<_>>();
        let candidate = FixCandidate {
            schema_version: FixCandidateSchemaVersion::V1,
            fix_candidate_id: id("candidate", "fixture"),
            observation_ids: before
                .iter()
                .flat_map(|finding| finding.observation_ids.iter().cloned())
                .collect(),
            applicability: Applicability::Safe,
            tool_native: true,
            patch_evidence_id: id("evidence", "patch"),
        };
        for finding in &mut before {
            finding.state = FindingState::FixProposed;
            finding.fix_candidate_id = Some(candidate.fix_candidate_id.clone());
        }
        let target_fingerprints = before
            .iter()
            .map(|finding| finding.fingerprint.clone())
            .collect::<Vec<_>>();
        let patch = inline_evidence(
            "patch",
            EvidenceSource::Patch,
            "text/x-diff",
            "--- a/file\n+++ b/file\n",
            None,
        );
        let snapshot = inline_evidence(
            "snapshot",
            EvidenceSource::Artifact,
            "application/vnd.diagnostic-triage.snapshot+json",
            "{\"findings\":[]}",
            None,
        );
        let execution_id = id("execution", "verification");
        let result = inline_evidence(
            "result",
            EvidenceSource::Diagnostic,
            "application/json",
            "{\"findings\":[]}",
            Some(execution_id.clone()),
        );
        let execution = execution(
            execution_id,
            &candidate,
            &patch,
            &snapshot,
            &result,
            target_fingerprints.clone(),
        );
        let patch_application = PatchApplication::Applied {
            patch_sha256: patch.sha256.clone(),
            base_snapshot_sha256: snapshot.sha256.clone(),
        };
        Self {
            candidate,
            targets: target_fingerprints,
            evidence: vec![patch, snapshot, result],
            executions: vec![execution],
            patch_application,
            before,
            after: Vec::new(),
        }
    }

    fn compare(&self) -> Result<SafeFixVerification, VerificationError> {
        compare_safe_fix(SafeFixComparisonInput {
            candidate: &self.candidate,
            target_fingerprints: &self.targets,
            evidence: &self.evidence,
            executions: &self.executions,
            patch_application: &self.patch_application,
            before_findings: &self.before,
            after_findings: &self.after,
        })
    }

    fn application_digests(&self) -> (Sha256Digest, Sha256Digest) {
        let patch = self
            .evidence
            .iter()
            .find(|item| item.source == EvidenceSource::Patch)
            .unwrap();
        let snapshot = self
            .evidence
            .iter()
            .find(|item| item.media_type == "application/vnd.diagnostic-triage.snapshot+json")
            .unwrap();
        (patch.sha256.clone(), snapshot.sha256.clone())
    }
}

fn rejected(result: SafeFixVerification) -> Vec<VerificationRejection> {
    match result {
        SafeFixVerification::Rejected { reasons } => reasons,
        SafeFixVerification::Verified(_) => panic!("comparison unexpectedly verified"),
    }
}

#[test]
fn disappearing_target_preserves_baseline_and_becomes_verified() {
    let fixture = Fixture::new(&[("target", Severity::Error)]);
    let SafeFixVerification::Verified(verified) = fixture.compare().unwrap() else {
        panic!("comparison did not verify");
    };

    assert_eq!(verified.verified_targets.len(), 1);
    assert_eq!(
        verified.verified_targets[0].finding_id,
        fixture.before[0].finding_id
    );
    assert_eq!(verified.verified_targets[0].state, FindingState::Verified);
    assert_eq!(
        verified.verified_targets[0].fix_candidate_id.as_ref(),
        Some(&fixture.candidate.fix_candidate_id)
    );
    assert_eq!(
        verified.verified_targets[0]
            .verification_execution_ids
            .as_deref(),
        Some(&[fixture.executions[0].execution_id.clone()][..])
    );
    assert!(verified.post_fix_findings.is_empty());
}

#[test]
fn verified_output_assembles_into_a_valid_session_report() {
    let fixture = Fixture::new(&[("target", Severity::Error)]);
    let SafeFixVerification::Verified(verified) = fixture.compare().unwrap() else {
        panic!("comparison did not verify");
    };
    let report = assemble_session_report(
        ReportAssemblyInput {
            session_id: id("session", "verified"),
            engine: diagnostic_triage_contracts::model::EngineIdentity {
                version: "0.1.0".into(),
                source_revision: SourceRevision::from_str(&"a".repeat(40)).unwrap(),
            },
            observations: vec![observation("target", Severity::Error)],
            findings: verified.verified_targets,
            evidence: fixture.evidence,
            fix_candidates: vec![fixture.candidate],
            executions: fixture.executions,
            evaluation_time: Some("2026-07-21T00:00:00Z".into()),
        },
        &PolicySnapshot::new(&[], &[]).unwrap(),
    )
    .unwrap();

    assert_eq!(report.findings[0].state, FindingState::Reported);
    assert_eq!(
        report.findings[0].pre_report_state,
        Some(PreReportState::Verified)
    );
}

#[test]
fn residual_target_is_a_structured_rejection() {
    let mut fixture = Fixture::new(&[("target", Severity::Error)]);
    fixture.after = vec![classified("target", Severity::Info)];

    let reasons = rejected(fixture.compare().unwrap());
    assert!(matches!(
        &reasons[0],
        VerificationRejection::TargetStillPresent { fingerprints }
            if fingerprints == &fixture.targets
    ));
}

#[test]
fn lower_new_finding_is_reported_but_equal_floor_is_rejected() {
    let mut allowed = Fixture::new(&[("target", Severity::Warning)]);
    let lower = classified("new-info", Severity::Info);
    allowed.after = vec![lower.clone()];
    let SafeFixVerification::Verified(verified) = allowed.compare().unwrap() else {
        panic!("lower-severity finding was rejected");
    };
    assert_eq!(
        verified.new_lower_severity_fingerprints,
        vec![lower.fingerprint]
    );

    let mut rejected_fixture = Fixture::new(&[("target", Severity::Warning)]);
    let equal = classified("new-warning", Severity::Warning);
    rejected_fixture.after = vec![equal.clone()];
    assert!(matches!(
        rejected(rejected_fixture.compare().unwrap()).as_slice(),
        [VerificationRejection::NewFindingAtOrAboveTargetFloor { fingerprints }]
            if fingerprints == &[equal.fingerprint]
    ));
}

#[test]
fn multiple_targets_use_the_minimum_severity_floor() {
    let mut fixture = Fixture::new(&[
        ("error-target", Severity::Error),
        ("warning-target", Severity::Warning),
    ]);
    let info = classified("new-info", Severity::Info);
    fixture.after = vec![info.clone()];
    assert!(matches!(
        fixture.compare().unwrap(),
        SafeFixVerification::Verified(_)
    ));

    let warning = classified("new-warning", Severity::Warning);
    fixture.after = vec![warning.clone()];
    assert!(matches!(
        rejected(fixture.compare().unwrap()).as_slice(),
        [VerificationRejection::NewFindingAtOrAboveTargetFloor { fingerprints }]
            if fingerprints == &[warning.fingerprint]
    ));
}

#[test]
fn severity_escalation_of_an_existing_finding_is_rejected() {
    let mut fixture = Fixture::new(&[("target", Severity::Error)]);
    let baseline = classified("existing", Severity::Info);
    let escalated = classified("existing", Severity::Warning);
    fixture.before.push(baseline.clone());
    fixture.after.push(escalated);

    assert!(matches!(
        rejected(fixture.compare().unwrap()).as_slice(),
        [VerificationRejection::ExistingSeverityEscalation { fingerprints }]
            if fingerprints == &[baseline.fingerprint]
    ));
}

#[test]
fn unsafe_and_manual_candidates_never_authorize_application() {
    for applicability in [Applicability::Unsafe, Applicability::Manual] {
        let mut fixture = Fixture::new(&[("target", Severity::Error)]);
        fixture.candidate.applicability = applicability;
        let reasons = rejected(fixture.compare().unwrap());
        assert!(matches!(
            reasons.as_slice(),
            [VerificationRejection::CandidateNotSafe { applicability: actual }]
                if actual == &applicability
        ));
    }
}

#[test]
fn patch_conflict_and_terminal_executions_have_fixed_reason_order() {
    let mut fixture = Fixture::new(&[("target", Severity::Error)]);
    let (patch_sha256, base_snapshot_sha256) = fixture.application_digests();
    fixture.patch_application = PatchApplication::Conflict {
        patch_sha256: patch_sha256.clone(),
        base_snapshot_sha256: base_snapshot_sha256.clone(),
        paths: vec![
            RepoPath::from_str("z.rs").unwrap(),
            RepoPath::from_str("a.rs").unwrap(),
            RepoPath::from_str("z.rs").unwrap(),
        ],
    };
    fixture.executions[0].status = ExecutionStatus::Incomplete;
    fixture.executions[0].exit_code = Nullable(None);
    fixture.executions[0].message = Some("provider timed out".into());

    let reasons = rejected(fixture.compare().unwrap());
    assert!(matches!(
        reasons.as_slice(),
        [
            VerificationRejection::PatchConflict { paths },
            VerificationRejection::RequiredProviderIncomplete { execution_ids }
        ] if paths == &vec![
            RepoPath::from_str("a.rs").unwrap(),
            RepoPath::from_str("z.rs").unwrap(),
        ] && execution_ids == &vec![fixture.executions[0].execution_id.clone()]
    ));

    fixture.patch_application = PatchApplication::Applied {
        patch_sha256,
        base_snapshot_sha256,
    };
    fixture.executions[0].status = ExecutionStatus::Unsupported;
    fixture.executions[0].message = Some("tool unsupported".into());
    assert!(matches!(
        rejected(fixture.compare().unwrap()).as_slice(),
        [VerificationRejection::RequiredProviderUnsupported { execution_ids }]
            if execution_ids == &[fixture.executions[0].execution_id.clone()]
    ));
}

#[test]
fn operational_failures_do_not_require_success_attribution() {
    let mut conflict = Fixture::new(&[("target", Severity::Error)]);
    let (patch_sha256, base_snapshot_sha256) = conflict.application_digests();
    conflict.patch_application = PatchApplication::Conflict {
        patch_sha256,
        base_snapshot_sha256,
        paths: vec![RepoPath::from_str("src/lib.rs").unwrap()],
    };
    conflict.executions[0].verification = None;
    assert!(matches!(
        rejected(conflict.compare().unwrap()).as_slice(),
        [VerificationRejection::PatchConflict { paths }]
            if paths == &[RepoPath::from_str("src/lib.rs").unwrap()]
    ));

    let mut incomplete = Fixture::new(&[("target", Severity::Error)]);
    incomplete.executions[0].status = ExecutionStatus::Incomplete;
    incomplete.executions[0].exit_code = Nullable(None);
    incomplete.executions[0].message = Some("provider timed out".into());
    incomplete.executions[0].verification = None;
    assert!(matches!(
        rejected(incomplete.compare().unwrap()).as_slice(),
        [VerificationRejection::RequiredProviderIncomplete { execution_ids }]
            if execution_ids == &[incomplete.executions[0].execution_id.clone()]
    ));
}

#[test]
fn attribution_and_evidence_mismatches_are_input_errors() {
    let mut patch_mismatch = Fixture::new(&[("target", Severity::Error)]);
    patch_mismatch.executions[0]
        .verification
        .as_mut()
        .unwrap()
        .patch_sha256 = Sha256Digest::from_str(&"0".repeat(64)).unwrap();
    assert!(matches!(
        patch_mismatch.compare(),
        Err(VerificationError::AttributionPatchMismatch { .. })
    ));

    let mut result_mismatch = Fixture::new(&[("target", Severity::Error)]);
    let result = result_mismatch
        .evidence
        .iter_mut()
        .find(|evidence| evidence.source == EvidenceSource::Diagnostic)
        .unwrap();
    let other_execution_id = id("execution", "other");
    result.execution_id = Some(other_execution_id.clone());
    let mut other_execution = result_mismatch.executions[0].clone();
    other_execution.execution_id = other_execution_id;
    other_execution.verification = None;
    result_mismatch.executions.push(other_execution);
    assert!(matches!(
        result_mismatch.compare(),
        Err(VerificationError::InvalidResultEvidence { .. })
    ));

    let mut application_mismatch = Fixture::new(&[("target", Severity::Error)]);
    let (_, base_snapshot_sha256) = application_mismatch.application_digests();
    application_mismatch.patch_application = PatchApplication::Applied {
        patch_sha256: Sha256Digest::from_str(&"0".repeat(64)).unwrap(),
        base_snapshot_sha256,
    };
    assert!(matches!(
        application_mismatch.compare(),
        Err(VerificationError::PatchApplicationDigestMismatch {
            field: "patch_sha256"
        })
    ));
}

#[test]
fn target_and_candidate_scope_must_be_exact() {
    let mut unknown_target = Fixture::new(&[("target", Severity::Error)]);
    unknown_target.targets = vec![classified("unknown", Severity::Error).fingerprint];
    assert!(matches!(
        unknown_target.compare(),
        Err(VerificationError::UnknownTarget { .. })
    ));

    let mut unknown_observation = Fixture::new(&[("target", Severity::Error)]);
    unknown_observation
        .candidate
        .observation_ids
        .push(id("observation", "unknown"));
    assert!(matches!(
        unknown_observation.compare(),
        Err(VerificationError::UnknownCandidateObservation { .. })
    ));
}

#[test]
fn candidate_scope_cannot_cross_tool_versions() {
    let mut fixture = Fixture::new(&[("target", Severity::Error)]);
    let mut other_observation = observation("other-tool", Severity::Info);
    other_observation.tool.version = "2.0.0".into();
    let other = build_finding_with_taxonomy(
        &other_observation,
        &Taxonomy {
            category: Category::Type,
            micro_category: MicroCategory::IncompatibleType,
        },
    )
    .unwrap();
    fixture
        .candidate
        .observation_ids
        .push(other_observation.observation_id);
    fixture.before.push(other);

    assert!(matches!(
        fixture.compare(),
        Err(VerificationError::CandidateToolMismatch { .. })
    ));
}

#[test]
fn duplicate_and_oversized_inputs_are_rejected_before_comparison() {
    let mut duplicate = Fixture::new(&[("target", Severity::Error)]);
    duplicate.targets.push(duplicate.targets[0].clone());
    assert!(matches!(
        duplicate.compare(),
        Err(VerificationError::DuplicateTarget { .. })
    ));

    let fixture = Fixture::new(&[("target", Severity::Error)]);
    let oversized_targets = vec![fixture.targets[0].clone(); MAX_VERIFICATION_TARGETS + 1];
    assert!(matches!(
        compare_safe_fix(SafeFixComparisonInput {
            candidate: &fixture.candidate,
            target_fingerprints: &oversized_targets,
            evidence: &fixture.evidence,
            executions: &fixture.executions,
            patch_application: &fixture.patch_application,
            before_findings: &fixture.before,
            after_findings: &fixture.after,
        }),
        Err(VerificationError::InvalidTargetCount)
    ));
}

#[test]
fn duplicate_findings_are_deduplicated_with_strictest_severity() {
    let mut fixture = Fixture::new(&[("target", Severity::Warning)]);
    let mut duplicate = classified("target", Severity::Error);
    duplicate.state = FindingState::FixProposed;
    duplicate.fix_candidate_id = Some(fixture.candidate.fix_candidate_id.clone());
    fixture.before.push(duplicate);

    let SafeFixVerification::Verified(verified) = fixture.compare().unwrap() else {
        panic!("deduplicated target did not verify");
    };
    assert_eq!(verified.verified_targets[0].severity, Severity::Error);
}

#[test]
fn all_input_permutations_produce_the_same_result() {
    let mut first = Fixture::new(&[
        ("target-z", Severity::Error),
        ("target-a", Severity::Warning),
    ]);
    first.after = vec![
        classified("new-z", Severity::Info),
        classified("new-a", Severity::Info),
    ];
    let expected = first.compare().unwrap();

    let mut permuted = first.clone();
    permuted.targets.reverse();
    permuted.before.reverse();
    permuted.after.reverse();
    permuted.evidence.reverse();
    permuted.candidate.observation_ids.reverse();
    permuted.executions[0]
        .verification
        .as_mut()
        .unwrap()
        .target_fingerprints
        .reverse();

    assert_eq!(permuted.compare().unwrap(), expected);
}

#[test]
fn conflict_path_bound_is_enforced() {
    let mut fixture = Fixture::new(&[("target", Severity::Error)]);
    let (patch_sha256, base_snapshot_sha256) = fixture.application_digests();
    fixture.patch_application = PatchApplication::Conflict {
        patch_sha256,
        base_snapshot_sha256,
        paths: (0..=MAX_VERIFICATION_TARGETS)
            .map(|index| RepoPath::from_str(&format!("src/{index}.rs")).unwrap())
            .collect(),
    };
    assert!(matches!(
        fixture.compare(),
        Err(VerificationError::ConflictPathsTooLarge { actual, max })
            if actual == MAX_VERIFICATION_TARGETS + 1 && max == MAX_VERIFICATION_TARGETS
    ));
}

#[test]
fn canonical_target_scope_rejects_observations_added_by_deduplication() {
    let mut fixture = Fixture::new(&[("target", Severity::Error)]);
    let mut duplicate = classified("target", Severity::Error);
    duplicate.observation_ids = vec![id("observation", "outside-scope")];
    fixture.before.push(duplicate);

    assert!(matches!(
        fixture.compare(),
        Err(VerificationError::TargetOutsideCandidateScope { .. })
    ));
}

#[test]
fn one_target_cannot_be_proposed_for_conflicting_candidates() {
    let mut fixture = Fixture::new(&[("target", Severity::Error)]);
    let mut conflicting = classified("target", Severity::Error);
    conflicting.state = FindingState::FixProposed;
    conflicting.fix_candidate_id = Some(id("candidate", "other"));
    fixture.before.push(conflicting);

    assert!(matches!(
        fixture.compare(),
        Err(VerificationError::TargetCandidateConflict { .. })
    ));
}

#[test]
fn cross_object_id_collisions_and_dangling_evidence_are_rejected() {
    let mut collision = Fixture::new(&[("target", Severity::Error)]);
    let colliding_id = collision.evidence[0].evidence_id.clone();
    collision.candidate.fix_candidate_id = colliding_id.clone();
    collision.before[0].fix_candidate_id = Some(colliding_id.clone());
    collision.executions[0]
        .verification
        .as_mut()
        .unwrap()
        .fix_candidate_id = colliding_id;
    assert!(matches!(
        collision.compare(),
        Err(VerificationError::DuplicateObjectId {
            field: "comparison objects",
            ..
        })
    ));

    let mut dangling = Fixture::new(&[("target", Severity::Error)]);
    let mut extra = inline_evidence(
        "dangling",
        EvidenceSource::Stdout,
        "text/plain",
        "diagnostic",
        Some(id("execution", "missing")),
    );
    extra.evidence_id = id("evidence", "dangling-extra");
    dangling.evidence.push(extra);
    assert!(matches!(
        dangling.compare(),
        Err(VerificationError::UnknownEvidenceExecution { .. })
    ));

    let mut observation_collision = Fixture::new(&[("target", Severity::Error)]);
    let colliding_id = observation_collision.evidence[0].evidence_id.clone();
    observation_collision.candidate.observation_ids = vec![colliding_id.clone()];
    observation_collision.before[0].observation_ids = vec![colliding_id];
    assert!(matches!(
        observation_collision.compare(),
        Err(VerificationError::DuplicateObjectId {
            field: "comparison objects",
            ..
        })
    ));

    let mut finding_evidence = Fixture::new(&[("target", Severity::Error)]);
    finding_evidence.before[0]
        .evidence_ids
        .push(id("evidence", "missing-finding-evidence"));
    assert!(matches!(
        finding_evidence.compare(),
        Err(VerificationError::UnknownFindingEvidence {
            phase: "before",
            ..
        })
    ));
}

#[test]
fn attribution_execution_must_be_required_and_bounded() {
    let mut optional = Fixture::new(&[("target", Severity::Error)]);
    optional.executions[0].required = false;
    assert!(matches!(
        optional.compare(),
        Err(VerificationError::AttributionExecutionNotRequired { .. })
    ));

    let mut oversized = Fixture::new(&[("target", Severity::Error)]);
    let patch = oversized
        .evidence
        .iter()
        .find(|item| item.source == EvidenceSource::Patch)
        .unwrap()
        .clone();
    let snapshot = oversized
        .evidence
        .iter()
        .find(|item| item.media_type == "application/vnd.diagnostic-triage.snapshot+json")
        .unwrap()
        .clone();
    for index in 1..=64 {
        let execution_id = id("execution", &format!("extra-{index}"));
        let result = inline_evidence(
            &format!("result-{index}"),
            EvidenceSource::Diagnostic,
            "application/json",
            "{\"findings\":[]}",
            Some(execution_id.clone()),
        );
        let execution = execution(
            execution_id,
            &oversized.candidate,
            &patch,
            &snapshot,
            &result,
            oversized.targets.clone(),
        );
        oversized.evidence.push(result);
        oversized.executions.push(execution);
    }
    assert!(matches!(
        oversized.compare(),
        Err(VerificationError::TargetExecutionLimit {
            actual: 65,
            max: 64,
            ..
        })
    ));
}

#[test]
fn aggregate_evidence_bytes_are_bounded_without_materializing_content() {
    let mut fixture = Fixture::new(&[("target", Severity::Error)]);
    for index in 0..65 {
        fixture.evidence.push(Evidence {
            schema_version: EvidenceSchemaVersion::V1,
            evidence_id: id("large-evidence", &index.to_string()),
            execution_id: None,
            source: EvidenceSource::Artifact,
            media_type: "application/octet-stream".into(),
            retained_bytes: 1_048_576,
            observed_bytes: 1_048_576,
            limit_bytes: 1_048_576,
            truncated: false,
            sha256: Sha256Digest::from_str(&"0".repeat(64)).unwrap(),
            relative_path: Some(RepoPath::from_str(&format!("artifacts/{index}.bin")).unwrap()),
            content: None,
        });
    }
    assert!(matches!(
        fixture.compare(),
        Err(VerificationError::EvidenceBytesTooLarge { .. })
    ));
}

#[test]
fn empty_targets_and_tool_mismatch_are_rejected() {
    let mut empty = Fixture::new(&[("target", Severity::Error)]);
    empty.targets.clear();
    assert!(matches!(
        empty.compare(),
        Err(VerificationError::InvalidTargetCount)
    ));

    let mut mismatch = Fixture::new(&[("target", Severity::Error)]);
    mismatch.executions[0].tool.version = "2.0.0".into();
    assert!(matches!(
        mismatch.compare(),
        Err(VerificationError::AttributionToolMismatch { .. })
    ));
}
