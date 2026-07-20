use std::str::FromStr;

use diagnostic_triage_contracts::{
    Fingerprint, Language, ObjectId, RepoPath,
    model::{
        Category, Finding, FindingSchemaVersion, FindingState, Location, MicroCategory, Position,
        Severity, Taxonomy, Tool,
    },
};
use diagnostic_triage_engine::{
    EngineError, EngineInputError,
    dedup::{MAX_DEDUPLICATION_FINDINGS, deduplicate_findings},
    deterministic_object_id,
    finding::{finding_id_for_finding, fingerprint_for_finding},
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

fn id(value: u64) -> ObjectId {
    ObjectId::from_str(&format!("019f7e95-0000-7000-8000-{value:012x}")).unwrap()
}

fn placeholder_fingerprint(value: u64) -> Fingerprint {
    Fingerprint::from_str(&format!("dtfp1:{value:064x}")).unwrap()
}

fn finding(fingerprint_value: u64, finding_id: u64, line: u32) -> Finding {
    let mut finding = Finding {
        schema_version: FindingSchemaVersion::V1,
        finding_id: id(finding_id),
        fingerprint: placeholder_fingerprint(0),
        observation_ids: vec![id(finding_id + 100)],
        tool: Tool {
            name: "ty".into(),
            version: "0.0.1".into(),
            rule_id: Some("invalid-argument-type".into()),
        },
        language: Language::from_str("python").unwrap(),
        severity: Severity::Warning,
        classification: Taxonomy {
            category: Category::Type,
            micro_category: MicroCategory::IncompatibleType,
        },
        message: format!("invalid argument {fingerprint_value}"),
        location: Some(Location {
            path: RepoPath::from_str("src/main.py").unwrap(),
            start: Position { line, column: 1 },
            end: None,
        }),
        symbol: Some("parse".into()),
        expected: None,
        observed: None,
        state: FindingState::Classified,
        evidence_ids: vec![id(finding_id + 200)],
        fix_candidate_id: None,
        verification_execution_ids: None,
    };
    finding.fingerprint = fingerprint_for_finding(&finding).unwrap();
    finding.finding_id = finding_id_for_finding(&finding).unwrap();
    finding
}

fn set_severity(finding: &mut Finding, severity: Severity) {
    finding.severity = severity;
    finding.finding_id = finding_id_for_finding(finding).unwrap();
}

#[test]
fn deduplication_is_order_independent_and_merges_observation_and_evidence_ids() {
    let first = finding(1, 1, 10);
    let mut second = finding(1, 2, 2);
    set_severity(&mut second, Severity::Error);
    let mut third = finding(1, 3, 60);
    set_severity(&mut third, Severity::Info);

    let forward = deduplicate_findings(vec![first.clone(), second.clone(), third.clone()]).unwrap();
    let reverse = deduplicate_findings(vec![third, second, first]).unwrap();

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(forward[0].severity, Severity::Error);
    assert_eq!(forward[0].location.as_ref().unwrap().start.line, 2);
    assert_eq!(forward[0].observation_ids, vec![id(101), id(102), id(103)]);
    assert_eq!(forward[0].evidence_ids, vec![id(201), id(202), id(203)]);
}

#[test]
fn deduplication_is_associative_and_idempotent() {
    let first = finding(1, 1, 10);
    let mut second = finding(1, 2, 2);
    set_severity(&mut second, Severity::Error);
    let mut third = finding(1, 3, 60);
    set_severity(&mut third, Severity::Info);

    let all = deduplicate_findings(vec![first.clone(), second.clone(), third.clone()]).unwrap();
    let pair = deduplicate_findings(vec![first, second]).unwrap();
    let grouped = deduplicate_findings(vec![pair[0].clone(), third]).unwrap();
    let repeated = deduplicate_findings(vec![all[0].clone(), all[0].clone()]).unwrap();

    assert_eq!(all, grouped);
    assert_eq!(all, repeated);
}

#[test]
fn deterministic_finding_ids_are_stable_for_repeated_and_relocated_observations() {
    let first = finding(1, 1, 90);
    let relocated = finding(1, 2, 12);

    assert_eq!(first.fingerprint, relocated.fingerprint);
    assert_eq!(first.finding_id, relocated.finding_id);
    assert_eq!(finding_id_for_finding(&first).unwrap(), first.finding_id);
}

#[test]
fn deterministic_ids_are_domain_separated_and_length_prefixed() {
    let first = deterministic_object_id("finding/v1", ["a", "bc"]).unwrap();
    let repeated = deterministic_object_id("finding/v1", ["a", "bc"]).unwrap();
    let repartitioned = deterministic_object_id("finding/v1", ["ab", "c"]).unwrap();
    let other_domain = deterministic_object_id("decision/v1", ["a", "bc"]).unwrap();

    assert_eq!(first, repeated);
    assert_ne!(first, repartitioned);
    assert_ne!(first, other_domain);
    assert_eq!(first.as_str().as_bytes()[14], b'8');
    assert!(matches!(
        deterministic_object_id("", ["field"]),
        Err(EngineError::Input(
            EngineInputError::EmptyDeterministicIdDomain
        ))
    ));
}

#[test]
fn forged_fingerprint_is_rejected_before_deduplication() {
    let first = finding(1, 1, 1);
    let mut forged = first.clone();
    forged.message = "different semantic context".into();

    assert!(matches!(
        deduplicate_findings(vec![first, forged]),
        Err(EngineError::FingerprintMismatch { .. })
    ));
}

#[test]
fn conflicting_classification_is_rejected_for_one_fingerprint() {
    let first = finding(1, 1, 1);
    let mut conflicting = finding(1, 2, 1);
    conflicting.classification = Taxonomy {
        category: Category::Runtime,
        micro_category: MicroCategory::Exception,
    };
    conflicting.finding_id = finding_id_for_finding(&conflicting).unwrap();

    assert!(matches!(
        deduplicate_findings(vec![first, conflicting]),
        Err(EngineError::ConflictingFinding {
            field: "classification",
            ..
        })
    ));
}

#[test]
fn deduplication_rejects_non_classified_lifecycle_input() {
    let mut finding = finding(1, 1, 1);
    finding.state = FindingState::Discovered;

    assert!(matches!(
        deduplicate_findings(vec![finding]),
        Err(EngineError::Input(
            EngineInputError::InvalidDeduplicationState
        ))
    ));
}

#[test]
fn same_fingerprint_with_different_tool_versions_is_rejected() {
    let first = finding(1, 1, 90);
    let mut second = finding(1, 2, 12);
    set_severity(&mut second, Severity::Error);
    second.tool.version = "0.0.2".into();

    assert!(matches!(
        deduplicate_findings(vec![first, second]),
        Err(EngineError::ConflictingFinding {
            field: "tool version",
            ..
        })
    ));
}

#[test]
fn deduplication_rejects_forged_finding_ids() {
    let mut forged = finding(1, 1, 1);
    forged.finding_id = id(999);

    assert!(matches!(
        deduplicate_findings(vec![forged]),
        Err(EngineError::FindingIdMismatch { .. })
    ));
}

#[test]
fn distinct_findings_are_sorted_by_fingerprint() {
    let output = deduplicate_findings(vec![finding(9, 1, 1), finding(2, 2, 1)]).unwrap();

    assert_eq!(output.len(), 2);
    assert!(output[0].fingerprint < output[1].fingerprint);
}

#[test]
fn provider_reference_assignment_does_not_choose_the_representative() {
    let mut first = finding(1, 1, 90);
    let mut second = finding(1, 2, 12);
    first.observation_ids = vec![id(900)];
    first.evidence_ids = vec![id(901)];
    second.observation_ids = vec![id(1)];
    second.evidence_ids = vec![id(2)];
    let baseline = deduplicate_findings(vec![first.clone(), second.clone()]).unwrap();

    std::mem::swap(&mut first.observation_ids, &mut second.observation_ids);
    std::mem::swap(&mut first.evidence_ids, &mut second.evidence_ids);
    let reassigned = deduplicate_findings(vec![second, first]).unwrap();

    assert_eq!(baseline, reassigned);
}

#[test]
fn empty_deduplication_is_an_empty_success() {
    assert!(deduplicate_findings(Vec::new()).unwrap().is_empty());
}

#[test]
fn deduplication_input_count_is_bounded_before_validation() {
    let mut forged = finding(1, 1, 1);
    forged.finding_id = id(999);
    let input = vec![forged; MAX_DEDUPLICATION_FINDINGS + 1];

    assert!(matches!(
        deduplicate_findings(input),
        Err(EngineError::Input(
            EngineInputError::DeduplicationInputTooLarge {
                actual,
                max: MAX_DEDUPLICATION_FINDINGS,
            }
        )) if actual == MAX_DEDUPLICATION_FINDINGS + 1
    ));
}

#[test]
fn merged_observation_references_are_bounded_during_union() {
    let first = finding(1, 1, 1);
    let mut second = finding(1, 2, 2);
    second.observation_ids = (0..1_024).map(|index| id(10_000 + index)).collect();

    assert!(matches!(
        deduplicate_findings(vec![first, second]),
        Err(EngineError::Input(
            EngineInputError::DeduplicatedReferenceLimit {
                field: "observation_ids",
                max: 1_024,
            }
        ))
    ));
}

#[test]
fn merged_evidence_references_are_bounded_during_union() {
    let first = finding(1, 1, 1);
    let mut second = finding(1, 2, 2);
    second.evidence_ids = (0..64).map(|index| id(20_000 + index)).collect();

    assert!(matches!(
        deduplicate_findings(vec![first, second]),
        Err(EngineError::Input(
            EngineInputError::DeduplicatedReferenceLimit {
                field: "evidence_ids",
                max: 64,
            }
        ))
    ));
}
