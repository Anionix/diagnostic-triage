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
    dedup::deduplicate_findings,
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
fn deduplication_is_order_independent_and_merges_references() {
    let first = finding(1, 1, 90);
    let mut second = finding(1, 2, 12);
    set_severity(&mut second, Severity::Error);
    second.tool.version = "0.0.2".into();

    let forward = deduplicate_findings(vec![first.clone(), second.clone()]).unwrap();
    let reverse = deduplicate_findings(vec![second, first]).unwrap();

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(forward[0].severity, Severity::Error);
    assert_eq!(forward[0].observation_ids, vec![id(101), id(102)]);
    assert_eq!(forward[0].evidence_ids, vec![id(201), id(202)]);
}

#[test]
fn representative_selection_ignores_provider_ids() {
    let mut preferred = finding(1, 7, 90);
    preferred.tool.version = "0.0.1".into();
    preferred.observation_ids = vec![id(900)];
    preferred.evidence_ids = vec![id(901)];

    let mut other = finding(1, 7, 120);
    other.tool.version = "0.0.2".into();
    other.observation_ids = vec![id(1)];
    other.evidence_ids = vec![id(2)];

    let baseline = deduplicate_findings(vec![preferred.clone(), other.clone()]).unwrap();

    preferred.observation_ids = vec![id(1)];
    preferred.evidence_ids = vec![id(2)];
    other.observation_ids = vec![id(900)];
    other.evidence_ids = vec![id(901)];
    let reassigned = deduplicate_findings(vec![other, preferred]).unwrap();

    assert_eq!(
        baseline[0].tool.version, reassigned[0].tool.version,
        "provider IDs must not choose the representative"
    );
    assert_eq!(baseline[0].location, reassigned[0].location);
    assert_eq!(baseline[0].location.as_ref().unwrap().start.line, 90);
}

#[test]
fn forged_finding_id_is_rejected_before_representative_selection() {
    let first = finding(1, 7, 90);
    let mut second = first.clone();
    second.finding_id = id(8);

    assert!(matches!(
        deduplicate_findings(vec![first, second]),
        Err(EngineError::FindingIdMismatch { .. })
    ));
}

#[test]
fn representative_selection_ignores_pre_merge_severity() {
    let mut first = finding(1, 7, 90);
    set_severity(&mut first, Severity::Warning);

    let mut second = finding(1, 7, 120);
    set_severity(&mut second, Severity::Error);
    let baseline = deduplicate_findings(vec![first.clone(), second.clone()]).unwrap();

    set_severity(&mut first, Severity::Error);
    set_severity(&mut second, Severity::Warning);
    let swapped = deduplicate_findings(vec![second, first]).unwrap();

    assert_eq!(baseline[0].severity, Severity::Error);
    assert_eq!(swapped[0].severity, Severity::Error);
    assert_eq!(baseline[0].location, swapped[0].location);
}

#[test]
fn distinct_findings_are_sorted_by_fingerprint() {
    let output = deduplicate_findings(vec![finding(9, 1, 1), finding(2, 2, 1)]).unwrap();
    assert!(output[0].fingerprint < output[1].fingerprint);
}

#[test]
fn a_forged_fingerprint_cannot_merge_different_paths() {
    let first = finding(1, 1, 1);
    let mut second = finding(1, 2, 1);
    second.location.as_mut().unwrap().path = RepoPath::from_str("src/other.py").unwrap();

    let error = deduplicate_findings(vec![first, second]).unwrap_err();
    assert!(error.to_string().contains("fingerprint inconsistent"));
}

#[test]
fn deterministic_ids_are_domain_separated_version_eight_uuids() {
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
