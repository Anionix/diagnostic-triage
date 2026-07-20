use std::str::FromStr;

use diagnostic_triage_contracts::{
    Language, ObjectId, RepoPath,
    model::{
        Category, Location, MicroCategory, Observation, ObservationSchemaVersion, Origin, Position,
        Severity, Taxonomy, Tool,
    },
};
use diagnostic_triage_engine::{
    EngineError, EngineInputError,
    classification::{ClassificationRule, RuleIdSelector},
    finding::{build_finding, build_finding_with_taxonomy, validate_finding_integrity},
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

fn observation() -> Observation {
    Observation {
        schema_version: ObservationSchemaVersion::V1,
        observation_id: ObjectId::from_str("019f7e95-0000-7000-8000-000000000001").unwrap(),
        tool: Tool {
            name: "ty".into(),
            version: "0.0.1".into(),
            rule_id: Some("invalid-argument-type".into()),
        },
        language: Language::from_str("python").unwrap(),
        severity: Severity::Error,
        origin: Origin::Normal,
        message: " invalid\n argument ".into(),
        location: Some(Location {
            path: RepoPath::from_str("src/main.py").unwrap(),
            start: Position {
                line: 10,
                column: 4,
            },
            end: None,
        }),
        symbol: Some(" parse ".into()),
        expected: Some(" int ".into()),
        observed: Some(" str ".into()),
        evidence_ids: Vec::new(),
    }
}

fn taxonomy() -> Taxonomy {
    Taxonomy {
        category: Category::Type,
        micro_category: MicroCategory::IncompatibleType,
    }
}

#[test]
fn finding_construction_normalizes_and_derives_stable_identity() {
    let first = build_finding_with_taxonomy(&observation(), &taxonomy()).unwrap();
    let repeated = build_finding_with_taxonomy(&observation(), &taxonomy()).unwrap();

    assert_eq!(first, repeated);
    assert_eq!(first.message, "invalid argument");
    assert_eq!(first.tool.name, "ty");
    assert_eq!(first.tool.version, "0.0.1");
    assert_eq!(first.tool.rule_id.as_deref(), Some("invalid-argument-type"));
    assert_eq!(first.symbol.as_deref(), Some("parse"));
    assert_eq!(first.expected.as_deref(), Some("int"));
    assert_eq!(first.observed.as_deref(), Some("str"));
    validate_finding_integrity(&first).unwrap();
}

#[test]
fn line_and_tool_version_changes_preserve_fingerprint() {
    let first = build_finding_with_taxonomy(&observation(), &taxonomy()).unwrap();
    let mut moved = observation();
    moved.location.as_mut().unwrap().start.line = 999;
    moved.tool.version = "0.1.0".into();
    let second = build_finding_with_taxonomy(&moved, &taxonomy()).unwrap();

    assert_eq!(first.fingerprint, second.fingerprint);
    assert_eq!(first.finding_id, second.finding_id);
    assert_ne!(first.location, second.location);
    assert_ne!(first.tool.version, second.tool.version);
}

#[test]
fn structured_catalog_rule_is_retained_outside_finding_contract() {
    let rule = ClassificationRule {
        id: "ty.invalid-argument".into(),
        tool_name: "ty".into(),
        native_rule_id: RuleIdSelector::Exact("invalid-argument-type".into()),
        language: None,
        origin: None,
        taxonomy: taxonomy(),
    };
    let classified = build_finding(&observation(), &[rule]).unwrap();

    assert_eq!(classified.classification_rule_id, "ty.invalid-argument");
    assert_eq!(classified.finding.classification, taxonomy());
}

#[test]
fn forged_fingerprint_is_rejected() {
    let mut finding = build_finding_with_taxonomy(&observation(), &taxonomy()).unwrap();
    finding.message = "different semantic context".into();

    assert!(matches!(
        validate_finding_integrity(&finding),
        Err(EngineError::FingerprintMismatch { .. })
    ));
}

#[test]
fn noncanonical_engine_finding_is_rejected_at_ingress() {
    let mut finding = build_finding_with_taxonomy(&observation(), &taxonomy()).unwrap();
    finding.tool.name = " ty ".into();

    assert!(matches!(
        validate_finding_integrity(&finding),
        Err(EngineError::Input(
            EngineInputError::NonCanonicalFindingField { field: "tool" }
        ))
    ));
}

#[test]
fn noncanonical_observation_tool_is_accepted_by_contract_but_rejected_by_engine() {
    let mut input = observation();
    input.tool = Tool {
        name: " ty ".into(),
        version: " 0.0.1 ".into(),
        rule_id: Some(" invalid-argument-type ".into()),
    };

    input.validate().unwrap();
    assert!(matches!(
        build_finding_with_taxonomy(&input, &taxonomy()),
        Err(EngineError::Input(
            EngineInputError::NonCanonicalFindingField { field: "tool" }
        ))
    ));
}

#[test]
fn forged_finding_id_is_rejected() {
    let mut finding = build_finding_with_taxonomy(&observation(), &taxonomy()).unwrap();
    finding.finding_id = ObjectId::from_str("019f7e95-0000-7000-8000-000000000999").unwrap();

    assert!(matches!(
        validate_finding_integrity(&finding),
        Err(EngineError::FindingIdMismatch { .. })
    ));
}

#[test]
fn policy_significant_fields_are_bound_to_finding_id() {
    let mut severity_changed = build_finding_with_taxonomy(&observation(), &taxonomy()).unwrap();
    severity_changed.severity = Severity::Info;
    assert!(matches!(
        validate_finding_integrity(&severity_changed),
        Err(EngineError::FindingIdMismatch { .. })
    ));

    let mut taxonomy_changed = build_finding_with_taxonomy(&observation(), &taxonomy()).unwrap();
    taxonomy_changed.classification = Taxonomy {
        category: Category::Runtime,
        micro_category: MicroCategory::Exception,
    };
    assert!(matches!(
        validate_finding_integrity(&taxonomy_changed),
        Err(EngineError::FindingIdMismatch { .. })
    ));
}

#[test]
fn whitespace_only_optional_identity_is_rejected() {
    let mut input = observation();
    input.symbol = Some(" \n ".into());

    assert!(matches!(
        build_finding_with_taxonomy(&input, &taxonomy()),
        Err(EngineError::Input(
            EngineInputError::EmptyNormalizedFindingField { field: "symbol" }
        ))
    ));
}
