use std::str::FromStr;

use diagnostic_triage_contracts::{
    Language, ObjectId,
    model::{
        Category, MicroCategory, Observation, ObservationSchemaVersion, Origin, Severity, Taxonomy,
        Tool,
    },
};
use diagnostic_triage_engine::{
    EngineError, EngineInputError,
    classification::{
        ClassificationRule, MAX_CLASSIFICATION_RULES, RuleIdSelector, classify_observation,
    },
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

fn observation(rule_id: Option<&str>) -> Observation {
    Observation {
        schema_version: ObservationSchemaVersion::V1,
        observation_id: ObjectId::from_str("019f7e95-0000-7000-8000-000000000001").unwrap(),
        tool: Tool {
            name: "ty".into(),
            version: "0.0.1".into(),
            rule_id: rule_id.map(str::to_owned),
        },
        language: Language::from_str("python").unwrap(),
        severity: Severity::Error,
        origin: Origin::Normal,
        message: "invalid argument".into(),
        location: None,
        symbol: Some("parse".into()),
        expected: None,
        observed: None,
        evidence_ids: Vec::new(),
    }
}

fn taxonomy(category: Category, micro_category: MicroCategory) -> Taxonomy {
    Taxonomy {
        category,
        micro_category,
    }
}

fn rule(id: &str, selector: RuleIdSelector, taxonomy: Taxonomy) -> ClassificationRule {
    ClassificationRule {
        id: id.into(),
        tool_name: "ty".into(),
        native_rule_id: selector,
        language: None,
        origin: None,
        taxonomy,
    }
}

#[test]
fn most_specific_rule_wins_independent_of_catalog_order() {
    let fallback = rule(
        "ty.fallback",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::Unknown),
    );
    let exact = rule(
        "ty.invalid-argument",
        RuleIdSelector::Exact("invalid-argument-type".into()),
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    let input = observation(Some("invalid-argument-type"));

    let forward = classify_observation(&input, &[fallback.clone(), exact.clone()]).unwrap();
    let reverse = classify_observation(&input, &[exact, fallback]).unwrap();

    assert_eq!(forward, reverse);
    assert_eq!(forward.rule_id, "ty.invalid-argument");
    assert_eq!(
        forward.taxonomy.micro_category,
        MicroCategory::IncompatibleType
    );
}

#[test]
fn absent_selector_does_not_match_present_rule_id() {
    let absent = rule(
        "ty.no-rule",
        RuleIdSelector::Absent,
        taxonomy(Category::Type, MicroCategory::Unknown),
    );
    assert!(matches!(
        classify_observation(&observation(Some("x")), &[absent]),
        Err(EngineError::Unclassified { .. })
    ));
}

#[test]
fn equal_specificity_with_different_taxonomy_is_rejected() {
    let first = rule(
        "a",
        RuleIdSelector::Exact("x".into()),
        taxonomy(Category::Type, MicroCategory::Unknown),
    );
    let second = rule(
        "b",
        RuleIdSelector::Exact("x".into()),
        taxonomy(Category::Correctness, MicroCategory::Unknown),
    );

    assert!(matches!(
        classify_observation(&observation(Some("x")), &[second, first]),
        Err(EngineError::AmbiguousClassification { rule_ids, .. }) if rule_ids == "a,b"
    ));
}

#[test]
fn ambiguous_classification_error_is_bounded() {
    let rules = (0..10)
        .map(|index| {
            rule(
                &format!("rule-{index}"),
                RuleIdSelector::Exact("x".to_owned()),
                if index == 9 {
                    taxonomy(Category::Correctness, MicroCategory::Unknown)
                } else {
                    taxonomy(Category::Type, MicroCategory::Unknown)
                },
            )
        })
        .collect::<Vec<_>>();

    assert!(matches!(
        classify_observation(&observation(Some("x")), &rules),
        Err(EngineError::AmbiguousClassification {
            rule_ids,
            omitted_rule_count: 2,
            ..
        }) if rule_ids.split(',').count() == 8
    ));
}

#[test]
fn invalid_taxonomy_pair_is_rejected_before_matching() {
    let invalid = rule(
        "invalid",
        RuleIdSelector::Any,
        taxonomy(Category::Syntax, MicroCategory::WrongResult),
    );
    assert!(matches!(
        classify_observation(&observation(None), &[invalid]),
        Err(EngineError::Contract(_))
    ));
}

#[test]
fn duplicate_catalog_ids_are_rejected() {
    let first = rule(
        "duplicate",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::Unknown),
    );
    let second = first.clone();

    assert!(matches!(
        classify_observation(&observation(None), &[first, second]),
        Err(EngineError::Input(
            EngineInputError::DuplicateClassificationRuleId { rule_id }
        )) if rule_id == "duplicate"
    ));
}

#[test]
fn malformed_catalog_identity_returns_typed_errors() {
    let invalid_id = rule(
        "",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::Unknown),
    );
    assert!(matches!(
        classify_observation(&observation(None), &[invalid_id]),
        Err(EngineError::Input(
            EngineInputError::InvalidClassificationRuleId { length: 0 }
        ))
    ));

    let oversized_id = rule(
        &"x".repeat(129),
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::Unknown),
    );
    assert!(matches!(
        classify_observation(&observation(None), &[oversized_id]),
        Err(EngineError::Input(
            EngineInputError::InvalidClassificationRuleId { length: 129 }
        ))
    ));

    let mut noncanonical_tool = rule(
        "tool",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::Unknown),
    );
    noncanonical_tool.tool_name = " ty ".to_owned();
    assert!(matches!(
        classify_observation(&observation(None), &[noncanonical_tool]),
        Err(EngineError::Input(
            EngineInputError::NonCanonicalClassificationToolName { .. }
        ))
    ));

    let noncanonical_rule = rule(
        "native-rule",
        RuleIdSelector::Exact(" native ".to_owned()),
        taxonomy(Category::Type, MicroCategory::Unknown),
    );
    assert!(matches!(
        classify_observation(&observation(Some("native")), &[noncanonical_rule]),
        Err(EngineError::Input(
            EngineInputError::NonCanonicalClassificationNativeRuleId { .. }
        ))
    ));
}

#[test]
fn noncanonical_observation_tool_is_rejected_before_matching() {
    let mut input = observation(Some("native"));
    input.tool.name = " ty ".to_owned();
    let catalog = vec![rule(
        "native",
        RuleIdSelector::Exact("native".to_owned()),
        taxonomy(Category::Type, MicroCategory::Unknown),
    )];

    assert!(matches!(
        classify_observation(&input, &catalog),
        Err(EngineError::Input(
            EngineInputError::NonCanonicalObservationTool { .. }
        ))
    ));
}

#[test]
fn classification_catalog_is_bounded_before_validation() {
    let taxonomy = taxonomy(Category::Type, MicroCategory::Unknown);
    let catalog = (0..=MAX_CLASSIFICATION_RULES)
        .map(|index| {
            rule(
                &format!("rule-{index}"),
                RuleIdSelector::Any,
                taxonomy.clone(),
            )
        })
        .collect::<Vec<_>>();

    assert!(matches!(
        classify_observation(&observation(None), &catalog),
        Err(EngineError::Input(
            EngineInputError::ClassificationCatalogTooLarge { actual, max }
        )) if actual == MAX_CLASSIFICATION_RULES + 1 && max == MAX_CLASSIFICATION_RULES
    ));
}
