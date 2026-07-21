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
        ClassificationAttribution, ClassificationMatch, ClassificationRule,
        MAX_CLASSIFICATION_RULES, RuleIdSelector, classify_observation,
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

fn native_observation(
    tool_name: &str,
    tool_version: &str,
    language: &str,
    rule_id: Option<&str>,
    message: &str,
) -> Observation {
    let mut input = observation(rule_id);
    tool_name.clone_into(&mut input.tool.name);
    tool_version.clone_into(&mut input.tool.version);
    input.language = Language::from_str(language).unwrap();
    message.clone_into(&mut input.message);
    input
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
        tool_version: None,
        native_rule_id: selector,
        language: None,
        origin: None,
        taxonomy,
    }
}

fn assert_catalog_rule(classification: &ClassificationMatch, expected_rule_id: &str) {
    assert_eq!(
        classification.attribution,
        ClassificationAttribution::CatalogRule {
            rule_id: expected_rule_id.to_owned(),
        }
    );
}

fn assert_builtin_unknown(classification: &ClassificationMatch) {
    assert_eq!(
        classification.attribution,
        ClassificationAttribution::BuiltinUnknown
    );
    assert_eq!(
        classification.taxonomy,
        taxonomy(Category::Unknown, MicroCategory::Unknown)
    );
}

#[test]
fn most_specific_rule_wins_independent_of_catalog_order() {
    let fallback = rule(
        "ty.fallback",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
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
    assert_catalog_rule(&forward, "ty.invalid-argument");
    assert_eq!(
        forward.taxonomy.micro_category,
        MicroCategory::IncompatibleType
    );
}

#[test]
fn exact_ruff_f821_mapping_precedes_builtin_unknown() {
    let mut exact = rule(
        "ruff.F821",
        RuleIdSelector::Exact("F821".to_owned()),
        taxonomy(Category::Type, MicroCategory::UnresolvedSymbol),
    );
    exact.tool_name = "ruff".to_owned();
    exact.language = Some(Language::from_str("python").unwrap());
    let input = native_observation(
        "ruff",
        "0.12.4",
        "python",
        Some("F821"),
        "Undefined name `value`",
    );

    let selected = classify_observation(&input, &[exact]).unwrap();

    assert_catalog_rule(&selected, "ruff.F821");
    assert_eq!(
        selected.taxonomy,
        taxonomy(Category::Type, MicroCategory::UnresolvedSymbol)
    );
}

#[test]
fn unmapped_native_diagnostics_use_typed_unknown_without_inference() {
    let mut f821 = rule(
        "ruff.F821",
        RuleIdSelector::Exact("F821".to_owned()),
        taxonomy(Category::Type, MicroCategory::UnresolvedSymbol),
    );
    f821.tool_name = "ruff".to_owned();
    f821.language = Some(Language::from_str("python").unwrap());
    let catalog = [f821];
    let observations = [
        native_observation(
            "ruff",
            "0.12.4",
            "python",
            Some("F401"),
            "Undefined name wording must not imply a type classification",
        ),
        native_observation(
            "ruff",
            "0.12.4",
            "python",
            Some("E501"),
            "syntax error wording must not imply a syntax classification",
        ),
        native_observation(
            "ruff",
            "0.12.4",
            "python",
            Some("B006"),
            "mutable default wording must not imply correctness",
        ),
        native_observation(
            "ruff",
            "0.12.4",
            "python",
            None,
            "missing native code remains unknown",
        ),
        native_observation(
            "biome",
            "2.1.3",
            "typescript",
            Some("lint/suspicious/noDoubleEquals"),
            "generic Biome diagnostic",
        ),
        native_observation(
            "rustc",
            "1.85.0",
            "rust",
            Some("E0308"),
            "generic rustc diagnostic",
        ),
    ];

    for input in observations {
        assert_builtin_unknown(&classify_observation(&input, &catalog).unwrap());
    }
}

#[test]
fn exact_tool_version_beats_generic_independent_of_catalog_order() {
    let mut generic = rule(
        "ty.generic",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    generic.native_rule_id = RuleIdSelector::Exact("invalid-argument-type".into());
    let mut exact = rule(
        "ty.versioned",
        RuleIdSelector::Exact("invalid-argument-type".into()),
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    exact.tool_version = Some("0.0.1".into());
    let input = observation(Some("invalid-argument-type"));

    let forward = classify_observation(&input, &[generic.clone(), exact.clone()]).unwrap();
    let reverse = classify_observation(&input, &[exact, generic]).unwrap();

    assert_eq!(forward, reverse);
    assert_catalog_rule(&forward, "ty.versioned");
    assert_eq!(
        forward.taxonomy.micro_category,
        MicroCategory::IncompatibleType
    );
}

#[test]
fn exact_tool_versions_select_their_own_taxonomy_without_ambiguity() {
    let mut first = rule(
        "ty.v1",
        RuleIdSelector::Exact("invalid-argument-type".into()),
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    first.tool_version = Some("0.0.1".into());
    let mut second = rule(
        "ty.v2",
        RuleIdSelector::Exact("invalid-argument-type".into()),
        taxonomy(Category::Correctness, MicroCategory::WrongResult),
    );
    second.tool_version = Some("0.0.2".into());
    let rules = [first, second];

    let first_match =
        classify_observation(&observation(Some("invalid-argument-type")), &rules).unwrap();
    let mut second_input = observation(Some("invalid-argument-type"));
    second_input.tool.version = "0.0.2".into();
    let second_match = classify_observation(&second_input, &rules).unwrap();

    assert_catalog_rule(&first_match, "ty.v1");
    assert_eq!(
        first_match.taxonomy.micro_category,
        MicroCategory::IncompatibleType
    );
    assert_catalog_rule(&second_match, "ty.v2");
    assert_eq!(
        second_match.taxonomy.micro_category,
        MicroCategory::WrongResult
    );
}

#[test]
fn wrong_exact_tool_version_does_not_match() {
    let mut versioned = rule(
        "ty.versioned",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    versioned.tool_version = Some("0.0.2".into());

    let mut input = observation(None);
    input.tool.version = "0.0.1".into();

    assert_builtin_unknown(&classify_observation(&input, &[versioned]).unwrap());
}

#[test]
fn generic_version_rule_remains_a_fallback_for_other_versions() {
    let generic = rule(
        "ty.generic",
        RuleIdSelector::Exact("invalid-argument-type".into()),
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    let mut versioned = rule(
        "ty.versioned",
        RuleIdSelector::Exact("invalid-argument-type".into()),
        taxonomy(Category::Correctness, MicroCategory::WrongResult),
    );
    versioned.tool_version = Some("0.0.2".into());
    let input = observation(Some("invalid-argument-type"));

    let selected = classify_observation(&input, &[versioned, generic]).unwrap();

    assert_catalog_rule(&selected, "ty.generic");
}

#[test]
fn tool_version_selector_uses_unicode_character_boundaries() {
    let boundary = "\u{e9}".repeat(64);
    let mut input = observation(None);
    input.tool.version.clone_from(&boundary);
    let mut accepted = rule(
        "version-boundary",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    accepted.tool_version = Some(boundary);

    assert_catalog_rule(
        &classify_observation(&input, &[accepted]).unwrap(),
        "version-boundary",
    );

    let mut rejected = rule(
        "version-overflow",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    rejected.tool_version = Some("\u{e9}".repeat(65));
    assert!(matches!(
        classify_observation(&observation(None), &[rejected]),
        Err(EngineError::Input(
            EngineInputError::InvalidClassificationToolVersion { .. }
        ))
    ));
}

#[test]
fn orthogonal_single_constraints_with_conflicting_taxonomy_are_ambiguous() {
    let mut version_only = rule(
        "ty.version-only",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    version_only.tool_version = Some("0.0.1".into());
    let rule_only = rule(
        "ty.rule-only",
        RuleIdSelector::Exact("invalid-argument-type".into()),
        taxonomy(Category::Correctness, MicroCategory::WrongResult),
    );

    assert!(matches!(
        classify_observation(
            &observation(Some("invalid-argument-type")),
            &[version_only, rule_only]
        ),
        Err(EngineError::AmbiguousClassification { .. })
    ));
}

#[test]
fn identically_constrained_rules_are_ambiguous_even_with_the_same_taxonomy() {
    let first = rule(
        "same-a",
        RuleIdSelector::Exact("x".into()),
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    let second = rule(
        "same-b",
        RuleIdSelector::Exact("x".into()),
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );

    assert!(matches!(
        classify_observation(&observation(Some("x")), &[first, second]),
        Err(EngineError::AmbiguousClassification { rule_ids, .. })
            if rule_ids == vec!["same-a", "same-b"]
    ));
}

#[test]
fn tool_versions_are_opaque_and_case_sensitive() {
    let generic = rule(
        "generic",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    let mut exact = rule(
        "exact",
        RuleIdSelector::Any,
        taxonomy(Category::Correctness, MicroCategory::WrongResult),
    );
    exact.tool_version = Some("V1.0.0+BUILD".into());

    let selected = classify_observation(&observation(None), &[exact, generic]).unwrap();

    assert_catalog_rule(&selected, "generic");
}

#[test]
fn absent_native_rule_selector_refines_any_for_missing_rule_id() {
    let fallback = rule(
        "fallback",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    let absent = rule(
        "absent",
        RuleIdSelector::Absent,
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );

    let selected = classify_observation(&observation(None), &[absent, fallback]).unwrap();

    assert_catalog_rule(&selected, "absent");
}

#[test]
fn unequal_constraint_counts_do_not_break_incomparable_ambiguity() {
    let mut three_constraints = rule(
        "three",
        RuleIdSelector::Exact("x".into()),
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    three_constraints.tool_version = Some("0.0.1".into());
    three_constraints.language = Some(Language::from_str("python").unwrap());
    let mut origin_only = rule(
        "origin",
        RuleIdSelector::Any,
        taxonomy(Category::Correctness, MicroCategory::WrongResult),
    );
    origin_only.origin = Some(Origin::Normal);

    assert!(matches!(
        classify_observation(
            &observation(Some("x")),
            &[three_constraints, origin_only]
        ),
        Err(EngineError::AmbiguousClassification { rule_ids, .. })
            if rule_ids == vec!["origin", "three"]
    ));
}

#[test]
fn later_combined_refinement_dominates_both_diamond_parents() {
    let mut version_only = rule(
        "version",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    version_only.tool_version = Some("0.0.1".into());
    let mut language_only = rule(
        "language",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    language_only.language = Some(Language::from_str("python").unwrap());
    let mut combined = rule(
        "combined",
        RuleIdSelector::Any,
        taxonomy(Category::Correctness, MicroCategory::WrongResult),
    );
    combined.tool_version = Some("0.0.1".into());
    combined.language = Some(Language::from_str("python").unwrap());

    let selected =
        classify_observation(&observation(None), &[version_only, language_only, combined]).unwrap();

    assert_catalog_rule(&selected, "combined");
}

#[test]
fn absent_selector_does_not_match_present_rule_id() {
    let absent = rule(
        "ty.no-rule",
        RuleIdSelector::Absent,
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    assert_builtin_unknown(&classify_observation(&observation(Some("x")), &[absent]).unwrap());
}

#[test]
fn equal_specificity_with_different_taxonomy_is_rejected() {
    let first = rule(
        "a",
        RuleIdSelector::Exact("x".into()),
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    let second = rule(
        "b",
        RuleIdSelector::Exact("x".into()),
        taxonomy(Category::Correctness, MicroCategory::WrongResult),
    );

    assert!(matches!(
        classify_observation(&observation(Some("x")), &[second, first]),
        Err(EngineError::AmbiguousClassification { rule_ids, .. })
            if rule_ids == vec!["a", "b"]
    ));
}

#[test]
fn ambiguous_rule_ids_remain_structured_when_ids_contain_commas() {
    let first = rule(
        "a,one",
        RuleIdSelector::Exact("x".into()),
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    let second = rule(
        "b,two",
        RuleIdSelector::Exact("x".into()),
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );

    assert!(matches!(
        classify_observation(&observation(Some("x")), &[second, first]),
        Err(EngineError::AmbiguousClassification { rule_ids, .. })
            if rule_ids == vec!["a,one", "b,two"]
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
                    taxonomy(Category::Correctness, MicroCategory::WrongResult)
                } else {
                    taxonomy(Category::Type, MicroCategory::IncompatibleType)
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
        }) if rule_ids.len() == 8
    ));
}

#[test]
fn maximum_supported_catalog_selects_a_unique_refinement_at_the_end() {
    let fallback_taxonomy = taxonomy(Category::Type, MicroCategory::IncompatibleType);
    let mut rules = (0..MAX_CLASSIFICATION_RULES - 1)
        .map(|index| {
            rule(
                &format!("fallback-{index:04}"),
                RuleIdSelector::Any,
                fallback_taxonomy.clone(),
            )
        })
        .collect::<Vec<_>>();
    rules.push(rule(
        "unique-refinement",
        RuleIdSelector::Exact("x".to_owned()),
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    ));

    let selected = classify_observation(&observation(Some("x")), &rules).unwrap();

    assert_eq!(rules.len(), MAX_CLASSIFICATION_RULES);
    assert_catalog_rule(&selected, "unique-refinement");
    assert_eq!(
        selected.taxonomy.micro_category,
        MicroCategory::IncompatibleType
    );
}

#[test]
fn maximum_supported_ambiguity_is_bounded_and_deterministic() {
    let shared_taxonomy = taxonomy(Category::Type, MicroCategory::IncompatibleType);
    let rules = (0..MAX_CLASSIFICATION_RULES)
        .rev()
        .map(|index| {
            rule(
                &format!("ambiguous-{index:04}"),
                RuleIdSelector::Exact("x".to_owned()),
                shared_taxonomy.clone(),
            )
        })
        .collect::<Vec<_>>();
    let expected_rule_ids = (0..8)
        .map(|index| format!("ambiguous-{index:04}"))
        .collect::<Vec<_>>();

    assert!(matches!(
        classify_observation(&observation(Some("x")), &rules),
        Err(EngineError::AmbiguousClassification {
            rule_ids,
            omitted_rule_count,
            ..
        }) if rule_ids == expected_rule_ids
            && omitted_rule_count == MAX_CLASSIFICATION_RULES - 8
    ));
}

#[test]
fn invalid_taxonomy_pair_is_rejected_before_matching() {
    let mut invalid = rule(
        "invalid",
        RuleIdSelector::Any,
        taxonomy(Category::Syntax, MicroCategory::WrongResult),
    );
    invalid.tool_name = "other-tool".to_owned();
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
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
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
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
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
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
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
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
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
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    assert!(matches!(
        classify_observation(&observation(Some("native")), &[noncanonical_rule]),
        Err(EngineError::Input(
            EngineInputError::NonCanonicalClassificationNativeRuleId { .. }
        ))
    ));

    let mut empty_tool_version = rule(
        "empty-version",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    empty_tool_version.tool_version = Some(String::new());
    assert!(matches!(
        classify_observation(&observation(None), &[empty_tool_version]),
        Err(EngineError::Input(
            EngineInputError::InvalidClassificationToolVersion { rule_id }
        )) if rule_id == "empty-version"
    ));

    let mut oversized_tool_version = rule(
        "oversized-version",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    oversized_tool_version.tool_version = Some("x".repeat(65));
    assert!(matches!(
        classify_observation(&observation(None), &[oversized_tool_version]),
        Err(EngineError::Input(
            EngineInputError::InvalidClassificationToolVersion { rule_id }
        )) if rule_id == "oversized-version"
    ));

    let mut noncanonical_tool_version = rule(
        "noncanonical-version",
        RuleIdSelector::Any,
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    );
    noncanonical_tool_version.tool_version = Some(" 0.0.1 ".into());
    assert!(matches!(
        classify_observation(&observation(None), &[noncanonical_tool_version]),
        Err(EngineError::Input(
            EngineInputError::NonCanonicalClassificationToolVersion { rule_id }
        )) if rule_id == "noncanonical-version"
    ));
}

#[test]
fn noncanonical_observation_tool_is_rejected_before_matching() {
    let mut input = observation(Some("native"));
    input.tool.name = " ty ".to_owned();
    let catalog = vec![rule(
        "native",
        RuleIdSelector::Exact("native".to_owned()),
        taxonomy(Category::Type, MicroCategory::IncompatibleType),
    )];

    assert!(matches!(
        classify_observation(&input, &catalog),
        Err(EngineError::Input(
            EngineInputError::NonCanonicalObservationTool { .. }
        ))
    ));
}

#[test]
fn invalid_observation_is_rejected_before_builtin_unknown() {
    let mut input = observation(None);
    input.message.clear();

    assert!(matches!(
        classify_observation(&input, &[]),
        Err(EngineError::Contract(_))
    ));
}

#[test]
fn classification_catalog_is_bounded_before_validation() {
    let taxonomy = taxonomy(Category::Type, MicroCategory::IncompatibleType);
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
