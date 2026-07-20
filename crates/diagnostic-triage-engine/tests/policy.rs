// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.
use std::str::FromStr;

use diagnostic_triage_contracts::model::{
    Category, DecisionAction, Finding, FindingSchemaVersion, FindingState, MicroCategory,
    PreReportState, Severity, Taxonomy, Tool, WaivedAction,
};
use diagnostic_triage_contracts::{Fingerprint, Language, ObjectId};
use diagnostic_triage_engine::finding::{finding_id_for_finding, fingerprint_for_finding};
use diagnostic_triage_engine::policy::{
    MAX_POLICY_RULES, MAX_POLICY_WAIVERS, PolicyAction, PolicyError, PolicyMatcher, PolicyRule,
    PolicySnapshot, PolicyWaiver, build_decision, evaluate_policy, policy_digest,
    validate_decision_integrity, validate_policy, validate_waivers,
};
use diagnostic_triage_engine::{EngineError, EngineInputError};

const EVALUATION_TIME: &str = "2026-07-20T00:00:00Z";
const FUTURE_EXPIRY: &str = "2026-07-21T00:00:00Z";
const FORGED_FINGERPRINT: &str =
    "dtfp1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn finding(category: Category, severity: Severity) -> Finding {
    let micro_category = match category {
        Category::Syntax => MicroCategory::ParseError,
        Category::Type => MicroCategory::IncompatibleType,
        Category::Correctness => MicroCategory::Assertion,
        Category::Build => MicroCategory::Compile,
        Category::Test => MicroCategory::Collection,
        Category::Runtime => MicroCategory::Exception,
        Category::Style => MicroCategory::Format,
        _ => MicroCategory::Unknown,
    };
    let mut finding = Finding {
        schema_version: FindingSchemaVersion::V1,
        finding_id: ObjectId::from_str("019f7e95-0000-7000-8000-000000000001").unwrap(),
        fingerprint: Fingerprint::from_str(FORGED_FINGERPRINT).unwrap(),
        observation_ids: vec![ObjectId::from_str("019f7e95-0000-7000-8000-000000000002").unwrap()],
        tool: Tool {
            name: "fixture-tool".to_owned(),
            version: "1.0.0".to_owned(),
            rule_id: Some("fixture.rule".to_owned()),
        },
        language: Language::from_str("rust").unwrap(),
        severity,
        classification: Taxonomy {
            category,
            micro_category,
        },
        message: "fixture finding".to_owned(),
        location: None,
        symbol: None,
        expected: None,
        observed: None,
        state: FindingState::Classified,
        pre_report_state: None,
        evidence_ids: vec![],
        fix_candidate_id: None,
        verification_execution_ids: None,
    };
    finding.fingerprint = fingerprint_for_finding(&finding).unwrap();
    finding.finding_id = finding_id_for_finding(&finding).unwrap();
    finding
}

fn rule(rule_id: &str, action: PolicyAction, category: Option<Category>) -> PolicyRule {
    PolicyRule::new(
        rule_id,
        PolicyMatcher {
            category,
            ..PolicyMatcher::default()
        },
        action,
    )
}

fn waiver(
    fingerprint: impl AsRef<str>,
    waived_action: WaivedAction,
    reason: &str,
    owner: &str,
    expires_at: &str,
) -> PolicyWaiver {
    PolicyWaiver {
        fingerprint: Fingerprint::from_str(fingerprint.as_ref()).unwrap(),
        waived_action,
        reason: reason.to_owned(),
        owner: owner.to_owned(),
        expires_at: expires_at.to_owned(),
    }
}

fn synthetic_fingerprint(index: usize) -> String {
    format!("dtfp1:{index:064x}")
}

fn default_rule_id(category: &Category) -> &'static str {
    match category {
        Category::Syntax => "default.error.syntax",
        Category::Type => "default.error.type",
        Category::Correctness => "default.error.correctness",
        Category::Build => "default.error.build",
        Category::Test => "default.error.test",
        _ => "default.observe",
    }
}

#[test]
fn policy_action_order_is_observe_warn_block() {
    assert!(PolicyAction::Observe < PolicyAction::Warn);
    assert!(PolicyAction::Warn < PolicyAction::Block);
}

#[test]
fn strongest_matching_action_wins_independent_of_rule_order() {
    let finding = finding(Category::Runtime, Severity::Warning);
    let rules = [
        rule("z-warning", PolicyAction::Warn, Some(Category::Runtime)),
        rule("a-block", PolicyAction::Block, Some(Category::Runtime)),
        rule("m-observe", PolicyAction::Observe, Some(Category::Runtime)),
    ];
    let permutations = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];

    for order in permutations {
        let ordered = order.map(|index| rules[index].clone());
        let decision = evaluate_policy(&finding, &ordered, &[], EVALUATION_TIME).unwrap();
        assert_eq!(decision.action, DecisionAction::Block);
        assert_eq!(decision.matched_rule_id, "a-block");
    }
}

#[test]
fn default_error_block_cannot_be_weakened_by_observe_or_warn_rules() {
    for category in [
        Category::Syntax,
        Category::Type,
        Category::Correctness,
        Category::Build,
        Category::Test,
    ] {
        for action in [PolicyAction::Observe, PolicyAction::Warn] {
            let decision = evaluate_policy(
                &finding(category.clone(), Severity::Error),
                &[rule("attempted-weaken", action, Some(category.clone()))],
                &[],
                EVALUATION_TIME,
            )
            .unwrap();
            assert_eq!(decision.action, DecisionAction::Block);
            assert_eq!(decision.matched_rule_id, default_rule_id(&category));
        }
    }
}

#[test]
fn default_policy_blocks_only_error_in_initial_blocking_categories() {
    for category in [
        Category::Syntax,
        Category::Type,
        Category::Correctness,
        Category::Build,
        Category::Test,
    ] {
        let decision = evaluate_policy(
            &finding(category.clone(), Severity::Error),
            &[],
            &[],
            EVALUATION_TIME,
        )
        .unwrap();
        assert_eq!(decision.action, DecisionAction::Block);
        assert_eq!(decision.matched_rule_id, default_rule_id(&category));
    }

    for severity in [Severity::Warning, Severity::Info] {
        let decision = evaluate_policy(
            &finding(Category::Syntax, severity),
            &[],
            &[],
            EVALUATION_TIME,
        )
        .unwrap();
        assert_eq!(decision.action, DecisionAction::Observe);
        assert_eq!(decision.matched_rule_id, "default.observe");
    }

    let decision = evaluate_policy(
        &finding(Category::Runtime, Severity::Error),
        &[],
        &[],
        EVALUATION_TIME,
    )
    .unwrap();
    assert_eq!(decision.action, DecisionAction::Observe);
    assert_eq!(decision.matched_rule_id, "default.observe");
}

#[test]
fn equal_actions_choose_the_lexicographically_smallest_rule_id() {
    let finding = finding(Category::Runtime, Severity::Info);
    let first = [
        rule("z-same-action", PolicyAction::Warn, Some(Category::Runtime)),
        rule("a-same-action", PolicyAction::Warn, Some(Category::Runtime)),
    ];
    let second = [first[1].clone(), first[0].clone()];

    assert_eq!(
        evaluate_policy(&finding, &first, &[], EVALUATION_TIME)
            .unwrap()
            .matched_rule_id,
        "a-same-action"
    );
    assert_eq!(
        evaluate_policy(&finding, &second, &[], EVALUATION_TIME)
            .unwrap()
            .matched_rule_id,
        "a-same-action"
    );
}

#[test]
fn waiver_requires_exact_fingerprint_and_action_and_strictly_future_expiry() {
    let finding = finding(Category::Syntax, Severity::Error);
    let fingerprint = finding.fingerprint.to_string();
    let exact = waiver(
        &fingerprint,
        WaivedAction::Block,
        "maintenance",
        "owner",
        FUTURE_EXPIRY,
    );
    let mismatched_fingerprint = waiver(
        FORGED_FINGERPRINT,
        WaivedAction::Block,
        "maintenance",
        "owner",
        FUTURE_EXPIRY,
    );
    let mismatched_action = waiver(
        &fingerprint,
        WaivedAction::Warn,
        "maintenance",
        "owner",
        FUTURE_EXPIRY,
    );
    let equal_expiry = waiver(
        &fingerprint,
        WaivedAction::Block,
        "maintenance",
        "owner",
        EVALUATION_TIME,
    );
    let expired = waiver(
        &fingerprint,
        WaivedAction::Block,
        "maintenance",
        "owner",
        "2026-07-19T23:59:59Z",
    );

    let decision =
        evaluate_policy(&finding, &[], std::slice::from_ref(&exact), EVALUATION_TIME).unwrap();
    assert_eq!(decision.action, DecisionAction::Waive);
    assert_eq!(decision.waiver, Some(exact));

    for candidate in [
        mismatched_fingerprint,
        mismatched_action,
        equal_expiry,
        expired,
    ] {
        let decision = evaluate_policy(&finding, &[], &[candidate], EVALUATION_TIME).unwrap();
        assert_eq!(decision.action, DecisionAction::Block);
        assert!(decision.waiver.is_none());
    }
}

#[test]
fn waiver_selection_is_deterministic_for_order_and_ties() {
    let finding = finding(Category::Syntax, Severity::Error);
    let fingerprint = finding.fingerprint.to_string();
    let candidates = [
        waiver(
            &fingerprint,
            WaivedAction::Block,
            "late",
            "owner",
            "2026-07-22T00:00:00Z",
        ),
        waiver(
            &fingerprint,
            WaivedAction::Block,
            "z-reason",
            "owner",
            FUTURE_EXPIRY,
        ),
        waiver(
            &fingerprint,
            WaivedAction::Block,
            "a-reason",
            "z-owner",
            FUTURE_EXPIRY,
        ),
        waiver(
            &fingerprint,
            WaivedAction::Block,
            "a-reason",
            "a-owner",
            FUTURE_EXPIRY,
        ),
    ];
    let mut reversed = candidates.clone();
    reversed.reverse();

    for ordered in [&candidates[..], &reversed[..]] {
        let selected = evaluate_policy(&finding, &[], ordered, EVALUATION_TIME)
            .unwrap()
            .waiver
            .unwrap();
        assert_eq!(selected.reason, "a-reason");
        assert_eq!(selected.owner, "a-owner");
        assert_eq!(selected.expires_at, FUTURE_EXPIRY);
    }
}

#[test]
fn waivers_can_only_suppress_the_matching_warn_or_block_action() {
    let finding = finding(Category::Runtime, Severity::Info);
    let fingerprint = finding.fingerprint.to_string();
    let warn = [rule("warn", PolicyAction::Warn, Some(Category::Runtime))];
    let block = [rule("block", PolicyAction::Block, Some(Category::Runtime))];

    let warn_with_block_waiver = waiver(
        &fingerprint,
        WaivedAction::Block,
        "reason",
        "owner",
        FUTURE_EXPIRY,
    );
    let block_with_warn_waiver = waiver(
        &fingerprint,
        WaivedAction::Warn,
        "reason",
        "owner",
        FUTURE_EXPIRY,
    );
    assert_eq!(
        evaluate_policy(&finding, &warn, &[warn_with_block_waiver], EVALUATION_TIME)
            .unwrap()
            .action,
        DecisionAction::Warn
    );
    assert_eq!(
        evaluate_policy(&finding, &block, &[block_with_warn_waiver], EVALUATION_TIME)
            .unwrap()
            .action,
        DecisionAction::Block
    );
}

#[test]
fn invalid_waivers_and_evaluation_times_return_typed_errors() {
    let finding = finding(Category::Syntax, Severity::Error);
    let fingerprint = finding.fingerprint.to_string();
    let invalid = [
        waiver(
            &fingerprint,
            WaivedAction::Block,
            "",
            "owner",
            FUTURE_EXPIRY,
        ),
        waiver(
            &fingerprint,
            WaivedAction::Block,
            "reason",
            "",
            FUTURE_EXPIRY,
        ),
        waiver(
            &fingerprint,
            WaivedAction::Block,
            "   ",
            "owner",
            FUTURE_EXPIRY,
        ),
        waiver(
            &fingerprint,
            WaivedAction::Block,
            "reason",
            "owner  team",
            FUTURE_EXPIRY,
        ),
        waiver(
            &fingerprint,
            WaivedAction::Block,
            &"x".repeat(2049),
            "owner",
            FUTURE_EXPIRY,
        ),
        waiver(
            &fingerprint,
            WaivedAction::Block,
            "reason",
            &"x".repeat(257),
            FUTURE_EXPIRY,
        ),
        waiver(
            &fingerprint,
            WaivedAction::Block,
            "reason",
            "owner",
            "not-a-date",
        ),
        waiver(
            &fingerprint,
            WaivedAction::Block,
            "reason",
            "owner",
            "2026-07-21T00:00:00+24:00",
        ),
    ];
    for (index, candidate) in invalid.into_iter().enumerate() {
        assert!(
            matches!(
                evaluate_policy(&finding, &[], &[candidate], EVALUATION_TIME),
                Err(PolicyError::InvalidWaiver { .. })
            ),
            "invalid waiver case {index} was accepted"
        );
    }

    let valid = waiver(
        &fingerprint,
        WaivedAction::Block,
        "reason",
        "owner",
        FUTURE_EXPIRY,
    );
    assert!(matches!(
        validate_waivers(&[valid.clone(), valid.clone()]),
        Err(PolicyError::DuplicateWaiver {
            first_index: 0,
            index: 1
        })
    ));
    for invalid_time in [
        "invalid-evaluation-time",
        "2026-07-20T00:00:00+24:00",
        "2026-07-20T00:00:00+23:60",
    ] {
        assert!(matches!(
            evaluate_policy(&finding, &[], std::slice::from_ref(&valid), invalid_time),
            Err(PolicyError::InvalidEvaluationTime)
        ));
    }
}

#[test]
fn forged_or_noncanonical_findings_and_duplicate_ids_are_rejected() {
    let mut forged = finding(Category::Syntax, Severity::Error);
    forged.message = "forged semantic context".to_owned();
    let forged_waiver = waiver(
        &forged.fingerprint,
        WaivedAction::Block,
        "reason",
        "owner",
        FUTURE_EXPIRY,
    );
    assert!(matches!(
        evaluate_policy(&forged, &[], &[forged_waiver], EVALUATION_TIME),
        Err(PolicyError::InvalidFinding {
            source: EngineError::FingerprintMismatch { .. }
        })
    ));
    let oversized_policy =
        vec![rule("oversized", PolicyAction::Observe, None); MAX_POLICY_RULES + 1];
    assert!(matches!(
        evaluate_policy(&forged, &oversized_policy, &[], EVALUATION_TIME),
        Err(PolicyError::RuleLimit { .. })
    ));
    assert!(matches!(
        build_decision(&forged, &oversized_policy, &[], EVALUATION_TIME),
        Err(PolicyError::RuleLimit { .. })
    ));

    let duplicate_policy = [
        rule("duplicate", PolicyAction::Observe, None),
        rule("duplicate", PolicyAction::Block, None),
    ];
    assert!(matches!(
        evaluate_policy(&forged, &duplicate_policy, &[], EVALUATION_TIME),
        Err(PolicyError::InvalidFinding { .. })
    ));
    assert!(matches!(
        build_decision(&forged, &duplicate_policy, &[], EVALUATION_TIME),
        Err(PolicyError::InvalidFinding { .. })
    ));

    let mut noncanonical = finding(Category::Runtime, Severity::Info);
    noncanonical.tool.name = " fixture-tool ".to_owned();
    assert!(matches!(
        evaluate_policy(&noncanonical, &[], &[], EVALUATION_TIME),
        Err(PolicyError::InvalidFinding {
            source: EngineError::Input(EngineInputError::NonCanonicalFindingField {
                field: "tool"
            })
        })
    ));

    let mut duplicate_observation_ids = finding(Category::Runtime, Severity::Info);
    duplicate_observation_ids
        .observation_ids
        .push(duplicate_observation_ids.observation_ids[0].clone());
    assert!(matches!(
        evaluate_policy(&duplicate_observation_ids, &[], &[], EVALUATION_TIME),
        Err(PolicyError::InvalidFinding { .. })
    ));

    let mut stale_id = finding(Category::Runtime, Severity::Info);
    stale_id.finding_id = ObjectId::from_str("019f7e95-0000-7000-8000-000000000099").unwrap();
    assert!(matches!(
        evaluate_policy(&stale_id, &[], &[], EVALUATION_TIME),
        Err(PolicyError::InvalidFinding {
            source: EngineError::FindingIdMismatch { .. }
        })
    ));
}

#[test]
fn policy_accepts_classified_or_later_effective_lifecycle_states() {
    let classified = finding(Category::Runtime, Severity::Info);
    let expected = evaluate_policy(&classified, &[], &[], EVALUATION_TIME).unwrap();
    let fix_id = ObjectId::from_str("019f7e95-0000-7000-8000-000000000010").unwrap();
    let execution_id = ObjectId::from_str("019f7e95-0000-7000-8000-000000000011").unwrap();

    let mut fix_proposed = classified.clone();
    fix_proposed.state = FindingState::FixProposed;
    fix_proposed.fix_candidate_id = Some(fix_id.clone());

    let mut verified = fix_proposed.clone();
    verified.state = FindingState::Verified;
    verified.verification_execution_ids = Some(vec![execution_id.clone()]);

    let mut reported_classified = classified.clone();
    reported_classified.state = FindingState::Reported;
    reported_classified.pre_report_state = Some(PreReportState::Classified);

    let mut reported_fix_proposed = fix_proposed.clone();
    reported_fix_proposed.state = FindingState::Reported;
    reported_fix_proposed.pre_report_state = Some(PreReportState::FixProposed);

    let mut reported_verified = verified.clone();
    reported_verified.state = FindingState::Reported;
    reported_verified.pre_report_state = Some(PreReportState::Verified);

    for candidate in [
        fix_proposed,
        verified,
        reported_classified,
        reported_fix_proposed,
        reported_verified,
    ] {
        assert_eq!(
            evaluate_policy(&candidate, &[], &[], EVALUATION_TIME).unwrap(),
            expected
        );
    }

    for state in [FindingState::Discovered, FindingState::Normalized] {
        let mut candidate = classified.clone();
        candidate.state = state;
        assert!(matches!(
            evaluate_policy(&candidate, &[], &[], EVALUATION_TIME),
            Err(PolicyError::InvalidFindingLifecycle { .. })
        ));
    }

    let mut missing_pre_report_state = classified.clone();
    missing_pre_report_state.state = FindingState::Reported;
    assert!(matches!(
        evaluate_policy(&missing_pre_report_state, &[], &[], EVALUATION_TIME),
        Err(PolicyError::InvalidFinding { .. })
    ));

    let mut pre_report_state_before_report = classified;
    pre_report_state_before_report.pre_report_state = Some(PreReportState::Classified);
    assert!(matches!(
        evaluate_policy(&pre_report_state_before_report, &[], &[], EVALUATION_TIME),
        Err(PolicyError::InvalidFinding { .. })
    ));
}

#[test]
fn duplicate_reserved_noncanonical_and_impossible_rules_are_rejected() {
    let finding = finding(Category::Runtime, Severity::Info);
    let duplicate = [
        rule("same", PolicyAction::Warn, None),
        rule("same", PolicyAction::Block, None),
    ];
    assert!(matches!(
        evaluate_policy(&finding, &duplicate, &[], EVALUATION_TIME),
        Err(PolicyError::DuplicateRuleId { .. })
    ));
    for reserved in [
        "default.observe",
        "default.error.syntax",
        "default.error.type",
        "default.error.correctness",
        "default.error.build",
        "default.error.test",
    ] {
        assert!(matches!(
            evaluate_policy(
                &finding,
                &[rule(reserved, PolicyAction::Block, None)],
                &[],
                EVALUATION_TIME,
            ),
            Err(PolicyError::ReservedRuleId { .. })
        ));
    }
    assert!(validate_policy(&[rule(" noncanonical-id ", PolicyAction::Observe, None)]).is_err());

    let impossible = PolicyRule::new(
        "impossible",
        PolicyMatcher {
            category: Some(Category::Syntax),
            micro_category: Some(MicroCategory::WrongResult),
            ..PolicyMatcher::default()
        },
        PolicyAction::Warn,
    );
    assert!(matches!(
        evaluate_policy(&finding, &[impossible], &[], EVALUATION_TIME),
        Err(PolicyError::InvalidTaxonomyMatcher { .. })
    ));
    let micro_only = PolicyRule::new(
        "micro-without-category",
        PolicyMatcher {
            micro_category: Some(MicroCategory::Unknown),
            ..PolicyMatcher::default()
        },
        PolicyAction::Block,
    );
    assert!(matches!(
        evaluate_policy(&finding, &[micro_only], &[], EVALUATION_TIME),
        Err(PolicyError::InvalidTaxonomyMatcher { .. })
    ));
}

#[test]
fn canonical_tool_rule_and_language_matchers_apply() {
    let finding = finding(Category::Runtime, Severity::Info);
    let matching = PolicyRule::new(
        "canonical-tool-rule-language",
        PolicyMatcher {
            severity: Some(Severity::Info),
            category: Some(Category::Runtime),
            micro_category: Some(MicroCategory::Exception),
            fingerprint: Some(finding.fingerprint.clone()),
            language: Some(Language::from_str("rust").unwrap()),
            tool_name: Some("fixture-tool".to_owned()),
            tool_version: Some("1.0.0".to_owned()),
            tool_rule_id: Some("fixture.rule".to_owned()),
        },
        PolicyAction::Block,
    );

    assert_eq!(
        evaluate_policy(
            &finding,
            std::slice::from_ref(&matching),
            &[],
            EVALUATION_TIME
        )
        .unwrap()
        .action,
        DecisionAction::Block
    );

    let mut mismatches = Vec::new();
    let mut severity = matching.clone();
    severity.matcher.severity = Some(Severity::Warning);
    mismatches.push(("severity", severity));
    let mut category = matching.clone();
    category.matcher.category = Some(Category::Style);
    category.matcher.micro_category = Some(MicroCategory::Format);
    mismatches.push(("category", category));
    let mut micro = matching.clone();
    micro.matcher.micro_category = Some(MicroCategory::Panic);
    mismatches.push(("micro_category", micro));
    let mut fingerprint = matching.clone();
    fingerprint.matcher.fingerprint = Some(Fingerprint::from_str(FORGED_FINGERPRINT).unwrap());
    mismatches.push(("fingerprint", fingerprint));
    let mut language = matching.clone();
    language.matcher.language = Some(Language::from_str("python").unwrap());
    mismatches.push(("language", language));
    let mut tool_name = matching.clone();
    tool_name.matcher.tool_name = Some("other-tool".to_owned());
    mismatches.push(("tool_name", tool_name));
    for version in ["1.0.1", "1.0.0-RC"] {
        let mut rule = matching.clone();
        rule.matcher.tool_version = Some(version.to_owned());
        mismatches.push(("tool_version", rule));
    }
    let mut tool_rule_id = matching.clone();
    tool_rule_id.matcher.tool_rule_id = Some("other.rule".to_owned());
    mismatches.push(("tool_rule_id", tool_rule_id));

    for (selector, mismatched) in mismatches {
        assert_eq!(
            evaluate_policy(&finding, &[mismatched], &[], EVALUATION_TIME)
                .unwrap()
                .action,
            DecisionAction::Observe,
            "{selector} must match exactly"
        );
    }
}

#[test]
fn malformed_rule_and_tool_matchers_return_typed_policy_errors() {
    let finding = finding(Category::Runtime, Severity::Info);
    assert!(matches!(
        evaluate_policy(
            &finding,
            &[PolicyRule::new(
                "",
                PolicyMatcher::default(),
                PolicyAction::Observe,
            )],
            &[],
            EVALUATION_TIME,
        ),
        Err(PolicyError::InvalidRuleId { .. })
    ));

    let invalid_matchers = [
        (
            "tool_name",
            PolicyMatcher {
                tool_name: Some(String::new()),
                ..PolicyMatcher::default()
            },
        ),
        (
            "tool_name",
            PolicyMatcher {
                tool_name: Some(" fixture-tool ".to_owned()),
                ..PolicyMatcher::default()
            },
        ),
        (
            "tool_version",
            PolicyMatcher {
                tool_version: Some("x".repeat(65)),
                ..PolicyMatcher::default()
            },
        ),
        (
            "tool_version",
            PolicyMatcher {
                tool_version: Some(" 1.0.0 ".to_owned()),
                ..PolicyMatcher::default()
            },
        ),
        (
            "tool_rule_id",
            PolicyMatcher {
                tool_rule_id: Some("x".repeat(129)),
                ..PolicyMatcher::default()
            },
        ),
        (
            "tool_rule_id",
            PolicyMatcher {
                tool_rule_id: Some(" fixture.rule ".to_owned()),
                ..PolicyMatcher::default()
            },
        ),
    ];
    for (field, matcher) in invalid_matchers {
        assert!(matches!(
            evaluate_policy(
                &finding,
                &[PolicyRule::new(
                    "valid-rule",
                    matcher,
                    PolicyAction::Observe,
                )],
                &[],
                EVALUATION_TIME,
            ),
            Err(PolicyError::InvalidToolMatcher {
                field: actual,
                ..
            }) if actual == field
        ));
    }
}

#[test]
fn policy_rule_and_waiver_aggregates_are_bounded() {
    let accepted_rules = (0..MAX_POLICY_RULES)
        .map(|index| rule(&format!("rule-{index}"), PolicyAction::Observe, None))
        .collect::<Vec<_>>();
    assert!(validate_policy(&accepted_rules).is_ok());

    let oversized_rules = (0..=MAX_POLICY_RULES)
        .map(|index| rule(&format!("rule-{index}"), PolicyAction::Observe, None))
        .collect::<Vec<_>>();
    assert!(matches!(
        validate_policy(&oversized_rules),
        Err(PolicyError::RuleLimit {
            actual,
            max: MAX_POLICY_RULES
        }) if actual == MAX_POLICY_RULES + 1
    ));
    assert!(matches!(
        evaluate_policy(
            &finding(Category::Runtime, Severity::Info),
            &oversized_rules,
            &[],
            EVALUATION_TIME,
        ),
        Err(PolicyError::RuleLimit {
            actual,
            max: MAX_POLICY_RULES
        }) if actual == MAX_POLICY_RULES + 1
    ));

    let accepted_waivers = (0..MAX_POLICY_WAIVERS)
        .map(|index| {
            waiver(
                synthetic_fingerprint(index),
                WaivedAction::Block,
                "reason",
                "owner",
                FUTURE_EXPIRY,
            )
        })
        .collect::<Vec<_>>();
    assert!(validate_waivers(&accepted_waivers).is_ok());

    let oversized_waivers = (0..=MAX_POLICY_WAIVERS)
        .map(|index| {
            waiver(
                synthetic_fingerprint(index),
                WaivedAction::Block,
                "reason",
                "owner",
                FUTURE_EXPIRY,
            )
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        validate_waivers(&oversized_waivers),
        Err(PolicyError::WaiverLimit {
            actual,
            max: MAX_POLICY_WAIVERS
        }) if actual == MAX_POLICY_WAIVERS + 1
    ));

    let duplicate_rules = [
        rule("duplicate", PolicyAction::Observe, None),
        rule("duplicate", PolicyAction::Block, None),
    ];
    assert!(matches!(
        PolicySnapshot::new(&duplicate_rules, &oversized_waivers),
        Err(PolicyError::WaiverLimit { .. })
    ));
    assert!(matches!(
        policy_digest(&duplicate_rules, &oversized_waivers),
        Err(PolicyError::WaiverLimit { .. })
    ));

    let mut forged = finding(Category::Runtime, Severity::Info);
    forged.message = "forged semantic context".to_owned();
    assert!(matches!(
        evaluate_policy(&forged, &[], &oversized_waivers, EVALUATION_TIME),
        Err(PolicyError::WaiverLimit { .. })
    ));
    assert!(matches!(
        build_decision(&forged, &[], &oversized_waivers, EVALUATION_TIME),
        Err(PolicyError::WaiverLimit { .. })
    ));
}

#[test]
fn policy_digest_is_order_independent_and_change_sensitive() {
    let finding = finding(Category::Runtime, Severity::Warning);
    let fingerprint = finding.fingerprint.to_string();
    let rules = [
        rule("warn", PolicyAction::Warn, Some(Category::Runtime)),
        rule("block", PolicyAction::Block, Some(Category::Runtime)),
    ];
    let waivers = [
        waiver(
            &fingerprint,
            WaivedAction::Block,
            "reason-b",
            "owner",
            "2026-07-22T00:00:00Z",
        ),
        waiver(
            &fingerprint,
            WaivedAction::Block,
            "reason-a",
            "owner",
            "2026-07-21T00:00:00Z",
        ),
    ];

    let forward_digest = policy_digest(&rules, &waivers).unwrap();
    let reverse_digest = policy_digest(
        &[rules[1].clone(), rules[0].clone()],
        &[waivers[1].clone(), waivers[0].clone()],
    )
    .unwrap();
    assert_eq!(forward_digest, reverse_digest);

    let mut changed_action = rules.to_vec();
    changed_action[0].action = PolicyAction::Block;
    assert_ne!(
        forward_digest,
        policy_digest(&changed_action, &waivers).unwrap()
    );

    let mut changed_matcher = rules.to_vec();
    changed_matcher[0].matcher.tool_version = Some("1.0.0".to_owned());
    assert_ne!(
        forward_digest,
        policy_digest(&changed_matcher, &waivers).unwrap()
    );

    let mut changed_waiver = waivers.to_vec();
    changed_waiver[0].reason = "changed reason".to_owned();
    assert_ne!(
        forward_digest,
        policy_digest(&rules, &changed_waiver).unwrap()
    );
}

#[test]
fn decision_materialization_is_order_independent_and_carries_policy_digest() {
    let finding = finding(Category::Runtime, Severity::Warning);
    let fingerprint = finding.fingerprint.to_string();
    let rules = [
        rule("warn", PolicyAction::Warn, Some(Category::Runtime)),
        rule("block", PolicyAction::Block, Some(Category::Runtime)),
    ];
    let waivers = [waiver(
        &fingerprint,
        WaivedAction::Block,
        "approved",
        "owner",
        FUTURE_EXPIRY,
    )];
    let digest = policy_digest(&rules, &waivers).unwrap();
    let snapshot = PolicySnapshot::new(&rules, &waivers).unwrap();
    let reversed_snapshot =
        PolicySnapshot::new(&[rules[1].clone(), rules[0].clone()], &[waivers[0].clone()]).unwrap();
    assert_eq!(snapshot, reversed_snapshot);
    assert_eq!(snapshot.digest(), &digest);
    assert_eq!(
        snapshot.evaluate(&finding, EVALUATION_TIME).unwrap(),
        evaluate_policy(&finding, &rules, &waivers, EVALUATION_TIME).unwrap()
    );
    let forward = build_decision(&finding, &rules, &waivers, EVALUATION_TIME).unwrap();
    assert_eq!(
        snapshot.build_decision(&finding, EVALUATION_TIME).unwrap(),
        forward
    );
    let reverse = build_decision(
        &finding,
        &[rules[1].clone(), rules[0].clone()],
        &[waivers[0].clone()],
        EVALUATION_TIME,
    )
    .unwrap();

    assert_eq!(forward, reverse);
    assert_eq!(forward.policy_digest, digest);
    assert_eq!(forward.action, DecisionAction::Waive);
    assert_eq!(forward.evaluated_at, EVALUATION_TIME);

    let equivalent_instant =
        build_decision(&finding, &rules, &waivers, "2026-07-19T19:00:00-05:00").unwrap();
    assert_ne!(forward.decision_id, equivalent_instant.decision_id);
}

#[test]
fn decision_integrity_binds_id_to_all_policy_result_fields() {
    let finding = finding(Category::Syntax, Severity::Error);
    let waiver = waiver(
        &finding.fingerprint,
        WaivedAction::Block,
        "approved reason",
        "owner",
        FUTURE_EXPIRY,
    );
    let decision = build_decision(&finding, &[], &[waiver], EVALUATION_TIME).unwrap();

    let mut altered_waiver = decision.clone();
    altered_waiver.waiver.as_mut().unwrap().reason = "altered reason".to_owned();
    assert!(matches!(
        validate_decision_integrity(&altered_waiver),
        Err(EngineError::DecisionIdMismatch { .. })
    ));

    let mut altered_action = decision.clone();
    altered_action.waiver = None;
    altered_action.action = DecisionAction::Block;
    assert!(matches!(
        validate_decision_integrity(&altered_action),
        Err(EngineError::DecisionIdMismatch { .. })
    ));

    let mut altered_rule = decision.clone();
    altered_rule.matched_rule_id = "altered-rule".to_owned();
    assert!(matches!(
        validate_decision_integrity(&altered_rule),
        Err(EngineError::DecisionIdMismatch { .. })
    ));

    let mut altered_time = decision.clone();
    altered_time.evaluated_at = "2026-07-20T00:00:01Z".to_owned();
    assert!(matches!(
        validate_decision_integrity(&altered_time),
        Err(EngineError::DecisionIdMismatch { .. })
    ));

    let mut forged_id = decision;
    forged_id.decision_id = ObjectId::from_str("019f7e95-0000-7000-8000-000000000099").unwrap();
    assert!(matches!(
        validate_decision_integrity(&forged_id),
        Err(EngineError::DecisionIdMismatch { .. })
    ));
}
