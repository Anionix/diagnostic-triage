// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.
use std::str::FromStr;

use diagnostic_triage_contracts::model::{
    Category, Finding, FindingSchemaVersion, FindingState, MicroCategory, Severity, Taxonomy, Tool,
    WaivedAction,
};
use diagnostic_triage_contracts::{Fingerprint, Language, ObjectId};
use diagnostic_triage_engine::finding::{finding_id_for_finding, fingerprint_for_finding};
use diagnostic_triage_engine::policy::{
    PolicyAction, PolicyError, PolicyMatcher, PolicyRule, PolicyWaiver, build_decision,
    evaluate_policy, policy_digest, validate_decision_integrity,
};

const EVALUATION_TIME: &str = "2026-07-20T00:00:00Z";
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

#[test]
fn matching_action_is_strictest_and_rule_order_independent() {
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
        assert_eq!(
            decision.action,
            diagnostic_triage_contracts::model::DecisionAction::Block
        );
        assert_eq!(decision.matched_rule_id, "a-block");
    }
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
fn default_policy_blocks_only_error_in_initial_blocking_categories() {
    for category in [
        Category::Syntax,
        Category::Type,
        Category::Correctness,
        Category::Build,
        Category::Test,
    ] {
        let decision = evaluate_policy(
            &finding(category, Severity::Error),
            &[],
            &[],
            EVALUATION_TIME,
        )
        .unwrap();
        assert_eq!(
            decision.action,
            diagnostic_triage_contracts::model::DecisionAction::Block
        );
        assert_eq!(decision.matched_rule_id, "default-error-block");
    }

    for severity in [Severity::Warning, Severity::Info] {
        let decision = evaluate_policy(
            &finding(Category::Syntax, severity),
            &[],
            &[],
            EVALUATION_TIME,
        )
        .unwrap();
        assert_eq!(
            decision.action,
            diagnostic_triage_contracts::model::DecisionAction::Observe
        );
    }

    let decision = evaluate_policy(
        &finding(Category::Runtime, Severity::Error),
        &[],
        &[],
        EVALUATION_TIME,
    )
    .unwrap();
    assert_eq!(
        decision.action,
        diagnostic_triage_contracts::model::DecisionAction::Observe
    );
}

#[test]
fn valid_waiver_is_strictly_after_evaluation_time() {
    let finding = finding(Category::Syntax, Severity::Error);
    let fingerprint = finding.fingerprint.to_string();
    let valid = waiver(
        &fingerprint,
        WaivedAction::Block,
        "maintenance window",
        "owner@example.test",
        "2026-07-20T00:00:00.000000001Z",
    );
    let equal = waiver(
        &fingerprint,
        WaivedAction::Block,
        "maintenance window",
        "owner@example.test",
        EVALUATION_TIME,
    );
    let expired = waiver(
        &fingerprint,
        WaivedAction::Block,
        "maintenance window",
        "owner@example.test",
        "2026-07-19T23:59:59Z",
    );

    let decision = evaluate_policy(&finding, &[], &[valid], EVALUATION_TIME).unwrap();
    assert_eq!(
        decision.action,
        diagnostic_triage_contracts::model::DecisionAction::Waive
    );
    assert!(decision.waiver.is_some());
    assert_eq!(
        evaluate_policy(&finding, &[], &[equal], EVALUATION_TIME)
            .unwrap()
            .action,
        diagnostic_triage_contracts::model::DecisionAction::Block
    );
    assert_eq!(
        evaluate_policy(&finding, &[], &[expired], EVALUATION_TIME)
            .unwrap()
            .action,
        diagnostic_triage_contracts::model::DecisionAction::Block
    );
}

#[test]
fn forged_fingerprint_cannot_be_waived() {
    let mut finding = finding(Category::Syntax, Severity::Error);
    finding.message = "forged semantic context".to_owned();
    let waiver = waiver(
        &finding.fingerprint,
        WaivedAction::Block,
        "reason",
        "owner",
        "2026-07-21T00:00:00Z",
    );

    assert!(matches!(
        evaluate_policy(&finding, &[], &[waiver], EVALUATION_TIME),
        Err(PolicyError::InvalidFinding {
            source: diagnostic_triage_engine::EngineError::FingerprintMismatch { .. }
        })
    ));
}

#[test]
fn invalid_or_mismatched_waivers_never_suppress() {
    let finding = finding(Category::Syntax, Severity::Error);
    let fingerprint = finding.fingerprint.to_string();
    let valid_but_mismatched = [
        waiver(
            "dtfp1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            WaivedAction::Block,
            "reason",
            "owner",
            "2026-07-21T00:00:00Z",
        ),
        waiver(
            &fingerprint,
            WaivedAction::Warn,
            "reason",
            "owner",
            "2026-07-21T00:00:00Z",
        ),
    ];

    for waiver in valid_but_mismatched {
        let decision = evaluate_policy(&finding, &[], &[waiver], EVALUATION_TIME).unwrap();
        assert_eq!(
            decision.action,
            diagnostic_triage_contracts::model::DecisionAction::Block
        );
        assert!(decision.waiver.is_none());
    }

    let invalid = [
        waiver(
            &fingerprint,
            WaivedAction::Block,
            "",
            "owner",
            "2026-07-21T00:00:00Z",
        ),
        waiver(
            &fingerprint,
            WaivedAction::Block,
            "reason",
            "",
            "2026-07-21T00:00:00Z",
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
    for (index, waiver) in invalid.into_iter().enumerate() {
        assert!(
            matches!(
                evaluate_policy(&finding, &[], &[waiver], EVALUATION_TIME),
                Err(PolicyError::InvalidWaiver { .. })
            ),
            "invalid waiver case {index} was accepted"
        );
    }
}

#[test]
fn invalid_evaluation_time_cannot_activate_a_waiver() {
    let finding = finding(Category::Syntax, Severity::Error);
    let fingerprint = finding.fingerprint.to_string();
    let valid = waiver(
        &fingerprint,
        WaivedAction::Block,
        "reason",
        "owner",
        "2026-07-21T00:00:00Z",
    );

    for invalid_time in [
        "invalid-evaluation-time",
        "2026-07-20T00:00:00+24:00",
        "2026-07-20T00:00:00+23:60",
    ] {
        assert!(matches!(
            evaluate_policy(&finding, &[], std::slice::from_ref(&valid), invalid_time),
            Err(PolicyError::InvalidEvaluationTime { .. })
        ));
    }
}

#[test]
fn duplicate_reserved_and_impossible_rules_are_rejected() {
    let finding = finding(Category::Runtime, Severity::Info);
    let duplicate = [
        rule("same", PolicyAction::Warn, None),
        rule("same", PolicyAction::Block, None),
    ];
    assert!(matches!(
        evaluate_policy(&finding, &duplicate, &[], EVALUATION_TIME),
        Err(PolicyError::DuplicateRuleId { .. })
    ));
    assert!(matches!(
        evaluate_policy(
            &finding,
            &[rule("default-error-block", PolicyAction::Block, None)],
            &[],
            EVALUATION_TIME,
        ),
        Err(PolicyError::ReservedRuleId { .. })
    ));
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
            language: Some(Language::from_str("rust").unwrap()),
            tool_name: Some("fixture-tool".to_owned()),
            tool_rule_id: Some("fixture.rule".to_owned()),
            ..PolicyMatcher::default()
        },
        PolicyAction::Block,
    );

    assert_eq!(
        evaluate_policy(&finding, &[matching], &[], EVALUATION_TIME)
            .unwrap()
            .action,
        diagnostic_triage_contracts::model::DecisionAction::Block
    );
}

#[test]
fn policy_digest_and_decision_are_order_independent() {
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
    let forward = build_decision(&finding, &rules, &waivers, EVALUATION_TIME).unwrap();
    let reverse = build_decision(
        &finding,
        &[rules[1].clone(), rules[0].clone()],
        &[waivers[1].clone(), waivers[0].clone()],
        EVALUATION_TIME,
    )
    .unwrap();

    assert_eq!(forward_digest, reverse_digest);
    assert_eq!(forward, reverse);
    assert_eq!(forward.policy_digest, forward_digest);
}

#[test]
fn waiver_contents_are_bound_to_decision_id() {
    let finding = finding(Category::Syntax, Severity::Error);
    let waiver = waiver(
        &finding.fingerprint,
        WaivedAction::Block,
        "approved reason",
        "owner",
        "2026-07-21T00:00:00Z",
    );
    let mut decision = build_decision(&finding, &[], &[waiver], EVALUATION_TIME).unwrap();
    decision.waiver.as_mut().unwrap().reason = "altered reason".to_owned();

    assert!(matches!(
        validate_decision_integrity(&decision),
        Err(diagnostic_triage_engine::EngineError::DecisionIdMismatch { .. })
    ));
}

#[test]
fn malformed_rule_and_tool_matchers_return_typed_policy_errors() {
    let finding = finding(Category::Runtime, Severity::Info);
    let malformed = [
        PolicyRule::new("", PolicyMatcher::default(), PolicyAction::Observe),
        PolicyRule::new(
            "valid-rule",
            PolicyMatcher {
                tool_name: Some(String::new()),
                ..PolicyMatcher::default()
            },
            PolicyAction::Observe,
        ),
        PolicyRule::new(
            "valid-rule",
            PolicyMatcher {
                tool_rule_id: Some("x".repeat(129)),
                ..PolicyMatcher::default()
            },
            PolicyAction::Observe,
        ),
        PolicyRule::new(
            "valid-rule",
            PolicyMatcher {
                tool_name: Some(" fixture-tool ".to_owned()),
                ..PolicyMatcher::default()
            },
            PolicyAction::Block,
        ),
        PolicyRule::new(
            "valid-rule",
            PolicyMatcher {
                tool_rule_id: Some(" fixture.rule ".to_owned()),
                ..PolicyMatcher::default()
            },
            PolicyAction::Block,
        ),
    ];

    assert!(matches!(
        evaluate_policy(&finding, &malformed[..1], &[], EVALUATION_TIME),
        Err(PolicyError::InvalidRuleId { .. })
    ));
    assert!(matches!(
        evaluate_policy(&finding, &malformed[1..2], &[], EVALUATION_TIME),
        Err(PolicyError::InvalidToolMatcher {
            field: "tool_name",
            ..
        })
    ));
    assert!(matches!(
        evaluate_policy(&finding, &malformed[2..], &[], EVALUATION_TIME),
        Err(PolicyError::InvalidToolMatcher {
            field: "tool_rule_id",
            ..
        })
    ));
    assert!(matches!(
        evaluate_policy(&finding, &malformed[3..], &[], EVALUATION_TIME),
        Err(PolicyError::InvalidToolMatcher {
            field: "tool_name",
            ..
        })
    ));
    assert!(matches!(
        evaluate_policy(&finding, &malformed[4..], &[], EVALUATION_TIME),
        Err(PolicyError::InvalidToolMatcher {
            field: "tool_rule_id",
            ..
        })
    ));
}
