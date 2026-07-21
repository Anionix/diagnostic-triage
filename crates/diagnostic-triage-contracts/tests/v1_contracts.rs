//! Golden compatibility tests for the checked-in v1 wire contract.

use std::{collections::HashSet, fs, path::PathBuf};

use diagnostic_triage_contracts::{
    COMMON_SCHEMA_V1, MODEL_SCHEMA_V1, PROTOCOL_SCHEMA_V1, RepoPath, SourceRevision,
    TAXONOMY_SCHEMA_V1,
    model::{
        Category, FindingState, Location, MicroCategory, Position, PreReportState, SessionReport,
        Taxonomy,
    },
    validate_report, validate_report_for_revision, validate_report_json, validate_session_jsonl,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

const VALID_SESSIONS: &[&str] = &[
    "valid-empty-session.jsonl",
    "valid-observer-session.jsonl",
    "valid-session.jsonl",
    "valid-unknown-optional-capability.jsonl",
];
const INVALID_SESSIONS: &[&str] = &[
    "invalid-completion-count.jsonl",
    "invalid-completion-nonfinal.jsonl",
    "invalid-duplicate-completion.jsonl",
    "invalid-duplicate-object-id.jsonl",
    "invalid-evidence-metadata.jsonl",
    "invalid-execution-attribution.jsonl",
    "invalid-fix-nonpatch-evidence.jsonl",
    "invalid-malformed-line.jsonl",
    "invalid-output-overflow.jsonl",
    "invalid-path-escape.jsonl",
    "invalid-protocol-version.jsonl",
    "invalid-provider-policy-event.jsonl",
    "invalid-request-id.jsonl",
    "invalid-required-capability.jsonl",
    "invalid-role-operation.jsonl",
    "invalid-sequence-gap.jsonl",
    "invalid-timeout-overrun.jsonl",
    "invalid-truncated-session.jsonl",
    "invalid-unnegotiated-event.jsonl",
];
const VALID_REPORTS: &[&str] = &[
    "valid-report.json",
    "valid-unsupported-report.json",
    "valid-verified-report.json",
];

// The v1 baseline contains 83 category/micro-category pairs. Keep this list
// explicit so an additive fallback cannot silently remove an established pair.
const BASE_TAXONOMY_PAIRS: &[(&str, &[&str])] = &[
    (
        "syntax",
        &[
            "parse-error",
            "invalid-token",
            "invalid-structure",
            "unknown",
        ],
    ),
    (
        "type",
        &[
            "incompatible-type",
            "missing-type",
            "nullability",
            "unresolved-symbol",
            "invalid-call",
            "contract-mismatch",
            "unknown",
        ],
    ),
    (
        "correctness",
        &[
            "assertion",
            "invariant",
            "wrong-result",
            "data-loss",
            "state-transition",
            "nondeterminism",
            "unknown",
        ],
    ),
    (
        "runtime",
        &[
            "exception",
            "panic",
            "abort",
            "signal",
            "import-failure",
            "initialization",
            "unknown",
        ],
    ),
    (
        "build",
        &[
            "compile",
            "link",
            "dependency-resolution",
            "code-generation",
            "configuration",
            "unknown",
        ],
    ),
    (
        "test",
        &[
            "collection",
            "setup",
            "assertion",
            "teardown",
            "flaky",
            "coverage-gate",
            "unknown",
        ],
    ),
    (
        "resource",
        &[
            "timeout",
            "memory-limit",
            "disk-limit",
            "output-limit",
            "file-descriptor-limit",
            "unknown",
        ],
    ),
    (
        "concurrency",
        &[
            "race",
            "deadlock",
            "livelock",
            "ordering",
            "atomicity",
            "unknown",
        ],
    ),
    (
        "security",
        &[
            "input-validation",
            "path-escape",
            "injection",
            "unsafe-deserialization",
            "permission",
            "secret-exposure",
            "unknown",
        ],
    ),
    (
        "environment",
        &[
            "tool-missing",
            "version-mismatch",
            "platform",
            "locale",
            "timezone",
            "network",
            "filesystem",
            "unknown",
        ],
    ),
    (
        "tooling",
        &[
            "protocol",
            "malformed-output",
            "provider-crash",
            "unsupported-version",
            "configuration",
            "unknown",
        ],
    ),
    (
        "style",
        &[
            "format",
            "lint",
            "documentation",
            "complexity",
            "deprecation",
            "unknown",
        ],
    ),
    (
        "robustness",
        &[
            "boundary-input",
            "malformed-input",
            "crash-resistance",
            "roundtrip-mismatch",
            "fuzz-finding",
            "unknown",
        ],
    ),
];

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/v1")
        .join(name)
}

fn fixture(name: &str) -> Vec<u8> {
    fs::read(fixture_path(name)).expect("golden fixture must be readable")
}

fn report_fixture() -> Value {
    serde_json::from_slice(&fixture("valid-report.json")).expect("report fixture is JSON")
}

fn verified_report_fixture() -> Value {
    serde_json::from_slice(&fixture("valid-verified-report.json"))
        .expect("verified report fixture is JSON")
}

fn observation_id(report: &Value) -> Value {
    report["observations"][0]["observation_id"].clone()
}

fn rejects_report(value: &Value) -> bool {
    validate_report_json(
        &serde_json::to_vec(value).expect("mutated report remains JSON serializable"),
    )
    .is_err()
}

fn set_execution_status(report: &mut Value, index: usize, status: &str, required: bool) {
    let execution = &mut report["executions"][index];
    execution["required"] = json!(required);
    execution["status"] = json!(status);
    if status == "COMPLETE" {
        execution["exit_code"] = json!(0);
        execution
            .as_object_mut()
            .expect("execution is an object")
            .remove("message");
    } else {
        execution["exit_code"] = Value::Null;
        execution["message"] = json!(format!("required execution ended as {status}"));
    }
}

fn assert_only_verdict_is_accepted(name: &str, report: &Value, expected: &str) {
    for actual in ["PASS", "POLICY_FAIL", "INCOMPLETE", "UNSUPPORTED"] {
        let mut candidate = report.clone();
        candidate["verdict"] = json!(actual);
        let accepted = validate_report_json(&serde_json::to_vec(&candidate).unwrap()).is_ok();
        assert_eq!(
            accepted,
            actual == expected,
            "{name}: verdict {actual} acceptance differs from expected {expected}",
        );
    }
}

fn evidence_mut<'a>(report: &'a mut Value, evidence_id: &str) -> &'a mut Value {
    report["evidence"]
        .as_array_mut()
        .expect("evidence is an array")
        .iter_mut()
        .find(|evidence| evidence["evidence_id"] == evidence_id)
        .expect("fixture contains the referenced evidence")
}

#[test]
fn canonical_schemas_are_embedded_and_have_unique_ids() {
    let schemas = [
        COMMON_SCHEMA_V1,
        MODEL_SCHEMA_V1,
        PROTOCOL_SCHEMA_V1,
        TAXONOMY_SCHEMA_V1,
    ];
    let mut identifiers = Vec::new();
    for schema in schemas {
        let value: serde_json::Value = serde_json::from_str(schema).expect("schema is JSON");
        identifiers.push(
            value["$id"]
                .as_str()
                .expect("canonical schema has an identifier")
                .to_owned(),
        );
    }
    identifiers.sort_unstable();
    identifiers.dedup();
    assert_eq!(identifiers.len(), schemas.len());
}

#[test]
fn location_v1_accepts_points_insertions_and_half_open_ranges() {
    let path: RepoPath = "src/unicode.rs".parse().expect("fixture path is valid");
    let locations = [
        Location {
            path: path.clone(),
            start: Position { line: 1, column: 1 },
            end: None,
        },
        Location {
            path: path.clone(),
            start: Position { line: 2, column: 3 },
            end: Some(Position { line: 2, column: 3 }),
        },
        Location {
            path: path.clone(),
            start: Position { line: 3, column: 2 },
            end: Some(Position { line: 3, column: 5 }),
        },
        Location {
            path,
            start: Position { line: 4, column: 2 },
            end: Some(Position { line: 5, column: 1 }),
        },
    ];

    for location in locations {
        location.validate().expect("valid v1 Location shape");
    }

    let reversed = Location {
        path: "src/unicode.rs".parse().unwrap(),
        start: Position { line: 2, column: 3 },
        end: Some(Position { line: 2, column: 2 }),
    };
    assert!(reversed.validate().is_err());
}

#[test]
fn common_schema_states_location_range_and_column_semantics() {
    let schema: Value = serde_json::from_str(COMMON_SCHEMA_V1).expect("common schema is JSON");
    let location = &schema["$defs"]["location"];
    let column = &schema["$defs"]["position"]["properties"]["column"];

    assert!(
        location["description"]
            .as_str()
            .is_some_and(|value| value.contains("half-open [start, end)"))
    );
    assert!(
        column["description"]
            .as_str()
            .is_some_and(|value| value.contains("Unicode code-point"))
    );
}

#[test]
fn accepts_every_valid_session_fixture() {
    for name in VALID_SESSIONS {
        validate_session_jsonl(&fixture(name)).unwrap_or_else(|error| panic!("{name}: {error}"));
    }
}

#[test]
fn rejects_every_invalid_session_fixture() {
    for name in INVALID_SESSIONS {
        assert!(
            validate_session_jsonl(&fixture(name)).is_err(),
            "accepted invalid fixture {name}"
        );
    }
}

#[test]
fn accepts_every_valid_report_fixture() {
    for name in VALID_REPORTS {
        validate_report_json(&fixture(name)).unwrap_or_else(|error| panic!("{name}: {error}"));
    }
}

#[test]
fn report_verdict_follows_required_execution_and_policy_precedence() {
    let block = report_fixture();
    assert_only_verdict_is_accepted("required complete with BLOCK", &block, "POLICY_FAIL");

    for action in ["OBSERVE", "WARN"] {
        let mut report = report_fixture();
        report["decisions"][0]["action"] = json!(action);
        assert_only_verdict_is_accepted(action, &report, "PASS");
    }

    let mut waived = report_fixture();
    waived["decisions"][0]["action"] = json!("WAIVE");
    waived["decisions"][0]["waiver"] = json!({
        "fingerprint": waived["findings"][0]["fingerprint"].clone(),
        "waived_action": "BLOCK",
        "reason": "accepted until the upstream fix lands",
        "owner": "maintainers",
        "expires_at": "2026-08-20T00:00:00Z"
    });
    assert_only_verdict_is_accepted("WAIVE", &waived, "PASS");

    let mut incomplete = report_fixture();
    set_execution_status(&mut incomplete, 0, "INCOMPLETE", true);
    assert_only_verdict_is_accepted("required INCOMPLETE with BLOCK", &incomplete, "INCOMPLETE");

    let mut unsupported = report_fixture();
    set_execution_status(&mut unsupported, 0, "UNSUPPORTED", true);
    assert_only_verdict_is_accepted(
        "required UNSUPPORTED with BLOCK",
        &unsupported,
        "UNSUPPORTED",
    );

    let mut mixed = unsupported.clone();
    let mut second = mixed["executions"][0].clone();
    second["execution_id"] = json!("019f7e95-0000-7000-8000-000000000199");
    mixed["executions"].as_array_mut().unwrap().push(second);
    set_execution_status(&mut mixed, 1, "INCOMPLETE", true);
    assert_only_verdict_is_accepted("required INCOMPLETE and UNSUPPORTED", &mixed, "INCOMPLETE");

    for status in ["INCOMPLETE", "UNSUPPORTED"] {
        let mut optional: Value = serde_json::from_slice(&fixture("valid-unsupported-report.json"))
            .expect("unsupported report fixture is JSON");
        set_execution_status(&mut optional, 0, status, false);
        assert_only_verdict_is_accepted(&format!("optional {status}"), &optional, "PASS");
    }

    let mut empty: Value = serde_json::from_slice(&fixture("valid-unsupported-report.json"))
        .expect("unsupported report fixture is JSON");
    empty["executions"] = json!([]);
    assert_only_verdict_is_accepted("empty report", &empty, "PASS");
}

#[test]
fn report_can_be_bound_to_an_external_source_pin() {
    let mut value = report_fixture();
    let expected = value["engine"]["source_revision"]
        .as_str()
        .expect("fixture source revision is a string")
        .parse::<SourceRevision>()
        .expect("fixture source revision is canonical");
    let report = validate_report_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    validate_report_for_revision(&report, &expected).expect("matching source pin is valid");

    let forged_revision = "f".repeat(40);
    value["engine"]["source_revision"] = json!(forged_revision);
    value["contract_sha256"] = json!(format!("{:x}", Sha256::digest(forged_revision.as_bytes())));
    let forged = validate_report_json(&serde_json::to_vec(&value).unwrap())
        .expect("a self-consistent report identity is locally valid");
    assert!(
        validate_report_for_revision(&forged, &expected).is_err(),
        "accepted a self-consistent identity that differs from the consumer pin"
    );
}

#[test]
fn typed_reports_round_trip_without_emitting_optional_nulls() {
    for name in VALID_REPORTS {
        let report =
            validate_report_json(&fixture(name)).unwrap_or_else(|error| panic!("{name}: {error}"));
        let encoded = serde_json::to_vec(&report).expect("typed report serializes");
        validate_report_json(&encoded).unwrap_or_else(|error| panic!("round-trip {name}: {error}"));
    }
}

#[test]
fn decision_evaluated_at_is_required_and_strictly_rfc3339() {
    let valid = report_fixture();
    validate_report_json(&serde_json::to_vec(&valid).expect("report remains JSON serializable"))
        .expect("decision with a strict evaluated_at is valid");

    let mut missing = valid.clone();
    missing["decisions"][0]
        .as_object_mut()
        .expect("decision is an object")
        .remove("evaluated_at");
    assert!(
        rejects_report(&missing),
        "accepted a Decision without evaluated_at"
    );

    for invalid_timestamp in [
        "not-a-date",
        "2026-07-21T00:00:00+24:00",
        "2026-02-29T00:00:00Z",
        "2026-07-21T00:00:00.1234567890Z",
    ] {
        let mut invalid = valid.clone();
        invalid["decisions"][0]["evaluated_at"] = json!(invalid_timestamp);
        assert!(
            rejects_report(&invalid),
            "accepted invalid Decision evaluated_at {invalid_timestamp:?}"
        );
    }
}

#[test]
fn report_rejects_decisions_with_mixed_evaluation_instants() {
    let mut report = report_fixture();
    let second_finding_id = "019f7e95-0000-7000-8000-000000000107";
    let second_decision_id = "019f7e95-0000-7000-8000-000000000108";

    let mut second_finding = report["findings"][0].clone();
    second_finding["finding_id"] = json!(second_finding_id);
    second_finding["fingerprint"] = json!(format!("dtfp1:{}", "d".repeat(64)));
    second_finding["message"] = json!("A second finding evaluated in the same report");
    report["findings"]
        .as_array_mut()
        .expect("findings is an array")
        .push(second_finding);

    let mut second_decision = report["decisions"][0].clone();
    second_decision["decision_id"] = json!(second_decision_id);
    second_decision["finding_id"] = json!(second_finding_id);
    second_decision["evaluated_at"] = json!("2026-07-21T01:00:00+01:00");
    report["decisions"]
        .as_array_mut()
        .expect("decisions is an array")
        .push(second_decision);

    validate_report_json(&serde_json::to_vec(&report).unwrap())
        .expect("equivalent offset spellings represent one evaluation instant");

    report["decisions"][1]["evaluated_at"] = json!("2026-07-21T00:00:01Z");
    assert!(
        rejects_report(&report),
        "accepted Decisions with mixed policy evaluation instants"
    );
}

#[test]
fn waive_expiry_must_be_strictly_after_evaluation_by_parsed_instant() {
    let mut report = report_fixture();
    report["verdict"] = json!("PASS");
    report["decisions"][0]["action"] = json!("WAIVE");
    report["decisions"][0]["evaluated_at"] = json!("2026-07-21T00:00:00Z");
    report["decisions"][0]["waiver"] = json!({
        "fingerprint": report["findings"][0]["fingerprint"].clone(),
        "waived_action": "BLOCK",
        "reason": "accepted until the upstream fix lands",
        "owner": "maintainers",
        "expires_at": "2026-08-20T00:00:00Z"
    });

    for (expiry, accepted) in [
        ("2026-07-21T00:00:00Z", false),
        ("2026-07-20T23:59:59.999999999Z", false),
        ("2026-07-21T01:00:00+01:00", false),
        ("2026-07-21T00:30:00+01:00", false),
        ("2026-07-20T23:30:00-01:00", true),
        ("2026-07-21T00:00:00.000000001Z", true),
    ] {
        let mut candidate = report.clone();
        candidate["decisions"][0]["waiver"]["expires_at"] = json!(expiry);
        if accepted {
            validate_report_json(&serde_json::to_vec(&candidate).unwrap())
                .unwrap_or_else(|error| panic!("rejected valid expiry {expiry}: {error}"));
        } else {
            assert!(
                rejects_report(&candidate),
                "accepted expiry {expiry} that is not after evaluation"
            );
        }
    }

    for (evaluated_at, expires_at) in [
        (
            "0000-01-01T00:00:00.000000000Z",
            "0000-01-01T00:00:00.000000001Z",
        ),
        (
            "9998-12-31T23:59:58.999999999Z",
            "9998-12-31T23:59:59.000000000Z",
        ),
    ] {
        let mut candidate = report.clone();
        candidate["decisions"][0]["evaluated_at"] = json!(evaluated_at);
        candidate["decisions"][0]["waiver"]["expires_at"] = json!(expires_at);
        validate_report_json(&serde_json::to_vec(&candidate).unwrap()).unwrap_or_else(|error| {
            panic!("rejected v1 boundary interval {evaluated_at}..{expires_at}: {error}")
        });
    }
}

#[test]
fn direct_report_deserialization_rejects_duplicate_keys() {
    let text = String::from_utf8(fixture("valid-report.json")).expect("report fixture is UTF-8");
    let duplicate = text.replacen(
        "\"verdict\": \"POLICY_FAIL\",",
        "\"verdict\": \"PASS\", \"verdict\": \"POLICY_FAIL\",",
        1,
    );
    assert_ne!(duplicate, text, "test must inject a duplicate key");
    assert!(serde_json::from_str::<SessionReport>(&duplicate).is_err());
}

#[test]
fn rust_taxonomy_acceptance_matches_every_canonical_pair() {
    let schema: Value = serde_json::from_str(TAXONOMY_SCHEMA_V1).expect("taxonomy schema is JSON");
    let branches = schema["oneOf"]
        .as_array()
        .expect("taxonomy schema has oneOf branches");
    let mut expected = HashSet::new();
    let mut categories = HashSet::new();
    let mut micro_categories = HashSet::new();

    for branch in branches {
        let category = branch["properties"]["category"]["const"]
            .as_str()
            .expect("taxonomy branch has a category")
            .to_owned();
        categories.insert(category.clone());
        for micro_category in branch["properties"]["micro_category"]["enum"]
            .as_array()
            .expect("taxonomy branch has micro-categories")
        {
            let micro_category = micro_category
                .as_str()
                .expect("micro-category is a string")
                .to_owned();
            micro_categories.insert(micro_category.clone());
            expected.insert((category.clone(), micro_category));
        }
    }

    let base_pairs: HashSet<_> = BASE_TAXONOMY_PAIRS
        .iter()
        .flat_map(|(category, micro_categories)| {
            micro_categories
                .iter()
                .map(move |micro_category| ((*category).to_owned(), (*micro_category).to_owned()))
        })
        .collect();
    assert_eq!(
        base_pairs.len(),
        83,
        "the v1 baseline pair catalog must be exhaustive"
    );

    let mut expected_with_additive_unknown = base_pairs.clone();
    expected_with_additive_unknown.insert(("unknown".into(), "unknown".into()));
    assert_eq!(expected, expected_with_additive_unknown);

    for (category, micro_category) in &base_pairs {
        let taxonomy = serde_json::from_value::<Taxonomy>(json!({
            "category": category,
            "micro_category": micro_category,
        }))
        .expect("every v1 baseline pair must deserialize");
        taxonomy.validate().unwrap_or_else(|error| {
            panic!("baseline pair {category}/{micro_category} rejected: {error}")
        });
    }

    for category in &categories {
        for micro_category in &micro_categories {
            let taxonomy = serde_json::from_value::<Taxonomy>(json!({
                "category": category,
                "micro_category": micro_category,
            }));
            let accepted = taxonomy.is_ok_and(|value| value.validate().is_ok());
            assert_eq!(
                accepted,
                expected.contains(&(category.clone(), micro_category.clone())),
                "taxonomy parity differs for {category}/{micro_category}",
            );
        }
    }
}

#[test]
fn top_level_unknown_accepts_only_unknown_micro_category() {
    Taxonomy {
        category: Category::Unknown,
        micro_category: MicroCategory::Unknown,
    }
    .validate()
    .unwrap();

    for invalid_micro_category in [MicroCategory::Compile, MicroCategory::Lint] {
        assert!(
            Taxonomy {
                category: Category::Unknown,
                micro_category: invalid_micro_category,
            }
            .validate()
            .is_err()
        );
    }
}

#[test]
fn category_scoped_unknown_is_preserved_for_every_base_category() {
    for category in [
        Category::Syntax,
        Category::Type,
        Category::Correctness,
        Category::Runtime,
        Category::Build,
        Category::Test,
        Category::Resource,
        Category::Concurrency,
        Category::Security,
        Category::Environment,
        Category::Tooling,
        Category::Style,
        Category::Robustness,
    ] {
        Taxonomy {
            category,
            micro_category: MicroCategory::Unknown,
        }
        .validate()
        .unwrap();
    }
}

#[test]
fn unknown_taxonomy_golden_fixtures_match_runtime_validation() {
    for (name, expected) in [
        (
            "taxonomy-unknown.json",
            json!({"category": "unknown", "micro_category": "unknown"}),
        ),
        (
            "taxonomy-syntax-unknown.json",
            json!({"category": "syntax", "micro_category": "unknown"}),
        ),
    ] {
        let valid = serde_json::from_slice::<Taxonomy>(&fixture(name))
            .expect("valid taxonomy fixture is typed JSON");
        valid.validate().unwrap();
        assert_eq!(serde_json::to_value(&valid).unwrap(), expected);
    }

    for name in [
        "taxonomy-invalid-syntax-wrong-result.json",
        "taxonomy-invalid-unknown-lint.json",
    ] {
        let invalid = serde_json::from_slice::<Taxonomy>(&fixture(name))
            .expect("invalid pair still uses known enum members");
        assert!(
            invalid.validate().is_err(),
            "accepted invalid fixture {name}"
        );
    }
}

#[test]
fn rejects_semantically_inconsistent_reports() {
    let mut candidates = Vec::new();

    let mut dangling = report_fixture();
    dangling["findings"][0]["observation_ids"] = json!(["019f7e95-0000-7000-8000-000000009999"]);
    candidates.push(("dangling reference", dangling));

    let mut duplicate = report_fixture();
    let evidence = duplicate["evidence"][0].clone();
    duplicate["evidence"]
        .as_array_mut()
        .expect("evidence is an array")
        .push(evidence);
    candidates.push(("duplicate object id", duplicate));

    let mut corrupt_evidence = report_fixture();
    corrupt_evidence["evidence"][0]["sha256"] = json!("f".repeat(64));
    candidates.push(("evidence digest", corrupt_evidence));

    let mut wrong_contract_digest = report_fixture();
    wrong_contract_digest["contract_sha256"] = json!("f".repeat(64));
    candidates.push(("contract identity", wrong_contract_digest));

    let mut reversed_location = report_fixture();
    reversed_location["findings"][0]["location"]["end"] = json!({"line": 6, "column": 1});
    candidates.push(("reversed location", reversed_location));

    let mut inconsistent_timing = report_fixture();
    inconsistent_timing["executions"][0]["phases_ms"]["total"] = json!(185);
    candidates.push(("phase total", inconsistent_timing));

    let mut inconsistent_performance = report_fixture();
    inconsistent_performance["executions"][0]["performance"]["budget_ms"] = json!(100);
    candidates.push(("performance status", inconsistent_performance));

    let mut inconsistent_cache = report_fixture();
    inconsistent_cache["executions"][0]["cache"]["restore_ms"] = json!(1);
    candidates.push(("cache availability", inconsistent_cache));

    let mut inconsistent_retry = report_fixture();
    inconsistent_retry["executions"][0]["retry"] =
        json!({"status": "UNAVAILABLE", "attempt": 1, "same_revision": true});
    candidates.push(("retry availability", inconsistent_retry));

    let mut inconsistent_runner = report_fixture();
    inconsistent_runner["executions"][0]["runner"] =
        json!({"status": "UNAVAILABLE", "os": "linux"});
    candidates.push(("runner availability", inconsistent_runner));

    let mut invalid_tool = report_fixture();
    invalid_tool["executions"][0]["tool"]["name"] = json!("");
    candidates.push(("tool identity", invalid_tool));

    let mut failed_verification = report_fixture();
    failed_verification["evidence"][0]["source"] = json!("PATCH");
    let observation_id = failed_verification["observations"][0]["observation_id"].clone();
    let evidence_id = failed_verification["evidence"][0]["evidence_id"].clone();
    let execution_id = failed_verification["executions"][0]["execution_id"].clone();
    failed_verification["fix_candidates"] = json!([{
        "schema_version": "diagnostic-triage.fix-candidate/v1",
        "fix_candidate_id": "019f7e95-0000-7000-8000-000000000107",
        "observation_ids": [observation_id],
        "applicability": "SAFE",
        "tool_native": true,
        "patch_evidence_id": evidence_id
    }]);
    failed_verification["findings"][0]["state"] = json!("VERIFIED");
    failed_verification["findings"][0]
        .as_object_mut()
        .unwrap()
        .remove("pre_report_state");
    failed_verification["findings"][0]["fix_candidate_id"] =
        json!("019f7e95-0000-7000-8000-000000000107");
    failed_verification["findings"][0]["verification_execution_ids"] = json!([execution_id]);
    failed_verification["executions"][0]["status"] = json!("INCOMPLETE");
    failed_verification["executions"][0]["exit_code"] = Value::Null;
    failed_verification["executions"][0]["message"] = json!("verification provider timed out");
    failed_verification["verdict"] = json!("INCOMPLETE");
    candidates.push(("failed verification", failed_verification));

    let mut missing_decision = report_fixture();
    missing_decision["decisions"] = json!([]);
    candidates.push(("missing decision", missing_decision));

    let mut orphan_observation = report_fixture();
    orphan_observation["findings"] = json!([]);
    orphan_observation["decisions"] = json!([]);
    orphan_observation["verdict"] = json!("PASS");
    candidates.push(("orphan observation", orphan_observation));

    for (name, candidate) in candidates {
        assert!(rejects_report(&candidate), "accepted {name}");
    }
}

#[test]
fn waiver_must_be_complete_and_bound_to_its_finding() {
    let mut report = report_fixture();
    report["verdict"] = json!("PASS");
    report["decisions"][0]["action"] = json!("WAIVE");
    report["decisions"][0]["waiver"] = json!({
        "waived_action": "BLOCK",
        "reason": "accepted until the upstream fix lands",
        "owner": "maintainers",
        "expires_at": "2026-08-20T00:00:00Z"
    });
    assert!(rejects_report(&report), "accepted incomplete waiver");

    report["decisions"][0]["waiver"]["fingerprint"] = json!(format!("dtfp1:{}", "f".repeat(64)));
    assert!(
        rejects_report(&report),
        "accepted waiver for another finding"
    );

    report["decisions"][0]["waiver"]["fingerprint"] = report["findings"][0]["fingerprint"].clone();
    validate_report_json(
        &serde_json::to_vec(&report).expect("mutated report remains JSON serializable"),
    )
    .expect("complete waiver bound to its finding is valid");
}

#[test]
fn verified_finding_requires_exact_execution_attribution() {
    let valid = verified_report_fixture();
    validate_report_json(
        &serde_json::to_vec(&valid).expect("verified report remains JSON serializable"),
    )
    .expect("candidate-bound verification execution is valid");

    let mut missing = valid.clone();
    missing["executions"][0]
        .as_object_mut()
        .expect("execution is an object")
        .remove("verification");
    assert!(
        rejects_report(&missing),
        "accepted a stale execution without verification attribution"
    );

    let mut dangling = valid.clone();
    dangling["executions"][0]["verification"]["fix_candidate_id"] =
        json!("019f7e95-0000-7000-8000-000000000999");
    assert!(
        rejects_report(&dangling),
        "accepted verification attribution to an unknown candidate"
    );

    let mut mismatched = valid.clone();
    let mut alternate = mismatched["fix_candidates"][0].clone();
    alternate["fix_candidate_id"] = json!("019f7e95-0000-7000-8000-000000000109");
    mismatched["fix_candidates"]
        .as_array_mut()
        .expect("fix_candidates is an array")
        .push(alternate);
    mismatched["executions"][0]["verification"]["fix_candidate_id"] =
        json!("019f7e95-0000-7000-8000-000000000109");
    assert!(
        rejects_report(&mismatched),
        "accepted verification attribution for a different candidate"
    );

    for adapter_kind in ["ENGINE", "OBSERVER"] {
        let mut invalid = valid.clone();
        invalid["executions"][0]["adapter_kind"] = json!(adapter_kind);
        assert!(
            rejects_report(&invalid),
            "accepted a {adapter_kind} execution as verification proof"
        );
    }

    for applicability in ["MANUAL", "UNSAFE"] {
        let mut invalid = valid.clone();
        invalid["fix_candidates"][0]["applicability"] = json!(applicability);
        assert!(
            rejects_report(&invalid),
            "accepted a {applicability} candidate as VERIFIED"
        );
    }
}

#[test]
fn reported_verified_finding_preserves_and_revalidates_proof() {
    let valid = verified_report_fixture();
    let mut reported = valid.clone();
    reported["findings"][0]["state"] = json!("REPORTED");
    reported["findings"][0]["pre_report_state"] = json!("VERIFIED");
    validate_report_json(&serde_json::to_vec(&reported).unwrap())
        .expect("reported verified proof remains valid");

    let mut typed = validate_report_json(&serde_json::to_vec(&valid).unwrap()).unwrap();
    let finding = typed.findings.remove(0);
    let fix_candidate_id = finding.fix_candidate_id.clone();
    let execution_ids = finding.verification_execution_ids.clone();
    let transitioned = finding.into_reported().expect("VERIFIED may be reported");
    assert_eq!(transitioned.state, FindingState::Reported);
    assert_eq!(
        transitioned.pre_report_state,
        Some(PreReportState::Verified)
    );
    assert_eq!(transitioned.fix_candidate_id, fix_candidate_id);
    assert_eq!(transitioned.verification_execution_ids, execution_ids);
    typed.findings.push(transitioned);
    validate_report(&typed).expect("typed reporting transition preserves valid proof");

    let mut missing_pre_state = reported.clone();
    missing_pre_state["findings"][0]
        .as_object_mut()
        .unwrap()
        .remove("pre_report_state");
    assert!(rejects_report(&missing_pre_state));

    let mut missing_candidate = reported.clone();
    missing_candidate["findings"][0]
        .as_object_mut()
        .unwrap()
        .remove("fix_candidate_id");
    assert!(rejects_report(&missing_candidate));

    let mut missing_executions = reported.clone();
    missing_executions["findings"][0]
        .as_object_mut()
        .unwrap()
        .remove("verification_execution_ids");
    assert!(rejects_report(&missing_executions));

    let mut incomplete = reported.clone();
    incomplete["executions"][0]["status"] = json!("INCOMPLETE");
    incomplete["executions"][0]["exit_code"] = Value::Null;
    incomplete["executions"][0]["message"] = json!("verification timed out");
    incomplete["verdict"] = json!("INCOMPLETE");
    assert!(rejects_report(&incomplete));

    let mut unsafe_candidate = reported.clone();
    unsafe_candidate["fix_candidates"][0]["applicability"] = json!("UNSAFE");
    assert!(rejects_report(&unsafe_candidate));

    let mut non_provider = reported.clone();
    non_provider["executions"][0]["adapter_kind"] = json!("OBSERVER");
    assert!(rejects_report(&non_provider));

    let mut downgraded_claim = reported;
    downgraded_claim["findings"][0]["pre_report_state"] = json!("CLASSIFIED");
    assert!(
        rejects_report(&downgraded_claim),
        "accepted a classified report that retained verified proof references"
    );
}

#[test]
fn verification_attribution_requires_patch_targets_result_and_tool_identity() {
    let valid = verified_report_fixture();
    validate_report_json(
        &serde_json::to_vec(&valid).expect("verified report remains JSON serializable"),
    )
    .expect("complete verification attribution is valid");

    let patch_id = valid["fix_candidates"][0]["patch_evidence_id"]
        .as_str()
        .expect("fix candidate patch evidence id is a string")
        .to_owned();
    let mut truncated_patch = valid.clone();
    let patch = evidence_mut(&mut truncated_patch, &patch_id);
    let retained_bytes = patch["retained_bytes"]
        .as_u64()
        .expect("patch retained bytes is an integer");
    patch["observed_bytes"] = json!(retained_bytes + 1);
    patch["truncated"] = json!(true);
    assert!(
        rejects_report(&truncated_patch),
        "accepted verification using truncated PATCH evidence"
    );

    let mut patch_relative_path = valid.clone();
    let patch = evidence_mut(&mut patch_relative_path, &patch_id);
    patch
        .as_object_mut()
        .expect("patch evidence is an object")
        .remove("content");
    patch["relative_path"] = json!("patches/fix.diff");
    assert!(
        rejects_report(&patch_relative_path),
        "accepted verification using a relative_path PATCH evidence"
    );

    let mut wrong_patch_digest = valid.clone();
    wrong_patch_digest["executions"][0]["verification"]["patch_sha256"] = json!("f".repeat(64));
    assert!(
        rejects_report(&wrong_patch_digest),
        "accepted verification with a digest unrelated to PATCH evidence"
    );

    let mut wrong_target_set = valid.clone();
    wrong_target_set["executions"][0]["verification"]["target_fingerprints"] =
        json!([format!("dtfp1:{}", "f".repeat(64))]);
    assert!(
        rejects_report(&wrong_target_set),
        "accepted verification for a target fingerprint outside the verified finding set"
    );

    let mut wrong_result_evidence = valid.clone();
    wrong_result_evidence["executions"][0]["verification"]["result_evidence_id"] =
        json!("019f7e95-0000-7000-8000-000000000999");
    assert!(
        rejects_report(&wrong_result_evidence),
        "accepted verification pointing at unknown result evidence"
    );

    let mut unrelated_diagnostic = valid.clone();
    unrelated_diagnostic["executions"][0]["verification"]["result_evidence_id"] =
        unrelated_diagnostic["evidence"][0]["evidence_id"].clone();
    assert!(
        rejects_report(&unrelated_diagnostic),
        "accepted verification pointing at an unrelated DIAGNOSTIC evidence"
    );

    for (label, execution_id) in [
        ("missing", None),
        ("wrong", Some(json!("019f7e95-0000-7000-8000-000000000999"))),
    ] {
        let mut invalid = valid.clone();
        let result_evidence_id = invalid["executions"][0]["verification"]["result_evidence_id"]
            .as_str()
            .expect("result evidence id is a string")
            .to_owned();
        let result = evidence_mut(&mut invalid, &result_evidence_id);
        match execution_id {
            Some(execution_id) => result["execution_id"] = execution_id,
            None => {
                result
                    .as_object_mut()
                    .expect("result evidence is an object")
                    .remove("execution_id");
            }
        }
        assert!(
            rejects_report(&invalid),
            "accepted result evidence with {label} execution attribution"
        );
    }

    let mut wrong_result_source = valid.clone();
    wrong_result_source["evidence"][2]["source"] = json!("PATCH");
    assert!(
        rejects_report(&wrong_result_source),
        "accepted verification whose result evidence has the wrong source"
    );

    for (field, value) in [("name", json!("black")), ("version", json!("0.12.3"))] {
        let mut wrong_tool = valid.clone();
        wrong_tool["executions"][0]["tool"][field] = value;
        assert!(
            rejects_report(&wrong_tool),
            "accepted verification with mismatched execution tool {field}"
        );
    }
}

#[test]
fn fix_proposed_finding_must_stay_within_candidate_observation_scope() {
    let mut report = verified_report_fixture();
    let out_of_scope_id = "019f7e95-0000-7000-8000-000000000111";
    let mut out_of_scope = report["observations"][0].clone();
    out_of_scope["observation_id"] = json!(out_of_scope_id);
    out_of_scope["message"] = json!("another diagnostic");
    report["observations"]
        .as_array_mut()
        .expect("observations is an array")
        .push(out_of_scope);
    report["findings"][0]["state"] = json!("FIX_PROPOSED");
    report["findings"][0]
        .as_object_mut()
        .unwrap()
        .remove("pre_report_state");
    report["findings"][0]["observation_ids"] = json!([out_of_scope_id]);
    report["findings"][0]
        .as_object_mut()
        .expect("finding is an object")
        .remove("verification_execution_ids");
    report["executions"][0]
        .as_object_mut()
        .expect("execution is an object")
        .remove("verification");

    assert!(
        rejects_report(&report),
        "accepted FIX_PROPOSED finding outside its candidate observation scope"
    );
}

#[test]
fn fix_candidate_rejects_observations_from_multiple_tool_identities() {
    let mut report = verified_report_fixture();
    let second_observation_id = "019f7e95-0000-7000-8000-000000000111";
    let mut second_observation = report["observations"][0].clone();
    second_observation["observation_id"] = json!(second_observation_id);
    second_observation["tool"]["name"] = json!("mypy");
    second_observation["tool"]["version"] = json!("1.0.0");
    report["observations"]
        .as_array_mut()
        .expect("observations is an array")
        .push(second_observation);
    report["fix_candidates"][0]["observation_ids"] =
        json!([observation_id(&report), second_observation_id]);

    assert!(
        rejects_report(&report),
        "accepted a fix candidate sourced from multiple tool identities"
    );
}

#[test]
fn fix_candidate_may_cover_multiple_rules_from_one_tool_version() {
    let mut report = verified_report_fixture();
    let second_observation_id = "019f7e95-0000-7000-8000-000000000111";
    let mut second_observation = report["observations"][0].clone();
    second_observation["observation_id"] = json!(second_observation_id);
    second_observation["tool"]["rule_id"] = json!("E501");
    second_observation["message"] = json!("line too long");
    report["observations"]
        .as_array_mut()
        .expect("observations is an array")
        .push(second_observation);
    report["fix_candidates"][0]["observation_ids"] =
        json!([observation_id(&report), second_observation_id]);
    let second_finding_id = "019f7e95-0000-7000-8000-000000000112";
    let mut second_finding = report["findings"][0].clone();
    second_finding["finding_id"] = json!(second_finding_id);
    second_finding["fingerprint"] = json!(format!("dtfp1:{}", "e".repeat(64)));
    second_finding["observation_ids"] = json!([second_observation_id]);
    second_finding["tool"]["rule_id"] = json!("E501");
    second_finding["message"] = json!("line too long");
    second_finding["state"] = json!("FIX_PROPOSED");
    second_finding
        .as_object_mut()
        .expect("finding is an object")
        .remove("verification_execution_ids");
    report["findings"]
        .as_array_mut()
        .expect("findings is an array")
        .push(second_finding);
    let mut second_decision = report["decisions"][0].clone();
    second_decision["decision_id"] = json!("019f7e95-0000-7000-8000-000000000113");
    second_decision["finding_id"] = json!(second_finding_id);
    report["decisions"]
        .as_array_mut()
        .expect("decisions is an array")
        .push(second_decision);

    validate_report_json(&serde_json::to_vec(&report).unwrap())
        .expect("one tool version may propose a candidate spanning multiple rules");
}

#[test]
fn finding_tool_must_match_every_source_observation_tool() {
    let mut report = report_fixture();
    let second_observation_id = "019f7e95-0000-7000-8000-000000000111";
    let mut second_observation = report["observations"][0].clone();
    second_observation["observation_id"] = json!(second_observation_id);
    second_observation["tool"]["name"] = json!("mypy");
    second_observation["tool"]["version"] = json!("1.0.0");
    report["observations"]
        .as_array_mut()
        .expect("observations is an array")
        .push(second_observation);
    report["findings"][0]["observation_ids"] =
        json!([observation_id(&report), second_observation_id]);

    assert!(
        rejects_report(&report),
        "accepted a finding whose tool differs from a source observation"
    );
}

#[test]
fn duplicate_finding_fingerprints_are_rejected() {
    let mut report = report_fixture();
    let mut duplicate = report["findings"][0].clone();
    duplicate["finding_id"] = json!("019f7e95-0000-7000-8000-000000000107");
    report["findings"]
        .as_array_mut()
        .expect("findings is an array")
        .push(duplicate);

    assert!(
        rejects_report(&report),
        "accepted duplicate finding fingerprints"
    );
}

#[test]
fn safe_fix_candidate_rejects_an_unrelated_observation_set() {
    let mut report = verified_report_fixture();
    let unrelated_observation_id = "019f7e95-0000-7000-8000-000000000111";
    let mut unrelated_observation = report["observations"][0].clone();
    unrelated_observation["observation_id"] = json!(unrelated_observation_id);
    unrelated_observation["message"] = json!("unrelated diagnostic");
    report["observations"]
        .as_array_mut()
        .expect("observations is an array")
        .push(unrelated_observation);
    report["fix_candidates"][0]["observation_ids"] = json!([unrelated_observation_id]);

    assert!(
        rejects_report(&report),
        "accepted a SAFE fix candidate containing an unrelated observation"
    );
}

#[test]
fn verification_requires_an_attributed_base_snapshot_evidence() {
    let valid = verified_report_fixture();
    validate_report_json(
        &serde_json::to_vec(&valid).expect("verified report remains JSON serializable"),
    )
    .expect("base snapshot evidence attribution is valid");

    let mut unknown = valid.clone();
    unknown["executions"][0]["verification"]["base_snapshot_evidence_id"] =
        json!("019f7e95-0000-7000-8000-000000000999");
    assert!(
        rejects_report(&unknown),
        "accepted verification pointing at unknown base snapshot evidence"
    );

    let base_snapshot_id = valid["executions"][0]["verification"]["base_snapshot_evidence_id"]
        .as_str()
        .expect("base snapshot evidence id is a string")
        .to_owned();

    let mut wrong_source = valid.clone();
    evidence_mut(&mut wrong_source, &base_snapshot_id)["source"] = json!("PATCH");
    assert!(
        rejects_report(&wrong_source),
        "accepted base snapshot evidence with the wrong source"
    );

    let mut wrong_media_type = valid.clone();
    evidence_mut(&mut wrong_media_type, &base_snapshot_id)["media_type"] =
        json!("application/octet-stream");
    assert!(
        rejects_report(&wrong_media_type),
        "accepted base snapshot evidence with the wrong media type"
    );

    let mut wrong_digest = valid.clone();
    wrong_digest["executions"][0]["verification"]["base_snapshot_sha256"] = json!("a".repeat(64));
    assert!(
        rejects_report(&wrong_digest),
        "accepted base snapshot evidence with a mismatched digest"
    );

    let mut relative_path = valid;
    let snapshot = evidence_mut(&mut relative_path, &base_snapshot_id);
    snapshot
        .as_object_mut()
        .expect("base snapshot evidence is an object")
        .remove("content");
    snapshot["relative_path"] = json!("snapshots/base.json");
    assert!(
        rejects_report(&relative_path),
        "accepted verification using a relative_path base snapshot"
    );
}

#[test]
fn verified_finding_rejects_truncated_base_snapshot_and_complete_result() {
    let valid = verified_report_fixture();
    let base_snapshot_id = valid["executions"][0]["verification"]["base_snapshot_evidence_id"]
        .as_str()
        .expect("base snapshot evidence id is a string")
        .to_owned();
    let result_id = valid["executions"][0]["verification"]["result_evidence_id"]
        .as_str()
        .expect("result evidence id is a string")
        .to_owned();

    for (label, evidence_id) in [
        ("base snapshot", base_snapshot_id.as_str()),
        ("result", result_id.as_str()),
    ] {
        let mut invalid = valid.clone();
        let evidence = evidence_mut(&mut invalid, evidence_id);
        let retained_bytes = evidence["retained_bytes"]
            .as_u64()
            .expect("retained bytes is an integer");
        evidence["observed_bytes"] = json!(retained_bytes + 1);
        evidence["truncated"] = json!(true);
        assert!(
            rejects_report(&invalid),
            "accepted VERIFIED finding with truncated {label} evidence"
        );
    }

    let mut result_relative_path = valid;
    let result = evidence_mut(&mut result_relative_path, &result_id);
    result
        .as_object_mut()
        .expect("result evidence is an object")
        .remove("content");
    result["relative_path"] = json!("receipts/result.txt");
    assert!(
        rejects_report(&result_relative_path),
        "accepted COMPLETE verification with a relative_path result evidence"
    );
}

#[test]
fn verification_rejects_reusing_snapshot_as_result_and_snapshot_media_as_result() {
    let valid = verified_report_fixture();
    let execution_id = valid["executions"][0]["execution_id"].clone();
    let base_snapshot_id = valid["executions"][0]["verification"]["base_snapshot_evidence_id"]
        .as_str()
        .expect("base snapshot evidence id is a string")
        .to_owned();
    let result_id = valid["executions"][0]["verification"]["result_evidence_id"]
        .as_str()
        .expect("result evidence id is a string")
        .to_owned();

    let mut same_evidence = valid.clone();
    same_evidence["executions"][0]["verification"]["result_evidence_id"] = json!(&base_snapshot_id);
    evidence_mut(&mut same_evidence, &base_snapshot_id)["execution_id"] = execution_id;
    assert!(
        rejects_report(&same_evidence),
        "accepted the same evidence as both base snapshot and verification result"
    );

    let mut snapshot_result = valid;
    evidence_mut(&mut snapshot_result, &result_id)["media_type"] =
        json!("application/vnd.diagnostic-triage.snapshot+json");
    assert!(
        rejects_report(&snapshot_result),
        "accepted snapshot media type for verification result evidence"
    );
}

#[test]
fn jsonl_evidence_execution_id_must_reference_an_execution_in_the_transcript() {
    let valid = String::from_utf8(fixture("valid-session.jsonl")).expect("fixture is UTF-8");
    let invalid = valid.replacen(
        "\"source\":\"DIAGNOSTIC\"",
        "\"execution_id\":\"019f7e95-0000-7000-8000-000000000999\",\"source\":\"DIAGNOSTIC\"",
        1,
    );
    assert_ne!(invalid, valid, "test must inject an execution reference");
    assert!(
        validate_session_jsonl(invalid.as_bytes()).is_err(),
        "accepted evidence attributed to an execution absent from the transcript"
    );
}

#[test]
fn jsonl_provider_execution_event_is_rejected_by_provider_role() {
    let input = String::from_utf8(fixture("valid-observer-session.jsonl"))
        .expect("observer fixture is UTF-8");
    let mut events = input
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("fixture line is JSON"))
        .collect::<Vec<_>>();
    events[0]["adapter"]["kind"] = json!("PROVIDER");
    events[0]["adapter"]["capabilities"] = json!(["diagnostic.check/v1"]);
    events[1]["operation"] = json!("CHECK");
    events[1]["required_capabilities"] = json!(["diagnostic.check/v1"]);
    events[2]["execution"]["adapter_kind"] = json!("PROVIDER");
    events[2]["execution"]["exit_code"] = json!(0);
    events[2]["execution"]["verification"] = json!({
        "fix_candidate_id": "019f7e95-0000-7000-8000-000000000108",
        "patch_sha256": "f7efec72998d2a5dfccffb6c8677c1f5219236675eac2657908456a3579166c0",
        "base_snapshot_sha256": "3b6a36b9dbd72d7d1ea5c498dbadaa424c19c25fe8bf6852fc13e7e214df8ffa",
        "base_snapshot_evidence_id": "019f7e95-0000-7000-8000-000000000109",
        "target_fingerprints": [
            "dtfp1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        ],
        "result_evidence_id": "019f7e95-0000-7000-8000-000000000110"
    });

    let session = events
        .iter()
        .map(|event| serde_json::to_string(event).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    assert!(
        validate_session_jsonl(session.as_bytes()).is_err(),
        "accepted a Provider execution event emitted by a Provider role"
    );
}

#[test]
fn jsonl_observer_execution_verification_is_rejected_by_model() {
    let input = String::from_utf8(fixture("valid-observer-session.jsonl"))
        .expect("observer fixture is UTF-8");
    let mut events = input
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("fixture line is JSON"))
        .collect::<Vec<_>>();
    events[2]["execution"]["verification"] = json!({
        "fix_candidate_id": "019f7e95-0000-7000-8000-000000000108",
        "patch_sha256": "f7efec72998d2a5dfccffb6c8677c1f5219236675eac2657908456a3579166c0",
        "base_snapshot_sha256": "3b6a36b9dbd72d7d1ea5c498dbadaa424c19c25fe8bf6852fc13e7e214df8ffa",
        "base_snapshot_evidence_id": "019f7e95-0000-7000-8000-000000000109",
        "target_fingerprints": [
            "dtfp1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        ],
        "result_evidence_id": "019f7e95-0000-7000-8000-000000000110"
    });

    let session = events
        .iter()
        .map(|event| serde_json::to_string(event).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    assert!(
        validate_session_jsonl(session.as_bytes()).is_err(),
        "accepted Observer execution verification attribution in JSONL"
    );
}

#[test]
fn observer_jsonl_may_attribute_evidence_to_its_execution() {
    let input = String::from_utf8(fixture("valid-observer-session.jsonl"))
        .expect("observer fixture is UTF-8");
    let mut events = input
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("fixture line is JSON"))
        .collect::<Vec<_>>();
    let request_id = events[1]["request_id"].clone();
    let execution_id = events[2]["execution"]["execution_id"].clone();
    events[2]["sequence"] = json!(1);
    events[3]["sequence"] = json!(2);
    events[3]["counts"]["evidence"] = json!(1);
    events.insert(
        2,
        json!({
            "protocol_version": "diagnostic-triage.protocol/v1",
            "kind": "evidence",
            "request_id": request_id,
            "sequence": 0,
            "evidence": {
                "schema_version": "diagnostic-triage.evidence/v1",
                "evidence_id": "019f7e95-0000-7000-8000-000000000203",
                "execution_id": execution_id,
                "source": "ARTIFACT",
                "media_type": "application/json",
                "retained_bytes": 0,
                "observed_bytes": 0,
                "limit_bytes": 1_048_576,
                "truncated": false,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "content": ""
            }
        }),
    );
    let session = events
        .iter()
        .map(|event| serde_json::to_string(event).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    validate_session_jsonl(session.as_bytes())
        .expect("observer evidence may reference an execution in the same transcript");
}

#[test]
fn failed_verification_receipts_remain_reportable_and_share_the_base_snapshot() {
    for (status, verdict) in [("INCOMPLETE", "INCOMPLETE"), ("UNSUPPORTED", "UNSUPPORTED")] {
        let mut report = verified_report_fixture();
        report["verdict"] = json!(verdict);
        report["findings"][0]["state"] = json!("FIX_PROPOSED");
        report["findings"][0]
            .as_object_mut()
            .unwrap()
            .remove("pre_report_state");
        report["executions"][0]["status"] = json!(status);
        report["executions"][0]["exit_code"] = Value::Null;
        report["executions"][0]["message"] = json!(format!(
            "verification execution is {}",
            status.to_lowercase()
        ));
        let result_id = report["executions"][0]["verification"]["result_evidence_id"]
            .as_str()
            .expect("result evidence id is a string")
            .to_owned();
        let result = evidence_mut(&mut report, &result_id);
        result
            .as_object_mut()
            .expect("result evidence is an object")
            .remove("content");
        result["relative_path"] = json!(format!("receipts/{}.txt", status.to_lowercase()));
        let retained_bytes = result["retained_bytes"]
            .as_u64()
            .expect("retained bytes is an integer");
        result["observed_bytes"] = json!(retained_bytes + 1);
        result["truncated"] = json!(true);
        validate_report_json(&serde_json::to_vec(&report).unwrap())
            .unwrap_or_else(|error| panic!("rejected non-inline {status} receipt: {error}"));

        report["findings"][0]["state"] = json!("REPORTED");
        report["findings"][0]["pre_report_state"] = json!("FIX_PROPOSED");
        validate_report_json(&serde_json::to_vec(&report).unwrap()).unwrap_or_else(|error| {
            panic!("rejected reported FIX_PROPOSED {status} receipt: {error}")
        });
    }

    let mut unsafe_receipt = verified_report_fixture();
    unsafe_receipt["findings"][0]["state"] = json!("FIX_PROPOSED");
    unsafe_receipt["findings"][0]
        .as_object_mut()
        .unwrap()
        .remove("pre_report_state");
    unsafe_receipt["fix_candidates"][0]["applicability"] = json!("UNSAFE");
    validate_report_json(&serde_json::to_vec(&unsafe_receipt).unwrap())
        .expect("FIX_PROPOSED may retain an UNSAFE verification attempt receipt");

    unsafe_receipt["findings"][0]["state"] = json!("REPORTED");
    unsafe_receipt["findings"][0]["pre_report_state"] = json!("FIX_PROPOSED");
    validate_report_json(&serde_json::to_vec(&unsafe_receipt).unwrap())
        .expect("reported FIX_PROPOSED may retain an UNSAFE verification attempt receipt");

    let mut non_provider_receipt = unsafe_receipt.clone();
    non_provider_receipt["executions"][0]["adapter_kind"] = json!("OBSERVER");
    assert!(
        rejects_report(&non_provider_receipt),
        "accepted a non-Provider FIX_PROPOSED verification attempt receipt"
    );

    unsafe_receipt["findings"][0]["pre_report_state"] = json!("VERIFIED");
    assert!(
        rejects_report(&unsafe_receipt),
        "accepted an UNSAFE candidate as a VERIFIED proof claim"
    );

    let mut report = verified_report_fixture();
    let mut second = report["executions"][0].clone();
    second["execution_id"] = json!("019f7e95-0000-8000-8000-000000000112");
    second["adapter_id"] = json!("ruff-secondary");
    let mut second_result = report["evidence"][2].clone();
    second_result["evidence_id"] = json!("019f7e95-0000-8000-8000-000000000113");
    second_result["execution_id"] = second["execution_id"].clone();
    second["verification"]["result_evidence_id"] = second_result["evidence_id"].clone();
    report["findings"][0]["verification_execution_ids"]
        .as_array_mut()
        .unwrap()
        .push(second["execution_id"].clone());
    report["executions"].as_array_mut().unwrap().push(second);
    report["evidence"]
        .as_array_mut()
        .unwrap()
        .push(second_result);
    validate_report_json(&serde_json::to_vec(&report).unwrap())
        .expect("same-candidate receipts may share a base snapshot");

    report["executions"][1]["verification"]["base_snapshot_sha256"] = json!("a".repeat(64));
    assert!(
        rejects_report(&report),
        "accepted same-candidate receipts with different base snapshots"
    );
}
