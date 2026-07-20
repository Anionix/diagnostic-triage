//! Golden compatibility tests for the checked-in v1 wire contract.

use std::{collections::HashSet, fs, path::PathBuf};

use diagnostic_triage_contracts::{
    COMMON_SCHEMA_V1, MODEL_SCHEMA_V1, PROTOCOL_SCHEMA_V1, TAXONOMY_SCHEMA_V1,
    model::{SessionReport, Taxonomy},
    validate_report_json, validate_session_jsonl,
};
use serde_json::{Value, json};

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
const VALID_REPORTS: &[&str] = &["valid-report.json", "valid-unsupported-report.json"];

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

fn rejects_report(value: &Value) -> bool {
    validate_report_json(
        &serde_json::to_vec(value).expect("mutated report remains JSON serializable"),
    )
    .is_err()
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
fn typed_reports_round_trip_without_emitting_optional_nulls() {
    for name in VALID_REPORTS {
        let report =
            validate_report_json(&fixture(name)).unwrap_or_else(|error| panic!("{name}: {error}"));
        let encoded = serde_json::to_vec(&report).expect("typed report serializes");
        validate_report_json(&encoded).unwrap_or_else(|error| panic!("round-trip {name}: {error}"));
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
    failed_verification["findings"][0]["fix_candidate_id"] =
        json!("019f7e95-0000-7000-8000-000000000107");
    failed_verification["findings"][0]["verification_execution_ids"] = json!([execution_id]);
    failed_verification["executions"][0]["status"] = json!("INCOMPLETE");
    failed_verification["executions"][0]["exit_code"] = Value::Null;
    failed_verification["executions"][0]["message"] = json!("verification provider timed out");
    candidates.push(("failed verification", failed_verification));

    let mut missing_decision = report_fixture();
    missing_decision["decisions"] = json!([]);
    candidates.push(("missing decision", missing_decision));

    for (name, candidate) in candidates {
        assert!(rejects_report(&candidate), "accepted {name}");
    }
}

#[test]
fn waiver_must_be_complete_and_bound_to_its_finding() {
    let mut report = report_fixture();
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
