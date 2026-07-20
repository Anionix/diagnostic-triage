use std::str::FromStr;

use diagnostic_triage_contracts::{
    ObjectId,
    model::{DecisionAction, Severity, Verdict, WaivedAction, Waiver},
    validate_report_json,
};
use diagnostic_triage_engine::{
    EngineError, canonicalize_session_report, compute_verdict,
    finding::{finding_id_for_finding, fingerprint_for_finding},
    policy::decision_id_for_decision,
    recompute_verdict,
};
use serde_json::Value;

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

fn report_value() -> Value {
    serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/v1/valid-report.json"
    ))
    .expect("valid report fixture is JSON")
}

fn report(value: &Value) -> diagnostic_triage_contracts::model::SessionReport {
    let mut report =
        validate_report_json(&serde_json::to_vec(value).expect("report value serializes"))
            .expect("report fixture mutation remains contract-valid");
    for finding in &mut report.findings {
        let original_id = finding.finding_id.clone();
        finding.fingerprint = fingerprint_for_finding(finding).expect("fixture finding normalizes");
        finding.finding_id = finding_id_for_finding(finding).expect("fixture finding ID derives");
        for decision in &mut report.decisions {
            if decision.finding_id == original_id {
                decision.finding_id = finding.finding_id.clone();
            }
        }
    }
    for decision in &mut report.decisions {
        decision.decision_id =
            decision_id_for_decision(decision).expect("fixture decision ID derives");
    }
    report
}

fn finalized(value: &Value) -> diagnostic_triage_contracts::model::SessionReport {
    canonicalize_session_report(report(value)).expect("report finalizes")
}

#[test]
fn canonicalization_is_invariant_under_collection_permutations() {
    let mut value = report_value();
    let extra_evidence = value["evidence"][0].clone();
    let mut extra_evidence = extra_evidence;
    extra_evidence["evidence_id"] =
        Value::String("019f7e95-0000-7000-8000-000000000107".to_owned());
    value["evidence"]
        .as_array_mut()
        .unwrap()
        .push(extra_evidence);
    value["observations"][0]["evidence_ids"] = serde_json::json!([
        "019f7e95-0000-7000-8000-000000000107",
        "019f7e95-0000-7000-8000-000000000102"
    ]);
    value["findings"][0]["evidence_ids"] = serde_json::json!([
        "019f7e95-0000-7000-8000-000000000107",
        "019f7e95-0000-7000-8000-000000000102"
    ]);

    let canonical = finalized(&value);
    value["evidence"].as_array_mut().unwrap().reverse();
    value["observations"][0]["evidence_ids"]
        .as_array_mut()
        .unwrap()
        .reverse();
    value["findings"][0]["evidence_ids"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let permuted = finalized(&value);

    assert_eq!(canonical, permuted);
    assert_eq!(
        canonical.evidence[0].evidence_id.as_str(),
        "019f7e95-0000-7000-8000-000000000102"
    );
    assert_eq!(
        canonical.observations[0].evidence_ids[0].as_str(),
        "019f7e95-0000-7000-8000-000000000102"
    );
}

#[test]
fn verdict_precedence_is_incomplete_then_unsupported_then_policy_fail_then_pass() {
    let mut value = report_value();
    value["verdict"] = Value::String("PASS".to_owned());
    value["executions"][0]["status"] = Value::String("UNSUPPORTED".to_owned());
    value["executions"][0]["exit_code"] = Value::Null;
    value["executions"][0]["message"] = Value::String("unsupported".to_owned());
    assert_eq!(finalized(&value).verdict, Verdict::Unsupported);

    let mut value = report_value();
    value["verdict"] = Value::String("PASS".to_owned());
    value["executions"][0]["status"] = Value::String("INCOMPLETE".to_owned());
    value["executions"][0]["exit_code"] = Value::Null;
    value["executions"][0]["message"] = Value::String("incomplete".to_owned());
    let mut unsupported = value["executions"][0].clone();
    unsupported["execution_id"] = Value::String("019f7e95-0000-7000-8000-000000000108".to_owned());
    unsupported["status"] = Value::String("UNSUPPORTED".to_owned());
    unsupported["message"] = Value::String("unsupported".to_owned());
    value["executions"]
        .as_array_mut()
        .unwrap()
        .push(unsupported);
    assert_eq!(finalized(&value).verdict, Verdict::Incomplete);

    let mut value = report_value();
    value["verdict"] = Value::String("PASS".to_owned());
    value["decisions"][0]["action"] = Value::String("OBSERVE".to_owned());
    assert_eq!(finalized(&value).verdict, Verdict::Pass);

    let report = report(&report_value());
    assert_eq!(compute_verdict(&report), Verdict::PolicyFail);
    assert_eq!(recompute_verdict(&report).unwrap(), Verdict::PolicyFail);
}

#[test]
fn optional_unsupported_execution_does_not_change_policy_verdict() {
    let mut value = report_value();
    value["executions"][0]["required"] = Value::Bool(false);
    value["executions"][0]["status"] = Value::String("UNSUPPORTED".to_owned());
    value["executions"][0]["exit_code"] = Value::Null;
    value["executions"][0]["message"] = Value::String("optional capability".to_owned());
    assert_eq!(finalized(&value).verdict, Verdict::PolicyFail);
}

#[test]
fn invalid_references_are_rejected_before_finalization() {
    let mut report = report(&report_value());
    report.observations[0].evidence_ids =
        vec![ObjectId::from_str("019f7e95-0000-7000-8000-000000000999").unwrap()];
    assert!(canonicalize_session_report(report).is_err());
}

#[test]
fn forged_finding_is_rejected_before_finalization() {
    let mut report = report(&report_value());
    report.findings[0].message = "forged semantic context".to_owned();

    assert!(matches!(
        canonicalize_session_report(report),
        Err(EngineError::FingerprintMismatch { .. })
    ));
}

#[test]
fn forged_decision_id_is_rejected_before_finalization() {
    let mut report = report(&report_value());
    report.decisions[0].decision_id =
        ObjectId::from_str("019f7e95-0000-7000-8000-000000000998").unwrap();

    assert!(matches!(
        canonicalize_session_report(report),
        Err(EngineError::DecisionIdMismatch { .. })
    ));
}

#[test]
fn altered_waiver_is_rejected_before_finalization() {
    let mut report = report(&report_value());
    report.decisions[0].action = DecisionAction::Waive;
    report.decisions[0].waiver = Some(Waiver {
        fingerprint: report.findings[0].fingerprint.clone(),
        waived_action: WaivedAction::Block,
        reason: "approved reason".to_owned(),
        owner: "owner".to_owned(),
        expires_at: "2026-07-21T00:00:00Z".to_owned(),
    });
    report.decisions[0].decision_id =
        decision_id_for_decision(&report.decisions[0]).expect("waived decision ID derives");
    report.decisions[0].waiver.as_mut().unwrap().reason = "altered reason".to_owned();

    assert!(matches!(
        canonicalize_session_report(report),
        Err(EngineError::DecisionIdMismatch { .. })
    ));
}

#[test]
fn altered_policy_input_is_rejected_before_finalization() {
    let mut report = report(&report_value());
    report.findings[0].severity = Severity::Info;

    assert!(matches!(
        canonicalize_session_report(report),
        Err(EngineError::FindingIdMismatch { .. })
    ));
}
