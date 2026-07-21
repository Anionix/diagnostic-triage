use std::{
    fs,
    io::{self, Write},
};

use diagnostic_triage_contracts::{
    RepoPath, Sha256Digest,
    model::{DecisionAction, ExecutionStatus, SessionReport, Verdict, WaivedAction, Waiver},
    validate_report_json,
};
use diagnostic_triage_runtime::{
    ReportFormat, Reporter, ReporterError, SarifReporter, ValidatedSessionReport, sarif_bytes,
    write_sarif,
};
use serde_json::{Value, json};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

fn report(name: &str) -> SessionReport {
    let bytes = fs::read(format!(
        "{}/../../tests/fixtures/v1/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("checked-in report fixture is readable");
    validate_report_json(&bytes).expect("checked-in report fixture is valid")
}

fn golden(name: &str) -> Value {
    let bytes = fs::read(format!(
        "{}/tests/golden/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("SARIF golden fixture is readable");
    serde_json::from_slice(&bytes).expect("SARIF golden fixture is JSON")
}

fn encoded_value(report: SessionReport) -> Value {
    let validated = ValidatedSessionReport::new(report).unwrap();
    serde_json::from_slice(&sarif_bytes(&validated).unwrap()).unwrap()
}

#[test]
fn finding_decision_location_and_complete_execution_match_golden() {
    let report = report("valid-report.json");
    let validated = ValidatedSessionReport::new(report.clone()).unwrap();
    let bytes = sarif_bytes(&validated).unwrap();
    let value = serde_json::from_slice::<Value>(&bytes).unwrap();

    assert_eq!(value, golden("valid-report.sarif.json"));
    assert_eq!(
        value["$schema"],
        "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
    );
    assert_eq!(value["version"], "2.1.0");
    assert_eq!(
        value["runs"][0]["tool"]["driver"]["name"],
        "diagnostic-triage"
    );
    assert_eq!(value["runs"][0]["results"][0]["ruleId"], "ruff/F821");
    assert_eq!(value["runs"][0]["results"][0]["level"], "error");
    assert_eq!(
        value["runs"][0]["results"][0]["message"]["text"],
        "Undefined name `x`"
    );
    assert_eq!(
        value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/example.py"
    );
    assert_eq!(
        value["runs"][0]["results"][0]["partialFingerprints"]["diagnosticTriageFingerprint/v1"],
        "dtfp1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    );
    assert_eq!(sarif_bytes(&validated).unwrap(), bytes);

    let mut writer_output = Vec::new();
    write_sarif(&report, &mut writer_output).unwrap();
    assert_eq!(writer_output, bytes);

    let mut trait_output = Vec::new();
    SarifReporter
        .write_report(&validated, &mut trait_output)
        .unwrap();
    assert_eq!(trait_output, bytes);
}

#[test]
fn incomplete_and_unsupported_executions_are_notifications() {
    let unsupported = encoded_value(report("valid-unsupported-report.json"));
    assert_eq!(unsupported, golden("unsupported-report.sarif.json"));
    assert_eq!(
        unsupported["runs"][0]["tool"]["driver"]["notifications"][0]["id"],
        "diagnostic-triage.execution.unsupported"
    );

    let mut incomplete_report = report("valid-unsupported-report.json");
    incomplete_report.verdict = Verdict::Incomplete;
    incomplete_report.executions[0].status = ExecutionStatus::Incomplete;
    incomplete_report.executions[0].message =
        Some("provider output ended before completion".to_owned());
    let incomplete = encoded_value(incomplete_report);

    assert_eq!(
        incomplete.pointer("/runs/0/invocations/0/toolExecutionNotifications/0"),
        Some(&json!({
            "descriptor": {"id": "diagnostic-triage.execution.incomplete"},
            "level": "error",
            "message": {"text": "provider output ended before completion"}
        }))
    );
    assert_eq!(
        incomplete.pointer("/runs/0/invocations/0/executionSuccessful"),
        Some(&json!(false))
    );
}

#[test]
fn empty_and_locationless_reports_use_valid_optional_shapes() {
    let mut empty = report("valid-report.json");
    empty.observations.clear();
    empty.findings.clear();
    empty.decisions.clear();
    empty.evidence.clear();
    empty.fix_candidates.clear();
    empty.executions.clear();
    empty.verdict = Verdict::Pass;
    let empty = encoded_value(empty);
    assert_eq!(empty["runs"][0]["results"], json!([]));
    assert_eq!(empty["runs"][0]["invocations"], json!([]));
    assert_eq!(empty["runs"][0]["tool"]["driver"]["rules"], json!([]));

    let mut locationless = report("valid-report.json");
    locationless.observations[0].location = None;
    locationless.observations[0].symbol = None;
    locationless.findings[0].location = None;
    locationless.findings[0].symbol = None;
    let locationless = encoded_value(locationless);
    assert!(
        locationless["runs"][0]["results"][0]
            .get("locations")
            .is_none()
    );
}

#[test]
fn point_locations_emit_an_explicit_zero_width_sarif_region() {
    let mut report = report("valid-report.json");
    report.observations[0].location.as_mut().unwrap().end = None;
    report.findings[0].location.as_mut().unwrap().end = None;
    let value = encoded_value(report);

    assert_eq!(
        value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"],
        json!({
            "startLine": 7,
            "startColumn": 12,
            "endLine": 7,
            "endColumn": 12
        })
    );
}

#[test]
fn repository_paths_are_utf8_percent_encoded_without_becoming_file_uris() {
    let mut report = report("valid-report.json");
    let path: RepoPath = "src/空 白:#?%\n\u{1f}.rs".parse().unwrap();
    report.observations[0].location.as_mut().unwrap().path = path.clone();
    report.findings[0].location.as_mut().unwrap().path = path;
    let value = encoded_value(report);
    let uri = value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        ["artifactLocation"]["uri"]
        .as_str()
        .unwrap();

    assert_eq!(uri, "src/%E7%A9%BA%20%E7%99%BD%3A%23%3F%25%0A%1F.rs");
    assert!(!uri.starts_with("file:"));
}

#[test]
fn waiver_becomes_an_accepted_external_suppression() {
    let mut report = report("valid-report.json");
    report.decisions[0].action = DecisionAction::Waive;
    report.decisions[0].waiver = Some(Waiver {
        fingerprint: report.findings[0].fingerprint.clone(),
        waived_action: WaivedAction::Block,
        reason: "accepted migration risk".to_owned(),
        owner: "security-team".to_owned(),
        expires_at: "2026-08-21T00:00:00Z".to_owned(),
    });
    report.verdict = Verdict::Pass;
    let value = encoded_value(report);

    assert_eq!(
        value["runs"][0]["results"][0]["suppressions"][0],
        json!({
            "kind": "external",
            "status": "accepted",
            "justification": "accepted migration risk"
        })
    );
    assert_eq!(
        value["runs"][0]["results"][0]["properties"]["waiver"],
        json!({
            "waivedAction": "BLOCK",
            "reason": "accepted migration risk",
            "owner": "security-team",
            "expiresAt": "2026-08-21T00:00:00Z"
        })
    );
}

#[test]
fn raw_evidence_content_is_not_exported() {
    let mut report = report("valid-report.json");
    let sensitive = "/Users/alice/project PRIVATE_TOKEN=do-not-export";
    report.evidence[0].content = Some(sensitive.to_owned());
    report.evidence[0].retained_bytes = sensitive.len() as u64;
    report.evidence[0].observed_bytes = sensitive.len() as u64;
    report.evidence[0].sha256 = Sha256Digest::compute(sensitive.as_bytes());
    let validated = ValidatedSessionReport::new(report).unwrap();
    let encoded = String::from_utf8(sarif_bytes(&validated).unwrap()).unwrap();

    assert!(!encoded.contains(sensitive));
}

#[test]
fn sarif_bytes_are_stable_when_valid_collection_order_changes() {
    let mut baseline = report("valid-report.json");
    let mut second_observation = baseline.observations[0].clone();
    second_observation.observation_id = "019f7e95-0000-7000-8000-000000000111".parse().unwrap();
    second_observation.tool.name = "mypy".to_owned();
    second_observation.tool.version = "1.17.0".to_owned();
    second_observation.tool.rule_id = Some("E999".to_owned());
    second_observation.message = "Second diagnostic".to_owned();
    baseline.observations.push(second_observation.clone());

    let mut second_finding = baseline.findings[0].clone();
    second_finding.finding_id = "019f7e95-0000-7000-8000-000000000112".parse().unwrap();
    second_finding.fingerprint =
        "dtfp1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .unwrap();
    second_finding.observation_ids = vec![second_observation.observation_id];
    second_finding.tool = second_observation.tool;
    second_finding.message = "Second diagnostic".to_owned();
    baseline.findings.push(second_finding.clone());

    let mut second_decision = baseline.decisions[0].clone();
    second_decision.decision_id = "019f7e95-0000-7000-8000-000000000113".parse().unwrap();
    second_decision.finding_id = second_finding.finding_id;
    baseline.decisions.push(second_decision);

    let mut second_execution = baseline.executions[0].clone();
    second_execution.execution_id = "019f7e95-0000-7000-8000-000000000204".parse().unwrap();
    second_execution.adapter_id = "mypy".parse().unwrap();
    second_execution.tool = second_finding.tool.clone();
    second_execution.tool.rule_id = None;
    baseline.executions.push(second_execution);
    let baseline = ValidatedSessionReport::new(baseline).unwrap();
    let expected = sarif_bytes(&baseline).unwrap();
    let value = serde_json::from_slice::<Value>(&expected).unwrap();
    assert_eq!(
        value["runs"][0]["tool"]["driver"]["rules"][0]["id"],
        "mypy/E999"
    );
    assert_eq!(
        value["runs"][0]["tool"]["driver"]["rules"][1]["id"],
        "ruff/F821"
    );
    assert_eq!(value["runs"][0]["results"][0]["ruleId"], "mypy/E999");

    let mut scrambled = baseline.as_report().clone();
    scrambled.observations.reverse();
    scrambled.findings.reverse();
    scrambled.decisions.reverse();
    scrambled.evidence.reverse();
    scrambled.fix_candidates.reverse();
    scrambled.executions.reverse();
    for finding in &mut scrambled.findings {
        finding.observation_ids.reverse();
        finding.evidence_ids.reverse();
        if let Some(execution_ids) = &mut finding.verification_execution_ids {
            execution_ids.reverse();
        }
    }
    let scrambled = ValidatedSessionReport::new(scrambled).unwrap();

    assert_eq!(sarif_bytes(&scrambled).unwrap(), expected);
}

#[test]
fn invalid_report_writes_nothing() {
    let mut report = report("valid-report.json");
    report.verdict = Verdict::Pass;
    let mut output = Vec::new();

    assert!(write_sarif(&report, &mut output).is_err());
    assert!(output.is_empty());
}

struct FailAfter {
    accepted: Vec<u8>,
    limit: usize,
}

impl Write for FailAfter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.accepted.len() == self.limit {
            return Err(io::Error::other("injected writer failure"));
        }
        let accepted = bytes.len().min(self.limit - self.accepted.len());
        self.accepted.extend_from_slice(&bytes[..accepted]);
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_failure_reports_the_accepted_prefix() {
    let report = report("valid-report.json");
    let expected = sarif_bytes(&ValidatedSessionReport::new(report.clone()).unwrap()).unwrap();
    let limit = expected.len() / 2;
    let mut writer = FailAfter {
        accepted: Vec::new(),
        limit,
    };

    let error = write_sarif(&report, &mut writer).unwrap_err();
    assert!(matches!(
        error,
        ReporterError::Io {
            format: ReportFormat::Sarif,
            ..
        }
    ));
    assert_eq!(writer.accepted, expected[..limit]);
}
