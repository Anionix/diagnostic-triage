use std::{
    fs,
    io::{self, Write},
};

use diagnostic_triage_contracts::{model::SessionReport, validate_report_json};
use diagnostic_triage_runtime::reporters::{
    CanonicalJsonReporter, MAX_REPORT_OUTPUT_BYTES, ReportFormat, Reporter, ReporterError,
    TsvReporter, ValidatedSessionReport, canonical_json_bytes, tsv_bytes, write_canonical_json,
    write_tsv,
};
use diagnostic_triage_runtime::{
    GitHubAnnotationReporter, github_annotations_bytes, write_github_annotations,
};
use sha2::{Digest, Sha256};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

fn report() -> SessionReport {
    validate_report_json(include_bytes!(
        "../../../tests/fixtures/v1/valid-report.json"
    ))
    .expect("checked-in report fixture is valid")
}

fn verified_report() -> SessionReport {
    validate_report_json(include_bytes!(
        "../../../tests/fixtures/v1/valid-verified-report.json"
    ))
    .expect("checked-in verified report fixture is valid")
}

fn golden(name: &str) -> Vec<u8> {
    fs::read(format!(
        "{}/tests/golden/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("reporter golden fixture is readable")
}

#[test]
fn empty_report_has_only_the_fixed_tsv_header() {
    let mut report = report();
    report.observations.clear();
    report.findings.clear();
    report.decisions.clear();
    report.evidence.clear();
    report.fix_candidates.clear();
    report.executions.clear();
    report.verdict = diagnostic_triage_contracts::model::Verdict::Pass;
    let validated = ValidatedSessionReport::new(report).unwrap();

    assert_eq!(tsv_bytes(&validated).unwrap(), golden("empty.tsv"));
}

#[test]
fn report_with_findings_matches_the_tsv_golden() {
    let validated = ValidatedSessionReport::new(report()).unwrap();

    assert_eq!(tsv_bytes(&validated).unwrap(), golden("valid-report.tsv"));
}

#[test]
fn report_with_findings_matches_the_github_annotations_golden() {
    let validated = ValidatedSessionReport::new(report()).unwrap();

    assert_eq!(
        github_annotations_bytes(&validated).unwrap(),
        golden("valid-report.github-annotations.txt")
    );
}

#[test]
fn github_annotations_escape_metadata_and_messages_by_context() {
    let mut report = report();
    report.observations[0].tool.name = "lint%:\r\n,".to_owned();
    report.observations[0].tool.rule_id = Some("R%:\r\n,1".to_owned());
    report.findings[0].tool = report.observations[0].tool.clone();
    report.findings[0].message = "problem %\r\n: comma, stays".to_owned();
    report.findings[0].location.as_mut().unwrap().path = "src/%weird:,line.rs".parse().unwrap();
    let validated = ValidatedSessionReport::new(report).unwrap();

    assert_eq!(
        github_annotations_bytes(&validated).unwrap(),
        golden("escaped.github-annotations.txt")
    );
}

#[test]
fn github_annotations_omit_unavailable_coordinates() {
    let mut report = report();
    report.observations[0].location.as_mut().unwrap().end = None;
    report.findings[0].location.as_mut().unwrap().end = None;
    let validated = ValidatedSessionReport::new(report.clone()).unwrap();
    let output = String::from_utf8(github_annotations_bytes(&validated).unwrap()).unwrap();

    assert_eq!(
        output,
        "::error file=src/example.py,line=7,col=12,title=ruff%3A F821::Undefined name `x`\n"
    );
    assert!(!output.contains("endLine="));
    assert!(!output.contains("endColumn="));

    report.observations[0].location = None;
    report.findings[0].location = None;
    let validated = ValidatedSessionReport::new(report).unwrap();
    let output = String::from_utf8(github_annotations_bytes(&validated).unwrap()).unwrap();

    assert_eq!(output, "::error title=ruff%3A F821::Undefined name `x`\n");
    for unavailable in ["file=", "line=", "endLine=", "col=", "endColumn="] {
        assert!(!output.contains(unavailable));
    }
}

#[test]
fn github_annotations_omit_columns_for_multiline_locations() {
    let mut report = report();
    let end = report.observations[0]
        .location
        .as_mut()
        .unwrap()
        .end
        .as_mut()
        .unwrap();
    end.line = 8;
    end.column = 3;
    report.findings[0].location = report.observations[0].location.clone();
    let validated = ValidatedSessionReport::new(report).unwrap();
    let output = String::from_utf8(github_annotations_bytes(&validated).unwrap()).unwrap();

    assert_eq!(
        output,
        "::error file=src/example.py,line=7,endLine=8,title=ruff%3A F821::Undefined name `x`\n"
    );
    assert!(!output.contains("col="));
    assert!(!output.contains("endColumn="));
}

#[test]
fn github_annotations_convert_exclusive_endpoints_to_inclusive_spans() {
    let mut report = report();
    report.observations[0]
        .location
        .as_mut()
        .unwrap()
        .end
        .as_mut()
        .unwrap()
        .column = 12;
    report.findings[0].location = report.observations[0].location.clone();
    let validated = ValidatedSessionReport::new(report.clone()).unwrap();
    let output = String::from_utf8(github_annotations_bytes(&validated).unwrap()).unwrap();
    assert_eq!(
        output,
        "::error file=src/example.py,line=7,endLine=7,col=12,title=ruff%3A F821::Undefined name `x`\n"
    );

    let end = report.observations[0]
        .location
        .as_mut()
        .unwrap()
        .end
        .as_mut()
        .unwrap();
    end.line = 8;
    end.column = 1;
    report.findings[0].location = report.observations[0].location.clone();
    let validated = ValidatedSessionReport::new(report).unwrap();
    let output = String::from_utf8(github_annotations_bytes(&validated).unwrap()).unwrap();

    assert_eq!(
        output,
        "::error file=src/example.py,line=7,endLine=7,title=ruff%3A F821::Undefined name `x`\n"
    );
}

#[test]
fn github_annotations_omit_coordinates_outside_the_runner_integer_range() {
    let mut report = report();
    let location = report.observations[0].location.as_mut().unwrap();
    location.start.line = i32::MAX as u32;
    location.start.column = i32::MAX as u32;
    location.end = None;
    report.findings[0].location = Some(location.clone());
    let validated = ValidatedSessionReport::new(report.clone()).unwrap();
    let output = String::from_utf8(github_annotations_bytes(&validated).unwrap()).unwrap();

    assert!(output.contains("line=2147483647,col=2147483647"));

    report.observations[0].location.as_mut().unwrap().start.line += 1;
    report.findings[0].location = report.observations[0].location.clone();
    let validated = ValidatedSessionReport::new(report).unwrap();
    let output = String::from_utf8(github_annotations_bytes(&validated).unwrap()).unwrap();

    assert_eq!(output, "::error title=ruff%3A F821::Undefined name `x`\n");
}

#[test]
fn github_annotations_keep_each_supported_coordinate_after_conversion() {
    const MAX: u32 = i32::MAX as u32;

    let mut report = report();
    let location = report.observations[0].location.as_mut().unwrap();
    location.start.line = 1;
    location.start.column = MAX;
    location.end.as_mut().unwrap().line = 1;
    location.end.as_mut().unwrap().column = MAX + 1;
    report.findings[0].location = Some(location.clone());
    let validated = ValidatedSessionReport::new(report.clone()).unwrap();
    let output = String::from_utf8(github_annotations_bytes(&validated).unwrap()).unwrap();
    assert!(output.contains("line=1,endLine=1,col=2147483647,endColumn=2147483647"));

    let location = report.observations[0].location.as_mut().unwrap();
    location.start.line = MAX - 1;
    location.start.column = 1;
    location.end.as_mut().unwrap().line = MAX + 1;
    location.end.as_mut().unwrap().column = 1;
    report.findings[0].location = Some(location.clone());
    let validated = ValidatedSessionReport::new(report.clone()).unwrap();
    let output = String::from_utf8(github_annotations_bytes(&validated).unwrap()).unwrap();
    assert!(output.contains("line=2147483646,endLine=2147483647"));
    assert!(!output.contains("col="));

    let location = report.observations[0].location.as_mut().unwrap();
    location.start.line = 7;
    location.start.column = 12;
    location.end.as_mut().unwrap().line = 8;
    location.end.as_mut().unwrap().column = MAX + 1;
    report.findings[0].location = Some(location.clone());
    let validated = ValidatedSessionReport::new(report).unwrap();
    let output = String::from_utf8(github_annotations_bytes(&validated).unwrap()).unwrap();
    assert!(output.contains("line=7,endLine=8"));
    assert!(!output.contains("col="));
}

#[test]
fn github_annotations_degrade_only_the_unsupported_coordinate_suffix() {
    const MAX: u32 = i32::MAX as u32;

    let mut report = report();
    let location = report.observations[0].location.as_mut().unwrap();
    location.start.column = MAX + 1;
    location.end = None;
    report.findings[0].location = Some(location.clone());
    let validated = ValidatedSessionReport::new(report.clone()).unwrap();
    let output = String::from_utf8(github_annotations_bytes(&validated).unwrap()).unwrap();
    assert!(output.contains("file=src/example.py,line=7,title="));
    assert!(!output.contains("col="));

    let location = report.observations[0].location.as_mut().unwrap();
    location.start.line = MAX;
    location.start.column = 1;
    location.end = Some(diagnostic_triage_contracts::model::Position {
        line: MAX + 1,
        column: 2,
    });
    report.findings[0].location = Some(location.clone());
    let validated = ValidatedSessionReport::new(report).unwrap();
    let output = String::from_utf8(github_annotations_bytes(&validated).unwrap()).unwrap();
    assert!(output.contains("file=src/example.py,line=2147483647,col=1,title="));
    assert!(!output.contains("endLine="));
}

#[test]
fn github_annotations_preserve_unicode() {
    let mut report = report();
    report.findings[0].message = "未定義の名前 `値`".to_owned();
    report.findings[0].tool.name = "型検査".to_owned();
    report.findings[0].tool.rule_id = None;
    report.observations[0].tool = report.findings[0].tool.clone();
    let validated = ValidatedSessionReport::new(report).unwrap();
    let output = String::from_utf8(github_annotations_bytes(&validated).unwrap()).unwrap();

    assert!(output.contains("title=型検査::未定義の名前 `値`"));
}

#[test]
fn github_annotations_ignore_operational_evidence_without_findings() {
    let validated = ValidatedSessionReport::from_json(include_bytes!(
        "../../../tests/fixtures/v1/valid-unsupported-report.json"
    ))
    .unwrap();

    assert_eq!(validated.as_report().executions.len(), 1);
    assert!(github_annotations_bytes(&validated).unwrap().is_empty());
}

#[test]
fn github_annotations_are_stable_when_input_order_changes() {
    let mut report = report();
    let mut earlier_finding = report.findings[0].clone();
    earlier_finding.finding_id = "019f7e95-0000-7000-8000-000000000120".parse().unwrap();
    earlier_finding.fingerprint =
        "dtfp1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .unwrap();
    earlier_finding.message = "Earlier fingerprint".to_owned();
    let mut earlier_decision = report.decisions[0].clone();
    earlier_decision.decision_id = "019f7e95-0000-7000-8000-000000000121".parse().unwrap();
    earlier_decision.finding_id = earlier_finding.finding_id.clone();
    report.findings.push(earlier_finding);
    report.decisions.push(earlier_decision);

    let baseline = ValidatedSessionReport::new(report.clone()).unwrap();
    let expected = github_annotations_bytes(&baseline).unwrap();
    report.findings.reverse();
    report.decisions.reverse();
    let scrambled = ValidatedSessionReport::new(report).unwrap();

    assert_eq!(github_annotations_bytes(&scrambled).unwrap(), expected);
    assert!(
        String::from_utf8(expected)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .ends_with("::Earlier fingerprint")
    );
}

#[test]
fn canonical_json_round_trips_through_the_contract_validator() {
    let report = report();
    let validated = ValidatedSessionReport::new(report.clone()).unwrap();
    let encoded = canonical_json_bytes(&validated).unwrap();
    let decoded = validate_report_json(&encoded).unwrap();

    assert_eq!(decoded, report);
}

#[test]
fn canonical_json_is_stable_when_valid_collection_order_changes() {
    let baseline = ValidatedSessionReport::new(report()).unwrap();
    let baseline_json = canonical_json_bytes(&baseline).unwrap();
    let mut scrambled = baseline.as_report().clone();
    scrambled.observations.reverse();
    scrambled.findings.reverse();
    scrambled.decisions.reverse();
    scrambled.evidence.reverse();
    scrambled.fix_candidates.reverse();
    scrambled.executions.reverse();
    for observation in &mut scrambled.observations {
        observation.evidence_ids.reverse();
    }
    for finding in &mut scrambled.findings {
        finding.observation_ids.reverse();
        finding.evidence_ids.reverse();
        if let Some(execution_ids) = &mut finding.verification_execution_ids {
            execution_ids.reverse();
        }
    }
    let scrambled = ValidatedSessionReport::new(scrambled).unwrap();

    assert_eq!(canonical_json_bytes(&scrambled).unwrap(), baseline_json);
}

#[test]
fn canonical_json_sorts_verified_fix_and_execution_branches() {
    let mut baseline = verified_report();
    let mut second_observation = baseline.observations[0].clone();
    second_observation.observation_id = "019f7e95-0000-7000-8000-000000000111".parse().unwrap();
    second_observation.message = "Second diagnostic".to_owned();
    baseline.observations.push(second_observation.clone());
    baseline.fix_candidates[0]
        .observation_ids
        .push(second_observation.observation_id.clone());

    let mut second_finding = baseline.findings[0].clone();
    second_finding.finding_id = "019f7e95-0000-7000-8000-000000000112".parse().unwrap();
    second_finding.fingerprint =
        "dtfp1:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            .parse()
            .unwrap();
    second_finding.observation_ids = vec![second_observation.observation_id];
    second_finding.message = "Second diagnostic".to_owned();
    baseline.findings.push(second_finding.clone());
    let mut second_decision = baseline.decisions[0].clone();
    second_decision.decision_id = "019f7e95-0000-7000-8000-000000000113".parse().unwrap();
    second_decision.finding_id = second_finding.finding_id;
    baseline.decisions.push(second_decision);
    baseline.executions[0]
        .verification
        .as_mut()
        .unwrap()
        .target_fingerprints
        .push(second_finding.fingerprint);

    let baseline = ValidatedSessionReport::new(baseline).unwrap();
    let baseline_json = canonical_json_bytes(&baseline).unwrap();
    let mut scrambled = baseline.as_report().clone();
    scrambled.fix_candidates[0].observation_ids.reverse();
    scrambled.executions[0]
        .verification
        .as_mut()
        .unwrap()
        .target_fingerprints
        .reverse();
    let scrambled = ValidatedSessionReport::new(scrambled).unwrap();

    assert_eq!(canonical_json_bytes(&scrambled).unwrap(), baseline_json);
}

#[test]
fn tsv_escapes_backslashes_tabs_and_newlines_without_mixing_diagnostics() {
    let mut report = report();
    let escaped = "line\twith\nnewline\\slash";
    report.observations[0].message = escaped.to_owned();
    report.findings[0].message = escaped.to_owned();
    report.findings[0].symbol = Some("symbol\twith\nnewline\\slash".to_owned());
    let validated = ValidatedSessionReport::new(report).unwrap();
    let mut output = Vec::new();

    write_tsv(validated.as_report(), &mut output).unwrap();
    let text = String::from_utf8(output).unwrap();

    assert!(text.contains("line\\twith\\nnewline\\\\slash"));
    assert!(text.contains("symbol\\twith\\nnewline\\\\slash"));
    assert!(!text.contains("operational"));
}

#[test]
fn tsv_escapes_every_remaining_ascii_control_and_del() {
    let mut report = report();
    report.findings[0].message = "nul\0form\x0cvertical\x0bdel\x7f".to_owned();
    let validated = ValidatedSessionReport::new(report).unwrap();
    let output = String::from_utf8(tsv_bytes(&validated).unwrap()).unwrap();

    assert!(output.contains("nul\\x00form\\x0cvertical\\x0bdel\\x7f"));
    assert!(
        !output
            .bytes()
            .any(|byte| byte < 0x20 && byte != b'\t' && byte != b'\n')
    );
    assert!(!output.bytes().any(|byte| byte == 0x7f));
}

#[test]
fn tsv_reversibly_neutralizes_formula_leading_bytes() {
    for (input, expected) in [
        ("=1+1", "\\x3d1+1"),
        ("+1", "\\x2b1"),
        ("-1", "\\x2d1"),
        ("@SUM(A1)", "\\x40SUM(A1)"),
    ] {
        let mut report = report();
        report.findings[0].message = input.to_owned();
        let validated = ValidatedSessionReport::new(report).unwrap();
        let output = String::from_utf8(tsv_bytes(&validated).unwrap()).unwrap();
        let message = output.lines().nth(1).unwrap().split('\t').nth(10).unwrap();

        assert_eq!(message, expected);
    }
}

#[test]
fn json_limit_does_not_block_a_tiny_tsv_projection() {
    let mut report = report();
    let content = "x".repeat(1_048_576);
    let digest = format!("{:x}", Sha256::digest(content.as_bytes()));
    for index in 0..64 {
        report
            .evidence
            .push(diagnostic_triage_contracts::model::Evidence {
                evidence_id: format!("019f7e95-0000-7000-8000-0000000002{index:02}")
                    .parse()
                    .unwrap(),
                retained_bytes: 1_048_576,
                observed_bytes: 1_048_576,
                limit_bytes: 1_048_576,
                sha256: digest.parse().unwrap(),
                content: Some(content.clone()),
                ..report.evidence[0].clone()
            });
    }
    let validated = ValidatedSessionReport::new(report).unwrap();
    let mut json_output = Vec::new();
    let error = CanonicalJsonReporter
        .write_report(&validated, &mut json_output)
        .unwrap_err();
    assert!(matches!(
        error,
        ReporterError::OutputTooLarge {
            format: ReportFormat::Json,
            max: MAX_REPORT_OUTPUT_BYTES,
        }
    ));
    assert!(json_output.is_empty());
    let output = tsv_bytes(&validated).unwrap();
    assert!(output.len() < 1024 * 1024);
}

#[test]
fn invalid_report_writes_no_operational_diagnostics_to_the_report_writer() {
    let mut report = report();
    report.verdict = diagnostic_triage_contracts::model::Verdict::Pass;
    let mut output = Vec::new();

    assert!(write_canonical_json(&report, &mut output).is_err());
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

fn assert_prefix_on_io_failure(
    format: ReportFormat,
    expected: &[u8],
    write: impl FnOnce(&mut FailAfter) -> Result<(), ReporterError>,
) {
    let limit = expected.len() / 2;
    let mut writer = FailAfter {
        accepted: Vec::new(),
        limit,
    };
    let error = write(&mut writer).unwrap_err();

    assert!(matches!(error, ReporterError::Io { format: actual, .. } if actual == format));
    assert_eq!(writer.accepted, expected[..limit]);
}

#[test]
fn writer_helpers_report_io_failure_after_an_accepted_prefix() {
    let report = report();
    let validated = ValidatedSessionReport::new(report.clone()).unwrap();
    let json = canonical_json_bytes(&validated).unwrap();
    let tsv = tsv_bytes(&validated).unwrap();
    let github_annotations = github_annotations_bytes(&validated).unwrap();

    assert_prefix_on_io_failure(ReportFormat::Json, &json, |writer| {
        write_canonical_json(&report, writer)
    });
    assert_prefix_on_io_failure(ReportFormat::Tsv, &tsv, |writer| write_tsv(&report, writer));
    assert_prefix_on_io_failure(ReportFormat::Json, &json, |writer| {
        CanonicalJsonReporter.write_report(&validated, writer)
    });
    assert_prefix_on_io_failure(ReportFormat::Tsv, &tsv, |writer| {
        TsvReporter.write_report(&validated, writer)
    });
    assert_prefix_on_io_failure(
        ReportFormat::GitHubAnnotations,
        &github_annotations,
        |writer| write_github_annotations(&report, writer),
    );
    assert_prefix_on_io_failure(
        ReportFormat::GitHubAnnotations,
        &github_annotations,
        |writer| GitHubAnnotationReporter.write_report(&validated, writer),
    );
}
