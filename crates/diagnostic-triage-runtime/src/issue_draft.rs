//! Typed, deterministic bug issue-draft projection.

use std::io::Write;

use diagnostic_triage_contracts::{
    AdapterId, Fingerprint, Language, ObjectId, Sha256Digest,
    model::{
        AdapterKind, Decision, DecisionAction, Evidence, EvidenceSource, Execution,
        ExecutionStatus, Finding, Location, Position, SessionReport, Severity, Taxonomy, Tool,
        Verdict, WaivedAction,
    },
    validate_report,
};

use crate::{
    issue_draft_sanitize::{
        SanitizeError, SanitizedText, sanitize_external_text, sanitize_repository_path_text,
    },
    reporters::{
        BoundedBuffer, MAX_REPORT_OUTPUT_BYTES, ReportFormat, Reporter, ReporterError,
        ValidatedSessionReport, write_encoded,
    },
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// Stable schema identity for the JSON bug issue-draft projection.
pub const BUG_ISSUE_DRAFT_SCHEMA_VERSION: &str = "diagnostic-triage.bug-issue-draft/v1";
/// The only label proposed by the JSON bug issue-draft projection.
pub const BUG_ISSUE_LABEL: &str = "bug";
/// Hard byte limit for one complete bug issue-draft representation.
pub const MAX_ISSUE_DRAFT_OUTPUT_BYTES: usize = MAX_REPORT_OUTPUT_BYTES;
const MARKDOWN_HEADER: &[u8] = b"# Diagnostic Triage bug issue draft\n\n> Draft only: no issue was posted.\n\n## Typed projection\n\n";

#[cfg(test)]
std::thread_local! {
    static EXECUTION_PROJECTION_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

macro_rules! draft_type {
    ($visibility:vis $name:ident { $($field:ident: $kind:ty),+ $(,)? }) => {
        #[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
        $visibility struct $name { $( $field: $kind, )+ }
    };
}
macro_rules! record {
    ($name:ident { $($field:ident = $value:expr),+ $(,)? }) => {
        $name { $( $field: $value, )+ }
    };
}

draft_type!(pub(crate) BugIssueDraftV1 { schema_version: &'static str, labels: [&'static str; 1], session_id: ObjectId, contract_sha256: Sha256Digest, policy_digest: Sha256Digest, verdict: Verdict, findings: Vec<BugFindingV1>, decisions: Vec<BugDecisionV1>, evidence: Vec<BugEvidenceRefV1>, executions: Vec<BugExecutionV1> });
draft_type!(BugToolV1 { name: SanitizedText, version: SanitizedText, rule_id: Option<SanitizedText> });
draft_type!(BugLocationV1 { path: SanitizedText, start: Position, end: Option<Position> });
draft_type!(BugFindingV1 { finding_id: ObjectId, fingerprint: Fingerprint, observation_ids: Vec<ObjectId>, tool: BugToolV1, language: Language, severity: Severity, taxonomy: Taxonomy, message: SanitizedText, location: Option<BugLocationV1>, symbol: Option<SanitizedText>, expected: Option<SanitizedText>, observed: Option<SanitizedText>, evidence_ids: Vec<ObjectId> });
#[rustfmt::skip]
draft_type!(BugWaiverV1 { fingerprint: Fingerprint, waived_action: WaivedAction, reason: SanitizedText, owner: SanitizedText, expires_at: SanitizedText });
#[rustfmt::skip]
draft_type!(BugDecisionV1 { decision_id: ObjectId, finding_id: ObjectId, action: DecisionAction, evaluated_at: SanitizedText, matched_rule_id: SanitizedText, waiver: Option<BugWaiverV1> });
draft_type!(BugEvidenceRefV1 { evidence_id: ObjectId, execution_id: Option<ObjectId>, source: EvidenceSource, sha256: Sha256Digest, relative_path: Option<SanitizedText> });
draft_type!(BugExecutionV1 { execution_id: ObjectId, adapter_id: AdapterId, adapter_kind: AdapterKind, tool: BugToolV1, required: bool, status: ExecutionStatus, exit_code: Option<u8>, message: Option<SanitizedText> });

/// JSON reporter for deterministic, sanitized bug issue drafts.
#[derive(Clone, Copy, Debug, Default)]
pub struct BugIssueDraftJsonReporter;

/// Markdown reporter for the same typed bug issue-draft projection.
#[derive(Clone, Copy, Debug, Default)]
pub struct BugIssueDraftMarkdownReporter;

impl Reporter for BugIssueDraftJsonReporter {
    fn write_report(
        &self,
        report: &ValidatedSessionReport,
        writer: &mut dyn Write,
    ) -> Result<(), ReporterError> {
        let bytes = bug_issue_draft_json_bytes(report)?;
        write_encoded(ReportFormat::BugIssueDraftJson, &bytes, writer)
    }
}

impl Reporter for BugIssueDraftMarkdownReporter {
    fn write_report(
        &self,
        report: &ValidatedSessionReport,
        writer: &mut dyn Write,
    ) -> Result<(), ReporterError> {
        let bytes = bug_issue_draft_markdown_bytes(report)?;
        write_encoded(ReportFormat::BugIssueDraftMarkdown, &bytes, writer)
    }
}

/// Encode one validated report as a complete bounded JSON bug issue draft.
///
/// # Errors
/// Returns a typed projection, encoding, or output-limit error.
pub fn bug_issue_draft_json_bytes(
    report: &ValidatedSessionReport,
) -> Result<Vec<u8>, ReporterError> {
    let draft = BugIssueDraftV1::project(report)?;
    encode_json(&draft, MAX_ISSUE_DRAFT_OUTPUT_BYTES)
}

/// Encode the typed JSON projection as a deterministic Markdown draft.
///
/// # Errors
/// Returns a typed projection, encoding, or output-limit error.
pub fn bug_issue_draft_markdown_bytes(
    report: &ValidatedSessionReport,
) -> Result<Vec<u8>, ReporterError> {
    encode_markdown(
        &bug_issue_draft_json_bytes(report)?,
        MAX_ISSUE_DRAFT_OUTPUT_BYTES,
    )
}

/// Validate, fully encode, and then write one JSON bug issue draft.
///
/// # Errors
/// Returns a typed contract, projection, encoding, output-limit, or writer error.
pub fn write_bug_issue_draft_json<W: Write + ?Sized>(
    report: &SessionReport,
    writer: &mut W,
) -> Result<(), ReporterError> {
    validate_report(report).map_err(ReporterError::Contract)?;
    let draft = BugIssueDraftV1::project_report(report, ReportFormat::BugIssueDraftJson)?;
    let bytes = encode_json(&draft, MAX_ISSUE_DRAFT_OUTPUT_BYTES)?;
    write_encoded(ReportFormat::BugIssueDraftJson, &bytes, writer)
}

/// Validate, fully encode, and then write one Markdown bug issue draft.
///
/// # Errors
/// Returns a typed contract, projection, encoding, output-limit, or writer error.
pub fn write_bug_issue_draft_markdown<W: Write + ?Sized>(
    report: &SessionReport,
    writer: &mut W,
) -> Result<(), ReporterError> {
    validate_report(report).map_err(ReporterError::Contract)?;
    let draft = BugIssueDraftV1::project_report(report, ReportFormat::BugIssueDraftMarkdown)?;
    let json = encode_json(&draft, MAX_ISSUE_DRAFT_OUTPUT_BYTES)?;
    let bytes = encode_markdown(&json, MAX_ISSUE_DRAFT_OUTPUT_BYTES)?;
    write_encoded(ReportFormat::BugIssueDraftMarkdown, &bytes, writer)
}

fn output_too_large(max: usize) -> ReporterError {
    ReporterError::OutputTooLarge {
        format: ReportFormat::BugIssueDraftJson,
        max,
    }
}

fn markdown_too_large(max: usize) -> ReporterError {
    ReporterError::OutputTooLarge {
        format: ReportFormat::BugIssueDraftMarkdown,
        max,
    }
}

fn projection_too_large(format: ReportFormat, max: usize) -> ReporterError {
    ReporterError::OutputTooLarge { format, max }
}

struct ProjectionCounter {
    bytes: Option<usize>,
    limit: usize,
}

impl ProjectionCounter {
    const fn new(limit: usize) -> Self {
        Self {
            bytes: Some(0),
            limit,
        }
    }

    fn measure<T: serde::Serialize>(
        &mut self,
        value: &T,
        format: ReportFormat,
    ) -> Result<(), ReporterError> {
        // Sources: https://docs.rs/serde_json/1.0.150/serde_json/fn.to_writer.html
        // and https://doc.rust-lang.org/std/io/trait.Write.html.
        serde_json::to_writer(&mut *self, value)
            .map_err(|source| ReporterError::Encoding { format, source })?;
        self.counted(format).map(drop)
    }

    fn charge(&mut self, bytes: usize, format: ReportFormat) -> Result<(), ReporterError> {
        self.record(bytes);
        self.counted(format).map(drop)
    }

    fn record(&mut self, bytes: usize) {
        self.bytes = self
            .bytes
            .and_then(|total| total.checked_add(bytes))
            .filter(|total| *total <= self.limit);
    }

    fn counted(&self, format: ReportFormat) -> Result<usize, ReporterError> {
        self.bytes
            .ok_or_else(|| projection_too_large(format, self.limit))
    }
}

impl Write for ProjectionCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.record(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn measure_collection<T: serde::Serialize>(
    counter: &mut ProjectionCounter,
    format: ReportFormat,
    values: impl Iterator<Item = Result<T, SanitizeError>>,
) -> Result<(), ReporterError> {
    for (index, value) in values.enumerate() {
        counter.charge(usize::from(index > 0), format)?;
        counter.measure(
            &value.map_err(|_| projection_too_large(format, counter.limit))?,
            format,
        )?;
    }
    Ok(())
}

fn measure_project_report(
    report: &SessionReport,
    limit: usize,
    format: ReportFormat,
) -> Result<usize, ReporterError> {
    // Own at most one projected item; build aggregate Vecs only after this exact JSON count fits.
    let empty = record!(BugIssueDraftV1 { schema_version = BUG_ISSUE_DRAFT_SCHEMA_VERSION, labels = [BUG_ISSUE_LABEL], session_id = report.session_id.clone(), contract_sha256 = report.contract_sha256.clone(), policy_digest = report.policy_digest.clone(), verdict = report.verdict.clone(), findings = Vec::new(), decisions = Vec::new(), evidence = Vec::new(), executions = Vec::new() });
    let mut counter = ProjectionCounter::new(limit);
    counter.measure(&empty, format)?;
    counter.charge(1, format)?; // The encoder appends one newline.
    macro_rules! measure {
        ($values:expr) => {
            measure_collection(&mut counter, format, $values)?
        };
    }
    measure!(report.findings.iter().map(project_finding));
    measure!(report.decisions.iter().map(project_decision));
    measure!(report.evidence.iter().map(project_evidence));
    measure!(report.executions.iter().map(project_execution));
    counter.counted(format)
}

fn encode_json(draft: &BugIssueDraftV1, limit: usize) -> Result<Vec<u8>, ReporterError> {
    let mut output = BoundedBuffer::new(limit);
    match serde_json::to_writer(&mut output, draft) {
        Ok(()) => {
            output
                .write_all(b"\n")
                .map_err(|_| output_too_large(limit))?;
            Ok(output.bytes)
        }
        Err(_) if output.exceeded => Err(output_too_large(limit)),
        Err(source) => Err(ReporterError::Encoding {
            format: ReportFormat::BugIssueDraftJson,
            source,
        }),
    }
}

fn encode_markdown(json: &[u8], limit: usize) -> Result<Vec<u8>, ReporterError> {
    // Source: https://spec.commonmark.org/current/#indented-code-blocks — four-space-indented lines are literal code.
    let mut output = BoundedBuffer::new(limit);
    output
        .write_all(MARKDOWN_HEADER)
        .map_err(|_| markdown_too_large(limit))?;
    for line in json.split_inclusive(|byte| *byte == b'\n') {
        output
            .write_all(b"    ")
            .and_then(|()| output.write_all(line))
            .map_err(|_| markdown_too_large(limit))?;
    }
    Ok(output.bytes)
}

impl BugIssueDraftV1 {
    pub(crate) fn project(report: &ValidatedSessionReport) -> Result<Self, ReporterError> {
        Self::project_report(report.as_report(), ReportFormat::BugIssueDraftJson)
    }

    fn project_report(report: &SessionReport, format: ReportFormat) -> Result<Self, ReporterError> {
        measure_project_report(report, MAX_ISSUE_DRAFT_OUTPUT_BYTES, format)?;
        Self::project_unchecked(report)
            .map_err(|_| projection_too_large(format, MAX_ISSUE_DRAFT_OUTPUT_BYTES))
    }

    fn project_unchecked(report: &SessionReport) -> Result<Self, SanitizeError> {
        // Sources: schemas/v1/session-report.schema.json and https://doc.rust-lang.org/std/primitive.slice.html#method.sort_by.
        let mut findings = report
            .findings
            .iter()
            .map(project_finding)
            .collect::<Result<Vec<_>, _>>()?;
        let mut decisions = report
            .decisions
            .iter()
            .map(project_decision)
            .collect::<Result<Vec<_>, SanitizeError>>()?;
        let mut evidence = report
            .evidence
            .iter()
            .map(project_evidence)
            .collect::<Result<Vec<_>, SanitizeError>>()?;
        let mut executions = report
            .executions
            .iter()
            .map(project_execution)
            .collect::<Result<Vec<_>, SanitizeError>>()?;
        findings.sort_by(|a, b| {
            a.fingerprint
                .cmp(&b.fingerprint)
                .then(a.finding_id.cmp(&b.finding_id))
        });
        decisions.sort_by(|a, b| {
            a.finding_id
                .cmp(&b.finding_id)
                .then(a.decision_id.cmp(&b.decision_id))
        });
        evidence.sort_by(|a, b| a.evidence_id.cmp(&b.evidence_id));
        executions.sort_by(|a, b| a.execution_id.cmp(&b.execution_id));
        Ok(
            record!(BugIssueDraftV1 { schema_version = BUG_ISSUE_DRAFT_SCHEMA_VERSION, labels = [BUG_ISSUE_LABEL], session_id = report.session_id.clone(), contract_sha256 = report.contract_sha256.clone(), policy_digest = report.policy_digest.clone(), verdict = report.verdict.clone(), findings = findings, decisions = decisions, evidence = evidence, executions = executions }),
        )
    }
}

#[rustfmt::skip]
fn project_decision(value: &Decision) -> Result<BugDecisionV1, SanitizeError> { Ok(record!(BugDecisionV1 { decision_id = value.decision_id.clone(), finding_id = value.finding_id.clone(), action = value.action.clone(), evaluated_at = text(&value.evaluated_at)?, matched_rule_id = text(&value.matched_rule_id)?, waiver = value.waiver.as_ref().map(|waiver| Ok(record!(BugWaiverV1 { fingerprint = waiver.fingerprint.clone(), waived_action = waiver.waived_action.clone(), reason = text(&waiver.reason)?, owner = text(&waiver.owner)?, expires_at = text(&waiver.expires_at)? }))).transpose()? })) }

#[rustfmt::skip]
fn project_evidence(value: &Evidence) -> Result<BugEvidenceRefV1, SanitizeError> { Ok(record!(BugEvidenceRefV1 { evidence_id = value.evidence_id.clone(), execution_id = value.execution_id.clone(), source = value.source.clone(), sha256 = value.sha256.clone(), relative_path = value.relative_path.as_ref().map(|path| sanitize_repository_path_text(path, MAX_REPORT_OUTPUT_BYTES)).transpose()? })) }

#[rustfmt::skip]
fn project_execution(value: &Execution) -> Result<BugExecutionV1, SanitizeError> {
    #[cfg(test)]
    EXECUTION_PROJECTION_CALLS.with(|calls| calls.set(calls.get() + 1));
    Ok(record!(BugExecutionV1 { execution_id = value.execution_id.clone(), adapter_id = value.adapter_id.clone(), adapter_kind = value.adapter_kind.clone(), tool = project_tool(&value.tool)?, required = value.required, status = value.status.clone(), exit_code = value.exit_code.0, message = optional_text(value.message.as_deref())? }))
}

fn project_finding(value: &Finding) -> Result<BugFindingV1, SanitizeError> {
    Ok(
        record!(BugFindingV1 { finding_id = value.finding_id.clone(), fingerprint = value.fingerprint.clone(), observation_ids = sorted_ids(&value.observation_ids), tool = project_tool(&value.tool)?, language = value.language.clone(), severity = value.severity.clone(), taxonomy = value.classification.clone(), message = text(&value.message)?, location = value.location.as_ref().map(project_location).transpose()?, symbol = optional_text(value.symbol.as_deref())?, expected = optional_text(value.expected.as_deref())?, observed = optional_text(value.observed.as_deref())?, evidence_ids = sorted_ids(&value.evidence_ids) }),
    )
}

fn project_location(value: &Location) -> Result<BugLocationV1, SanitizeError> {
    Ok(
        record!(BugLocationV1 { path = sanitize_repository_path_text(&value.path, MAX_REPORT_OUTPUT_BYTES)?, start = value.start.clone(), end = value.end.clone() }),
    )
}

fn project_tool(value: &Tool) -> Result<BugToolV1, SanitizeError> {
    Ok(
        record!(BugToolV1 { name = text(&value.name)?, version = text(&value.version)?, rule_id = optional_text(value.rule_id.as_deref())? }),
    )
}

fn text(value: &str) -> Result<SanitizedText, SanitizeError> {
    sanitize_external_text(value, MAX_REPORT_OUTPUT_BYTES)
}

fn optional_text(value: Option<&str>) -> Result<Option<SanitizedText>, SanitizeError> {
    value.map(text).transpose()
}

fn sorted_ids(value: &[ObjectId]) -> Vec<ObjectId> {
    let mut value = value.to_vec();
    value.sort();
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use diagnostic_triage_contracts::model::{DecisionAction, ExecutionStatus, SessionReport};
    use std::io;

    const VALID: &[u8] = include_bytes!("../../../tests/fixtures/v1/valid-report.json");
    const UNSUPPORTED: &[u8] =
        include_bytes!("../../../tests/fixtures/v1/valid-unsupported-report.json");
    const VERIFIED: &[u8] = include_bytes!("../../../tests/fixtures/v1/valid-verified-report.json");
    fn report(bytes: &[u8]) -> SessionReport {
        ValidatedSessionReport::from_json(bytes)
            .unwrap()
            .into_report()
    }
    fn project(report: SessionReport) -> BugIssueDraftV1 {
        BugIssueDraftV1::project(&ValidatedSessionReport::new(report).unwrap()).unwrap()
    }

    #[test]
    fn projects_all_verdicts_and_omits_unlisted_material() {
        let mut pass = report(VALID);
        pass.decisions[0].action = DecisionAction::Waive;
        pass.decisions[0].waiver = Some(diagnostic_triage_contracts::model::Waiver {
            fingerprint: pass.findings[0].fingerprint.clone(),
            waived_action: WaivedAction::Block,
            reason: "token=hidden".into(),
            owner: "maintainers".into(),
            expires_at: "2026-08-20T00:00:00Z".into(),
        });
        pass.verdict = Verdict::Pass;
        let mut incomplete = report(UNSUPPORTED);
        incomplete.executions[0].status = ExecutionStatus::Incomplete;
        incomplete.verdict = Verdict::Incomplete;
        assert_eq!(project(report(VALID)).verdict, Verdict::PolicyFail);
        assert_eq!(project(incomplete).verdict, Verdict::Incomplete);
        assert_eq!(project(report(UNSUPPORTED)).verdict, Verdict::Unsupported);
        pass.observations[0].location = None;
        pass.findings[0].location = None;
        pass.observations[0].expected = Some("token=hidden".into());
        pass.findings[0].expected = pass.observations[0].expected.clone();
        pass.observations[0].observed = Some("observed".into());
        pass.findings[0].observed = pass.observations[0].observed.clone();
        let session_id = pass.session_id.clone();
        let evidence_sha256 = pass.evidence[0].sha256.clone();
        let draft = project(pass);
        let debug = format!("{draft:?}");
        assert_eq!(draft.session_id, session_id);
        assert_eq!(draft.verdict, Verdict::Pass);
        assert!(draft.findings[0].location.is_none());
        let finding = &draft.findings[0];
        let expected = finding.expected.as_ref().unwrap().as_str();
        assert_eq!(expected, "token=[REDACTED_SECRET]");
        assert_eq!(finding.observed.as_ref().unwrap().as_str(), "observed");
        assert_eq!(finding.tool.rule_id.as_ref().unwrap().as_str(), "F821");
        assert_eq!(draft.evidence[0].sha256, evidence_sha256);
        let waiver = draft.decisions[0].waiver.as_ref().unwrap();
        assert_eq!(waiver.reason.as_str(), "token=[REDACTED_SECRET]");
        assert_eq!(draft.executions[0].status, ExecutionStatus::Complete);
        assert!(debug.contains("Type") && debug.contains("UnresolvedSymbol"));
        assert!(!debug.contains("content") && !debug.contains("runner"));
        let verified = format!("{:?}", project(report(VERIFIED)));
        assert!(!verified.contains("--- a/") && !verified.contains("tree_sha256"));
    }

    #[test]
    fn multiple_findings_are_permutation_stable() {
        let mut report = report(VALID);
        let mut finding = report.findings[0].clone();
        finding.finding_id = "019f7e95-0000-7000-8000-000000000120".parse().unwrap();
        finding.fingerprint = format!("dtfp1:{}", "a".repeat(64)).parse().unwrap();
        let mut decision = report.decisions[0].clone();
        decision.decision_id = "019f7e95-0000-7000-8000-000000000121".parse().unwrap();
        decision.finding_id = finding.finding_id.clone();
        report.findings.push(finding);
        report.decisions.push(decision);
        let expected = project(report.clone());
        let expected_markdown =
            bug_issue_draft_markdown_bytes(&ValidatedSessionReport::new(report.clone()).unwrap())
                .unwrap();
        report.findings.reverse();
        report.decisions.reverse();
        assert_eq!(
            bug_issue_draft_markdown_bytes(&ValidatedSessionReport::new(report.clone()).unwrap())
                .unwrap(),
            expected_markdown
        );
        assert_eq!(project(report), expected);
    }

    struct PrefixWriter(Vec<u8>);

    impl Write for PrefixWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                self.0.push(bytes[0]);
                Ok(1)
            } else {
                Err(io::Error::other("injected writer failure"))
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn json_matches_golden_and_omits_forbidden_material() {
        let report = ValidatedSessionReport::from_json(VALID).unwrap();
        let bytes = bug_issue_draft_json_bytes(&report).unwrap();
        assert_eq!(
            bytes,
            include_bytes!("../tests/golden/valid-report.issue.json")
        );
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["schema_version"], BUG_ISSUE_DRAFT_SCHEMA_VERSION);
        assert_eq!(value["labels"], serde_json::json!([BUG_ISSUE_LABEL]));
        let text = String::from_utf8(bytes).unwrap();
        for forbidden in [
            "\"content\"",
            "environment",
            "/Users/",
            "posting",
            "api.github",
        ] {
            assert!(!text.contains(forbidden), "leaked {forbidden}");
        }
    }

    #[test]
    fn exact_limit_succeeds_and_one_byte_over_is_typed() {
        let report = ValidatedSessionReport::from_json(VALID).unwrap();
        let draft = BugIssueDraftV1::project(&report).unwrap();
        let bytes = encode_json(&draft, MAX_ISSUE_DRAFT_OUTPUT_BYTES).unwrap();
        assert_eq!(encode_json(&draft, bytes.len()).unwrap(), bytes);
        let limit = bytes.len() - 1;
        assert!(
            matches!(encode_json(&draft, limit), Err(ReporterError::OutputTooLarge { format: ReportFormat::BugIssueDraftJson, max }) if max == limit)
        );
    }

    #[test]
    fn projection_preflight_counts_aggregate_expansion_before_collection() {
        let mut input = report(VALID);
        for suffix in 0x190..=0x191 {
            let mut execution = input.executions[0].clone();
            execution.execution_id = format!("019f7e95-0000-7000-8000-{suffix:012x}")
                .parse()
                .unwrap();
            execution.message = Some("\0".repeat(64));
            input.executions.push(execution);
        }
        let report = ValidatedSessionReport::new(input).unwrap();
        let draft = BugIssueDraftV1::project_unchecked(report.as_report()).unwrap();
        let exact = encode_json(&draft, MAX_ISSUE_DRAFT_OUTPUT_BYTES)
            .unwrap()
            .len();
        assert_eq!(
            measure_project_report(report.as_report(), exact, ReportFormat::BugIssueDraftJson)
                .unwrap(),
            exact
        );
        let mut prefix = report.as_report().clone();
        prefix.executions.truncate(2);
        let second_execution_end =
            measure_project_report(&prefix, usize::MAX, ReportFormat::BugIssueDraftJson).unwrap();
        EXECUTION_PROJECTION_CALLS.with(|calls| calls.set(0));
        assert!(matches!(
            measure_project_report(
                report.as_report(),
                second_execution_end - 1,
                ReportFormat::BugIssueDraftJson
            ),
            Err(ReporterError::OutputTooLarge { format: ReportFormat::BugIssueDraftJson, max }) if max == second_execution_end - 1
        ));
        EXECUTION_PROJECTION_CALLS.with(|calls| assert_eq!(calls.get(), 2));
    }

    #[test]
    fn bytes_are_stable_when_evidence_order_changes() {
        let mut report = report(VERIFIED);
        let expected =
            bug_issue_draft_json_bytes(&ValidatedSessionReport::new(report.clone()).unwrap())
                .unwrap();
        report.evidence.reverse();
        assert_eq!(
            bug_issue_draft_json_bytes(&ValidatedSessionReport::new(report).unwrap()).unwrap(),
            expected
        );
    }

    #[test]
    fn invalid_input_writes_nothing_and_writer_failure_keeps_prefix() {
        let mut invalid = report(VALID);
        invalid.decisions.clear();
        let mut output = Vec::new();
        assert!(matches!(
            write_bug_issue_draft_json(&invalid, &mut output),
            Err(ReporterError::Contract(_))
        ));
        assert!(output.is_empty());
        let mut writer = PrefixWriter(Vec::new());
        let error = write_bug_issue_draft_json(&report(VALID), &mut writer).unwrap_err();
        assert!(matches!(
            error,
            ReporterError::Io {
                format: ReportFormat::BugIssueDraftJson,
                ..
            }
        ));
        assert_eq!(writer.0.len(), 1);
    }

    #[test]
    fn markdown_matches_golden_and_embeds_the_same_projection() {
        let report = ValidatedSessionReport::from_json(VALID).unwrap();
        let json = bug_issue_draft_json_bytes(&report).unwrap();
        let markdown = bug_issue_draft_markdown_bytes(&report).unwrap();
        assert_eq!(
            markdown,
            include_bytes!("../tests/golden/valid-report.issue.md")
        );
        assert_eq!(&markdown[MARKDOWN_HEADER.len() + 4..], json);
        assert!(
            MARKDOWN_HEADER
                .windows(19)
                .any(|part| part == b"no issue was posted")
        );
    }

    #[test]
    fn markdown_isolates_unicode_control_secret_path_and_delimiters() {
        let mut report = report(VALID);
        let payload = "日本語 **bold** `code` token=ghp_abcdefghijklmnopqrst /Users/st\n\u{202e}";
        report.observations[0].message = payload.into();
        report.findings[0].message = payload.into();
        report.observations[0].location = None;
        report.findings[0].location = None;
        let validated = ValidatedSessionReport::new(report).unwrap();
        let markdown =
            String::from_utf8(bug_issue_draft_markdown_bytes(&validated).unwrap()).unwrap();
        for expected in [
            "日本語",
            "[REDACTED_SECRET]",
            "[REDACTED_PATH]",
            "[CONTROL-U+000A]",
            "[BIDI-U+202E]",
            "\"location\":null",
        ] {
            assert!(markdown.contains(expected), "missing {expected}");
        }
        assert!(!markdown.contains("ghp_abcdefghijklmnopqrst") && !markdown.contains("/Users/st"));
        assert!(
            markdown[MARKDOWN_HEADER.len()..]
                .lines()
                .all(|line| line.starts_with("    "))
        );
    }

    #[test]
    fn markdown_represents_every_verdict_without_inference() {
        let mut pass = report(VALID);
        pass.decisions[0].action = DecisionAction::Warn;
        pass.verdict = Verdict::Pass;
        let mut incomplete = report(UNSUPPORTED);
        incomplete.executions[0].status = ExecutionStatus::Incomplete;
        incomplete.verdict = Verdict::Incomplete;
        for (report, verdict) in [
            (pass, "PASS"),
            (report(VALID), "POLICY_FAIL"),
            (incomplete, "INCOMPLETE"),
            (report(UNSUPPORTED), "UNSUPPORTED"),
        ] {
            let report = ValidatedSessionReport::new(report).unwrap();
            let markdown =
                String::from_utf8(bug_issue_draft_markdown_bytes(&report).unwrap()).unwrap();
            assert!(markdown.contains(&format!("\"verdict\":\"{verdict}\"")));
        }
    }

    #[test]
    fn markdown_limit_and_writer_boundaries_are_typed() {
        let validated = ValidatedSessionReport::from_json(VALID).unwrap();
        let json = bug_issue_draft_json_bytes(&validated).unwrap();
        let bytes = encode_markdown(&json, MAX_ISSUE_DRAFT_OUTPUT_BYTES).unwrap();
        assert_eq!(encode_markdown(&json, bytes.len()).unwrap(), bytes);
        let limit = bytes.len() - 1;
        assert!(
            matches!(encode_markdown(&json, limit), Err(ReporterError::OutputTooLarge { format: ReportFormat::BugIssueDraftMarkdown, max }) if max == limit)
        );
        let mut invalid = report(VALID);
        invalid.decisions.clear();
        let mut output = Vec::new();
        assert!(matches!(
            write_bug_issue_draft_markdown(&invalid, &mut output),
            Err(ReporterError::Contract(_))
        ));
        assert!(output.is_empty());
        let mut writer = PrefixWriter(Vec::new());
        let error = write_bug_issue_draft_markdown(&report(VALID), &mut writer).unwrap_err();
        assert!(matches!(
            error,
            ReporterError::Io {
                format: ReportFormat::BugIssueDraftMarkdown,
                ..
            }
        ));
        assert_eq!(writer.0.len(), 1);
    }
}
