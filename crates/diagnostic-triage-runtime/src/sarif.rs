//! Deterministic SARIF 2.1.0 projection for validated session reports.

use std::{collections::BTreeMap, io::Write};

use diagnostic_triage_contracts::{
    model::{
        Decision, DecisionAction, Execution, ExecutionStatus, Finding, Location, SessionReport,
        Severity, VerificationAttribution, Waiver,
    },
    validate_report,
};
use serde::Serialize;

use crate::reporters::{
    BoundedBuffer, MAX_REPORT_OUTPUT_BYTES, ReportFormat, Reporter, ReporterError,
    ValidatedSessionReport, write_encoded,
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

const SARIF_SCHEMA: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";

/// A SARIF 2.1.0 reporter for external diagnostic consumers.
#[allow(
    clippy::module_name_repetitions,
    reason = "the public name distinguishes this implementation of Reporter"
)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SarifReporter;

impl Reporter for SarifReporter {
    fn write_report(
        &self,
        report: &ValidatedSessionReport,
        writer: &mut dyn Write,
    ) -> Result<(), ReporterError> {
        let bytes = sarif_bytes(report)?;
        write_encoded(ReportFormat::Sarif, &bytes, writer)
    }
}

/// Validate and write one deterministic SARIF 2.1.0 log.
///
/// Validation and bounded encoding complete before the first write. A writer
/// I/O failure can still occur after that writer accepted a prefix.
///
/// # Errors
///
/// Returns [`ReporterError`] when validation, projection, bounded encoding, or
/// the intended write fails.
pub fn write_sarif<W: Write + ?Sized>(
    report: &SessionReport,
    writer: &mut W,
) -> Result<(), ReporterError> {
    validate_report(report).map_err(ReporterError::Contract)?;
    let bytes = encode_sarif(report, MAX_REPORT_OUTPUT_BYTES)?;
    write_encoded(ReportFormat::Sarif, &bytes, writer)
}

/// Encode a validated report as one complete bounded SARIF 2.1.0 buffer.
///
/// # Errors
///
/// Returns [`ReporterError`] when projection or bounded encoding fails.
pub fn sarif_bytes(report: &ValidatedSessionReport) -> Result<Vec<u8>, ReporterError> {
    encode_sarif(report.as_report(), MAX_REPORT_OUTPUT_BYTES)
}

fn encode_sarif(report: &SessionReport, limit: usize) -> Result<Vec<u8>, ReporterError> {
    let projection = SarifLog::new(report)?;
    let mut output = BoundedBuffer::new(limit);
    match serde_json::to_writer(&mut output, &projection) {
        Ok(()) => Ok(output.bytes),
        Err(_source) if output.exceeded => Err(ReporterError::OutputTooLarge {
            format: ReportFormat::Sarif,
            max: limit,
        }),
        Err(source) => Err(ReporterError::Encoding {
            format: ReportFormat::Sarif,
            source,
        }),
    }
}

#[derive(Serialize)]
struct SarifLog<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: [SarifRun<'a>; 1],
}

impl<'a> SarifLog<'a> {
    fn new(report: &'a SessionReport) -> Result<Self, ReporterError> {
        let mut findings = report.findings.iter().collect::<Vec<_>>();
        findings.sort_by(|left, right| {
            left.fingerprint
                .cmp(&right.fingerprint)
                .then_with(|| left.finding_id.cmp(&right.finding_id))
        });
        let decisions = report
            .decisions
            .iter()
            .map(|decision| (decision.finding_id.as_str(), decision))
            .collect::<BTreeMap<_, _>>();

        let mut rules = BTreeMap::new();
        for finding in &findings {
            let id = sarif_rule_id(finding);
            rules
                .entry(id.clone())
                .or_insert_with(|| SarifRule::new(id, finding));
        }
        let rule_indexes = rules
            .keys()
            .enumerate()
            .map(|(index, id)| (id.clone(), index))
            .collect::<BTreeMap<_, _>>();

        let mut results = Vec::with_capacity(findings.len());
        for finding in findings {
            let Some(decision) = decisions.get(finding.finding_id.as_str()) else {
                return Err(ReporterError::MissingDecision {
                    finding_id: finding.finding_id.to_string(),
                });
            };
            let rule_id = sarif_rule_id(finding);
            let rule_index = rule_indexes[&rule_id];
            results.push(SarifResult::new(
                report, finding, decision, rule_id, rule_index,
            ));
        }

        let mut executions = report.executions.iter().collect::<Vec<_>>();
        executions.sort_by(|left, right| left.execution_id.cmp(&right.execution_id));
        let mut notification_descriptors = BTreeMap::new();
        for execution in &executions {
            if let Some(metadata) = notification_metadata(&execution.status) {
                notification_descriptors
                    .entry(metadata.id)
                    .or_insert_with(|| SarifNotificationDescriptor::new(metadata));
            }
        }
        let invocations = executions.into_iter().map(SarifInvocation::new).collect();
        let run = SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "diagnostic-triage",
                    version: &report.engine.version,
                    rules: rules.into_values().collect(),
                    notifications: notification_descriptors.into_values().collect(),
                    properties: SarifDriverProperties {
                        source_revision: report.engine.source_revision.as_str(),
                        contract_sha256: report.contract_sha256.as_str(),
                    },
                },
            },
            automation_details: SarifAutomationDetails {
                id: report.session_id.as_str(),
            },
            invocations,
            results,
            properties: SarifRunProperties {
                policy_digest: report.policy_digest.as_str(),
                verdict: &report.verdict,
            },
        };
        Ok(Self {
            schema: SARIF_SCHEMA,
            version: SARIF_VERSION,
            runs: [run],
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun<'a> {
    tool: SarifTool<'a>,
    automation_details: SarifAutomationDetails<'a>,
    invocations: Vec<SarifInvocation<'a>>,
    results: Vec<SarifResult<'a>>,
    properties: SarifRunProperties<'a>,
}

#[derive(Serialize)]
struct SarifTool<'a> {
    driver: SarifDriver<'a>,
}

#[derive(Serialize)]
struct SarifDriver<'a> {
    name: &'static str,
    version: &'a str,
    rules: Vec<SarifRule>,
    notifications: Vec<SarifNotificationDescriptor>,
    properties: SarifDriverProperties<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriverProperties<'a> {
    source_revision: &'a str,
    contract_sha256: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifAutomationDetails<'a> {
    id: &'a str,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage<String>,
}

impl SarifRule {
    fn new(id: String, finding: &Finding) -> Self {
        let name = finding
            .tool
            .rule_id
            .clone()
            .unwrap_or_else(|| taxonomy_name(finding));
        Self {
            id,
            short_description: SarifMessage { text: name.clone() },
            name,
        }
    }
}

#[derive(Clone, Copy)]
struct NotificationMetadata {
    id: &'static str,
    name: &'static str,
    description: &'static str,
}

#[derive(Serialize)]
struct SarifNotificationDescriptor {
    id: &'static str,
    name: &'static str,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage<&'static str>,
}

impl SarifNotificationDescriptor {
    const fn new(metadata: NotificationMetadata) -> Self {
        Self {
            id: metadata.id,
            name: metadata.name,
            short_description: SarifMessage {
                text: metadata.description,
            },
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult<'a> {
    rule_id: String,
    rule_index: usize,
    level: &'static str,
    message: SarifMessage<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    locations: Vec<SarifLocation<'a>>,
    partial_fingerprints: SarifPartialFingerprints<'a>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    suppressions: Vec<SarifSuppression<'a>>,
    properties: SarifResultProperties<'a>,
}

impl<'a> SarifResult<'a> {
    fn new(
        report: &'a SessionReport,
        finding: &'a Finding,
        decision: &'a Decision,
        rule_id: String,
        rule_index: usize,
    ) -> Self {
        let locations = if finding.location.is_some() || finding.symbol.is_some() {
            vec![SarifLocation::new(
                finding.location.as_ref(),
                finding.symbol.as_deref(),
            )]
        } else {
            Vec::new()
        };
        let suppressions = decision
            .waiver
            .as_ref()
            .map(|waiver| SarifSuppression {
                kind: "external",
                status: "accepted",
                justification: &waiver.reason,
            })
            .into_iter()
            .collect();
        Self {
            rule_id,
            rule_index,
            level: sarif_level(&finding.severity),
            message: SarifMessage {
                text: &finding.message,
            },
            locations,
            partial_fingerprints: SarifPartialFingerprints {
                diagnostic_triage_fingerprint: finding.fingerprint.as_str(),
            },
            suppressions,
            properties: SarifResultProperties::new(report, finding, decision),
        }
    }
}

#[derive(Serialize)]
struct SarifMessage<T> {
    text: T,
}

#[derive(Serialize)]
struct SarifPartialFingerprints<'a> {
    #[serde(rename = "diagnosticTriageFingerprint/v1")]
    diagnostic_triage_fingerprint: &'a str,
}

#[derive(Serialize)]
struct SarifSuppression<'a> {
    kind: &'static str,
    status: &'static str,
    justification: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResultProperties<'a> {
    finding_id: &'a str,
    tool_name: &'a str,
    tool_version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    native_rule_id: Option<&'a str>,
    language: &'a str,
    category: String,
    micro_category: String,
    lifecycle_state: &'a diagnostic_triage_contracts::model::FindingState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pre_report_state: Option<&'a diagnostic_triage_contracts::model::PreReportState>,
    observation_ids: Vec<&'a str>,
    evidence_ids: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix_candidate_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    verification_execution_ids: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed: Option<&'a str>,
    decision_id: &'a str,
    decision_action: &'a DecisionAction,
    evaluated_at: &'a str,
    policy_digest: &'a str,
    matched_rule_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    waiver: Option<SarifWaiverProperties<'a>>,
    session_verdict: &'a diagnostic_triage_contracts::model::Verdict,
}

impl<'a> SarifResultProperties<'a> {
    fn new(report: &'a SessionReport, finding: &'a Finding, decision: &'a Decision) -> Self {
        Self {
            finding_id: finding.finding_id.as_str(),
            tool_name: &finding.tool.name,
            tool_version: &finding.tool.version,
            native_rule_id: finding.tool.rule_id.as_deref(),
            language: finding.language.as_str(),
            category: enum_wire(&finding.classification.category),
            micro_category: enum_wire(&finding.classification.micro_category),
            lifecycle_state: &finding.state,
            pre_report_state: finding.pre_report_state.as_ref(),
            observation_ids: sorted_ids(&finding.observation_ids),
            evidence_ids: sorted_ids(&finding.evidence_ids),
            fix_candidate_id: finding
                .fix_candidate_id
                .as_ref()
                .map(diagnostic_triage_contracts::ObjectId::as_str),
            verification_execution_ids: finding
                .verification_execution_ids
                .as_deref()
                .map_or_else(Vec::new, sorted_ids),
            symbol: finding.symbol.as_deref(),
            expected: finding.expected.as_deref(),
            observed: finding.observed.as_deref(),
            decision_id: decision.decision_id.as_str(),
            decision_action: &decision.action,
            evaluated_at: &decision.evaluated_at,
            policy_digest: decision.policy_digest.as_str(),
            matched_rule_id: &decision.matched_rule_id,
            waiver: decision.waiver.as_ref().map(SarifWaiverProperties::new),
            session_verdict: &report.verdict,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifWaiverProperties<'a> {
    waived_action: &'a diagnostic_triage_contracts::model::WaivedAction,
    reason: &'a str,
    owner: &'a str,
    expires_at: &'a str,
}

impl<'a> SarifWaiverProperties<'a> {
    fn new(waiver: &'a Waiver) -> Self {
        Self {
            waived_action: &waiver.waived_action,
            reason: &waiver.reason,
            owner: &waiver.owner,
            expires_at: &waiver.expires_at,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    physical_location: Option<SarifPhysicalLocation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    logical_locations: Vec<SarifLogicalLocation<'a>>,
}

impl<'a> SarifLocation<'a> {
    fn new(location: Option<&Location>, symbol: Option<&'a str>) -> Self {
        Self {
            physical_location: location.map(|location| {
                let end = location.end.as_ref().unwrap_or(&location.start);
                SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: encode_repo_relative_uri(location.path.as_str()),
                    },
                    region: SarifRegion {
                        start_line: location.start.line,
                        start_column: location.start.column,
                        end_line: end.line,
                        end_column: end.column,
                    },
                }
            }),
            logical_locations: symbol
                .map(|name| SarifLogicalLocation { name })
                .into_iter()
                .collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
}

#[derive(Serialize)]
struct SarifLogicalLocation<'a> {
    name: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifInvocation<'a> {
    execution_successful: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tool_execution_notifications: Vec<SarifNotification<'a>>,
    properties: SarifInvocationProperties<'a>,
}

impl<'a> SarifInvocation<'a> {
    fn new(execution: &'a Execution) -> Self {
        let notification = notification_metadata(&execution.status);
        let tool_execution_notifications = notification
            .map(|metadata| SarifNotification {
                descriptor: SarifDescriptorReference { id: metadata.id },
                level: if execution.required {
                    "error"
                } else {
                    "warning"
                },
                message: SarifMessage {
                    text: execution
                        .message
                        .as_deref()
                        .expect("validated terminal execution has a message"),
                },
            })
            .into_iter()
            .collect();
        Self {
            execution_successful: notification.is_none(),
            exit_code: execution.exit_code.0,
            tool_execution_notifications,
            properties: SarifInvocationProperties::new(execution),
        }
    }
}

fn notification_metadata(status: &ExecutionStatus) -> Option<NotificationMetadata> {
    match status {
        ExecutionStatus::Complete => None,
        ExecutionStatus::Incomplete => Some(NotificationMetadata {
            id: "diagnostic-triage.execution.incomplete",
            name: "INCOMPLETE",
            description: "The diagnostic execution did not complete.",
        }),
        ExecutionStatus::Unsupported => Some(NotificationMetadata {
            id: "diagnostic-triage.execution.unsupported",
            name: "UNSUPPORTED",
            description: "The requested diagnostic execution is unsupported.",
        }),
    }
}

#[derive(Serialize)]
struct SarifNotification<'a> {
    descriptor: SarifDescriptorReference,
    level: &'static str,
    message: SarifMessage<&'a str>,
}

#[derive(Serialize)]
struct SarifDescriptorReference {
    id: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifInvocationProperties<'a> {
    execution_id: &'a str,
    adapter_id: &'a str,
    adapter_kind: &'a diagnostic_triage_contracts::model::AdapterKind,
    tool_name: &'a str,
    tool_version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    native_rule_id: Option<&'a str>,
    toolchain_fingerprint: &'a diagnostic_triage_contracts::model::ToolchainFingerprint,
    required: bool,
    status: &'a ExecutionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
    phases_ms: &'a diagnostic_triage_contracts::model::ExecutionPhases,
    performance: &'a diagnostic_triage_contracts::model::Performance,
    cache: &'a diagnostic_triage_contracts::model::Cache,
    retry: &'a diagnostic_triage_contracts::model::Retry,
    runner: &'a diagnostic_triage_contracts::model::Runner,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification: Option<SarifVerificationProperties<'a>>,
}

impl<'a> SarifInvocationProperties<'a> {
    fn new(execution: &'a Execution) -> Self {
        Self {
            execution_id: execution.execution_id.as_str(),
            adapter_id: execution.adapter_id.as_str(),
            adapter_kind: &execution.adapter_kind,
            tool_name: &execution.tool.name,
            tool_version: &execution.tool.version,
            native_rule_id: execution.tool.rule_id.as_deref(),
            toolchain_fingerprint: &execution.toolchain_fingerprint,
            required: execution.required,
            status: &execution.status,
            message: execution.message.as_deref(),
            phases_ms: &execution.phases_ms,
            performance: &execution.performance,
            cache: &execution.cache,
            retry: &execution.retry,
            runner: &execution.runner,
            verification: execution
                .verification
                .as_deref()
                .map(SarifVerificationProperties::new),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifVerificationProperties<'a> {
    fix_candidate_id: &'a str,
    patch_sha256: &'a str,
    base_snapshot_sha256: &'a str,
    base_snapshot_evidence_id: &'a str,
    target_fingerprints: Vec<&'a str>,
    result_evidence_id: &'a str,
}

impl<'a> SarifVerificationProperties<'a> {
    fn new(verification: &'a VerificationAttribution) -> Self {
        let mut target_fingerprints = verification
            .target_fingerprints
            .iter()
            .map(diagnostic_triage_contracts::Fingerprint::as_str)
            .collect::<Vec<_>>();
        target_fingerprints.sort_unstable();
        Self {
            fix_candidate_id: verification.fix_candidate_id.as_str(),
            patch_sha256: verification.patch_sha256.as_str(),
            base_snapshot_sha256: verification.base_snapshot_sha256.as_str(),
            base_snapshot_evidence_id: verification.base_snapshot_evidence_id.as_str(),
            target_fingerprints,
            result_evidence_id: verification.result_evidence_id.as_str(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRunProperties<'a> {
    policy_digest: &'a str,
    verdict: &'a diagnostic_triage_contracts::model::Verdict,
}

fn sarif_rule_id(finding: &Finding) -> String {
    let identity = finding
        .tool
        .rule_id
        .clone()
        .unwrap_or_else(|| taxonomy_name(finding));
    format!(
        "{}/{}",
        escape_rule_component(&finding.tool.name),
        escape_rule_component(&identity)
    )
}

fn taxonomy_name(finding: &Finding) -> String {
    format!(
        "{}.{}",
        enum_wire(&finding.classification.category),
        enum_wire(&finding.classification.micro_category)
    )
}

fn escape_rule_component(value: &str) -> String {
    percent_encode_utf8(value, false)
}

fn encode_repo_relative_uri(path: &str) -> String {
    percent_encode_utf8(path, true)
}

fn percent_encode_utf8(value: &str, preserve_slash: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~')
            || (preserve_slash && byte == b'/')
        {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

fn enum_wire<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .expect("contract enum serialization cannot fail")
        .trim_matches('"')
        .to_owned()
}

fn sorted_ids(values: &[diagnostic_triage_contracts::ObjectId]) -> Vec<&str> {
    let mut ids = values
        .iter()
        .map(diagnostic_triage_contracts::ObjectId::as_str)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

#[cfg(test)]
mod tests {
    use diagnostic_triage_contracts::validate_report_json;

    use super::{ReportFormat, ReporterError, encode_sarif};

    #[test]
    fn bounded_sarif_encoding_is_exact_and_all_or_error() {
        let report = validate_report_json(include_bytes!(
            "../../../tests/fixtures/v1/valid-report.json"
        ))
        .unwrap();
        let expected = encode_sarif(&report, usize::MAX).unwrap();

        assert_eq!(encode_sarif(&report, expected.len()).unwrap(), expected);
        assert!(matches!(
            encode_sarif(&report, expected.len() - 1),
            Err(ReporterError::OutputTooLarge {
                format: ReportFormat::Sarif,
                max
            }) if max == expected.len() - 1
        ));
    }
}
