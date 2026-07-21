//! Bounded, deterministic reporters for validated v1 session reports.
//!
//! The owned-byte encoders are the all-or-error boundary for validation and
//! encoding. Writer helpers encode completely before their first write, but an
//! arbitrary [`Write`] implementation can still accept a prefix before
//! returning an I/O error; destination-level atomicity is the caller's concern.

use std::{collections::BTreeMap, fmt, io, io::Write};

use diagnostic_triage_contracts::model::{
    Decision, Evidence, Execution, Finding, FixCandidate, Observation, SessionReport,
    VerificationAttribution,
};
use diagnostic_triage_contracts::{
    ContractError, MAX_REPORT_BYTES, validate_report, validate_report_json,
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// The hard byte limit shared by all runtime report formats.
pub const MAX_REPORT_OUTPUT_BYTES: usize = MAX_REPORT_BYTES;

/// The fixed TSV projection header, in wire order.
///
/// Columns are `session_id`, `finding_id`, `fingerprint`, `tool_name`,
/// `tool_version`, `rule_id`, `language`, `severity`, `category`,
/// `micro_category`, `message`, `path`, `start_line`, `start_column`,
/// `end_line`, `end_column`, `symbol`, `finding_state`, `pre_report_state`,
/// `decision_id`, `action`, `evaluated_at`, `policy_digest`, `matched_rule_id`,
/// and `verdict`. Field values escape backslash, tab, line feed, and carriage
/// return as `\\`, `\t`, `\n`, and `\r`, respectively. Other ASCII controls
/// and DEL use the reversible `\xNN` form. To prevent spreadsheet formula
/// interpretation, `=`, `+`, `-`, and `@` also use `\xNN` when they are the
/// first byte of a cell.
pub const TSV_HEADER: &str = "session_id\tfinding_id\tfingerprint\ttool_name\ttool_version\trule_id\tlanguage\tseverity\tcategory\tmicro_category\tmessage\tpath\tstart_line\tstart_column\tend_line\tend_column\tsymbol\tfinding_state\tpre_report_state\tdecision_id\taction\tevaluated_at\tpolicy_digest\tmatched_rule_id\tverdict";

/// A report format implemented by the runtime reporter boundary.
pub trait Reporter {
    /// Encode a complete report, then attempt to write its owned bytes.
    ///
    /// Implementations in this crate do not call `writer` when bounded
    /// encoding fails. If `writer` itself fails, it may already have accepted
    /// a prefix because [`Write`] has no rollback contract.
    ///
    /// # Errors
    ///
    /// Returns [`ReporterError`] when validation, bounded encoding, or the
    /// intended writer fails.
    fn write_report(
        &self,
        report: &ValidatedSessionReport,
        writer: &mut dyn Write,
    ) -> Result<(), ReporterError>;
}

/// A report that has passed the v1 report contracts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSessionReport(SessionReport);

impl ValidatedSessionReport {
    /// Validate an already decoded report before handing it to a reporter.
    ///
    /// # Errors
    ///
    /// Returns [`ReporterError::Contract`] when the report violates a v1
    /// invariant.
    pub fn new(report: SessionReport) -> Result<Self, ReporterError> {
        validate_report(&report).map_err(ReporterError::Contract)?;
        Ok(Self(report))
    }

    /// Decode and validate one JSON report through the shared contract parser.
    ///
    /// # Errors
    ///
    /// Returns [`ReporterError::Contract`] when the input is malformed or
    /// violates a v1 invariant.
    pub fn from_json(input: &[u8]) -> Result<Self, ReporterError> {
        let report = validate_report_json(input).map_err(ReporterError::Contract)?;
        Ok(Self(report))
    }

    /// Borrow the validated contract report without changing it.
    #[must_use]
    pub const fn as_report(&self) -> &SessionReport {
        &self.0
    }

    /// Consume the wrapper and return the validated contract report.
    #[must_use]
    pub fn into_report(self) -> SessionReport {
        self.0
    }
}

impl AsRef<SessionReport> for ValidatedSessionReport {
    fn as_ref(&self) -> &SessionReport {
        self.as_report()
    }
}

impl TryFrom<SessionReport> for ValidatedSessionReport {
    type Error = ReporterError;

    fn try_from(report: SessionReport) -> Result<Self, Self::Error> {
        Self::new(report)
    }
}

/// Output formats supported by this reporter slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportFormat {
    /// Compact canonical JSON representing the complete v1 report.
    Json,
    /// A SARIF 2.1.0 projection for external diagnostic consumers.
    Sarif,
    /// A tab-separated finding/decision projection.
    Tsv,
    /// GitHub workflow-command annotations for policy decisions.
    GitHubAnnotations,
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Json => "JSON",
            Self::Sarif => "SARIF",
            Self::Tsv => "TSV",
            Self::GitHubAnnotations => "GitHub annotations",
        })
    }
}

/// Errors raised before or during report output.
#[derive(Debug, Error)]
pub enum ReporterError {
    /// The input was not a semantically valid v1 report.
    #[error("report contract validation failed")]
    Contract(#[source] ContractError),
    /// The encoded report would exceed the hard report output limit.
    #[error("{format} report exceeds the {max}-byte output limit")]
    OutputTooLarge { format: ReportFormat, max: usize },
    /// A valid report did not contain the decision required by its contract.
    #[error("finding {finding_id} has no policy decision")]
    MissingDecision { finding_id: String },
    /// The report could not be encoded.
    #[error("{format} report encoding failed")]
    Encoding {
        format: ReportFormat,
        #[source]
        source: serde_json::Error,
    },
    /// The intended output writer rejected the report bytes.
    ///
    /// The writer may have accepted a prefix before returning this error.
    #[error("writing {format} report failed")]
    Io {
        format: ReportFormat,
        #[source]
        source: io::Error,
    },
}

/// The complete canonical JSON reporter.
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalJsonReporter;

impl Reporter for CanonicalJsonReporter {
    fn write_report(
        &self,
        report: &ValidatedSessionReport,
        writer: &mut dyn Write,
    ) -> Result<(), ReporterError> {
        let bytes = canonical_json_bytes(report)?;
        write_encoded(ReportFormat::Json, &bytes, writer)
    }
}

/// The fixed-schema TSV finding/decision projection reporter.
#[derive(Clone, Copy, Debug, Default)]
pub struct TsvReporter;

impl Reporter for TsvReporter {
    fn write_report(
        &self,
        report: &ValidatedSessionReport,
        writer: &mut dyn Write,
    ) -> Result<(), ReporterError> {
        let bytes = tsv_bytes(report)?;
        write_encoded(ReportFormat::Tsv, &bytes, writer)
    }
}

/// Validate and write a canonical JSON report to `writer`.
///
/// Validation and bounded encoding finish before the first call to `writer`,
/// so those failures write no bytes. An I/O failure can occur after `writer`
/// accepted a prefix. Use [`canonical_json_bytes`] and a destination-specific
/// transactional commit when destination-level atomicity is required.
///
/// # Errors
///
/// Returns [`ReporterError`] when validation, bounded encoding, or the
/// intended writer fails.
pub fn write_canonical_json<W: Write + ?Sized>(
    report: &SessionReport,
    writer: &mut W,
) -> Result<(), ReporterError> {
    validate_report(report).map_err(ReporterError::Contract)?;
    let bytes = encode_json(report, MAX_REPORT_OUTPUT_BYTES)?;
    write_encoded(ReportFormat::Json, &bytes, writer)
}

/// Validate and write a deterministic TSV finding/decision projection.
///
/// Validation and bounded encoding finish before the first call to `writer`,
/// so those failures write no bytes. An I/O failure can occur after `writer`
/// accepted a prefix. Use [`tsv_bytes`] and a destination-specific
/// transactional commit when destination-level atomicity is required.
///
/// # Errors
///
/// Returns [`ReporterError`] when validation, bounded encoding, or the
/// intended writer fails.
pub fn write_tsv<W: Write + ?Sized>(
    report: &SessionReport,
    writer: &mut W,
) -> Result<(), ReporterError> {
    validate_report(report).map_err(ReporterError::Contract)?;
    let bytes = encode_tsv(report, MAX_REPORT_OUTPUT_BYTES)?;
    write_encoded(ReportFormat::Tsv, &bytes, writer)
}

/// Encode a validated report as bounded canonical JSON bytes.
///
/// This returns one complete owned buffer or an error and never exposes a
/// partial encoding.
///
/// # Errors
///
/// Returns [`ReporterError::OutputTooLarge`] when the encoded report exceeds
/// the hard output limit, or [`ReporterError::Encoding`] if serialization
/// fails.
pub fn canonical_json_bytes(report: &ValidatedSessionReport) -> Result<Vec<u8>, ReporterError> {
    encode_json(report.as_report(), MAX_REPORT_OUTPUT_BYTES)
}

/// Encode a validated report as bounded TSV bytes.
///
/// This returns one complete owned buffer or an error and never exposes a
/// partial encoding.
///
/// # Errors
///
/// Returns [`ReporterError::OutputTooLarge`] when the encoded report exceeds
/// the hard output limit, or another [`ReporterError`] for projection failure.
pub fn tsv_bytes(report: &ValidatedSessionReport) -> Result<Vec<u8>, ReporterError> {
    encode_tsv(report.as_report(), MAX_REPORT_OUTPUT_BYTES)
}

pub(crate) fn write_encoded<W: Write + ?Sized>(
    format: ReportFormat,
    bytes: &[u8],
    writer: &mut W,
) -> Result<(), ReporterError> {
    writer
        .write_all(bytes)
        .map_err(|source| ReporterError::Io { format, source })
}

fn encode_json(report: &SessionReport, limit: usize) -> Result<Vec<u8>, ReporterError> {
    let mut output = BoundedBuffer::new(limit);
    match serde_json::to_writer(&mut output, &CanonicalReport::new(report)) {
        Ok(()) => Ok(output.bytes),
        Err(_source) if output.exceeded => Err(ReporterError::OutputTooLarge {
            format: ReportFormat::Json,
            max: limit,
        }),
        Err(source) => Err(ReporterError::Encoding {
            format: ReportFormat::Json,
            source,
        }),
    }
}

fn encode_tsv(report: &SessionReport, limit: usize) -> Result<Vec<u8>, ReporterError> {
    let mut output = BoundedBuffer::new(limit);
    write_tsv_projection(report, &mut output).map_err(|error| match error {
        TsvProjectionError::MissingDecision { finding_id } => {
            ReporterError::MissingDecision { finding_id }
        }
        TsvProjectionError::Io(source) => map_tsv_io(source, &output),
    })?;
    Ok(output.bytes)
}

#[derive(Debug)]
enum TsvProjectionError {
    MissingDecision { finding_id: String },
    Io(io::Error),
}

fn write_tsv_projection<W: Write + ?Sized>(
    report: &SessionReport,
    output: &mut W,
) -> Result<(), TsvProjectionError> {
    write_tsv_header(output).map_err(TsvProjectionError::Io)?;

    let decisions = report
        .decisions
        .iter()
        .map(|decision| (decision.finding_id.as_str(), decision))
        .collect::<BTreeMap<_, _>>();
    let mut findings = report.findings.iter().collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        left.fingerprint
            .cmp(&right.fingerprint)
            .then_with(|| left.finding_id.cmp(&right.finding_id))
    });
    for finding in findings {
        let Some(decision) = decisions.get(finding.finding_id.as_str()) else {
            return Err(TsvProjectionError::MissingDecision {
                finding_id: finding.finding_id.to_string(),
            });
        };
        write_tsv_row(output, report, finding, decision).map_err(TsvProjectionError::Io)?;
    }
    Ok(())
}

fn map_tsv_io(source: io::Error, output: &BoundedBuffer) -> ReporterError {
    if output.exceeded {
        ReporterError::OutputTooLarge {
            format: ReportFormat::Tsv,
            max: output.limit,
        }
    } else {
        ReporterError::Io {
            format: ReportFormat::Tsv,
            source,
        }
    }
}

struct CanonicalReport<'a> {
    report: &'a SessionReport,
    observations: Vec<CanonicalObservation<'a>>,
    findings: Vec<CanonicalFinding<'a>>,
    decisions: Vec<&'a Decision>,
    evidence: Vec<&'a Evidence>,
    fix_candidates: Vec<CanonicalFixCandidate<'a>>,
    executions: Vec<CanonicalExecution<'a>>,
}

impl<'a> CanonicalReport<'a> {
    fn new(report: &'a SessionReport) -> Self {
        let mut observations = report.observations.iter().collect::<Vec<_>>();
        observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
        let mut findings = report.findings.iter().collect::<Vec<_>>();
        findings.sort_by(|left, right| {
            left.fingerprint
                .cmp(&right.fingerprint)
                .then_with(|| left.finding_id.cmp(&right.finding_id))
        });
        let mut decisions = report.decisions.iter().collect::<Vec<_>>();
        decisions.sort_by(|left, right| {
            left.finding_id
                .cmp(&right.finding_id)
                .then_with(|| left.decision_id.cmp(&right.decision_id))
        });
        let mut evidence = report.evidence.iter().collect::<Vec<_>>();
        evidence.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
        let mut fix_candidates = report.fix_candidates.iter().collect::<Vec<_>>();
        fix_candidates.sort_by(|left, right| left.fix_candidate_id.cmp(&right.fix_candidate_id));
        let mut executions = report.executions.iter().collect::<Vec<_>>();
        executions.sort_by(|left, right| left.execution_id.cmp(&right.execution_id));

        Self {
            report,
            observations: observations.into_iter().map(CanonicalObservation).collect(),
            findings: findings.into_iter().map(CanonicalFinding).collect(),
            decisions,
            evidence,
            fix_candidates: fix_candidates
                .into_iter()
                .map(CanonicalFixCandidate)
                .collect(),
            executions: executions.into_iter().map(CanonicalExecution).collect(),
        }
    }
}

impl Serialize for CanonicalReport<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let report = self.report;
        let mut state = serializer.serialize_struct("SessionReport", 12)?;
        state.serialize_field("schema_version", &report.schema_version)?;
        state.serialize_field("session_id", &report.session_id)?;
        state.serialize_field("engine", &report.engine)?;
        state.serialize_field("contract_sha256", &report.contract_sha256)?;
        state.serialize_field("policy_digest", &report.policy_digest)?;
        state.serialize_field("verdict", &report.verdict)?;
        state.serialize_field("observations", &self.observations)?;
        state.serialize_field("findings", &self.findings)?;
        state.serialize_field("decisions", &self.decisions)?;
        state.serialize_field("evidence", &self.evidence)?;
        state.serialize_field("fix_candidates", &self.fix_candidates)?;
        state.serialize_field("executions", &self.executions)?;
        state.end()
    }
}

struct SortedValues<'a, T>(&'a [T]);

impl<T: Ord + Serialize> Serialize for SortedValues<'_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut values = self.0.iter().collect::<Vec<_>>();
        values.sort_unstable();
        values.serialize(serializer)
    }
}

struct CanonicalObservation<'a>(&'a Observation);

impl Serialize for CanonicalObservation<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = self.0;
        let field_count = 8
            + usize::from(value.location.is_some())
            + usize::from(value.symbol.is_some())
            + usize::from(value.expected.is_some())
            + usize::from(value.observed.is_some());
        let mut state = serializer.serialize_struct("Observation", field_count)?;
        state.serialize_field("schema_version", &value.schema_version)?;
        state.serialize_field("observation_id", &value.observation_id)?;
        state.serialize_field("tool", &value.tool)?;
        state.serialize_field("language", &value.language)?;
        state.serialize_field("severity", &value.severity)?;
        state.serialize_field("origin", &value.origin)?;
        state.serialize_field("message", &value.message)?;
        if let Some(location) = &value.location {
            state.serialize_field("location", location)?;
        }
        if let Some(symbol) = &value.symbol {
            state.serialize_field("symbol", symbol)?;
        }
        if let Some(expected) = &value.expected {
            state.serialize_field("expected", expected)?;
        }
        if let Some(observed) = &value.observed {
            state.serialize_field("observed", observed)?;
        }
        state.serialize_field("evidence_ids", &SortedValues(&value.evidence_ids))?;
        state.end()
    }
}

struct CanonicalFinding<'a>(&'a Finding);

impl Serialize for CanonicalFinding<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = self.0;
        let field_count = 11
            + usize::from(value.location.is_some())
            + usize::from(value.symbol.is_some())
            + usize::from(value.expected.is_some())
            + usize::from(value.observed.is_some())
            + usize::from(value.pre_report_state.is_some())
            + usize::from(value.fix_candidate_id.is_some())
            + usize::from(value.verification_execution_ids.is_some());
        let mut state = serializer.serialize_struct("Finding", field_count)?;
        state.serialize_field("schema_version", &value.schema_version)?;
        state.serialize_field("finding_id", &value.finding_id)?;
        state.serialize_field("fingerprint", &value.fingerprint)?;
        state.serialize_field("observation_ids", &SortedValues(&value.observation_ids))?;
        state.serialize_field("tool", &value.tool)?;
        state.serialize_field("language", &value.language)?;
        state.serialize_field("severity", &value.severity)?;
        state.serialize_field("classification", &value.classification)?;
        state.serialize_field("message", &value.message)?;
        if let Some(location) = &value.location {
            state.serialize_field("location", location)?;
        }
        if let Some(symbol) = &value.symbol {
            state.serialize_field("symbol", symbol)?;
        }
        if let Some(expected) = &value.expected {
            state.serialize_field("expected", expected)?;
        }
        if let Some(observed) = &value.observed {
            state.serialize_field("observed", observed)?;
        }
        state.serialize_field("state", &value.state)?;
        if let Some(pre_report_state) = &value.pre_report_state {
            state.serialize_field("pre_report_state", pre_report_state)?;
        }
        state.serialize_field("evidence_ids", &SortedValues(&value.evidence_ids))?;
        if let Some(fix_candidate_id) = &value.fix_candidate_id {
            state.serialize_field("fix_candidate_id", fix_candidate_id)?;
        }
        if let Some(execution_ids) = &value.verification_execution_ids {
            state.serialize_field("verification_execution_ids", &SortedValues(execution_ids))?;
        }
        state.end()
    }
}

struct CanonicalFixCandidate<'a>(&'a FixCandidate);

impl Serialize for CanonicalFixCandidate<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = self.0;
        let mut state = serializer.serialize_struct("FixCandidate", 6)?;
        state.serialize_field("schema_version", &value.schema_version)?;
        state.serialize_field("fix_candidate_id", &value.fix_candidate_id)?;
        state.serialize_field("observation_ids", &SortedValues(&value.observation_ids))?;
        state.serialize_field("applicability", &value.applicability)?;
        state.serialize_field("tool_native", &value.tool_native)?;
        state.serialize_field("patch_evidence_id", &value.patch_evidence_id)?;
        state.end()
    }
}

struct CanonicalExecution<'a>(&'a Execution);

impl Serialize for CanonicalExecution<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = self.0;
        let field_count =
            14 + usize::from(value.message.is_some()) + usize::from(value.verification.is_some());
        let mut state = serializer.serialize_struct("Execution", field_count)?;
        state.serialize_field("schema_version", &value.schema_version)?;
        state.serialize_field("execution_id", &value.execution_id)?;
        state.serialize_field("adapter_id", &value.adapter_id)?;
        state.serialize_field("adapter_kind", &value.adapter_kind)?;
        state.serialize_field("tool", &value.tool)?;
        state.serialize_field("toolchain_fingerprint", &value.toolchain_fingerprint)?;
        state.serialize_field("required", &value.required)?;
        state.serialize_field("status", &value.status)?;
        state.serialize_field("exit_code", &value.exit_code)?;
        if let Some(message) = &value.message {
            state.serialize_field("message", message)?;
        }
        state.serialize_field("phases_ms", &value.phases_ms)?;
        state.serialize_field("performance", &value.performance)?;
        state.serialize_field("cache", &value.cache)?;
        state.serialize_field("retry", &value.retry)?;
        state.serialize_field("runner", &value.runner)?;
        if let Some(verification) = value.verification.as_deref() {
            state.serialize_field("verification", &CanonicalVerification(verification))?;
        }
        state.end()
    }
}

struct CanonicalVerification<'a>(&'a VerificationAttribution);

impl Serialize for CanonicalVerification<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = self.0;
        let mut state = serializer.serialize_struct("VerificationAttribution", 6)?;
        state.serialize_field("fix_candidate_id", &value.fix_candidate_id)?;
        state.serialize_field("patch_sha256", &value.patch_sha256)?;
        state.serialize_field("base_snapshot_sha256", &value.base_snapshot_sha256)?;
        state.serialize_field(
            "base_snapshot_evidence_id",
            &value.base_snapshot_evidence_id,
        )?;
        state.serialize_field(
            "target_fingerprints",
            &SortedValues(&value.target_fingerprints),
        )?;
        state.serialize_field("result_evidence_id", &value.result_evidence_id)?;
        state.end()
    }
}

fn write_tsv_header<W: Write + ?Sized>(output: &mut W) -> io::Result<()> {
    output.write_all(TSV_HEADER.as_bytes())?;
    output.write_all(b"\n")
}

fn write_tsv_row<W: Write + ?Sized>(
    output: &mut W,
    report: &SessionReport,
    finding: &diagnostic_triage_contracts::model::Finding,
    decision: &Decision,
) -> io::Result<()> {
    let (path, start_line, start_column, end_line, end_column) =
        finding.location.as_ref().map_or_else(
            || {
                (
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                )
            },
            |location| {
                (
                    location.path.to_string(),
                    location.start.line.to_string(),
                    location.start.column.to_string(),
                    location
                        .end
                        .as_ref()
                        .map_or_else(String::new, |position| position.line.to_string()),
                    location
                        .end
                        .as_ref()
                        .map_or_else(String::new, |position| position.column.to_string()),
                )
            },
        );
    let fields = [
        report.session_id.to_string(),
        finding.finding_id.to_string(),
        finding.fingerprint.to_string(),
        finding.tool.name.clone(),
        finding.tool.version.clone(),
        finding.tool.rule_id.clone().unwrap_or_default(),
        finding.language.to_string(),
        enum_wire(&finding.severity),
        enum_wire(&finding.classification.category),
        enum_wire(&finding.classification.micro_category),
        finding.message.clone(),
        path,
        start_line,
        start_column,
        end_line,
        end_column,
        finding.symbol.clone().unwrap_or_default(),
        enum_wire(&finding.state),
        finding
            .pre_report_state
            .as_ref()
            .map_or_else(String::new, enum_wire),
        decision.decision_id.to_string(),
        enum_wire(&decision.action),
        decision.evaluated_at.clone(),
        decision.policy_digest.to_string(),
        decision.matched_rule_id.clone(),
        enum_wire(&report.verdict),
    ];
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            output.write_all(b"\t")?;
        }
        write_tsv_field(output, field)?;
    }
    output.write_all(b"\n")
}

fn enum_wire<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .expect("contract enums and scalar serialization cannot fail")
        .trim_matches('"')
        .to_owned()
}

fn write_tsv_field<W: Write + ?Sized>(output: &mut W, value: &str) -> io::Result<()> {
    for (index, byte) in value.bytes().enumerate() {
        if index == 0 && matches!(byte, b'=' | b'+' | b'-' | b'@') {
            write_hex_escape(output, byte)?;
            continue;
        }
        match byte {
            b'\\' => output.write_all(b"\\\\")?,
            b'\t' => output.write_all(b"\\t")?,
            b'\n' => output.write_all(b"\\n")?,
            b'\r' => output.write_all(b"\\r")?,
            0x00..=0x1f | 0x7f => write_hex_escape(output, byte)?,
            byte => output.write_all(&[byte])?,
        }
    }
    Ok(())
}

fn write_hex_escape<W: Write + ?Sized>(output: &mut W, byte: u8) -> io::Result<()> {
    let hex = b"0123456789abcdef";
    output.write_all(&[
        b'\\',
        b'x',
        hex[usize::from(byte >> 4)],
        hex[usize::from(byte & 0x0f)],
    ])
}

pub(crate) struct BoundedBuffer {
    pub(crate) bytes: Vec<u8>,
    pub(crate) limit: usize,
    pub(crate) exceeded: bool,
}

impl BoundedBuffer {
    pub(crate) const fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next_len) = self.bytes.len().checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("report output byte count overflow"));
        };
        if next_len > self.limit {
            self.exceeded = true;
            return Err(io::Error::other(
                "report output exceeds the hard byte limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ReportFormat, ReporterError, TSV_HEADER, encode_json, encode_tsv};
    use diagnostic_triage_contracts::validate_report_json;
    use serde_json::json;

    #[test]
    fn bounded_json_encoding_stops_at_the_limit_with_a_typed_error() {
        let report = validate_report_json(include_bytes!(
            "../../../tests/fixtures/v1/valid-report.json"
        ))
        .unwrap();
        let error = encode_json(&report, 8).unwrap_err();
        assert!(matches!(
            error,
            ReporterError::OutputTooLarge {
                format: ReportFormat::Json,
                max: 8
            }
        ));
    }

    #[test]
    fn tsv_header_is_not_csv_named() {
        assert!(TSV_HEADER.contains('\t'));
        assert!(!TSV_HEADER.contains(','));
        assert!(
            serde_json::to_string(&json!(TSV_HEADER))
                .unwrap()
                .contains("\\t")
        );
    }

    #[test]
    fn bounded_tsv_encoding_rejects_overflow() {
        let report = validate_report_json(include_bytes!(
            "../../../tests/fixtures/v1/valid-report.json"
        ))
        .unwrap();
        let error = encode_tsv(&report, TSV_HEADER.len()).unwrap_err();
        assert!(matches!(
            error,
            ReporterError::OutputTooLarge {
                format: ReportFormat::Tsv,
                max
            } if max == TSV_HEADER.len()
        ));
    }

    #[test]
    fn bounded_tsv_encoding_accepts_the_exact_escape_heavy_boundary() {
        let mut report = validate_report_json(include_bytes!(
            "../../../tests/fixtures/v1/valid-report.json"
        ))
        .unwrap();
        report.findings[0].message =
            "slash\\tab\tline\nreturn\rnull\0control\x1fdel\x7f".to_owned();

        let expected = encode_tsv(&report, usize::MAX).unwrap();
        assert_eq!(encode_tsv(&report, expected.len()).unwrap(), expected);
        assert!(matches!(
            encode_tsv(&report, expected.len() - 1),
            Err(ReporterError::OutputTooLarge {
                format: ReportFormat::Tsv,
                max
            }) if max == expected.len() - 1
        ));
    }
}
