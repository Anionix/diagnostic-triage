//! Deterministic GitHub workflow-command annotations for validated reports.

use std::{collections::BTreeMap, io::Write};

use diagnostic_triage_contracts::{
    model::{DecisionAction, Finding, Location, SessionReport},
    validate_report,
};

use crate::reporters::{
    MAX_REPORT_OUTPUT_BYTES, ReportFormat, Reporter, ReporterError, ValidatedSessionReport,
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// A GitHub workflow-command annotation projection of report Findings.
#[derive(Clone, Copy, Debug, Default)]
pub struct GitHubAnnotationReporter;

impl Reporter for GitHubAnnotationReporter {
    fn write_report(
        &self,
        report: &ValidatedSessionReport,
        writer: &mut dyn Write,
    ) -> Result<(), ReporterError> {
        let bytes = github_annotations_bytes(report)?;
        write_annotations(&bytes, writer)
    }
}

/// Validate and write deterministic GitHub workflow-command annotations.
///
/// Validation and bounded encoding finish before the first call to `writer`,
/// so those failures write no bytes. An I/O failure can occur after `writer`
/// accepted a prefix. Use [`github_annotations_bytes`] and a
/// destination-specific transactional commit when destination-level atomicity
/// is required.
///
/// Only Findings with Decisions become annotations. Execution and Verdict
/// messages remain operational evidence and are never projected as source
/// findings.
///
/// # Errors
///
/// Returns [`ReporterError`] when validation, bounded encoding, or the
/// intended writer fails.
pub fn write_github_annotations<W: Write + ?Sized>(
    report: &SessionReport,
    writer: &mut W,
) -> Result<(), ReporterError> {
    validate_report(report).map_err(ReporterError::Contract)?;
    let bytes = encode_github_annotations(report, MAX_REPORT_OUTPUT_BYTES)?;
    write_annotations(&bytes, writer)
}

/// Encode a validated report as bounded GitHub workflow-command annotations.
///
/// The returned buffer is complete and deterministically ordered by
/// `(fingerprint, finding_id)`. Reports without Findings produce an empty
/// buffer, including operational `INCOMPLETE` and `UNSUPPORTED` reports.
///
/// # Errors
///
/// Returns [`ReporterError::OutputTooLarge`] when the complete projection
/// would exceed the hard output limit, or another [`ReporterError`] when a
/// required Finding/Decision relationship is unavailable.
pub fn github_annotations_bytes(report: &ValidatedSessionReport) -> Result<Vec<u8>, ReporterError> {
    encode_github_annotations(report.as_report(), MAX_REPORT_OUTPUT_BYTES)
}

fn write_annotations<W: Write + ?Sized>(bytes: &[u8], writer: &mut W) -> Result<(), ReporterError> {
    writer.write_all(bytes).map_err(|source| ReporterError::Io {
        format: ReportFormat::GitHubAnnotations,
        source,
    })
}

fn encode_github_annotations(
    report: &SessionReport,
    limit: usize,
) -> Result<Vec<u8>, ReporterError> {
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

    let mut output = AnnotationBuffer::new(limit);
    for finding in findings {
        let Some(decision) = decisions.get(finding.finding_id.as_str()) else {
            return Err(ReporterError::MissingDecision {
                finding_id: finding.finding_id.to_string(),
            });
        };
        write_annotation(&mut output, finding, &decision.action)?;
    }
    Ok(output.bytes)
}

fn write_annotation(
    output: &mut AnnotationBuffer,
    finding: &Finding,
    action: &DecisionAction,
) -> Result<(), ReporterError> {
    output.push(b"::")?;
    output.push(annotation_level(action))?;

    let mut has_metadata = false;
    if let Some(location) = &finding.location {
        write_github_location(output, &mut has_metadata, location)?;
    }

    output.push(if has_metadata { b",title=" } else { b" title=" })?;
    write_escaped(output, &finding.tool.name, EscapeContext::Metadata)?;
    if let Some(rule_id) = finding.tool.rule_id.as_deref() {
        write_escaped(output, ": ", EscapeContext::Metadata)?;
        write_escaped(output, rule_id, EscapeContext::Metadata)?;
    }
    output.push(b"::")?;
    write_escaped(output, &finding.message, EscapeContext::Message)?;
    output.push(b"\n")
}

fn write_github_location(
    output: &mut AnnotationBuffer,
    has_metadata: &mut bool,
    location: &Location,
) -> Result<(), ReporterError> {
    const MAX_GITHUB_COORDINATE: u32 = i32::MAX as u32;

    if location.start.line > MAX_GITHUB_COORDINATE {
        return Ok(());
    }

    write_metadata(output, has_metadata, b"file", location.path.as_str())?;
    write_number_metadata(output, has_metadata, b"line", location.start.line)?;
    match &location.end {
        None => {
            write_start_column(output, has_metadata, location.start.column)?;
        }
        Some(end) if end.line == location.start.line => {
            write_number_metadata(output, has_metadata, b"endLine", end.line)?;
            let start_column_supported =
                write_start_column(output, has_metadata, location.start.column)?;
            let inclusive_end_column = end.column.saturating_sub(1);
            if start_column_supported
                && end.column > location.start.column
                && inclusive_end_column <= MAX_GITHUB_COORDINATE
            {
                write_number_metadata(output, has_metadata, b"endColumn", inclusive_end_column)?;
            }
        }
        Some(end) => {
            let inclusive_end_line = end.line - u32::from(end.column == 1);
            if inclusive_end_line <= MAX_GITHUB_COORDINATE {
                write_number_metadata(output, has_metadata, b"endLine", inclusive_end_line)?;
            } else {
                write_start_column(output, has_metadata, location.start.column)?;
            }
        }
    }
    Ok(())
}

fn write_start_column(
    output: &mut AnnotationBuffer,
    has_metadata: &mut bool,
    column: u32,
) -> Result<bool, ReporterError> {
    if column > i32::MAX as u32 {
        return Ok(false);
    }
    write_number_metadata(output, has_metadata, b"col", column)?;
    Ok(true)
}

fn write_metadata(
    output: &mut AnnotationBuffer,
    has_metadata: &mut bool,
    key: &[u8],
    value: &str,
) -> Result<(), ReporterError> {
    output.push(if *has_metadata { b"," } else { b" " })?;
    *has_metadata = true;
    output.push(key)?;
    output.push(b"=")?;
    write_escaped(output, value, EscapeContext::Metadata)
}

fn write_number_metadata(
    output: &mut AnnotationBuffer,
    has_metadata: &mut bool,
    key: &[u8],
    value: u32,
) -> Result<(), ReporterError> {
    write_metadata(output, has_metadata, key, &value.to_string())
}

const fn annotation_level(action: &DecisionAction) -> &'static [u8] {
    match action {
        DecisionAction::Block => b"error",
        DecisionAction::Warn => b"warning",
        DecisionAction::Observe | DecisionAction::Waive => b"notice",
    }
}

#[derive(Clone, Copy)]
enum EscapeContext {
    Metadata,
    Message,
}

fn write_escaped(
    output: &mut AnnotationBuffer,
    value: &str,
    context: EscapeContext,
) -> Result<(), ReporterError> {
    for byte in value.bytes() {
        let escaped = match byte {
            b'%' => Some(b"%25".as_slice()),
            b'\r' => Some(b"%0D".as_slice()),
            b'\n' => Some(b"%0A".as_slice()),
            b':' if matches!(context, EscapeContext::Metadata) => Some(b"%3A".as_slice()),
            b',' if matches!(context, EscapeContext::Metadata) => Some(b"%2C".as_slice()),
            _ => None,
        };
        if let Some(escaped) = escaped {
            output.push(escaped)?;
        } else {
            output.push(&[byte])?;
        }
    }
    Ok(())
}

struct AnnotationBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl AnnotationBuffer {
    const fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), ReporterError> {
        let within_limit = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_some_and(|next_len| next_len <= self.limit);
        if !within_limit {
            return Err(ReporterError::OutputTooLarge {
                format: ReportFormat::GitHubAnnotations,
                max: self.limit,
            });
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use diagnostic_triage_contracts::{model::DecisionAction, validate_report_json};

    use super::{annotation_level, encode_github_annotations};
    use crate::reporters::{ReportFormat, ReporterError};

    #[test]
    fn policy_actions_map_to_annotation_levels() {
        for (action, level) in [
            (DecisionAction::Block, b"error".as_slice()),
            (DecisionAction::Warn, b"warning".as_slice()),
            (DecisionAction::Observe, b"notice".as_slice()),
            (DecisionAction::Waive, b"notice".as_slice()),
        ] {
            assert_eq!(annotation_level(&action), level);
        }
    }

    #[test]
    fn bounded_encoding_is_all_or_nothing_at_the_exact_limit() {
        let report = validate_report_json(include_bytes!(
            "../../../tests/fixtures/v1/valid-report.json"
        ))
        .unwrap();
        let expected = encode_github_annotations(&report, usize::MAX).unwrap();

        assert_eq!(
            encode_github_annotations(&report, expected.len()).unwrap(),
            expected
        );
        assert!(matches!(
            encode_github_annotations(&report, expected.len() - 1),
            Err(ReporterError::OutputTooLarge {
                format: ReportFormat::GitHubAnnotations,
                max
            }) if max == expected.len() - 1
        ));
    }
}
