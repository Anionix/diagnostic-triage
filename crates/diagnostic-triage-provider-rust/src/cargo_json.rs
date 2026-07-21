//! Typed boundary for Cargo and rustc JSON Lines messages.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use serde::Deserialize;
use thiserror::Error;

const MAX_DIAGNOSTICS: usize = 10_000;
const MAX_SPANS: usize = 64;
const MAX_CHILDREN: usize = 64;
const MAX_CODE_CHARS: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CargoReport {
    pub(crate) diagnostics: Vec<RustcDiagnostic>,
    pub(crate) success: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct RustcDiagnostic {
    pub(crate) message: String,
    pub(crate) code: Option<RustcCode>,
    pub(crate) level: String,
    #[serde(default)]
    pub(crate) spans: Vec<RustcSpan>,
    #[serde(default)]
    pub(crate) children: Vec<RustcChild>,
    pub(crate) rendered: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct RustcCode {
    pub(crate) code: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct RustcChild {
    pub(crate) message: String,
    pub(crate) level: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct RustcSpan {
    pub(crate) file_name: String,
    pub(crate) line_start: u64,
    pub(crate) line_end: u64,
    pub(crate) column_start: u64,
    pub(crate) column_end: u64,
    pub(crate) is_primary: bool,
}

#[derive(Debug, Error)]
pub(crate) enum CargoJsonError {
    #[error("Cargo JSON stream is empty or lacks build-finished")]
    MissingBuildFinished,
    #[error("Cargo JSON object is incomplete at end of stream")]
    PartialObject,
    #[error("Cargo JSON is malformed: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("Cargo JSON violates the typed boundary: {0}")]
    Invalid(String),
}

#[derive(Debug, Deserialize)]
struct CompilerMessage {
    reason: String,
    message: RustcDiagnostic,
}

#[derive(Debug, Deserialize)]
struct BuildFinished {
    reason: String,
    success: bool,
}

/// Parse Cargo's documented one-JSON-object-per-line stream.
///
/// Cargo documents that procedural macros and other tools may write arbitrary
/// non-JSON lines. Such lines remain in raw Evidence and are not guess-parsed;
/// a line beginning with `{` is treated as a claimed Cargo object and must be
/// valid and complete.
pub(crate) fn parse_cargo_jsonl(input: &[u8]) -> Result<CargoReport, CargoJsonError> {
    let mut diagnostics = Vec::new();
    let mut finished = None;

    for chunk in input.split_inclusive(|byte| *byte == b'\n') {
        let complete = chunk.last() == Some(&b'\n');
        let mut line = if complete {
            &chunk[..chunk.len().saturating_sub(1)]
        } else {
            chunk
        };
        if line.last() == Some(&b'\r') {
            line = &line[..line.len().saturating_sub(1)];
        }
        if line.first() != Some(&b'{') {
            continue;
        }
        if !complete {
            return Err(CargoJsonError::PartialObject);
        }
        if finished.is_some() {
            return Err(CargoJsonError::Invalid(
                "structured message follows build-finished".to_owned(),
            ));
        }

        let value = serde_json::from_slice::<serde_json::Value>(line)?;
        let reason = value
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CargoJsonError::Invalid("message reason is missing".to_owned()))?;
        match reason {
            "compiler-message" => {
                let envelope = serde_json::from_value::<CompilerMessage>(value)?;
                if envelope.reason != "compiler-message" {
                    return Err(CargoJsonError::Invalid(
                        "compiler-message reason changed while decoding".to_owned(),
                    ));
                }
                validate_diagnostic(&envelope.message)?;
                diagnostics.push(envelope.message);
                if diagnostics.len() > MAX_DIAGNOSTICS {
                    return Err(CargoJsonError::Invalid(format!(
                        "diagnostic count exceeds {MAX_DIAGNOSTICS}"
                    )));
                }
            }
            "build-finished" => {
                let envelope = serde_json::from_value::<BuildFinished>(value)?;
                if envelope.reason != "build-finished" {
                    return Err(CargoJsonError::Invalid(
                        "build-finished reason changed while decoding".to_owned(),
                    ));
                }
                finished = Some(envelope.success);
            }
            _ => {}
        }
    }

    finished
        .map(|success| CargoReport {
            diagnostics,
            success,
        })
        .ok_or(CargoJsonError::MissingBuildFinished)
}

fn validate_diagnostic(diagnostic: &RustcDiagnostic) -> Result<(), CargoJsonError> {
    if diagnostic.message.is_empty() {
        return Err(CargoJsonError::Invalid(
            "diagnostic message is empty".to_owned(),
        ));
    }
    if diagnostic.level.is_empty() {
        return Err(CargoJsonError::Invalid(
            "diagnostic level is empty".to_owned(),
        ));
    }
    if diagnostic.spans.len() > MAX_SPANS {
        return Err(CargoJsonError::Invalid(format!(
            "diagnostic span count exceeds {MAX_SPANS}"
        )));
    }
    if diagnostic.children.len() > MAX_CHILDREN {
        return Err(CargoJsonError::Invalid(format!(
            "diagnostic child count exceeds {MAX_CHILDREN}"
        )));
    }
    if diagnostic
        .code
        .as_ref()
        .is_some_and(|code| code.code.is_empty() || code.code.chars().count() > MAX_CODE_CHARS)
    {
        return Err(CargoJsonError::Invalid(
            "diagnostic code is outside the v1 bound".to_owned(),
        ));
    }
    for span in &diagnostic.spans {
        if span.file_name.is_empty()
            || span.line_start == 0
            || span.line_end == 0
            || span.column_start == 0
            || span.column_end == 0
            || (span.line_end, span.column_end) < (span.line_start, span.column_start)
            || u32::try_from(span.line_start).is_err()
            || u32::try_from(span.line_end).is_err()
            || u32::try_from(span.column_start).is_err()
            || u32::try_from(span.column_end).is_err()
        {
            return Err(CargoJsonError::Invalid(
                "diagnostic span is outside the v1 position range".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CargoJsonError, parse_cargo_jsonl};

    #[test]
    fn parses_compiler_messages_and_terminal_status() {
        let report = parse_cargo_jsonl(
            concat!(
                "not-json from a procedural macro\n",
                "{\"reason\":\"compiler-message\",\"message\":{\"message\":\"bad type\",\"code\":{\"code\":\"E0308\"},\"level\":\"error\",\"spans\":[],\"children\":[],\"rendered\":\"error[E0308]: bad type\\n\"}}\n",
                "{\"reason\":\"build-finished\",\"success\":false}\n"
            )
            .as_bytes(),
        )
        .expect("documented Cargo messages parse");

        assert!(!report.success);
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].code.as_ref().unwrap().code, "E0308");
    }

    #[test]
    fn rejects_malformed_partial_and_post_terminal_objects() {
        for input in [
            "{\n",
            "{\"reason\":\"compiler-artifact\"}",
            "{\"reason\":\"build-finished\",\"success\":true}\n{\"reason\":\"compiler-artifact\"}\n",
        ] {
            assert!(parse_cargo_jsonl(input.as_bytes()).is_err());
        }
        assert!(matches!(
            parse_cargo_jsonl(b"noise only\n"),
            Err(CargoJsonError::MissingBuildFinished)
        ));
    }
}
