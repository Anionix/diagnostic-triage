//! Versioned Finding fingerprint construction.

use std::str::FromStr;

use diagnostic_triage_contracts::model::Tool;
use diagnostic_triage_contracts::{Fingerprint, Language, RepoPath};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::normalize::{NormalizedContext, collapse_whitespace};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

pub const FINGERPRINT_VERSION: &str = "diagnostic-triage.fingerprint/v1";

/// An invariant failure while constructing a Finding fingerprint.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FingerprintError {
    /// A required textual field was empty after canonicalization.
    #[error("fingerprint field {field} must not be empty")]
    EmptyField { field: &'static str },
    /// A field could not be represented by the canonical length prefix.
    #[error("fingerprint field {field} is too large")]
    FieldTooLarge { field: &'static str },
    /// The generated value did not satisfy the contracts crate's scalar type.
    #[error("generated fingerprint failed contract validation: {reason}")]
    InvalidFingerprint { reason: &'static str },
    /// The plain Tool object failed its contracts validation.
    #[error("fingerprint tool is invalid: {reason}")]
    InvalidTool { reason: String },
}

/// Typed inputs for the v1 Finding fingerprint.
///
/// The input deliberately has no location field: line and column changes must
/// not change a Finding fingerprint. Likewise, `Tool::version` is not encoded;
/// tool identity is represented by `Tool::name` and its optional rule id.
pub struct FindingFingerprintInput<'a> {
    /// Tool identity and optional rule identity.
    pub tool: &'a Tool,
    /// Canonical language identifier from the contracts crate.
    pub language: &'a Language,
    /// Canonical repository-relative path from the contracts crate.
    pub path: Option<&'a RepoPath>,
    /// Optional source symbol associated with the diagnostic.
    pub symbol: Option<&'a str>,
    /// Normalized message/context pair.
    pub normalized_context: &'a NormalizedContext,
}

impl<'a> FindingFingerprintInput<'a> {
    /// Construct typed fingerprint inputs from contract values.
    #[must_use]
    pub fn new(
        tool: &'a Tool,
        language: &'a Language,
        path: Option<&'a RepoPath>,
        symbol: Option<&'a str>,
        normalized_context: &'a NormalizedContext,
    ) -> Self {
        Self {
            tool,
            language,
            path,
            symbol,
            normalized_context,
        }
    }
}

/// Build a stable `dtfp1:` SHA-256 Finding fingerprint.
///
/// # Errors
///
/// Returns an error for invalid Tool data, empty normalized identity fields,
/// oversized inputs, or an internally invalid scalar result.
pub fn fingerprint(input: &FindingFingerprintInput<'_>) -> Result<Fingerprint, FingerprintError> {
    input
        .tool
        .validate()
        .map_err(|error| FingerprintError::InvalidTool {
            reason: error.to_string(),
        })?;
    let tool_name = canonical_text("tool name", &input.tool.name)?;
    let rule_id = input
        .tool
        .rule_id
        .as_deref()
        .map(|value| canonical_text("rule id", value))
        .transpose()?;
    let symbol = input
        .symbol
        .map(|value| canonical_text("symbol", value))
        .transpose()?;
    let context = input.normalized_context.as_str();
    if context.is_empty() {
        return Err(FingerprintError::EmptyField {
            field: "normalized context",
        });
    }

    let mut encoded = Vec::new();
    append_field(&mut encoded, "fingerprint version", FINGERPRINT_VERSION)?;
    append_field(&mut encoded, "tool name", &tool_name)?;
    append_optional_field(&mut encoded, "rule id", rule_id.as_deref())?;
    append_field(&mut encoded, "language", input.language.as_str())?;
    append_optional_field(
        &mut encoded,
        "repository path",
        input.path.map(RepoPath::as_str),
    )?;
    append_optional_field(&mut encoded, "symbol", symbol.as_deref())?;
    append_field(&mut encoded, "normalized context", context)?;

    let digest = Sha256::digest(encoded);
    let value = format!("dtfp1:{digest:x}");
    Fingerprint::from_str(&value).map_err(|reason| FingerprintError::InvalidFingerprint { reason })
}

/// Alias with an explicit name for callers constructing a Finding.
///
/// # Errors
///
/// Returns the same invariant errors as [`fingerprint`].
pub fn fingerprint_finding(
    tool: &Tool,
    language: &Language,
    path: Option<&RepoPath>,
    symbol: Option<&str>,
    normalized_context: &NormalizedContext,
) -> Result<Fingerprint, FingerprintError> {
    fingerprint(&FindingFingerprintInput::new(
        tool,
        language,
        path,
        symbol,
        normalized_context,
    ))
}

fn canonical_text(field: &'static str, value: &str) -> Result<String, FingerprintError> {
    let canonical = collapse_whitespace(value);
    if canonical.is_empty() {
        return Err(FingerprintError::EmptyField { field });
    }
    Ok(canonical)
}

fn append_field(
    output: &mut Vec<u8>,
    field: &'static str,
    value: &str,
) -> Result<(), FingerprintError> {
    let length =
        u64::try_from(value.len()).map_err(|_| FingerprintError::FieldTooLarge { field })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn append_optional_field(
    output: &mut Vec<u8>,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), FingerprintError> {
    match value {
        Some(value) => {
            output.push(1);
            append_field(output, field, value)?;
        }
        None => output.push(0),
    }
    Ok(())
}
