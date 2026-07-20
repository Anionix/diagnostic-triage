//! Deterministic normalization for diagnostic messages and context.

use std::fmt::{self, Write as _};

use thiserror::Error;

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// The normalization rules used by the v1 fingerprint input.
pub const NORMALIZATION_VERSION: &str = "diagnostic-triage.normalize/v1";
/// Maximum Unicode scalar count accepted by a v1 diagnostic text component.
pub const MAX_DIAGNOSTIC_TEXT_CHARS: usize = 8192;

/// An invariant failure while constructing normalized diagnostic context.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NormalizationError {
    /// The diagnostic message was empty or contained only whitespace.
    #[error("diagnostic message must not be empty after normalization")]
    EmptyMessage,
    /// A normalized component exceeded the v1 length-prefix range.
    #[error("normalized context component is too large")]
    ComponentTooLarge,
}

/// Typed diagnostic text fields accepted by the normalizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticText<'a> {
    /// Required native diagnostic message.
    pub message: &'a str,
    /// Optional expected value or source context.
    pub expected: Option<&'a str>,
    /// Optional observed value or source context.
    pub observed: Option<&'a str>,
}

impl<'a> DiagnosticText<'a> {
    /// Construct a diagnostic text value with explicit optional context fields.
    #[must_use]
    pub const fn new(
        message: &'a str,
        expected: Option<&'a str>,
        observed: Option<&'a str>,
    ) -> Self {
        Self {
            message,
            expected,
            observed,
        }
    }
}

/// A normalized, boundary-preserving message and optional context fields.
///
/// Each component has Unicode whitespace collapsed to one ASCII space and is
/// trimmed. Non-whitespace code points are preserved byte-for-byte; v1 does
/// not apply NFC or compatibility normalization. The components are encoded
/// as a versioned byte stream with an explicit presence tag and a fixed-width
/// length prefix for every field. This keeps arbitrary Unicode and control
/// characters, including U+001F, inside a field instead of using delimiters.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NormalizedContext(String);

impl NormalizedContext {
    /// Return the canonical representation used by the fingerprint encoder.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the value and return its canonical representation.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for NormalizedContext {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for NormalizedContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Normalize a diagnostic message.
///
/// # Errors
///
/// Returns an error when the input exceeds the v1 bound or no
/// non-whitespace text remains.
pub fn normalize_message(message: &str) -> Result<String, NormalizationError> {
    require_bounded_component(message)?;
    let normalized = collapse_whitespace(message);
    if normalized.is_empty() {
        return Err(NormalizationError::EmptyMessage);
    }
    Ok(normalized)
}

/// Normalize one context string, allowing an empty context.
///
/// # Errors
///
/// Returns [`NormalizationError::ComponentTooLarge`] when the input exceeds
/// the v1 diagnostic text bound.
pub fn normalize_context(context: &str) -> Result<String, NormalizationError> {
    require_bounded_component(context)?;
    Ok(collapse_whitespace(context))
}

/// Normalize a message and its context into one boundary-preserving value.
///
/// # Errors
///
/// Returns an error for an empty message or an unrepresentable component length.
pub fn normalize_message_and_context(
    message: &str,
    context: &str,
) -> Result<NormalizedContext, NormalizationError> {
    normalize_diagnostic(&DiagnosticText::new(message, Some(context), None))
}

/// Normalize a message and an optional context into one canonical value.
///
/// # Errors
///
/// Returns an error for an empty message or an unrepresentable component length.
pub fn normalize_message_context(
    message: &str,
    context: Option<&str>,
) -> Result<NormalizedContext, NormalizationError> {
    normalize_diagnostic(&DiagnosticText::new(message, context, None))
}

/// Normalize a message with explicit expected and observed context fields.
///
/// # Errors
///
/// Returns an error for an empty message or an unrepresentable component length.
pub fn normalize_diagnostic(
    diagnostic: &DiagnosticText<'_>,
) -> Result<NormalizedContext, NormalizationError> {
    let message = normalize_message(diagnostic.message)?;
    let expected = diagnostic
        .expected
        .map(normalize_context)
        .transpose()?
        .unwrap_or_default();
    let observed = diagnostic
        .observed
        .map(normalize_context)
        .transpose()?
        .unwrap_or_default();

    let mut encoded = String::new();
    append_length_prefixed(&mut encoded, NORMALIZATION_VERSION)?;
    append_optional_field(&mut encoded, Some(&message))?;
    append_optional_field(&mut encoded, diagnostic.expected.map(|_| expected.as_str()))?;
    append_optional_field(&mut encoded, diagnostic.observed.map(|_| observed.as_str()))?;

    Ok(NormalizedContext(encoded))
}

pub(crate) fn collapse_whitespace(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut pending_space = false;

    for character in value.chars() {
        if is_v1_whitespace(character) {
            pending_space = true;
            continue;
        }

        if pending_space && !normalized.is_empty() {
            normalized.push(' ');
        }
        normalized.push(character);
        pending_space = false;
    }

    normalized
}

const fn is_v1_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'..='\u{000d}'
            | '\u{0020}'
            | '\u{0085}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn append_length_prefixed(output: &mut String, value: &str) -> Result<(), NormalizationError> {
    let length = u64::try_from(value.len()).map_err(|_| NormalizationError::ComponentTooLarge)?;
    write!(output, "{length:016x}").map_err(|_| NormalizationError::ComponentTooLarge)?;
    output.push_str(value);
    Ok(())
}

fn require_bounded_component(value: &str) -> Result<(), NormalizationError> {
    if value.chars().count() > MAX_DIAGNOSTIC_TEXT_CHARS {
        Err(NormalizationError::ComponentTooLarge)
    } else {
        Ok(())
    }
}

fn append_optional_field(
    output: &mut String,
    value: Option<&str>,
) -> Result<(), NormalizationError> {
    match value {
        Some(value) => {
            output.push('1');
            append_length_prefixed(output, value)?;
        }
        None => output.push('0'),
    }
    Ok(())
}
