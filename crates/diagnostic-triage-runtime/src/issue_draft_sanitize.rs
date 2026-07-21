//! Bounded neutralization kernel for untrusted issue-draft text.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SanitizedText(String);

impl SanitizedText {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum SanitizeError {
    #[error("sanitized text exceeds the {max_bytes}-byte output limit")]
    OutputLimitExceeded { max_bytes: usize },
}

struct BoundedText {
    value: String,
    max_bytes: usize,
}

impl BoundedText {
    fn new(input_len: usize, max_bytes: usize) -> Self {
        Self {
            value: String::with_capacity(input_len.min(max_bytes)),
            max_bytes,
        }
    }

    fn push_str(&mut self, value: &str) -> Result<(), SanitizeError> {
        if value.len() > self.max_bytes.saturating_sub(self.value.len()) {
            return Err(SanitizeError::OutputLimitExceeded {
                max_bytes: self.max_bytes,
            });
        }
        self.value.push_str(value);
        Ok(())
    }

    fn push_char(&mut self, value: char) -> Result<(), SanitizeError> {
        if value.len_utf8() > self.max_bytes.saturating_sub(self.value.len()) {
            return Err(SanitizeError::OutputLimitExceeded {
                max_bytes: self.max_bytes,
            });
        }
        self.value.push(value);
        Ok(())
    }

    fn finish(self) -> SanitizedText {
        SanitizedText(self.value)
    }
}

pub(crate) fn sanitize_external_text(
    value: &str,
    max_bytes: usize,
) -> Result<SanitizedText, SanitizeError> {
    // LLM contract: UNTRUSTED -> NEUTRALIZED -> BOUNDED; overflow -> REJECTED.
    if value.len() > max_bytes {
        return Err(SanitizeError::OutputLimitExceeded { max_bytes });
    }
    let mut output = BoundedText::new(value.len(), max_bytes);
    for character in value.chars() {
        let kind = if is_bidi_control(character) {
            Some("BIDI")
        } else if is_pinned_format_character(character) {
            Some("FORMAT")
        } else if character.is_ascii_control() {
            Some("CONTROL")
        } else {
            None
        };
        if let Some(kind) = kind {
            output.push_str(&format!("[{kind}-U+{:04X}]", u32::from(character)))?;
        } else {
            output.push_char(character)?;
        }
    }
    Ok(output.finish())
}

fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn is_pinned_format_character(character: char) -> bool {
    // Explicitly pinned: changing this set changes the sanitizer contract.
    matches!(
        character,
        '\u{00ad}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061c}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08e2}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

#[cfg(test)]
mod tests {
    use super::{SanitizeError, sanitize_external_text};

    #[test]
    fn neutralizes_pinned_unsafe_characters_without_changing_safe_unicode() {
        let cases = [
            ("plain 日本語", "plain 日本語"),
            ("line\nnext", "line[CONTROL-U+000A]next"),
            ("delete\u{7f}", "delete[CONTROL-U+007F]"),
            ("non-ASCII control\u{85}", "non-ASCII control\u{85}"),
            ("rtl\u{202e}", "rtl[BIDI-U+202E]"),
            ("isolate\u{2066}", "isolate[BIDI-U+2066]"),
            ("join\u{180e}", "join[FORMAT-U+180E]"),
            ("tag\u{e0001}", "tag[FORMAT-U+E0001]"),
        ];

        for (input, expected) in cases {
            let actual = sanitize_external_text(input, 256).unwrap();
            assert_eq!(actual.as_str(), expected, "input {input:?}");
        }
    }

    #[test]
    fn exact_output_bound_succeeds_and_one_byte_over_fails_closed() {
        let expected = "[CONTROL-U+0000]";
        assert_eq!(
            sanitize_external_text("\0", expected.len())
                .unwrap()
                .as_str(),
            expected
        );
        assert_eq!(
            sanitize_external_text("\0", expected.len() - 1),
            Err(SanitizeError::OutputLimitExceeded {
                max_bytes: expected.len() - 1,
            })
        );
        assert_eq!(
            sanitize_external_text("ab", 1),
            Err(SanitizeError::OutputLimitExceeded { max_bytes: 1 })
        );
    }

    #[test]
    fn identical_input_has_identical_output() {
        let input = "日本語\u{202e}\n";
        assert_eq!(
            sanitize_external_text(input, 256),
            sanitize_external_text(input, 256)
        );
    }
}
