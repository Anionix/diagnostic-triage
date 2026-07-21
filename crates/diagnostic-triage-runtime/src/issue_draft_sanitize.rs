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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SecretKeyMatch {
    end: usize,
    cli_dashes: u8,
}

fn recognize_secret_key(value: &str, index: usize) -> Option<SecretKeyMatch> {
    const MAX_SPAN: usize = 256;
    const MAX_MARKERS: u8 = 8;

    let bytes = value.as_bytes();
    let prefix = value.get(..index)?;
    if prefix.chars().next_back().is_some_and(|character| {
        if character.is_ascii() {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
        } else {
            !character.is_whitespace()
        }
    }) {
        return None;
    }

    let mut cursor = index;
    let mut cli_dashes = 0;
    while cli_dashes < 2 && bytes.get(cursor) == Some(&b'-') {
        cursor += 1;
        cli_dashes += 1;
    }
    if bytes.get(cursor) == Some(&b'-') {
        return None;
    }

    let key_start = cursor;
    let mut normalized = String::with_capacity(16);
    let mut markers = 0;
    let mut needs_alphanumeric = false;
    while cursor - key_start <= MAX_SPAN {
        let Some(byte) = bytes.get(cursor).copied() else {
            break;
        };
        if byte.is_ascii_alphanumeric() {
            if normalized.len() == 32 {
                return None;
            }
            normalized.push(char::from(byte.to_ascii_lowercase()));
            cursor += 1;
            needs_alphanumeric = false;
        } else if matches!(byte, b'_' | b'-') {
            if normalized.is_empty() || needs_alphanumeric {
                return None;
            }
            cursor += 1;
            needs_alphanumeric = true;
        } else if let Some(end) = neutralization_marker_end(value, cursor) {
            if normalized.is_empty() || markers == MAX_MARKERS || end - key_start > MAX_SPAN {
                return None;
            }
            cursor = end;
            markers += 1;
            needs_alphanumeric = true;
        } else {
            break;
        }
    }
    if cursor - key_start > MAX_SPAN || needs_alphanumeric {
        return None;
    }
    let suffix_allowed = cursor == value.len()
        || bytes
            .get(cursor)
            .is_some_and(|byte| matches!(byte, b'=' | b':'))
        || skip_assignment_whitespace(value, cursor) > cursor;
    if !suffix_allowed || !is_secret_key(&normalized) {
        return None;
    }
    Some(SecretKeyMatch {
        end: cursor,
        cli_dashes,
    })
}

fn neutralization_marker_end(value: &str, index: usize) -> Option<usize> {
    let tail = value.get(index..)?;
    let rest = tail
        .strip_prefix("[FORMAT-U+")
        .or_else(|| tail.strip_prefix("[BIDI-U+"))?;
    let close = rest.bytes().take(7).position(|byte| byte == b']')?;
    let digits = rest.get(..close)?;
    (matches!(digits.len(), 4..=6)
        && digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F')))
    .then_some(index + tail.len() - rest.len() + digits.len() + 1)
}

fn is_secret_key(value: &str) -> bool {
    matches!(
        value,
        "token"
            | "apikey"
            | "password"
            | "passwd"
            | "secret"
            | "clientsecret"
            | "accesstoken"
            | "refreshtoken"
            | "privatekey"
    )
}

fn unquoted_secret_at(value: &str, index: usize) -> Option<(usize, usize)> {
    let matched = recognize_secret_key(value, index)?;
    let bytes = value.as_bytes();
    let mut cursor = matched.end;
    if matched.cli_dashes > 0 {
        if bytes.get(cursor) == Some(&b'=') {
            let value_start = cursor + 1;
            cursor = skip_assignment_whitespace(value, value_start);
            if cursor > value_start && looks_like_assignment(value, cursor) {
                return None;
            }
        } else if skip_assignment_whitespace(value, cursor) > cursor {
            cursor = skip_assignment_whitespace(value, cursor);
            if matches!(bytes.get(cursor), Some(b'=' | b':')) {
                return None;
            }
            if looks_like_assignment(value, cursor) {
                return None;
            }
        } else {
            return None;
        }
    } else {
        cursor = skip_assignment_whitespace(value, cursor);
        if !matches!(bytes.get(cursor), Some(b'=' | b':')) {
            return None;
        }
        let value_start = cursor + 1;
        cursor = skip_assignment_whitespace(value, value_start);
        if matches!(bytes.get(cursor), Some(b'=' | b':'))
            || (cursor > value_start && looks_like_assignment(value, cursor))
        {
            return None;
        }
    }
    if cursor >= bytes.len()
        || bytes.get(cursor).is_some_and(|byte| is_quote(*byte))
        || (bytes.get(cursor) == Some(&b'\\')
            && bytes.get(cursor + 1).is_some_and(|byte| is_quote(*byte)))
    {
        return None;
    }
    let end = unquoted_value_end(value, cursor);
    (end > cursor).then_some((cursor, end))
}

fn unquoted_value_end(value: &str, start: usize) -> usize {
    let bytes = value.as_bytes();
    let mut cursor = start;
    while cursor < value.len() {
        let character = value[cursor..].chars().next().expect("UTF-8 boundary");
        let ascii_delimiter = matches!(character, ' ' | ',' | ';' | '&');
        if (character.is_whitespace() || ascii_delimiter)
            && !(ascii_delimiter && is_escaped(bytes, start, cursor))
        {
            break;
        }
        cursor += character.len_utf8();
    }
    cursor
}

fn is_escaped(bytes: &[u8], start: usize, cursor: usize) -> bool {
    let mut boundary = cursor;
    while boundary > start && bytes[boundary - 1] == b'\\' {
        boundary -= 1;
    }
    (cursor - boundary) % 2 == 1
}

fn skip_assignment_whitespace(value: &str, mut cursor: usize) -> usize {
    const MARKERS: [&str; 5] = [
        "[CONTROL-U+0009]",
        "[CONTROL-U+000A]",
        "[CONTROL-U+000B]",
        "[CONTROL-U+000C]",
        "[CONTROL-U+000D]",
    ];
    while cursor < value.len() {
        if let Some(marker) = MARKERS
            .iter()
            .find(|marker| value[cursor..].starts_with(**marker))
        {
            cursor += marker.len();
        } else {
            let character = value[cursor..].chars().next().expect("UTF-8 boundary");
            if !character.is_whitespace() {
                break;
            }
            cursor += character.len_utf8();
        }
    }
    cursor
}

fn looks_like_assignment(value: &str, start: usize) -> bool {
    let mut cursor = start;
    while let Some(character) = value[cursor..].chars().next() {
        if !(character.is_alphanumeric() || matches!(character, '_' | '-')) {
            break;
        }
        cursor += character.len_utf8();
    }
    cursor > start
        && value
            .as_bytes()
            .get(skip_assignment_whitespace(value, cursor))
            .is_some_and(|byte| matches!(byte, b'=' | b':'))
}

fn is_quote(byte: u8) -> bool {
    matches!(byte, b'\'' | b'"')
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
    use super::{SanitizeError, recognize_secret_key, sanitize_external_text, unquoted_secret_at};

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

    #[test]
    fn recognizes_only_bounded_secret_keys() {
        for key in [
            "token",
            "api_key",
            "password",
            "passwd",
            "secret",
            "client_secret",
            "access_token",
            "refresh_token",
            "private_key",
        ] {
            let input = format!("{key}=");
            assert_eq!(recognize_secret_key(&input, 0).unwrap().end, key.len());
        }

        let cases = [
            ("API-KEY:", 0, ":", 0),
            ("--client-secret value", 0, " value", 2),
            ("日本 token=", "日本 ".len(), "=", 0),
            ("tok[FORMAT-U+200B]en=", 0, "=", 0),
            ("to[BIDI-U+202E][FORMAT-U+200B]ken=", 0, "=", 0),
        ];
        for (input, index, suffix, cli_dashes) in cases {
            let matched = recognize_secret_key(input, index).unwrap();
            assert_eq!(&input[matched.end..], suffix, "input {input:?}");
            assert_eq!(matched.cli_dashes, cli_dashes, "input {input:?}");
        }
    }

    #[test]
    fn rejects_ambiguous_boundaries_and_malformed_markers() {
        let cases = [
            ("tokenize=", 0),
            ("api-key_extra=", 0),
            ("日本token=", "日本".len()),
            ("token\u{301}=", 0),
            ("---token=", 0),
            ("[FORMAT-U+200B]token=", 0),
            ("token[FORMAT-U+200B]=", 0),
            ("tok[FORMAT-U+200b]en=", 0),
            ("tok[FORMAT-U+1234567]en=", 0),
            ("tok[FORMAT-U+200Ben=", 0),
        ];
        for (input, index) in cases {
            assert_eq!(recognize_secret_key(input, index), None, "input {input:?}");
        }

        let too_many = format!("t{}oken=", "[FORMAT-U+200B]".repeat(9));
        assert_eq!(recognize_secret_key(&too_many, 0), None);
    }

    #[test]
    fn malformed_marker_prefix_scanning_is_bounded() {
        let prefix = "[FORMAT-U+";
        let input = prefix.repeat(10_000);
        for index in (0..input.len()).step_by(prefix.len()) {
            assert_eq!(recognize_secret_key(&input, index), None);
        }
    }

    #[test]
    fn parses_only_present_unquoted_secret_value_spans() {
        let cases = [
            ("token=secret next=ok", "secret"),
            ("--client-secret tiny rest", "tiny"),
            ("-API_KEY=value;next", "value"),
            ("token=foo\\ bar tail", "foo\\ bar"),
            ("token=trailing\\", "trailing\\"),
            ("token[CONTROL-U+0009]=secret", "secret"),
            ("token\u{2003}=secret", "secret"),
            ("--token[CONTROL-U+0009]secret", "secret"),
            ("token=secret\u{2003}next", "secret"),
            (
                "token=secret[CONTROL-U+000A]next=ok",
                "secret[CONTROL-U+000A]next=ok",
            ),
        ];
        for (input, expected_value) in cases {
            let (start, end) = unquoted_secret_at(input, 0).unwrap();
            assert_eq!(&input[start..end], expected_value, "input {input:?}");
        }

        for input in [
            "token",
            "token=",
            "token=;",
            "token=,next",
            "token= next=ok",
            "token=: next=ok",
            "--token",
            "--token=",
            "--token= next=ok",
            "--token:value",
            "--token =value",
            "token='secret'",
            "token=\"secret\"",
            r#"token=\"secret\""#,
            "token secret",
        ] {
            assert_eq!(unquoted_secret_at(input, 0), None, "input {input:?}");
        }
    }

    #[test]
    fn escaped_ascii_delimiters_use_backslash_parity() {
        for delimiter in [' ', ',', ';', '&'] {
            for slash_count in 0..=4 {
                let slashes = "\\".repeat(slash_count);
                let input = format!("token=value{slashes}{delimiter}tail");
                let (_, end) = unquoted_secret_at(&input, 0).unwrap();
                let expected_end = if slash_count % 2 == 0 {
                    input.find(delimiter).unwrap()
                } else {
                    input.len()
                };
                assert_eq!(end, expected_end, "input {input:?}");
            }
        }
    }

    #[test]
    fn repeated_nonsecret_assignments_are_preserved() {
        let input = "name=value;".repeat(10_000);
        let actual = sanitize_external_text(&input, input.len()).unwrap();
        assert_eq!(actual.as_str(), input);
    }
}
