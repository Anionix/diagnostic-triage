//! Bounded neutralization kernel for untrusted issue-draft text.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

#[cfg(test)]
std::thread_local! {
    static ASSIGNMENT_WHITESPACE_SCAN_STEPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

const PROVIDER_TOKEN_PREFIXES: &[(&str, usize, bool)] = &[
    ("ghp_", 20, false),
    ("gho_", 20, false),
    ("ghu_", 20, false),
    ("ghs_", 20, true),
    ("ghr_", 20, false),
    ("github_pat_", 20, false),
    ("glpat-", 20, false),
    ("gloas-", 20, false),
    ("gldt-", 20, false),
    ("glrt-", 20, false),
    ("glrtr-", 20, false),
    ("glcbt-", 20, false),
    ("glptt-", 20, false),
    ("glft-", 20, false),
    ("glimt-", 20, false),
    ("glagent-", 20, false),
    ("glwt-", 20, false),
    ("glsoat-", 20, false),
    ("glffct-", 20, false),
    ("npm_", 32, false),
    ("sk-", 32, false),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SanitizationMode {
    ExternalText,
    Identifier,
    RepositoryPath,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SanitizedText(String);

impl SanitizedText {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MarkerKind {
    Bidi,
    Format,
    Control,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GeneratedMarker {
    start: usize,
    end: usize,
    kind: MarkerKind,
    code_point: u32,
}

impl GeneratedMarker {
    const fn new(start: usize, end: usize, kind: MarkerKind, code_point: u32) -> Self {
        Self {
            start,
            end,
            kind,
            code_point,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NeutralizedText {
    text: SanitizedText,
    markers: Vec<GeneratedMarker>,
}

impl NeutralizedText {
    fn as_str(&self) -> &str {
        self.text.as_str()
    }

    fn marker_at(&self, start: usize) -> Option<GeneratedMarker> {
        self.markers
            .binary_search_by_key(&start, |marker| marker.start)
            .ok()
            .map(|index| self.markers[index])
    }

    fn marker_ending_at(&self, end: usize) -> Option<GeneratedMarker> {
        self.markers
            .binary_search_by_key(&end, |marker| marker.end)
            .ok()
            .map(|index| self.markers[index])
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

    fn len(&self) -> usize {
        self.value.len()
    }

    fn finish(self) -> SanitizedText {
        SanitizedText(self.value)
    }
}

pub(crate) fn sanitize_external_text(
    value: &str,
    max_bytes: usize,
) -> Result<SanitizedText, SanitizeError> {
    sanitize_text(value, max_bytes, SanitizationMode::ExternalText)
}

pub(crate) fn sanitize_identifier_text(
    value: &str,
    max_bytes: usize,
) -> Result<SanitizedText, SanitizeError> {
    sanitize_text(value, max_bytes, SanitizationMode::Identifier)
}

pub(crate) fn sanitize_repository_path_text(
    value: &diagnostic_triage_contracts::RepoPath,
    max_bytes: usize,
) -> Result<SanitizedText, SanitizeError> {
    // LLM contract: VALIDATED_REPO_PATH -> EXPLICIT_TOKEN_REDACTED | GENERIC_COMPONENT_PRESERVED.
    sanitize_text(value.as_str(), max_bytes, SanitizationMode::RepositoryPath)
}

fn sanitize_text(
    value: &str,
    max_bytes: usize,
    mode: SanitizationMode,
) -> Result<SanitizedText, SanitizeError> {
    let neutralized = neutralize_external_text(value, max_bytes)?;
    redact_secret_assignments(&neutralized, max_bytes, mode)
}

fn neutralize_external_text(
    value: &str,
    max_bytes: usize,
) -> Result<NeutralizedText, SanitizeError> {
    // LLM contract: UNTRUSTED -> NEUTRALIZED -> BOUNDED; overflow -> REJECTED.
    if value.len() > max_bytes {
        return Err(SanitizeError::OutputLimitExceeded { max_bytes });
    }
    let mut output = BoundedText::new(value.len(), max_bytes);
    let mut markers = Vec::new();
    for character in value.chars() {
        let marker = if is_bidi_control(character) {
            Some((MarkerKind::Bidi, "BIDI"))
        } else if is_pinned_format_character(character) {
            Some((MarkerKind::Format, "FORMAT"))
        } else if character.is_ascii_control() {
            Some((MarkerKind::Control, "CONTROL"))
        } else {
            None
        };
        if let Some((kind, label)) = marker {
            let start = output.len();
            output.push_str(&format!("[{label}-U+{:04X}]", u32::from(character)))?;
            markers.push(GeneratedMarker::new(
                start,
                output.len(),
                kind,
                u32::from(character),
            ));
        } else {
            output.push_char(character)?;
        }
    }
    Ok(NeutralizedText {
        text: output.finish(),
        markers,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SecretKeyMatch {
    end: usize,
    cli_dashes: u8,
}

fn recognize_secret_key(value: &str, index: usize) -> Option<SecretKeyMatch> {
    const GITLAB_SESSION_KEY: &str = "_gitlab_session";
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

    if value.get(index..)?.starts_with(GITLAB_SESSION_KEY) {
        let end = index + GITLAB_SESSION_KEY.len();
        // LLM contract: COOKIE_KEY -> EXACT_EQUALS -> VALUE_REDACTED; near miss -> GENERIC_KEY_SCAN.
        if bytes.get(end) == Some(&b'=') {
            return Some(SecretKeyMatch { end, cli_dashes: 0 });
        }
    }

    // LLM contract: INPUT_BOUNDARY -> POSSIBLE_KEY_START | REJECTED_BEFORE_SUFFIX_SCAN.
    let first = bytes.get(index)?;
    if !first.is_ascii_alphanumeric() && *first != b'-' {
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
            if normalized.len() >= 32 {
                return None;
            }
            normalized.push(char::from(byte.to_ascii_lowercase()));
            cursor += 1;
            needs_alphanumeric = false;
        } else if matches!(byte, b'_' | b'-') {
            if normalized.is_empty() || needs_alphanumeric || normalized.len() >= 32 {
                return None;
            }
            normalized.push('_');
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
    // LLM contract: CANDIDATE -> POSITION_PRESERVED -> DECLARED_ALIAS | REJECTED.
    matches!(
        value,
        "token"
            | "api_key"
            | "password"
            | "passwd"
            | "secret"
            | "client_secret"
            | "access_token"
            | "refresh_token"
            | "private_key"
    )
}

fn redact_secret_assignments(
    neutralized: &NeutralizedText,
    max_bytes: usize,
    mode: SanitizationMode,
) -> Result<SanitizedText, SanitizeError> {
    // LLM contract: NEUTRALIZED -> EXPLICIT_REDACTED -> SHAPE_REDACTED | IDENTIFIER_PRESERVED.
    let value = neutralized.as_str();
    let mut output = BoundedText::new(value.len(), max_bytes);
    let mut index = 0;
    while index < value.len() {
        if let Some((start, end)) = unquoted_secret_at_with_provenance(neutralized, index)
            .or_else(|| quoted_secret_at_with_provenance(neutralized, index))
            .or_else(|| json_quoted_secret_at(neutralized, index))
            .or_else(|| authorization_secret_at(neutralized, index))
            .or_else(|| match mode {
                SanitizationMode::ExternalText => token_shape_at(value, index, true),
                SanitizationMode::RepositoryPath => token_shape_at(value, index, false),
                SanitizationMode::Identifier => None,
            })
        {
            output.push_str(&value[index..start])?;
            output.push_str("[REDACTED_SECRET]")?;
            index = end;
        } else {
            let character = value[index..].chars().next().expect("UTF-8 boundary");
            output.push_char(character)?;
            index += character.len_utf8();
        }
    }
    Ok(output.finish())
}

fn token_shape_at(value: &str, index: usize, include_generic: bool) -> Option<(usize, usize)> {
    is_word_boundary(value, index, true).then_some(())?;
    let end = provider_token_end(value, index)
        .or_else(|| jwt_token_end(value, index))
        .or_else(|| {
            include_generic
                .then(|| generic_token_end(value, index))
                .flatten()
        })?;
    Some((index, end))
}

fn provider_token_end(value: &str, index: usize) -> Option<usize> {
    const MAX_PROVIDER_BYTES: usize = 1_024;
    let tail = value.get(index..)?;
    let &(prefix, minimum, allow_dot) = PROVIDER_TOKEN_PREFIXES
        .iter()
        .find(|(prefix, _, _)| tail.starts_with(prefix))?;
    let end = bounded_token_end(value, index, MAX_PROVIDER_BYTES, allow_dot)?;
    (end - index - prefix.len() >= minimum && is_word_boundary(value, end, false)).then_some(end)
}

fn jwt_token_end(value: &str, index: usize) -> Option<usize> {
    const MAX_JWT_BYTES: usize = 1_024;
    value.get(index..)?.starts_with("eyJ").then_some(())?;
    let mut cursor = index;
    for segment in 0..3 {
        let remaining = MAX_JWT_BYTES.checked_sub(cursor - index)?;
        let end = bounded_token_end(value, cursor, remaining, false)?;
        (end > cursor).then_some(())?;
        cursor = end;
        if segment < 2 {
            (value.as_bytes().get(cursor) == Some(&b'.')).then_some(())?;
            cursor += 1;
        }
    }
    (cursor - index >= 32 && is_word_boundary(value, cursor, false)).then_some(cursor)
}

fn generic_token_end(value: &str, index: usize) -> Option<usize> {
    const MIN_BYTES: usize = 32;
    const MAX_BYTES: usize = 128;
    let end = bounded_token_end(value, index, MAX_BYTES, false)?;
    let token = &value.as_bytes()[index..end];
    let diverse = token.iter().any(u8::is_ascii_lowercase)
        && token.iter().any(u8::is_ascii_uppercase)
        && token.iter().any(u8::is_ascii_digit)
        && token.iter().any(|byte| matches!(byte, b'_' | b'-'));
    ((MIN_BYTES..=MAX_BYTES).contains(&token.len())
        && diverse
        && is_word_boundary(value, end, false))
    .then_some(end)
}

fn bounded_token_end(
    value: &str,
    index: usize,
    max_bytes: usize,
    allow_dot: bool,
) -> Option<usize> {
    let mut cursor = index;
    while value.as_bytes().get(cursor).is_some_and(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-') || (allow_dot && *byte == b'.')
    }) {
        if cursor - index == max_bytes {
            return None;
        }
        cursor += 1;
    }
    Some(cursor)
}

fn unquoted_secret_at(value: &str, index: usize) -> Option<(usize, usize)> {
    unquoted_secret_at_inner(value, index, None)
}

fn unquoted_secret_at_with_provenance(
    neutralized: &NeutralizedText,
    index: usize,
) -> Option<(usize, usize)> {
    unquoted_secret_at_inner(neutralized.as_str(), index, Some(neutralized))
}

fn unquoted_secret_at_inner(
    value: &str,
    index: usize,
    neutralized: Option<&NeutralizedText>,
) -> Option<(usize, usize)> {
    let cursor = secret_value_start(value, index, neutralized)?;
    let bytes = value.as_bytes();
    if cursor >= bytes.len()
        || bytes.get(cursor).is_some_and(|byte| is_quote(*byte))
        || (bytes.get(cursor) == Some(&b'\\')
            && bytes.get(cursor + 1).is_some_and(|byte| is_quote(*byte)))
    {
        return None;
    }
    let end = unquoted_value_end(value, cursor, None);
    (end > cursor).then_some((cursor, end))
}

fn quoted_secret_at(value: &str, index: usize) -> Option<(usize, usize)> {
    quoted_secret_at_inner(value, index, None)
}

fn quoted_secret_at_with_provenance(
    neutralized: &NeutralizedText,
    index: usize,
) -> Option<(usize, usize)> {
    quoted_secret_at_inner(neutralized.as_str(), index, Some(neutralized))
}

fn quoted_secret_at_inner(
    value: &str,
    index: usize,
    neutralized: Option<&NeutralizedText>,
) -> Option<(usize, usize)> {
    let cursor = secret_value_start(value, index, neutralized)?;
    let bytes = value.as_bytes();
    let (start, quote, escaped_outer) =
        if let Some(quote) = bytes.get(cursor).copied().filter(|byte| is_quote(*byte)) {
            (cursor + 1, quote, false)
        } else if bytes.get(cursor) == Some(&b'\\') {
            let quote = bytes
                .get(cursor + 1)
                .copied()
                .filter(|byte| is_quote(*byte))?;
            (cursor + 2, quote, true)
        } else {
            return None;
        };
    if start >= bytes.len() {
        return None;
    }
    let end = if escaped_outer {
        escaped_quoted_value_end(bytes, start, quote)
    } else {
        raw_quoted_value_end(bytes, start, quote)
    };
    (end > start).then_some((start, end))
}

fn json_quoted_secret_at(neutralized: &NeutralizedText, index: usize) -> Option<(usize, usize)> {
    let value = neutralized.as_str();
    let bytes = value.as_bytes();
    if bytes.get(index) != Some(&b'"') || !is_json_key_boundary(neutralized, index) {
        return None;
    }

    let mut cursor = index + 1;
    let mut normalized = String::with_capacity(16);
    let mut needs_alphanumeric = false;
    while let Some(byte) = bytes.get(cursor).copied() {
        if byte.is_ascii_alphanumeric() {
            if normalized.len() >= 32 {
                return None;
            }
            normalized.push(char::from(byte.to_ascii_lowercase()));
            cursor += 1;
            needs_alphanumeric = false;
        } else if matches!(byte, b'_' | b'-') {
            if normalized.is_empty() || needs_alphanumeric || normalized.len() >= 32 {
                return None;
            }
            normalized.push('_');
            cursor += 1;
            needs_alphanumeric = true;
        } else {
            break;
        }
    }
    if needs_alphanumeric || bytes.get(cursor) != Some(&b'"') || !is_secret_key(&normalized) {
        return None;
    }

    cursor = skip_json_whitespace(neutralized, cursor + 1);
    if bytes.get(cursor) != Some(&b':') {
        return None;
    }
    cursor = skip_json_whitespace(neutralized, cursor + 1);
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    let start = cursor + 1;
    if start >= bytes.len() {
        return None;
    }
    let end = raw_quoted_value_end(bytes, start, b'"');
    (end > start).then_some((start, end))
}

fn skip_json_whitespace(neutralized: &NeutralizedText, mut cursor: usize) -> usize {
    loop {
        if neutralized.as_str().as_bytes().get(cursor) == Some(&b' ') {
            cursor += 1;
        } else if let Some(marker) = neutralized
            .marker_at(cursor)
            .filter(|marker| is_json_whitespace_marker(*marker))
        {
            cursor = marker.end;
        } else {
            break;
        }
    }
    cursor
}

fn is_json_key_boundary(neutralized: &NeutralizedText, index: usize) -> bool {
    let bytes = neutralized.as_str().as_bytes();
    let mut cursor = index;
    loop {
        while cursor > 0 && bytes[cursor - 1] == b' ' {
            cursor -= 1;
        }
        if let Some(marker) = neutralized
            .marker_ending_at(cursor)
            .filter(|marker| is_json_whitespace_marker(*marker))
        {
            cursor = marker.start;
        } else {
            break;
        }
    }
    cursor > 0 && matches!(bytes[cursor - 1], b'{' | b',')
}

fn is_json_whitespace_marker(marker: GeneratedMarker) -> bool {
    marker.kind == MarkerKind::Control && matches!(marker.code_point, 0x0009 | 0x000a | 0x000d)
}

fn authorization_secret_at(neutralized: &NeutralizedText, index: usize) -> Option<(usize, usize)> {
    let value = neutralized.as_str();
    let bytes = value.as_bytes();
    let mut cursor =
        if let Some(key_end) = generated_keyword_end(neutralized, index, b"authorization") {
            let separator = skip_provenance_whitespace(neutralized, key_end);
            matches!(bytes.get(separator), Some(b'=' | b':')).then_some(())?;
            // LLM contract: AUTH_KEY -> RECORD_BOUNDARY_EMPTY | SAME_RECORD_CREDENTIAL.
            let value_start = separator + 1;
            let (cursor, crossed_record_boundary) =
                skip_authorization_value_whitespace(neutralized, value_start);
            if let Some(assignment_separator) =
                assignment_separator_at(value, cursor, Some(neutralized))
            {
                if crossed_record_boundary {
                    return None;
                }
                return authorization_assignment_credential_at(
                    neutralized,
                    cursor,
                    assignment_separator,
                );
            }
            cursor
        } else {
            let scheme_end = authorization_scheme_end(neutralized, index)?;
            let value_start = skip_provenance_whitespace(neutralized, scheme_end);
            (value_start > scheme_end).then_some(())?;
            return credential_value_at(neutralized, value_start);
        };

    if let Some(scheme_end) = authorization_scheme_end(neutralized, cursor) {
        let value_start = skip_provenance_whitespace(neutralized, scheme_end);
        (value_start > scheme_end).then_some(())?;
        cursor = value_start;
    }
    credential_value_at(neutralized, cursor)
}

fn authorization_scheme_end(neutralized: &NeutralizedText, index: usize) -> Option<usize> {
    generated_keyword_end(neutralized, index, b"basic")
        .or_else(|| generated_keyword_end(neutralized, index, b"bearer"))
}

fn generated_keyword_end(
    neutralized: &NeutralizedText,
    index: usize,
    keyword: &[u8],
) -> Option<usize> {
    const MAX_MARKERS: u8 = 8;
    const MAX_SPAN: usize = 256;

    let value = neutralized.as_str();
    is_word_boundary(value, index, true).then_some(())?;
    let mut cursor = index;
    let mut marker_count = 0;
    for (position, expected) in keyword.iter().enumerate() {
        if position > 0 {
            while let Some(marker) = neutralized
                .marker_at(cursor)
                .filter(|marker| matches!(marker.kind, MarkerKind::Bidi | MarkerKind::Format))
            {
                marker_count += 1;
                if marker_count > MAX_MARKERS || marker.end - index > MAX_SPAN {
                    return None;
                }
                cursor = marker.end;
            }
        }
        (value.as_bytes().get(cursor)?.to_ascii_lowercase() == *expected).then_some(())?;
        cursor += 1;
    }
    is_word_boundary(value, cursor, false).then_some(cursor)
}

fn skip_provenance_whitespace(neutralized: &NeutralizedText, mut cursor: usize) -> usize {
    loop {
        if let Some(marker) = neutralized
            .marker_at(cursor)
            .filter(|marker| is_assignment_whitespace_marker(*marker))
        {
            cursor = marker.end;
            continue;
        }
        let Some(character) = neutralized.as_str()[cursor..].chars().next() else {
            break;
        };
        if !character.is_whitespace() {
            break;
        }
        cursor += character.len_utf8();
    }
    cursor
}

fn skip_authorization_value_whitespace(
    neutralized: &NeutralizedText,
    mut cursor: usize,
) -> (usize, bool) {
    let mut crossed_record_boundary = false;
    loop {
        if let Some(marker) = neutralized
            .marker_at(cursor)
            .filter(|marker| is_assignment_whitespace_marker(*marker))
        {
            crossed_record_boundary |= matches!(marker.code_point, 0x000a | 0x000d);
            cursor = marker.end;
            continue;
        }
        let Some(character) = neutralized.as_str()[cursor..].chars().next() else {
            break;
        };
        if !character.is_whitespace() {
            break;
        }
        cursor += character.len_utf8();
    }
    (cursor, crossed_record_boundary)
}

fn is_assignment_whitespace_marker(marker: GeneratedMarker) -> bool {
    marker.kind == MarkerKind::Control && matches!(marker.code_point, 0x0009..=0x000d)
}

fn credential_value_at(neutralized: &NeutralizedText, cursor: usize) -> Option<(usize, usize)> {
    let value = neutralized.as_str();
    let bytes = value.as_bytes();
    if let Some(quote) = bytes.get(cursor).copied().filter(|byte| is_quote(*byte)) {
        let start = cursor + 1;
        let end = raw_quoted_value_end(bytes, start, quote);
        return (end > start).then_some((start, end));
    }
    if bytes.get(cursor) == Some(&b'\\') {
        if let Some(quote) = bytes
            .get(cursor + 1)
            .copied()
            .filter(|byte| is_quote(*byte))
        {
            let start = cursor + 2;
            let end = escaped_quoted_value_end(bytes, start, quote);
            return (end > start).then_some((start, end));
        }
    }
    let mut end = unquoted_value_end(value, cursor, Some(neutralized));
    if let Some(quote_start) = authorization_quote_start(neutralized, cursor, end) {
        end = quote_start;
    }
    (end > cursor).then_some((cursor, end))
}

fn authorization_assignment_credential_at(
    neutralized: &NeutralizedText,
    start: usize,
    separator: usize,
) -> Option<(usize, usize)> {
    let value = neutralized.as_str();
    let bytes = value.as_bytes();
    let (mut cursor, crossed_record_boundary) =
        skip_authorization_value_whitespace(neutralized, separator + 1);
    if crossed_record_boundary && looks_like_assignment(value, cursor, Some(neutralized)) {
        return None;
    }
    if let Some(scheme_end) = authorization_scheme_end(neutralized, cursor) {
        let credential_start = skip_provenance_whitespace(neutralized, scheme_end);
        (credential_start > scheme_end).then_some(())?;
        cursor = credential_start;
    }
    let (content_start, content_end, redaction_end) =
        if let Some(quote) = bytes.get(cursor).copied().filter(|byte| is_quote(*byte)) {
            let content_start = cursor + 1;
            let content_end = raw_quoted_value_end(bytes, content_start, quote);
            let redaction_end = content_end
                + usize::from(bytes.get(content_end).is_some_and(|byte| *byte == quote));
            (content_start, content_end, redaction_end)
        } else if bytes.get(cursor) == Some(&b'\\')
            && bytes.get(cursor + 1).is_some_and(|byte| is_quote(*byte))
        {
            let quote = bytes
                .get(cursor + 1)
                .copied()
                .expect("escaped quote checked above");
            let content_start = cursor + 2;
            let content_end = escaped_quoted_value_end(bytes, content_start, quote);
            let has_closing_quote = bytes.get(content_end) == Some(&b'\\')
                && bytes.get(content_end + 1) == Some(&quote);
            let redaction_end = content_end + usize::from(has_closing_quote) * 2;
            (content_start, content_end, redaction_end)
        } else {
            let content_end = unquoted_value_end(value, cursor, Some(neutralized));
            (cursor, content_end, content_end)
        };
    (content_end > content_start).then_some((start, redaction_end))
}

// LLM contract: SCHEME_MATCHED -> RAW_OR_ESCAPED_QUOTE_BOUNDARY -> CREDENTIAL_BOUNDED.
fn authorization_quote_start(
    neutralized: &NeutralizedText,
    start: usize,
    end: usize,
) -> Option<usize> {
    let bytes = neutralized.as_str().as_bytes();
    (start..end).find_map(|cursor| {
        (is_quote(bytes[cursor]) && is_authorization_quote_suffix(neutralized, cursor + 1)).then(
            || {
                if is_escaped(bytes, start, cursor) {
                    cursor - 1
                } else {
                    cursor
                }
            },
        )
    })
}

fn is_authorization_quote_suffix(neutralized: &NeutralizedText, index: usize) -> bool {
    if neutralized
        .marker_at(index)
        .is_some_and(is_assignment_whitespace_marker)
    {
        return true;
    }
    let bytes = neutralized.as_str().as_bytes();
    let Some(suffix) = bytes.get(index..) else {
        return false;
    };
    if suffix.is_empty() {
        return true;
    }
    matches!(suffix[0], b',' | b';' | b'&' | b'}' | b']' | b')')
        || std::str::from_utf8(suffix)
            .ok()
            .and_then(|value| value.chars().next())
            .is_some_and(char::is_whitespace)
}

fn is_word_boundary(value: &str, index: usize, before: bool) -> bool {
    let character = if before {
        value.get(..index).and_then(|side| side.chars().next_back())
    } else {
        value.get(index..).and_then(|side| side.chars().next())
    };
    character
        .is_none_or(|character| !character.is_alphanumeric() && !matches!(character, '_' | '-'))
}

fn secret_value_start(
    value: &str,
    index: usize,
    neutralized: Option<&NeutralizedText>,
) -> Option<usize> {
    let matched = recognize_secret_key(value, index)?;
    let bytes = value.as_bytes();
    let mut cursor = matched.end;
    if matched.cli_dashes > 0 {
        if bytes.get(cursor) == Some(&b'=') {
            let value_start = cursor + 1;
            cursor = skip_assignment_whitespace_with_provenance(value, value_start, neutralized);
            if cursor > value_start && looks_like_assignment(value, cursor, neutralized) {
                return None;
            }
        } else if skip_assignment_whitespace_with_provenance(value, cursor, neutralized) > cursor {
            cursor = skip_assignment_whitespace_with_provenance(value, cursor, neutralized);
            if matches!(bytes.get(cursor), Some(b'=' | b':')) {
                return None;
            }
            if looks_like_assignment(value, cursor, neutralized) {
                return None;
            }
        } else {
            return None;
        }
    } else {
        cursor = skip_assignment_whitespace_with_provenance(value, cursor, neutralized);
        if !matches!(bytes.get(cursor), Some(b'=' | b':')) {
            return None;
        }
        let value_start = cursor + 1;
        cursor = skip_assignment_whitespace_with_provenance(value, value_start, neutralized);
        if matches!(bytes.get(cursor), Some(b'=' | b':'))
            || (cursor > value_start && looks_like_assignment(value, cursor, neutralized))
        {
            return None;
        }
    }
    Some(cursor)
}

fn raw_quoted_value_end(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut cursor = start;
    while cursor < bytes.len() {
        if bytes[cursor] == quote && !is_escaped(bytes, start, cursor) {
            break;
        }
        cursor += 1;
    }
    cursor
}

fn escaped_quoted_value_end(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut cursor = start;
    while cursor + 1 < bytes.len() {
        if bytes[cursor] == b'\\' && bytes[cursor + 1] == quote && !is_escaped(bytes, start, cursor)
        {
            return cursor;
        }
        cursor += 1;
    }
    bytes.len()
}

fn unquoted_value_end(value: &str, start: usize, neutralized: Option<&NeutralizedText>) -> usize {
    let bytes = value.as_bytes();
    let mut cursor = start;
    while cursor < value.len() {
        if neutralized
            .and_then(|text| text.marker_at(cursor))
            .is_some_and(is_assignment_whitespace_marker)
        {
            break;
        }
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
        #[cfg(test)]
        ASSIGNMENT_WHITESPACE_SCAN_STEPS.with(|steps| steps.set(steps.get() + 1));
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

fn skip_assignment_whitespace_with_provenance(
    value: &str,
    cursor: usize,
    neutralized: Option<&NeutralizedText>,
) -> usize {
    neutralized.map_or_else(
        || skip_assignment_whitespace(value, cursor),
        |text| skip_provenance_whitespace(text, cursor),
    )
}

fn looks_like_assignment(value: &str, start: usize, neutralized: Option<&NeutralizedText>) -> bool {
    assignment_separator_at(value, start, neutralized).is_some()
}

fn assignment_separator_at(
    value: &str,
    start: usize,
    neutralized: Option<&NeutralizedText>,
) -> Option<usize> {
    const MAX_MARKERS: u8 = 8;
    const MAX_MARKER_SPAN: usize = 256;

    // LLM contract: CANDIDATE -> PROVENANCE_MARKERS_BOUNDED -> ASSIGNMENT | REJECTED.
    let mut cursor = start;
    let mut marker_count = 0;
    let mut saw_key_character = false;
    let mut needs_key_character = false;
    while let Some(character) = value[cursor..].chars().next() {
        if saw_key_character && value.as_bytes().get(cursor) == Some(&b'[') {
            if let Some(marker) = neutralized
                .and_then(|text| text.marker_at(cursor))
                .filter(|marker| matches!(marker.kind, MarkerKind::Bidi | MarkerKind::Format))
            {
                marker_count += 1;
                if marker_count > MAX_MARKERS || marker.end - start > MAX_MARKER_SPAN {
                    return None;
                }
                cursor = marker.end;
                needs_key_character = true;
                continue;
            }
        }
        if !(character.is_alphanumeric() || matches!(character, '_' | '-')) {
            break;
        }
        cursor += character.len_utf8();
        saw_key_character = true;
        needs_key_character = false;
    }
    if !saw_key_character || needs_key_character {
        return None;
    }
    let separator = skip_assignment_whitespace_with_provenance(value, cursor, neutralized);
    value
        .as_bytes()
        .get(separator)
        .is_some_and(|byte| matches!(byte, b'=' | b':'))
        .then_some(separator)
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
    use super::{
        ASSIGNMENT_WHITESPACE_SCAN_STEPS, GeneratedMarker, MarkerKind, PROVIDER_TOKEN_PREFIXES,
        SanitizeError, neutralize_external_text, quoted_secret_at, recognize_secret_key,
        sanitize_external_text, sanitize_identifier_text, sanitize_repository_path_text,
        unquoted_secret_at,
    };

    #[test]
    fn records_only_generated_marker_provenance_in_output_order() {
        let control = "[CONTROL-U+0009]";
        let bidi = "[BIDI-U+202E]";
        let format = "[FORMAT-U+180E]";
        let expected = format!("{control}{bidi}{format}[CONTROL-U+0009]");
        let actual =
            neutralize_external_text("\t\u{202e}\u{180e}[CONTROL-U+0009]", expected.len()).unwrap();

        assert_eq!(actual.as_str(), expected);
        assert_eq!(
            actual.markers,
            [
                GeneratedMarker::new(0, control.len(), MarkerKind::Control, 0x0009),
                GeneratedMarker::new(
                    control.len(),
                    control.len() + bidi.len(),
                    MarkerKind::Bidi,
                    0x202e,
                ),
                GeneratedMarker::new(
                    control.len() + bidi.len(),
                    control.len() + bidi.len() + format.len(),
                    MarkerKind::Format,
                    0x180e,
                ),
            ]
        );
        assert_eq!(
            neutralize_external_text("\0", control.len() - 1),
            Err(SanitizeError::OutputLimitExceeded {
                max_bytes: control.len() - 1,
            })
        );
    }

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
    fn impossible_key_starts_do_not_scan_suffix_whitespace() {
        ASSIGNMENT_WHITESPACE_SCAN_STEPS.with(|steps| steps.set(0));
        assert!(recognize_secret_key("token \t=value", 0).is_some());
        assert!(ASSIGNMENT_WHITESPACE_SCAN_STEPS.with(std::cell::Cell::get) > 0);

        ASSIGNMENT_WHITESPACE_SCAN_STEPS.with(|steps| steps.set(0));
        let whitespace = " \t\n\u{2003}".repeat(64);
        for (index, _) in whitespace.char_indices() {
            assert_eq!(recognize_secret_key(&whitespace, index), None);
        }
        assert_eq!(
            ASSIGNMENT_WHITESPACE_SCAN_STEPS.with(std::cell::Cell::get),
            0
        );
    }

    #[test]
    fn secret_key_aliases_preserve_separator_positions() {
        let accepted = [
            "token",
            "api_key",
            "api-key",
            "password",
            "passwd",
            "secret",
            "client_secret",
            "client-secret",
            "access_token",
            "access-token",
            "refresh_token",
            "refresh-token",
            "private_key",
            "private-key",
        ];
        for key in accepted {
            let input = format!("{key}=");
            assert_eq!(recognize_secret_key(&input, 0).unwrap().end, key.len());
        }

        for key in [
            "apikey",
            "clientsecret",
            "s-e-c-r-e-t",
            "pa-ssword",
            "api__key",
            "api--key",
            "--_token",
            "token_",
            "api-key-",
        ] {
            let input = format!("{key}=");
            assert_eq!(recognize_secret_key(&input, 0), None, "key {key:?}");
        }
    }

    #[test]
    fn redacts_only_declared_secret_key_aliases() {
        let input = "api-key=one client_secret=two";
        assert_eq!(
            sanitize_external_text(input, 4096).unwrap().as_str(),
            "api-key=[REDACTED_SECRET] client_secret=[REDACTED_SECRET]"
        );

        for (input, expected) in [
            ("s-e-c-r-e-t=public", "s-e-c-r-e-t=public"),
            ("pa-ssword:public", "pa-ssword:public"),
            ("apikey=public", "apikey=public"),
            (
                r#"{"clientsecret":"public","client-secret":"private"}"#,
                r#"{"clientsecret":"public","client-secret":"[REDACTED_SECRET]"}"#,
            ),
        ] {
            assert_eq!(
                sanitize_external_text(input, 4096).unwrap().as_str(),
                expected,
                "input {input:?}"
            );
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
    fn redacts_documented_gitlab_session_cookie_at_exact_boundaries() {
        // Sources: docs.gitlab.com/security/tokens/#token-prefixes and
        // docs.gitlab.com/api/rest/authentication/#session-cookie.
        let cases = [
            (
                "_gitlab_session=opaquevalue",
                "_gitlab_session=[REDACTED_SECRET]",
            ),
            (
                "_gitlab_session=\"opaquevalue\"",
                "_gitlab_session=\"[REDACTED_SECRET]\"",
            ),
            (
                "_gitlab_session='opaquevalue'",
                "_gitlab_session='[REDACTED_SECRET]'",
            ),
            (
                "Cookie: a=1;_gitlab_session=opaquevalue; theme=dark",
                "Cookie: a=1;_gitlab_session=[REDACTED_SECRET]; theme=dark",
            ),
            (
                "Set-Cookie: _gitlab_session=opaquevalue; Path=/; HttpOnly",
                "Set-Cookie: _gitlab_session=[REDACTED_SECRET]; Path=/; HttpOnly",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                sanitize_external_text(input, 4096).unwrap().as_str(),
                expected,
                "input {input:?}"
            );
        }

        for input in [
            "x_gitlab_session=opaquevalue",
            "-_gitlab_session=opaquevalue",
            "_gitlab_sessions=opaquevalue",
            "_gitlab_session_id=opaquevalue",
            "_gitlab-session=opaquevalue",
            "_GITLAB_SESSION=opaquevalue",
            "_gitlab_session: opaquevalue",
            "_gitlab_session =opaquevalue",
            "_gitlab_session=",
        ] {
            assert_eq!(sanitize_external_text(input, 4096).unwrap().as_str(), input);
        }

        let expected = "_gitlab_session=[REDACTED_SECRET]";
        assert_eq!(
            sanitize_external_text("_gitlab_session=x", expected.len())
                .unwrap()
                .as_str(),
            expected
        );
        assert_eq!(
            sanitize_external_text("_gitlab_session=x", expected.len() - 1),
            Err(SanitizeError::OutputLimitExceeded {
                max_bytes: expected.len() - 1,
            })
        );

        let repeated = "_gitlab_sessionx=public;".repeat(10_000);
        assert_eq!(
            sanitize_external_text(&repeated, repeated.len())
                .unwrap()
                .as_str(),
            repeated
        );
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
    fn parses_raw_and_escaped_quoted_secret_value_spans() {
        let cases = [
            (r#"token="secret" next"#, "secret"),
            ("token='秘密' tail", "秘密"),
            (r#"--client-secret "tiny" rest"#, "tiny"),
            (r#"token="a\"b" tail"#, r#"a\"b"#),
            (r#"token=\"secret\" tail"#, "secret"),
            (r"token=\'secret\' tail", "secret"),
            (r#"token="missing"#, "missing"),
            (r#"token=\"missing"#, "missing"),
        ];
        for (input, expected_value) in cases {
            let (start, end) = quoted_secret_at(input, 0).unwrap();
            assert_eq!(&input[start..end], expected_value, "input {input:?}");
        }

        for input in [
            "token=\"\"",
            "token=''",
            r#"token=\"\""#,
            "token=\"",
            r#"token=\""#,
            r#""token":"secret""#,
        ] {
            assert_eq!(quoted_secret_at(input, 0), None, "input {input:?}");
        }
    }

    #[test]
    fn quoted_delimiters_use_fixed_backslash_parity() {
        for slash_count in 0..=4 {
            let slashes = "\\".repeat(slash_count);
            let input = format!("token=\"value{slashes}\"tail");
            let expected = if slash_count % 2 == 0 {
                format!("value{slashes}")
            } else {
                format!("value{slashes}\"tail")
            };
            let (start, end) = quoted_secret_at(&input, 0).unwrap();
            assert_eq!(&input[start..end], expected, "raw input {input:?}");

            let input = format!("token=\\\"value{slashes}\\\"tail");
            let expected = if slash_count % 2 == 0 {
                format!("value{slashes}")
            } else {
                format!("value{slashes}\\\"tail")
            };
            let (start, end) = quoted_secret_at(&input, 0).unwrap();
            assert_eq!(&input[start..end], expected, "escaped input {input:?}");
        }
    }

    #[test]
    fn redacts_quoted_spans_and_preserves_outer_delimiters() {
        let cases = [
            ("token=\"secret\" next", "token=\"[REDACTED_SECRET]\" next"),
            ("token='秘密' tail", "token='[REDACTED_SECRET]' tail"),
            (
                "token=\\\"secret\\\" next",
                "token=\\\"[REDACTED_SECRET]\\\" next",
            ),
            ("token=\"missing", "token=\"[REDACTED_SECRET]"),
            ("token=\\\"missing", "token=\\\"[REDACTED_SECRET]"),
            (
                "token=one password='two' client_secret=\\\"three\\\" end",
                "token=[REDACTED_SECRET] password='[REDACTED_SECRET]' client_secret=\\\"[REDACTED_SECRET]\\\" end",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                sanitize_external_text(input, 4096).unwrap().as_str(),
                expected,
                "input {input:?}"
            );
        }

        for input in ["token=\"\"", "token=''", "token=\\\"\\\""] {
            assert_eq!(sanitize_external_text(input, 4096).unwrap().as_str(), input);
        }
    }

    #[test]
    fn quoted_redaction_obeys_the_exact_output_bound() {
        let expected = "token=\"[REDACTED_SECRET]\"";
        assert_eq!(
            sanitize_external_text("token=\"x\"", expected.len())
                .unwrap()
                .as_str(),
            expected
        );
        assert_eq!(
            sanitize_external_text("token=\"x\"", expected.len() - 1),
            Err(SanitizeError::OutputLimitExceeded {
                max_bytes: expected.len() - 1,
            })
        );
    }

    #[test]
    fn redacts_compact_and_provenance_aware_json_secrets() {
        let cases = [
            (
                r#"{"token":"secret","name":"ok"}"#,
                r#"{"token":"[REDACTED_SECRET]","name":"ok"}"#,
            ),
            (
                r#"{"API_KEY":"秘密"}"#,
                r#"{"API_KEY":"[REDACTED_SECRET]"}"#,
            ),
            (
                "{\n  \"token\"\t:\r \"secret\"\n}",
                "{[CONTROL-U+000A]  \"token\"[CONTROL-U+0009]:[CONTROL-U+000D] \"[REDACTED_SECRET]\"[CONTROL-U+000A]}",
            ),
            (
                "{\"token\"\u{000b}:\"PUBLIC\"}",
                "{\"token\"[CONTROL-U+000B]:\"PUBLIC\"}",
            ),
            (
                "{\"token\"\u{000c}:\"PUBLIC\"}",
                "{\"token\"[CONTROL-U+000C]:\"PUBLIC\"}",
            ),
            (
                r#"{"token":"a\"b","password":"two"}"#,
                r#"{"token":"[REDACTED_SECRET]","password":"[REDACTED_SECRET]"}"#,
            ),
            ("{\"token\":\"missing", "{\"token\":\"[REDACTED_SECRET]"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                sanitize_external_text(input, 4096).unwrap().as_str(),
                expected,
                "input {input:?}"
            );
        }
    }

    #[test]
    fn rejects_non_json_or_unprovenanced_key_separators() {
        for input in [
            r#"{"name":"PUBLIC"}"#,
            r#"{"token":""}"#,
            r#"{"token":'PUBLIC'}"#,
            r#"{"tok\u0065n":"PUBLIC"}"#,
            r#"{"token-":"PUBLIC"}"#,
            r#"{"to--ken":"PUBLIC"}"#,
            r#"{"note":"embedded \"token\":\"PUBLIC\" text"}"#,
            r#"prefix "token":"PUBLIC""#,
            r#"{"token"[CONTROL-U+0009]:"PUBLIC"}"#,
            "{\"token\"\u{2003}:\"PUBLIC\"}",
        ] {
            assert_eq!(
                sanitize_external_text(input, 4096).unwrap().as_str(),
                input,
                "input {input:?}"
            );
        }
    }

    #[test]
    fn json_redaction_obeys_the_exact_output_bound() {
        let expected = r#"{"token":"[REDACTED_SECRET]"}"#;
        assert_eq!(
            sanitize_external_text(r#"{"token":"x"}"#, expected.len())
                .unwrap()
                .as_str(),
            expected
        );
        assert_eq!(
            sanitize_external_text(r#"{"token":"x"}"#, expected.len() - 1),
            Err(SanitizeError::OutputLimitExceeded {
                max_bytes: expected.len() - 1,
            })
        );
    }

    #[test]
    fn redacts_authorization_and_bare_scheme_credentials() {
        let cases = [
            (
                "Authorization: Basic credential, next=ok",
                "Authorization: Basic [REDACTED_SECRET], next=ok",
            ),
            (
                "authorization = bearer TOKEN; next=ok",
                "authorization = bearer [REDACTED_SECRET]; next=ok",
            ),
            (
                "AUTHORIZATION: opaque&next=ok",
                "AUTHORIZATION: [REDACTED_SECRET]&next=ok",
            ),
            ("Basic abc123 tail", "Basic [REDACTED_SECRET] tail"),
            (
                "Bearer \"secret\" tail",
                "Bearer \"[REDACTED_SECRET]\" tail",
            ),
            ("Bearer abc'def tail", "Bearer [REDACTED_SECRET] tail"),
            (
                "Bea\u{200b}rer value tail",
                "Bea[FORMAT-U+200B]rer [REDACTED_SECRET] tail",
            ),
            (
                "Bearer value\nnext=ok",
                "Bearer [REDACTED_SECRET][CONTROL-U+000A]next=ok",
            ),
            (
                "Authori\u{202e}zation:\topaque, next=ok",
                "Authori[BIDI-U+202E]zation:[CONTROL-U+0009][REDACTED_SECRET], next=ok",
            ),
        ];

        for (input, expected) in cases {
            let actual = sanitize_external_text(input, 4096).unwrap();
            assert_eq!(actual.as_str(), expected, "input {input:?}");
        }
    }

    #[test]
    fn escaped_quoted_authorization_preserves_delimiters_and_bounds() {
        let cases = [
            (
                r#"Bearer \"secret\" tail"#,
                r#"Bearer \"[REDACTED_SECRET]\" tail"#,
            ),
            (
                r"Basic \'secret\' tail",
                r"Basic \'[REDACTED_SECRET]\' tail",
            ),
            (
                r#"Authorization: Bearer \"secret\"; next=ok"#,
                r#"Authorization: Bearer \"[REDACTED_SECRET]\"; next=ok"#,
            ),
            (r#"Bearer \"missing"#, r#"Bearer \"[REDACTED_SECRET]"#),
        ];

        for (input, expected) in cases {
            let required_bytes = input.len().max(expected.len());
            assert_eq!(
                sanitize_external_text(input, required_bytes)
                    .unwrap_or_else(|error| panic!("input {input:?}: {error}"))
                    .as_str(),
                expected,
                "input {input:?}"
            );
            assert_eq!(
                sanitize_external_text(input, required_bytes - 1),
                Err(SanitizeError::OutputLimitExceeded {
                    max_bytes: required_bytes - 1,
                }),
                "input {input:?}"
            );
        }
    }

    #[test]
    fn quoted_authorization_preserves_enclosing_delimiters_and_following_fields() {
        let cases = [
            (
                r#"{"Authorization":"Bearer TOKEN","name":"ok"}"#,
                r#"{"Authorization":"Bearer [REDACTED_SECRET]","name":"ok"}"#,
            ),
            (
                r#"{"Authorization":"Basic TOKEN","name":"ok"}"#,
                r#"{"Authorization":"Basic [REDACTED_SECRET]","name":"ok"}"#,
            ),
            (
                r#"{\"Authorization\":\"Bearer TOKEN\",\"name\":\"ok\"}"#,
                r#"{\"Authorization\":\"Bearer [REDACTED_SECRET]\",\"name\":\"ok\"}"#,
            ),
            (
                r#"{"Authorization":"  Bearer TOKEN","name":"ok"}"#,
                r#"{"Authorization":"  Bearer [REDACTED_SECRET]","name":"ok"}"#,
            ),
            (
                r#"{"Authorization":"Bearer TOKEN"#,
                r#"{"Authorization":"Bearer [REDACTED_SECRET]"#,
            ),
            (
                r#"{\"Authorization\":\"Basic TOKEN"#,
                r#"{\"Authorization\":\"Basic [REDACTED_SECRET]"#,
            ),
            (
                "\"Bearer TOKEN\"\nnext=ok",
                "\"Bearer [REDACTED_SECRET]\"[CONTROL-U+000A]next=ok",
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(
                sanitize_external_text(input, expected.len())
                    .unwrap()
                    .as_str(),
                expected,
                "input {input:?}"
            );
            assert_eq!(
                sanitize_external_text(input, expected.len() - 1),
                Err(SanitizeError::OutputLimitExceeded {
                    max_bytes: expected.len() - 1,
                }),
                "bound for {input:?}"
            );
        }
    }

    #[test]
    fn rejects_missing_ambiguous_or_spoofed_scheme_values() {
        for input in [
            "Basic",
            "Bearer , next=ok",
            "Authorization: Basic",
            "Authorization: Bearer, next=ok",
            "Basic=secret",
            "xBearer secret",
            "Bearerish secret",
            "αBearer secret",
            "Bearerβ secret",
            "Bea[FORMAT-U+200B]rer secret",
        ] {
            let actual = sanitize_external_text(input, 4096).unwrap();
            assert_eq!(actual.as_str(), input, "input {input:?}");
        }
    }

    #[test]
    fn redacts_assignment_shaped_authorization_credentials_on_the_same_record() {
        let cases = [
            (
                "Authorization: ApiKey=abcdef",
                "Authorization: [REDACTED_SECRET]",
            ),
            (
                "Authorization: Credential=abcdef",
                "Authorization: [REDACTED_SECRET]",
            ),
            (
                "Authorization: token = abcdef",
                "Authorization: [REDACTED_SECRET]",
            ),
            (
                "Authorization: token = abcdef next=ok",
                "Authorization: [REDACTED_SECRET] next=ok",
            ),
            (
                "Authorization: ApiKey= abcdef",
                "Authorization: [REDACTED_SECRET]",
            ),
            (
                "Authorization: token=Bearer abcdef",
                "Authorization: [REDACTED_SECRET]",
            ),
            (
                "Authorization: Credential = \"abcdef\"",
                "Authorization: [REDACTED_SECRET]",
            ),
            (
                "Authorization: Credential = \"abcdef\", next=ok",
                "Authorization: [REDACTED_SECRET], next=ok",
            ),
            (
                r#"Authorization: token = \"abcdef\""#,
                "Authorization: [REDACTED_SECRET]",
            ),
            (
                r"Authorization: Credential=\abcdef",
                "Authorization: [REDACTED_SECRET]",
            ),
            (
                "authorization:\tcredential=abcdef",
                "authorization:[CONTROL-U+0009][REDACTED_SECRET]",
            ),
            (
                "Authorization:\nnext=ok",
                "Authorization:[CONTROL-U+000A]next=ok",
            ),
            (
                "Authorization: token=\nnext=ok",
                "Authorization: token=[CONTROL-U+000A]next=ok",
            ),
            (
                "Authorization: token=\nBearer abcdef",
                "Authorization: [REDACTED_SECRET]",
            ),
            (
                "Authorization: token = \r\nnext=ok",
                "Authorization: token = [CONTROL-U+000D][CONTROL-U+000A]next=ok",
            ),
            (
                "Authorization: token=\tnext=ok",
                "Authorization: [REDACTED_SECRET]",
            ),
            (
                "Authorization: token=[CONTROL-U+000A]next=ok",
                "Authorization: [REDACTED_SECRET]",
            ),
            (
                "Authorization:\r\nnext=ok",
                "Authorization:[CONTROL-U+000D][CONTROL-U+000A]next=ok",
            ),
        ];

        for (input, expected) in cases {
            let neutralized_bytes = neutralize_external_text(input, 4096)
                .unwrap()
                .as_str()
                .len();
            let required_bytes = neutralized_bytes.max(expected.len());
            assert_eq!(
                sanitize_external_text(input, required_bytes)
                    .unwrap_or_else(|error| panic!("input {input:?}: {error}"))
                    .as_str(),
                expected,
                "input {input:?}"
            );
            assert_eq!(
                sanitize_external_text(input, required_bytes - 1),
                Err(SanitizeError::OutputLimitExceeded {
                    max_bytes: required_bytes - 1,
                }),
                "input {input:?}"
            );
        }
    }

    #[test]
    fn empty_authorization_preserves_only_provenance_backed_following_assignments() {
        let cases = [
            (
                "Authorization:\nnext=ok",
                "Authorization:[CONTROL-U+000A]next=ok",
            ),
            (
                "Authorization:   next=ok",
                "Authorization:   [REDACTED_SECRET]",
            ),
            (
                "Authorization:\tnext=ok",
                "Authorization:[CONTROL-U+0009][REDACTED_SECRET]",
            ),
            ("--token=\nnext=ok", "--token=[CONTROL-U+000A]next=ok"),
            (
                "Authorization:[CONTROL-U+000A]next=ok",
                "Authorization:[REDACTED_SECRET]",
            ),
            (
                "--token=[CONTROL-U+000A]next=ok",
                "--token=[REDACTED_SECRET]",
            ),
            (
                "Authorization:\nBearer credential",
                "Authorization:[CONTROL-U+000A]Bearer [REDACTED_SECRET]",
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(
                sanitize_external_text(input, input.len().max(expected.len()))
                    .unwrap()
                    .as_str(),
                expected,
                "input {input:?}"
            );
        }

        let input = "Authorization:\nnext=ok";
        let expected = "Authorization:[CONTROL-U+000A]next=ok";
        assert_eq!(
            sanitize_external_text(input, expected.len() - 1),
            Err(SanitizeError::OutputLimitExceeded {
                max_bytes: expected.len() - 1,
            })
        );
    }

    #[test]
    fn authorization_redaction_is_bounded_on_repeated_nonmatches() {
        let expected = "Bearer [REDACTED_SECRET]";
        assert_eq!(
            sanitize_external_text("Bearer x", expected.len())
                .unwrap()
                .as_str(),
            expected
        );
        assert_eq!(
            sanitize_external_text("Bearer x", expected.len() - 1),
            Err(SanitizeError::OutputLimitExceeded {
                max_bytes: expected.len() - 1,
            })
        );

        let input = "basicish bearerish authorizationish ".repeat(10_000);
        let actual = sanitize_external_text(&input, input.len()).unwrap();
        assert_eq!(actual.as_str(), input);
    }

    #[test]
    fn redacts_documented_provider_and_jwt_token_shapes() {
        // Sources: docs.github.com/.../about-authentication-to-github#githubs-token-formats,
        // docs.gitlab.com/security/tokens/#token-prefixes, and
        // github.blog/changelog/2021-09-23-npm-has-a-new-access-token-format/.
        // Payload lengths and `sk-` are this sanitizer's explicit bounded v1 contract.
        for &(prefix, minimum, allow_dot) in PROVIDER_TOKEN_PREFIXES {
            let mut payload = "A1".repeat(minimum.div_ceil(2));
            if allow_dot {
                payload.insert(minimum / 2, '.');
            }
            let input = format!("before {prefix}{payload}, after");
            let expected = "before [REDACTED_SECRET], after";
            let actual = sanitize_external_text(&input, 4096).unwrap();
            assert_eq!(actual.as_str(), expected);
        }

        // rfc-editor.org/rfc/rfc7519.html: JWS compact form has three base64url parts.
        let jwt = "eyJhbGciOiJIUzI1NiJ9.e30.c2lnbmF0dXJlMDEyMzQ1Njc4OTA";
        let actual = sanitize_external_text(jwt, 4096).unwrap();
        assert_eq!(actual.as_str(), "[REDACTED_SECRET]");

        let generic = "Ab1_".repeat(8);
        let actual = sanitize_external_text(&generic, 4096).unwrap();
        assert_eq!(actual.as_str(), "[REDACTED_SECRET]");
    }

    #[test]
    fn preserves_identifiers_and_rejects_token_shape_spoofs() {
        let finding_id = "019f7e95-0000-7000-8000-000000000105";
        let digest = "a".repeat(64);
        let generic = "Ab1_".repeat(8);
        for identifier in [
            finding_id,
            digest.as_str(),
            "F821",
            "sk-linter",
            "ghp_A1A1A1A1A1A1A1A1A1A1",
            generic.as_str(),
        ] {
            let actual = sanitize_identifier_text(identifier, 4096).unwrap();
            assert_eq!(actual.as_str(), identifier);
        }

        for input in [
            finding_id,
            digest.as_str(),
            "sk-linter",
            "ghp_short",
            "a.b.c",
        ] {
            let actual = sanitize_external_text(input, 4096).unwrap();
            assert_eq!(actual.as_str(), input);
        }
        let actual = sanitize_external_text("ghp_A1A1A1A1A1\u{200b}A1A1A1A1A1", 4096).unwrap();
        assert_eq!(actual.as_str(), "ghp_A1A1A1A1A1[FORMAT-U+200B]A1A1A1A1A1");
    }

    #[test]
    fn preserves_repository_relative_path_components_without_weakening_token_redaction() {
        let first = "Ab1_".repeat(8);
        let second = "Cd2-".repeat(8);
        let ambiguous = format!("logs/{first}/trace.txt");
        assert_eq!(
            sanitize_external_text(&ambiguous, 4096).unwrap().as_str(),
            "logs/[REDACTED_SECRET]/trace.txt"
        );
        for path in [
            format!("dist/{first}/bundle.js"),
            format!("資料/{first}/詳細/{second}/mod.rs"),
            format!("{first}/bundle.js"),
            format!("dist/{first}"),
        ] {
            let repo_path = path.parse().unwrap();
            let actual = sanitize_repository_path_text(&repo_path, path.len()).unwrap();
            assert_eq!(actual.as_str(), path);
        }

        let path = format!("dist/{first}/bundle.js");
        let repo_path = path.parse().unwrap();
        assert_eq!(
            sanitize_repository_path_text(&repo_path, path.len() - 1),
            Err(SanitizeError::OutputLimitExceeded {
                max_bytes: path.len() - 1,
            })
        );

        for input in [
            first.clone(),
            format!("https://example.test/{first}/bundle.js"),
            format!("/dist/{first}/bundle.js"),
            format!("../dist/{first}/bundle.js"),
        ] {
            let actual = sanitize_external_text(&input, 4096).unwrap();
            assert!(actual.as_str().contains("[REDACTED_SECRET]"));
        }

        let provider = format!("dist/ghp_{}/bundle.js", "A1".repeat(10));
        let provider_path = provider.parse().unwrap();
        assert_eq!(
            sanitize_repository_path_text(&provider_path, 4096)
                .unwrap()
                .as_str(),
            "dist/[REDACTED_SECRET]/bundle.js"
        );
        let jwt = "eyJhbGciOiJIUzI1NiJ9.e30.c2lnbmF0dXJlMDEyMzQ1Njc4OTA";
        let jwt_path = format!("dist/{jwt}/bundle.js");
        let jwt_repo_path = jwt_path.parse().unwrap();
        assert_eq!(
            sanitize_repository_path_text(&jwt_repo_path, 4096)
                .unwrap()
                .as_str(),
            "dist/[REDACTED_SECRET]/bundle.js"
        );

        let repeated = std::iter::repeat_n(first.as_str(), 10_000)
            .collect::<Vec<_>>()
            .join("/");
        let redacted = std::iter::repeat_n("[REDACTED_SECRET]", 10_000)
            .collect::<Vec<_>>()
            .join("/");
        assert_eq!(
            sanitize_external_text(&repeated, repeated.len())
                .unwrap()
                .as_str(),
            redacted
        );
    }

    #[test]
    fn token_scanning_is_bounded_on_long_and_repeated_prefixes() {
        for input in ["A".repeat(31), "A".repeat(129)] {
            assert_eq!(
                sanitize_external_text(&input, 4096).unwrap().as_str(),
                input
            );
        }
        let input = "ghp_short sk-linter not.a.jwt ".repeat(10_000);
        let actual = sanitize_external_text(&input, input.len()).unwrap();
        assert_eq!(actual.as_str(), input);
    }

    #[test]
    fn redacts_every_parsed_unquoted_secret_span() {
        let cases = [
            ("token=secret next=ok", "token=[REDACTED_SECRET] next=ok"),
            (
                "--client-secret tiny rest",
                "--client-secret [REDACTED_SECRET] rest",
            ),
            ("token=foo\\ bar tail", "token=[REDACTED_SECRET] tail"),
            ("token=trailing\\", "token=[REDACTED_SECRET]"),
            ("token\t=secret", "token[CONTROL-U+0009]=[REDACTED_SECRET]"),
            ("token\u{2003}=secret", "token\u{2003}=[REDACTED_SECRET]"),
            ("token=secret\nnext=ok", "token=[REDACTED_SECRET]"),
            (
                "token=one name=ok api_key=two;done",
                "token=[REDACTED_SECRET] name=ok api_key=[REDACTED_SECRET];done",
            ),
            ("日本 token=秘密 rest", "日本 token=[REDACTED_SECRET] rest"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                sanitize_external_text(input, 4096).unwrap().as_str(),
                expected,
                "input {input:?}"
            );
        }
    }

    #[test]
    fn redaction_obeys_delimiter_parity_and_exact_output_bound() {
        for delimiter in [' ', ',', ';', '&'] {
            for slash_count in 0..=4 {
                let slashes = "\\".repeat(slash_count);
                let input = format!("token=value{slashes}{delimiter}tail");
                let expected = if slash_count % 2 == 0 {
                    format!("token=[REDACTED_SECRET]{delimiter}tail")
                } else {
                    "token=[REDACTED_SECRET]".to_owned()
                };
                assert_eq!(
                    sanitize_external_text(&input, expected.len())
                        .unwrap()
                        .as_str(),
                    expected
                );
            }
        }

        let expected = "token=[REDACTED_SECRET]";
        assert_eq!(
            sanitize_external_text("token=x", expected.len())
                .unwrap()
                .as_str(),
            expected
        );
        assert_eq!(
            sanitize_external_text("token=x", expected.len() - 1),
            Err(SanitizeError::OutputLimitExceeded {
                max_bytes: expected.len() - 1,
            })
        );
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

    #[test]
    fn marker_normalized_following_assignments_preserve_only_bounded_provenance() {
        for (input, expected) in [
            (
                "token= api\u{200b}key=public",
                "token= api[FORMAT-U+200B]key=public",
            ),
            (
                "token= client\u{202e}id=public",
                "token= client[BIDI-U+202E]id=public",
            ),
            (
                "token= api[FORMAT-U+200B]key=public",
                "token= [REDACTED_SECRET]",
            ),
            (
                "token= client[BIDI-U+202E]id=public",
                "token= [REDACTED_SECRET]",
            ),
        ] {
            assert_eq!(
                sanitize_external_text(input, 4096).unwrap().as_str(),
                expected,
                "input {input:?}"
            );
        }

        let eight_markers = format!("token= a{}key=public", "\u{200b}".repeat(8));
        let eight_expected = format!("token= a{}key=public", "[FORMAT-U+200B]".repeat(8));
        assert_eq!(
            sanitize_external_text(&eight_markers, 4096)
                .unwrap()
                .as_str(),
            eight_expected
        );

        let exact_span = format!("token= {}\u{200b}key=public", "a".repeat(241));
        let exact_expected = format!("token= {}[FORMAT-U+200B]key=public", "a".repeat(241));
        assert_eq!(
            sanitize_external_text(&exact_span, 4096).unwrap().as_str(),
            exact_expected
        );

        for input in [
            format!("token= a{}key=public", "\u{200b}".repeat(9)),
            format!("token= {}\u{200b}key=public", "a".repeat(242)),
        ] {
            assert_eq!(
                sanitize_external_text(&input, 4096).unwrap().as_str(),
                "token= [REDACTED_SECRET]"
            );
        }
    }
}
