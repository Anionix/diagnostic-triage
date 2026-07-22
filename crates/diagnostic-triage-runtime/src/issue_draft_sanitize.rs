//! Bounded neutralization kernel for untrusted issue-draft text.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

#[cfg(test)]
std::thread_local! {
    static ASSIGNMENT_WHITESPACE_SCAN_STEPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static URL_PARSE_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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
const PATH_TERMINATORS: &str = "'\"`)]},;&<>|";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SanitizationMode {
    ExternalText,
    Identifier,
    RepositoryPath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebUrlSpan {
    Preserve(usize),
    Reject(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnquotedSpacePolicy {
    Continue,
    RequireFollowingSeparator,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(transparent)]
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
    let mut web_url_until = 0;
    let mut url_checked_until = 0;
    let mut double_quote = None;
    while index < value.len() {
        if index >= url_checked_until {
            match web_url_span(neutralized, index) {
                Some(WebUrlSpan::Preserve(end)) => {
                    url_checked_until = end;
                    web_url_until = end;
                }
                Some(WebUrlSpan::Reject(end)) => url_checked_until = end,
                None => {}
            }
        }
        let redaction = unquoted_secret_at_with_provenance(neutralized, index)
            .or_else(|| quoted_secret_at_with_provenance(neutralized, index))
            .or_else(|| json_quoted_secret_at(neutralized, index))
            .or_else(|| authorization_secret_at(neutralized, index))
            .or_else(|| match mode {
                SanitizationMode::ExternalText => token_shape_at(value, index, true),
                SanitizationMode::RepositoryPath => token_shape_at(value, index, false),
                SanitizationMode::Identifier => None,
            })
            .map(|(start, end)| (start, end, "[REDACTED_SECRET]"))
            .or_else(|| {
                (mode == SanitizationMode::ExternalText && index >= web_url_until)
                    .then(|| absolute_path_end(neutralized, index, double_quote))
                    .flatten()
                    .map(|end| (index, end, "[REDACTED_PATH]"))
            });
        if let Some((start, end, marker)) = redaction {
            output.push_str(&value[index..start])?;
            output.push_str(marker)?;
            advance_double_quote_context(value, index, end, &mut double_quote);
            index = end;
        } else {
            let character = value[index..].chars().next().expect("UTF-8 boundary");
            output.push_char(character)?;
            let end = index + character.len_utf8();
            advance_double_quote_context(value, index, end, &mut double_quote);
            index = end;
        }
    }
    Ok(output.finish())
}

fn web_url_span(neutralized: &NeutralizedText, index: usize) -> Option<WebUrlSpan> {
    path_boundary(neutralized, index).then_some(())?;
    let value = neutralized.as_str();
    let tail = value.get(index..)?;
    let scheme_len = ["http://", "https://"]
        .into_iter()
        .find(|scheme| {
            tail.get(..scheme.len())
                .is_some_and(|v| v.eq_ignore_ascii_case(scheme))
        })?
        .len();
    let delimiter = |c: char| c.is_whitespace() || matches!(c, '\'' | '"' | '<' | '>');
    let mut cursor = index + scheme_len;
    while cursor < value.len() && neutralized.marker_at(cursor).is_none() {
        let character = value[cursor..].chars().next().expect("UTF-8 boundary");
        if delimiter(character) {
            break;
        }
        cursor += character.len_utf8();
    }
    let candidate = &value[index..cursor];
    #[cfg(test)]
    URL_PARSE_ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
    Some(
        if !candidate.contains('\\') && url::Url::parse(candidate).is_ok() {
            WebUrlSpan::Preserve(cursor)
        } else {
            WebUrlSpan::Reject(cursor)
        },
    )
}

fn absolute_path_end(
    neutralized: &NeutralizedText,
    index: usize,
    double_quote: Option<bool>,
) -> Option<usize> {
    path_boundary(neutralized, index).then_some(())?;
    let value = neutralized.as_str();
    let (root_end, policy) = absolute_root(value, index)?;
    let end = path_span_end(neutralized, index, root_end, policy, double_quote);
    let cookie_root = end == root_end
        && value
            .get(index.saturating_sub(5)..root_end)
            .is_some_and(|span| span.eq_ignore_ascii_case("path=/"))
        && value.as_bytes().get(end) == Some(&b';');
    (!cookie_root).then_some(end)
}

fn absolute_root(value: &str, index: usize) -> Option<(usize, UnquotedSpacePolicy)> {
    let mut root = index;
    let tail = value.get(index..)?;
    if tail.len() >= 5 && tail.as_bytes()[..5].eq_ignore_ascii_case(b"file:") {
        root += 5;
    }
    let bytes = value.as_bytes();
    if bytes.get(root).is_some_and(u8::is_ascii_alphabetic) && bytes.get(root + 1) == Some(&b':') {
        return separator_end(value, root + 2).map(|(end, _)| (end, UnquotedSpacePolicy::Continue));
    }
    let (first, forward) = separator_end(value, root)?;
    let malformed_web = ["http:", "https:"].into_iter().any(|scheme| {
        index >= scheme.len() && value[index - scheme.len()..index].eq_ignore_ascii_case(scheme)
    });
    if root > index || forward {
        return Some((first, UnquotedSpacePolicy::Continue));
    }
    if malformed_web {
        return Some((first, UnquotedSpacePolicy::RequireFollowingSeparator));
    }
    if let Some((end, second_forward)) = separator_end(value, first) {
        return (!second_forward).then_some((end, UnquotedSpacePolicy::Continue));
    }
    single_backslash_root_end(value, root, first)
        .map(|end| (end, UnquotedSpacePolicy::RequireFollowingSeparator))
}

fn single_backslash_root_end(
    value: &str,
    root_start: usize,
    component_start: usize,
) -> Option<usize> {
    // Sources: https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats, https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file.
    // LLM contract: SINGLE_BACKSLASH -> TWO_TYPED_COMPONENTS -> ROOTED_PATH | ESCAPE_PRESERVED.
    let quote = value
        .as_bytes()
        .get(root_start.wrapping_sub(1))
        .copied()
        .filter(|byte| is_quote(*byte));
    let first_end = typed_windows_component_end(value, component_start, 1, quote)?;
    let (second_start, _) = separator_end(value, first_end)?;
    let second_end = typed_windows_component_end(value, second_start, 1, quote)?;
    let first = value.get(component_start..first_end)?;
    let second = value.get(second_start..second_end)?;
    if !is_known_windows_root(first)
        && looks_like_escape_sequence(first, second)
        && separator_end(value, second_end).is_none()
    {
        return None;
    }
    Some(component_start)
}

fn typed_windows_component_end(
    value: &str,
    start: usize,
    minimum_chars: usize,
    quote: Option<u8>,
) -> Option<usize> {
    let mut cursor = start;
    let mut component_chars = 0usize;
    while cursor < value.len() {
        if separator_end(value, cursor).is_some() {
            break;
        }
        let character = value[cursor..].chars().next().expect("UTF-8 boundary");
        if quote.is_some_and(|quote| character == char::from(quote))
            || quote.is_none()
                && (character.is_whitespace() || PATH_TERMINATORS.contains(character))
        {
            break;
        }
        if !is_typed_windows_component_character(character) {
            return None;
        }
        component_chars += 1;
        cursor += character.len_utf8();
    }
    (component_chars >= minimum_chars).then_some(cursor)
}

fn is_typed_windows_component_character(character: char) -> bool {
    !character.is_control() && !r#"<>:"/\|?*"#.contains(character)
}

fn is_known_windows_root(component: &str) -> bool {
    ["Users", "Windows"]
        .into_iter()
        .any(|root| component.eq_ignore_ascii_case(root))
}

fn looks_like_escape_sequence(first: &str, second: &str) -> bool {
    (starts_compound_escape(first) || first.chars().next().is_some_and(is_single_escape_head))
        && (is_escape_component(second) || starts_compound_escape(second))
        || first.starts_with('Q') && second.starts_with('E')
        || [first, second].into_iter().all(starts_octal_escape)
}

fn is_escape_component(component: &str) -> bool {
    let mut characters = component.chars();
    let Some(head) = characters.next() else {
        return false;
    };
    let tail = characters.as_str();
    if tail.is_empty() || tail == "+" {
        return is_single_escape_head(head);
    }
    is_compound_escape_component(component)
}

fn starts_octal_escape(component: &str) -> bool {
    matches!(component.as_bytes().first(), Some(b'0'..=b'7'))
}

fn is_single_escape_head(head: char) -> bool {
    matches!(
        head,
        '0' | 'A'
            | 'a'
            | 'b'
            | 'B'
            | 'd'
            | 'D'
            | 'e'
            | 'E'
            | 'f'
            | 'G'
            | 'n'
            | 'Q'
            | 'r'
            | 's'
            | 'S'
            | 't'
            | 'v'
            | 'w'
            | 'W'
            | 'z'
            | 'Z'
    )
}

fn is_compound_escape_component(component: &str) -> bool {
    let mut characters = component.chars();
    let Some(head) = characters.next() else {
        return false;
    };
    let tail = characters.as_str();
    match head {
        'x' | 'X' => tail.len() == 2 && tail.bytes().all(|byte| byte.is_ascii_hexdigit()),
        'u' | 'U' => {
            matches!(tail.len(), 4 | 8) && tail.bytes().all(|byte| byte.is_ascii_hexdigit())
        }
        'c' | 'C' => tail.len() == 1 && tail.bytes().all(|byte| byte.is_ascii_alphabetic()),
        'p' | 'P' => tail.len() <= 3 && tail.chars().all(char::is_alphabetic),
        _ => false,
    }
}

fn starts_compound_escape(component: &str) -> bool {
    let bytes = component.as_bytes();
    match bytes.first() {
        Some(b'x' | b'X') => bytes
            .get(1..3)
            .is_some_and(|tail| tail.iter().all(u8::is_ascii_hexdigit)),
        Some(b'u') => bytes
            .get(1..5)
            .is_some_and(|tail| tail.iter().all(u8::is_ascii_hexdigit)),
        Some(b'U') => bytes
            .get(1..9)
            .is_some_and(|tail| tail.iter().all(u8::is_ascii_hexdigit)),
        Some(b'p' | b'P') => bytes
            .get(1)
            .is_some_and(|category| b"LMNPSZC".contains(category)),
        Some(b'c' | b'C') => bytes.get(1).is_some_and(u8::is_ascii_alphabetic),
        _ => false,
    }
}

fn separator_end(value: &str, index: usize) -> Option<(usize, bool)> {
    match value.as_bytes().get(index) {
        Some(b'/') => Some((index + 1, true)),
        Some(b'\\') => Some((index + 1, false)),
        _ => value.get(index..index.saturating_add(3)).and_then(|part| {
            ["%2f", "%5c"]
                .into_iter()
                .position(|separator| part.eq_ignore_ascii_case(separator))
                .map(|kind| (index + 3, kind == 0))
        }),
    }
}

fn advance_double_quote_context(value: &str, start: usize, end: usize, active: &mut Option<bool>) {
    // LLM contract: UNQUOTED <-> DOUBLE_QUOTED; each consumed span advances once.
    for cursor in start..end {
        if value.as_bytes()[cursor] == b'"' {
            let escaped = is_escaped(value.as_bytes(), 0, cursor);
            match *active {
                None => *active = Some(escaped),
                Some(kind) if kind == escaped => *active = None,
                Some(_) => {}
            }
        }
    }
}

fn path_quote_context(value: &str, start: usize, double_quote: Option<bool>) -> Option<(u8, bool)> {
    if let Some(escaped) = double_quote {
        return Some((b'"', escaped));
    }
    let subject_start = ["http:", "https:"]
        .into_iter()
        .find_map(|scheme| {
            let candidate = start.checked_sub(scheme.len())?;
            value
                .get(candidate..start)?
                .eq_ignore_ascii_case(scheme)
                .then_some(candidate)
        })
        .unwrap_or(start);
    let quote_index = subject_start.checked_sub(1)?;
    let quote = *value.as_bytes().get(quote_index)?;
    is_quote(quote).then(|| (quote, is_escaped(value.as_bytes(), 0, quote_index)))
}

fn path_span_end(
    neutralized: &NeutralizedText,
    start: usize,
    mut cursor: usize,
    unquoted_space: UnquotedSpacePolicy,
    double_quote: Option<bool>,
) -> usize {
    let value = neutralized.as_str();
    let bytes = value.as_bytes();
    let quote_context = path_quote_context(value, start, double_quote);
    let quote = quote_context.map(|(quote, _)| quote);
    let escaped_outer = quote_context.is_some_and(|(_, escaped)| escaped);
    let mut pending_space = None;
    let mut typed_after_space = false;
    while cursor < value.len() && token_shape_at(value, cursor, true).is_none() {
        if neutralized.marker_at(cursor).is_some() {
            break;
        }
        if quote.is_some_and(|quote| {
            (!escaped_outer && bytes[cursor] == quote && !is_escaped(bytes, start, cursor))
                || (escaped_outer
                    && bytes[cursor] == b'\\'
                    && bytes.get(cursor + 1) == Some(&quote)
                    && !is_escaped(bytes, start, cursor))
        }) {
            break;
        }
        let character = value[cursor..].chars().next().expect("UTF-8 boundary");
        if unquoted_space == UnquotedSpacePolicy::RequireFollowingSeparator
            && separator_end(value, cursor).is_none()
            && !is_typed_windows_component_character(character)
        {
            break;
        }
        if quote.is_none() {
            if character.is_whitespace() {
                if character != ' ' {
                    break;
                }
                if unquoted_space == UnquotedSpacePolicy::RequireFollowingSeparator {
                    pending_space.get_or_insert(cursor);
                    typed_after_space = false;
                    cursor += 1;
                    continue;
                }
            }
            if PATH_TERMINATORS.contains(character)
                && unquoted_space == UnquotedSpacePolicy::Continue
            {
                break;
            }
            if pending_space.is_some() {
                if separator_end(value, cursor).is_some() {
                    if !typed_after_space {
                        break;
                    }
                    pending_space = None;
                    typed_after_space = false;
                } else if is_typed_windows_component_character(character) {
                    typed_after_space = true;
                } else {
                    break;
                }
            }
        }
        cursor += character.len_utf8();
    }
    pending_space.unwrap_or(cursor)
}

fn path_boundary(neutralized: &NeutralizedText, index: usize) -> bool {
    // Sources: https://www.rfc-editor.org/rfc/rfc8089, https://url.spec.whatwg.org/, https://docs.rs/url/2.5.8/url/struct.Url.html#method.parse, https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats. LLM contract: CANDIDATE -> WEB_URL_PRESERVED | ABSOLUTE_PATH_REDACTED | RELATIVE_PRESERVED.
    let previous = neutralized.as_str()[..index].chars().next_back();
    neutralized.marker_ending_at(index).is_some()
        || previous.is_none_or(|c| !c.is_alphanumeric() && !"_-.\\/%".contains(c))
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
    let escaped_key = if bytes.get(index) == Some(&b'"') {
        false
    } else if bytes.get(index) == Some(&b'\\') && bytes.get(index + 1) == Some(&b'"') {
        true
    } else {
        return None;
    };
    if !is_json_key_boundary(neutralized, index) {
        return None;
    }

    let mut cursor = index + 1 + usize::from(escaped_key);
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
    let closing_key_width =
        if escaped_key && bytes.get(cursor) == Some(&b'\\') && bytes.get(cursor + 1) == Some(&b'"')
        {
            2
        } else if !escaped_key && bytes.get(cursor) == Some(&b'"') {
            1
        } else {
            return None;
        };
    let authorization = normalized == "authorization";
    if needs_alphanumeric || (!authorization && !is_secret_key(&normalized)) {
        return None;
    }

    cursor = skip_json_whitespace(neutralized, cursor + closing_key_width);
    if bytes.get(cursor) != Some(&b':') {
        return None;
    }
    cursor = skip_json_whitespace(neutralized, cursor + 1);
    let escaped_value = if bytes.get(cursor) == Some(&b'"') {
        false
    } else if bytes.get(cursor) == Some(&b'\\') && bytes.get(cursor + 1) == Some(&b'"') {
        true
    } else {
        return None;
    };
    let start = cursor + 1 + usize::from(escaped_value);
    if start >= bytes.len() {
        return None;
    }
    let end = if escaped_value {
        escaped_json_quoted_value_end(bytes, start, b'"')
    } else {
        raw_quoted_value_end(bytes, start, b'"')
    };
    if authorization {
        // LLM contract: JSON_AUTH_VALUE -> ASSIGNMENT_RECOGNIZED -> VALUE_BOUNDED | REJECTED.
        let (assignment_start, crossed_record_boundary) =
            skip_authorization_value_whitespace(neutralized, start);
        if crossed_record_boundary || assignment_start >= end {
            return None;
        }
        let separator = assignment_separator_at(value, assignment_start, Some(neutralized))?;
        return authorization_assignment_credential_at(
            neutralized,
            assignment_start,
            separator,
            end,
        );
    }
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
                    value.len(),
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
    limit: usize,
) -> Option<(usize, usize)> {
    let value = neutralized.as_str();
    let bytes = value.as_bytes();
    let limit = limit.min(bytes.len());
    (separator < limit).then_some(())?;
    let (mut cursor, crossed_record_boundary) =
        skip_authorization_value_whitespace(neutralized, separator + 1);
    (cursor < limit).then_some(())?;
    if crossed_record_boundary && looks_like_assignment(value, cursor, Some(neutralized)) {
        return None;
    }
    // LLM contract: AUTH_SCHEME -> SAME_RECORD_CREDENTIAL | RECORD_BOUNDARY_PRESERVED.
    if let Some(scheme_end) =
        authorization_scheme_end(neutralized, cursor).filter(|end| *end <= limit)
    {
        let (credential_start, crossed_record_boundary) =
            skip_authorization_value_whitespace(neutralized, scheme_end);
        (credential_start > scheme_end).then_some(())?;
        if crossed_record_boundary
            && credential_start < limit
            && looks_like_assignment(value, credential_start, Some(neutralized))
        {
            return Some((start, scheme_end));
        }
        (credential_start < limit).then_some(())?;
        cursor = credential_start;
    }
    let (content_start, content_end, redaction_end) = if let Some(quote) =
        bytes.get(cursor).copied().filter(|byte| is_quote(*byte))
    {
        let content_start = cursor + 1;
        let content_end = raw_quoted_value_end(&bytes[..limit], content_start, quote);
        let redaction_end = content_end
            + usize::from(
                content_end < limit && bytes.get(content_end).is_some_and(|byte| *byte == quote),
            );
        (content_start, content_end, redaction_end)
    } else if bytes.get(cursor) == Some(&b'\\')
        && bytes.get(cursor + 1).is_some_and(|byte| is_quote(*byte))
    {
        let quote = bytes
            .get(cursor + 1)
            .copied()
            .expect("escaped quote checked above");
        let content_start = cursor + 2;
        let content_end = escaped_quoted_value_end(&bytes[..limit], content_start, quote);
        let has_closing_quote = content_end + 1 < limit
            && bytes.get(content_end) == Some(&b'\\')
            && bytes.get(content_end + 1) == Some(&quote);
        let redaction_end = content_end + usize::from(has_closing_quote) * 2;
        (content_start, content_end, redaction_end)
    } else {
        let content_end = unquoted_value_end_bounded(value, cursor, Some(neutralized), limit);
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
        } else {
            // LLM contract: CLI_SEPARATOR -> PROVENANCE_ONLY_REJECTED | LITERAL_VALUE_BOUNDED.
            let (separator_end, provenance_backed) =
                skip_key_separator_whitespace(value, cursor, neutralized);
            if separator_end <= cursor {
                return None;
            }
            cursor = separator_end;
            if matches!(bytes.get(cursor), Some(b'=' | b':')) {
                if provenance_backed {
                    return None;
                }
                let value_start = cursor + 1;
                cursor =
                    skip_assignment_whitespace_with_provenance(value, value_start, neutralized);
                if cursor > value_start && looks_like_assignment(value, cursor, neutralized) {
                    return None;
                }
            } else if provenance_backed && looks_like_assignment(value, cursor, neutralized) {
                return None;
            }
        }
    } else {
        cursor = skip_key_separator_whitespace(value, cursor, neutralized).0;
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

fn escaped_json_quoted_value_end(bytes: &[u8], start: usize, quote: u8) -> usize {
    // LLM contract: ESCAPED_JSON_VALUE -> INNER_QUOTE_SKIPPED -> OUTER_QUOTE | EOF.
    // One escaped JSON layer gives outer quotes 4k+1 slashes and inner quotes 4k+3.
    let mut cursor = start;
    let mut backslash_run = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            backslash_run += 1;
        } else {
            if bytes[cursor] == quote && backslash_run % 4 == 1 {
                return cursor - 1;
            }
            backslash_run = 0;
        }
        cursor += 1;
    }
    bytes.len()
}

fn unquoted_value_end(value: &str, start: usize, neutralized: Option<&NeutralizedText>) -> usize {
    unquoted_value_end_bounded(value, start, neutralized, value.len())
}

fn unquoted_value_end_bounded(
    value: &str,
    start: usize,
    neutralized: Option<&NeutralizedText>,
    limit: usize,
) -> usize {
    let bytes = value.as_bytes();
    let mut cursor = start;
    while cursor < limit.min(value.len()) {
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

fn skip_key_separator_whitespace(
    value: &str,
    cursor: usize,
    neutralized: Option<&NeutralizedText>,
) -> (usize, bool) {
    // LLM contract: SEPARATOR_PREFIX -> PROVENANCE_ONLY | LITERAL_TAINTED | ABSENT.
    let provenance_end = skip_assignment_whitespace_with_provenance(value, cursor, neutralized);
    if neutralized.is_none() {
        return (provenance_end, true);
    }
    let literal_end = skip_assignment_whitespace(value, provenance_end);
    if literal_end > provenance_end {
        return (literal_end, false);
    }
    (provenance_end, provenance_end > cursor)
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
    fn redacts_absolute_paths_without_consuming_safe_context() {
        let redacted = "[REDACTED_PATH]";
        let cases = [
            (r"C:\", redacted),
            (r"\\server\share", redacted),
            (r"\Users\alice+dev=qa@host#1$^(!%done\repo", redacted),
            ("prefix \\Users\\a safe", "prefix [REDACTED_PATH] safe"),
            ("prefix %5CUsers%5CA safe", "prefix [REDACTED_PATH] safe"),
            (r"\Windows\System32", redacted),
            (r"\Windows\n", redacted),
            (r"\A\Data", redacted),
            (r"\x64data\secret.txt", redacted),
            (r"\x64data\n\secret.txt", redacted),
            (r"\101foo\102bar\secret", redacted),
            ("\\Cafe\u{301}\\Docs", redacted),
            (r#""\O'Brien Program\secret.txt""#, r#""[REDACTED_PATH]""#),
            (
                r#""%5CO'Brien Program%5Csecret.txt""#,
                r#""[REDACTED_PATH]""#,
            ),
            ("%5C%5cserver%2Fshare", redacted),
            ("file:///etc/passwd", redacted),
            ("FILE:%2fUsers%2FA", redacted),
            ("C:%5CUsers%2FA", redacted),
            (r#""C:\Program Files\a""#, r#""[REDACTED_PATH]""#),
            (r#"\"/a b\" tail"#, r#"\"[REDACTED_PATH]\" tail"#),
            (r#""/a/with\"q/x" tail"#, r#""[REDACTED_PATH]" tail"#),
            ("see /Users/A/My Project, then", "see [REDACTED_PATH], then"),
            ("https:/Users/a", "https:[REDACTED_PATH]"),
            ("https://[x]/a", "https:[REDACTED_PATH]][REDACTED_PATH]"),
            ("https://%ZZ/Users/a", "https:[REDACTED_PATH]"),
            ("https://%25/Users/a", "https:[REDACTED_PATH]"),
            ("https://a:b:443/Users/a", "https:[REDACTED_PATH]"),
            (r"https://example.test\Users\a", "https:[REDACTED_PATH]"),
            (r"https:\Users\a", "https:[REDACTED_PATH]"),
            ("https://x\n/a", "https://x[CONTROL-U+000A][REDACTED_PATH]"),
            ("http://x?token=secret", "http://x?token=[REDACTED_SECRET]"),
        ];
        for (input, expected) in cases {
            let actual = sanitize_external_text(input, 8_192).unwrap();
            assert_eq!(actual.as_str(), expected, "input {input:?}");
        }
        let preserved = concat!(
            "https://例え.テスト:443/Users/a?next=/etc\nhttps://https://Users/a\nhttps://%E4%BE%8B%E3%81%88.test/Users/a\nhttps://[::1]/Users/a\n",
            "url=https://example.test/a?next=/Users/a\n<https://example.test/a>\n日本語/src.rs\nfile:src/lib.rs\n",
            "C:relative\\file.rs\npattern \\d+\\w+\nliteral \\n\\t and regex \\p{Letter}+\\s*\nanchors \\bword\\b and \\Afoo\\z\nescapes \\x20\\u00A0, \\x41\\x42, \\u0041\\u0042, \\pL\\pN, \\cA\\cB, \\123\\234, and \\101foo\\102bar\nquoted \\Qfoo\\Ebar and suffixed \\nfoo\\t\ncompound suffixes \\u0041foo\\n, \\x41foo\\n, \\pLfoo\\n, and reversed \\n\\u0041foo",
        );
        for input in preserved.lines() {
            let actual = sanitize_external_text(input, 8_192).unwrap();
            assert_eq!(actual.as_str(), input);
        }
        let mixed = r#"path="\Users\alice\repo"; regex=\d+\w+"#;
        assert_eq!(
            sanitize_external_text(mixed, 8_192).unwrap().as_str(),
            r#"path="[REDACTED_PATH]"; regex=\d+\w+"#
        );
        let rooted = r"\Windows\n";
        assert_eq!(
            sanitize_external_text(rooted, redacted.len())
                .unwrap()
                .as_str(),
            redacted
        );
        assert_eq!(
            sanitize_external_text(rooted, redacted.len() - 1),
            Err(SanitizeError::OutputLimitExceeded {
                max_bytes: redacted.len() - 1,
            })
        );
        let input = format!("/{}, safe /etc", "a".repeat(4_096));
        let actual = sanitize_external_text(&input, input.len()).unwrap();
        assert_eq!(actual.as_str(), "[REDACTED_PATH], safe [REDACTED_PATH]");
        assert!(sanitize_external_text("/", redacted.len()).is_ok());
        assert!(sanitize_external_text("/", redacted.len() - 1).is_err());
        super::URL_PARSE_ATTEMPTS.with(|attempts| attempts.set(0));
        let repeated = "<https://%25/a>".repeat(128);
        sanitize_external_text(&repeated, repeated.len() * 2).unwrap();
        assert_eq!(super::URL_PARSE_ATTEMPTS.with(std::cell::Cell::get), 128);
    }

    #[test]
    fn redacts_spaced_single_backslash_paths_without_consuming_prose() {
        let cases = [
            (r"https:\Users\Alice Smith\repo", "https:[REDACTED_PATH]"),
            (r"https:\Users\O'Brien Smith\repo", "https:[REDACTED_PATH]"),
            (r"https:\Users\R&D\repo", "https:[REDACTED_PATH]"),
            (
                r#"\"x https:\Users\O'Brien Smith\repo\""#,
                r#"\"x https:[REDACTED_PATH]\""#,
            ),
            (
                r"https:\Users\Alice Smith\repo safe",
                "https:[REDACTED_PATH] safe",
            ),
            (
                r"https:\Users\Alice Mary Smith\repo safe",
                "https:[REDACTED_PATH] safe",
            ),
            (
                "https:%5CUsers%5CAlice Smith%5Crepo",
                "https:[REDACTED_PATH]",
            ),
            (
                r"prefix \Users\Alice Smith\repo safe",
                "prefix [REDACTED_PATH] safe",
            ),
            (
                r"https:\Users\Alice note?\repo safe",
                r"https:[REDACTED_PATH] note?\repo safe",
            ),
            (
                r#"{"path":"https:\\Users\\Alice Smith\\repo"}"#,
                r#"{"path":"https:[REDACTED_PATH]"}"#,
            ),
            (
                r#"{"path":"https:\\Users\\O'Brien Smith\\repo"}"#,
                r#"{"path":"https:[REDACTED_PATH]"}"#,
            ),
            (
                r#"{"path":"prefix https:\\Users\\O'Brien Smith\\repo"}"#,
                r#"{"path":"prefix https:[REDACTED_PATH]"}"#,
            ),
            (
                r#"{"message":"https:\\Users\\Alice Smith\\repo* safe"}"#,
                r#"{"message":"https:[REDACTED_PATH]* safe"}"#,
            ),
        ];
        for (input, expected) in cases {
            let actual = sanitize_external_text(input, 8_192).unwrap();
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

    fn assert_review_followup_authorization_cases(cases: &[(&str, &str)]) {
        for &(input, expected) in cases {
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
                "bound for {input:?}"
            );
        }
    }

    #[test]
    fn review_followup_authorization_json_assignment_values() {
        let cases = [
            (
                r#"{"Authorization":"Credential=abcdef","name":"ok"}"#,
                r#"{"Authorization":"[REDACTED_SECRET]","name":"ok"}"#,
            ),
            (
                r#"{ "Authorization" : "token : abcdef", "name" : "ok" }"#,
                r#"{ "Authorization" : "[REDACTED_SECRET]", "name" : "ok" }"#,
            ),
            (
                r#"{\"Authorization\":\"Credential=abcdef\",\"name\":\"ok\"}"#,
                r#"{\"Authorization\":\"[REDACTED_SECRET]\",\"name\":\"ok\"}"#,
            ),
            (
                r#"{\"Authorization\":\"Credential=\\\"abcdef\\\"\",\"name\":\"ok\"}"#,
                r#"{\"Authorization\":\"[REDACTED_SECRET]\",\"name\":\"ok\"}"#,
            ),
            (
                r#"{\"Authorization\":\"Credential=\\\"abcdef"#,
                r#"{\"Authorization\":\"[REDACTED_SECRET]"#,
            ),
            (
                r#"{"Authorization":"Credential=\"abcdef\"","name":"ok"}"#,
                r#"{"Authorization":"[REDACTED_SECRET]","name":"ok"}"#,
            ),
            (
                r#"{"Authorization":"  token=Bearer abcdef","name":"ok"}"#,
                r#"{"Authorization":"  [REDACTED_SECRET]","name":"ok"}"#,
            ),
            (
                r#"{"Authorization":"Credential=[CONTROL-U+000A]next=ok","name":"ok"}"#,
                r#"{"Authorization":"[REDACTED_SECRET]","name":"ok"}"#,
            ),
            (
                r#"{"Authorization":"Credential=abcdef"#,
                r#"{"Authorization":"[REDACTED_SECRET]"#,
            ),
        ];

        assert_review_followup_authorization_cases(&cases);
    }

    #[test]
    fn review_followup_authorization_scheme_record_boundaries() {
        let cases = [
            (
                "Authorization: token=Bearer\nnext=ok",
                "Authorization: [REDACTED_SECRET][CONTROL-U+000A]next=ok",
            ),
            (
                "Authorization=Credential=Basic\rnext=ok",
                "Authorization=[REDACTED_SECRET][CONTROL-U+000D]next=ok",
            ),
            (
                "Authorization: token=Bearer\r\nnext=ok",
                "Authorization: [REDACTED_SECRET][CONTROL-U+000D][CONTROL-U+000A]next=ok",
            ),
            (
                "Authorization=token=Basic abcdef\nnext=ok",
                "Authorization=[REDACTED_SECRET][CONTROL-U+000A]next=ok",
            ),
        ];

        assert_review_followup_authorization_cases(&cases);
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
    fn literal_control_marker_secret_separators_fail_closed() {
        let cases = [
            (
                "token[CONTROL-U+0009]=secret",
                "token[CONTROL-U+0009]=[REDACTED_SECRET]",
            ),
            (
                "--token[CONTROL-U+0009]secret",
                "--token[CONTROL-U+0009][REDACTED_SECRET]",
            ),
            (
                "--token[CONTROL-U+000A]next=ok",
                "--token[CONTROL-U+000A][REDACTED_SECRET]",
            ),
            ("token=[CONTROL-U+000A]next=ok", "token=[REDACTED_SECRET]"),
            ("--token\nnext=ok", "--token[CONTROL-U+000A]next=ok"),
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
    fn mixed_provenance_and_literal_secret_separators_fail_closed() {
        let cases = [
            (
                "token\t[CONTROL-U+0009]=secret",
                "token[CONTROL-U+0009][CONTROL-U+0009]=[REDACTED_SECRET]",
            ),
            (
                "api_key \r[CONTROL-U+000D]:secret",
                "api_key [CONTROL-U+000D][CONTROL-U+000D]:[REDACTED_SECRET]",
            ),
            (
                "--token\t[CONTROL-U+0009]secret",
                "--token[CONTROL-U+0009][CONTROL-U+0009][REDACTED_SECRET]",
            ),
            (
                "--token\t[CONTROL-U+0009]=secret",
                "--token[CONTROL-U+0009][CONTROL-U+0009]=[REDACTED_SECRET]",
            ),
            (
                "--token\r[CONTROL-U+000D]:secret",
                "--token[CONTROL-U+000D][CONTROL-U+000D]:[REDACTED_SECRET]",
            ),
            (
                "--token[CONTROL-U+0009]=secret",
                "--token[CONTROL-U+0009]=[REDACTED_SECRET]",
            ),
            ("--token\t=secret", "--token[CONTROL-U+0009]=secret"),
            (
                "--token\t[CONTROL-U+0009]=\nnext=ok",
                "--token[CONTROL-U+0009][CONTROL-U+0009]=[CONTROL-U+000A]next=ok",
            ),
            (
                "--token\t[CONTROL-U+0009]=",
                "--token[CONTROL-U+0009][CONTROL-U+0009]=",
            ),
            (
                "--token\n[CONTROL-U+000A]next=ok",
                "--token[CONTROL-U+000A][CONTROL-U+000A][REDACTED_SECRET]",
            ),
            (
                "token\t[CONTROL-U+0009][CONTROL-U+000D]=secret",
                "token[CONTROL-U+0009][CONTROL-U+0009][CONTROL-U+000D]=[REDACTED_SECRET]",
            ),
        ];

        for (input, expected) in cases {
            let required_bytes = neutralize_external_text(input, 4096)
                .unwrap()
                .as_str()
                .len()
                .max(expected.len());
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
                "bound for {input:?}"
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
