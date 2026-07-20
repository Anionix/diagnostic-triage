#[path = "../src/fingerprint.rs"]
mod fingerprint;
#[path = "../src/normalize.rs"]
mod normalize;

use diagnostic_triage_contracts::model::{Location, Position, Tool};
use diagnostic_triage_contracts::{Language, RepoPath};
use fingerprint::{FindingFingerprintInput, FingerprintError, fingerprint, fingerprint_finding};
use normalize::{
    DiagnosticText, MAX_DIAGNOSTIC_TEXT_CHARS, NormalizationError, normalize_context,
    normalize_diagnostic, normalize_message, normalize_message_and_context,
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

fn fixture() -> (Tool, Language, RepoPath) {
    (
        Tool {
            name: "rustc".to_owned(),
            version: "1.85.0".to_owned(),
            rule_id: Some("E0308".to_owned()),
        },
        "rust".parse().expect("fixture language is valid"),
        "src/lib.rs".parse().expect("fixture path is valid"),
    )
}

fn digest(
    tool: &Tool,
    language: &Language,
    path: Option<&RepoPath>,
    symbol: Option<&str>,
    message: &str,
    context: &str,
) -> String {
    let normalized =
        normalize_message_and_context(message, context).expect("fixture message is valid");
    fingerprint(&FindingFingerprintInput::new(
        tool,
        language,
        path,
        symbol,
        &normalized,
    ))
    .expect("fixture fingerprint is valid")
    .to_string()
}

#[test]
fn whitespace_normalization_is_stable() {
    let (tool, language, path) = fixture();
    assert_eq!(
        digest(
            &tool,
            &language,
            Some(&path),
            Some("crate::parse"),
            "  mismatched\n types\t ",
            " expected: i32\r\n observed: u32 ",
        ),
        digest(
            &tool,
            &language,
            Some(&path),
            Some("crate::parse"),
            "mismatched types",
            "expected: i32 observed: u32",
        )
    );
}

#[test]
fn location_and_tool_version_are_not_fingerprint_inputs() {
    let (mut tool, language, path) = fixture();
    let first = digest(
        &tool,
        &language,
        Some(&path),
        Some("crate::parse"),
        "mismatched types",
        "expected i32 observed u32",
    );

    let first_location = Location {
        path: path.clone(),
        start: Position {
            line: 10,
            column: 2,
        },
        end: Some(Position {
            line: 10,
            column: 5,
        }),
    };
    tool.version = "1.86.0".to_owned();
    let second_location = Location {
        path: path.clone(),
        start: Position {
            line: 999,
            column: 77,
        },
        end: None,
    };

    assert_ne!(first_location.start.line, second_location.start.line);
    assert_ne!(first_location.start.column, second_location.start.column);
    assert_eq!(
        first,
        digest(
            &tool,
            &language,
            Some(&path),
            Some("crate::parse"),
            "mismatched types",
            "expected i32 observed u32",
        )
    );
}

#[test]
fn absent_path_differs_from_repository_root() {
    let (tool, language, path) = fixture();
    let without_path = digest(
        &tool,
        &language,
        None,
        Some("crate::parse"),
        "mismatched types",
        "expected i32 observed u32",
    );
    let root: RepoPath = ".".parse().expect("repository root is valid");
    let with_root = digest(
        &tool,
        &language,
        Some(&root),
        Some("crate::parse"),
        "mismatched types",
        "expected i32 observed u32",
    );

    assert_ne!(without_path, with_root);
    assert_ne!(path, root);
}

#[test]
fn rule_symbol_path_and_context_are_sensitive() {
    let (tool, language, path) = fixture();
    let baseline = digest(
        &tool,
        &language,
        Some(&path),
        Some("crate::parse"),
        "mismatched types",
        "expected i32 observed u32",
    );

    let mut changed_rule = tool.clone();
    changed_rule.rule_id = Some("E0382".to_owned());
    assert_ne!(
        baseline,
        digest(
            &changed_rule,
            &language,
            Some(&path),
            Some("crate::parse"),
            "mismatched types",
            "expected i32 observed u32",
        )
    );
    assert_ne!(
        baseline,
        digest(
            &tool,
            &language,
            Some(&path),
            Some("crate::other"),
            "mismatched types",
            "expected i32 observed u32",
        )
    );
    let other_path: RepoPath = "src/main.rs".parse().expect("fixture path is valid");
    assert_ne!(
        baseline,
        digest(
            &tool,
            &language,
            Some(&other_path),
            Some("crate::parse"),
            "mismatched types",
            "expected i32 observed u32",
        )
    );
    assert_ne!(
        baseline,
        digest(
            &tool,
            &language,
            Some(&path),
            Some("crate::parse"),
            "mismatched types",
            "expected i64 observed u32",
        )
    );
}

#[test]
fn normalization_rejects_empty_messages() {
    assert!(normalize::normalize_message_context(" \n\t ", Some("context")).is_err());
}

#[test]
fn public_normalizers_reject_oversized_components_before_copying() {
    let oversized = "x".repeat(MAX_DIAGNOSTIC_TEXT_CHARS + 1);

    assert_eq!(
        normalize_message(&oversized),
        Err(NormalizationError::ComponentTooLarge)
    );
    assert_eq!(
        normalize_context(&oversized),
        Err(NormalizationError::ComponentTooLarge)
    );
    assert!(matches!(
        normalize_diagnostic(&DiagnosticText::new("message", Some(&oversized), None)),
        Err(NormalizationError::ComponentTooLarge)
    ));
}

#[test]
fn fingerprint_rejects_an_oversized_symbol() {
    let (tool, language, path) = fixture();
    let normalized = normalize_message_and_context("message", "context").unwrap();
    let symbol = "s".repeat(513);

    assert_eq!(
        fingerprint_finding(&tool, &language, Some(&path), Some(&symbol), &normalized),
        Err(FingerprintError::FieldTooLarge { field: "symbol" })
    );
}

#[test]
fn length_prefixes_prevent_control_character_delimiter_collisions() {
    let left = normalize_diagnostic(&DiagnosticText::new(
        "message",
        Some("expected-left\u{1f}observed-right"),
        None,
    ))
    .expect("left diagnostic is valid");
    let right = normalize_diagnostic(&DiagnosticText::new(
        "message\u{1f}expected-left",
        Some("observed-right"),
        None,
    ))
    .expect("right diagnostic is valid");

    assert_ne!(left.as_str(), right.as_str());
    assert!(!left.clone().into_inner().is_empty());
}

#[test]
fn length_prefixes_preserve_field_boundaries() {
    let (mut tool, language, path) = fixture();
    let baseline = digest(
        &tool,
        &language,
        Some(&path),
        Some("ab"),
        "message",
        "context",
    );
    let normalized =
        normalize_message_and_context("message", "context").expect("fixture message is valid");
    assert_eq!(
        baseline,
        fingerprint_finding(&tool, &language, Some(&path), Some("ab"), &normalized,)
            .expect("fixture fingerprint is valid")
            .to_string()
    );

    tool.rule_id = Some("E0308ab".to_owned());
    assert_ne!(
        baseline,
        digest(
            &tool,
            &language,
            Some(&path),
            Some("a"),
            "message",
            "context",
        )
    );
}

#[test]
fn canonical_context_remains_utf8_above_single_byte_lengths() {
    let message = "x".repeat(200);
    let normalized = normalize_diagnostic(&DiagnosticText::new(&message, None, None))
        .expect("a 200-byte message is valid");

    assert!(
        normalized
            .as_str()
            .is_char_boundary(normalized.as_str().len())
    );
    assert!(normalized.as_str().contains(&message));
}

#[test]
fn v1_whitespace_set_is_frozen() {
    assert_eq!(normalize_message("a\u{2007}b").unwrap(), "a b");
    assert_eq!(normalize_message("a\u{200b}b").unwrap(), "a\u{200b}b");
}

#[test]
fn v1_preserves_distinct_unicode_normalization_forms() {
    assert_ne!(
        normalize_message("caf\u{e9}").unwrap(),
        normalize_message("cafe\u{301}").unwrap()
    );
}

#[test]
fn malformed_plain_tool_values_are_rejected() {
    let (mut tool, language, path) = fixture();
    tool.version.clear();
    let normalized = normalize_message_and_context("message", "context").unwrap();

    assert!(fingerprint_finding(&tool, &language, Some(&path), None, &normalized).is_err());
}
