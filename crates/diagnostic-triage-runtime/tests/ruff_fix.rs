use std::fs;
use std::str::FromStr;

use diagnostic_triage_contracts::model::{
    Applicability, Evidence, EvidenceSchemaVersion, EvidenceSource, FixCandidate,
    FixCandidateSchemaVersion, Location, Observation, ObservationSchemaVersion, Origin, Position,
    Severity, Tool,
};
use diagnostic_triage_contracts::{Language, ObjectId, RepoPath, Sha256Digest};
use diagnostic_triage_runtime::{
    CanonicalRuffFix, MAX_RUFF_FIX_STRING_BYTES, RUFF_FIX_MEDIA_TYPE, RuffFixError, RuffFixLimits,
    ScratchChange, ScratchError, ScratchLimits, ScratchWorkspace, canonicalize_ruff_fix,
};
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

const TARGET: &str = "src/example.py";
const PREIMAGE: &[u8] = b"import os\nvalue = 1\nprint(value)\n";
const RESULT: &[u8] = b"\nvalue = 42\n# print(value)\n";
const PATCH_SHA256: &str = "a3c06ed655b4f4dfe7a9c5103160539d3c662129092d46ce20babd0a3aa494f0";

struct Harness {
    repo: TempDir,
    workspace: ScratchWorkspace,
    observation: Observation,
    candidate: FixCandidate,
    evidence: Evidence,
}

fn object_id(value: &str) -> ObjectId {
    ObjectId::from_str(value).expect("test ObjectId")
}

fn fixture_document() -> String {
    include_str!("golden/ruff-safe-fix.json").trim().to_owned()
}

fn fixture_patch() -> &'static str {
    include_str!("golden/ruff-safe-fix.patch.json").trim()
}

fn write_target(repo: &TempDir, path: &str, contents: &[u8]) {
    let target = repo.path().join(path);
    fs::create_dir_all(target.parent().expect("target parent")).expect("create target parent");
    fs::write(target, contents).expect("write target");
}

fn source_evidence(content: String) -> Evidence {
    let bytes = u64::try_from(content.len()).expect("fixture length");
    Evidence {
        schema_version: EvidenceSchemaVersion::V1,
        evidence_id: object_id("019f7e95-0000-7000-8000-000000000003"),
        execution_id: None,
        source: EvidenceSource::Patch,
        media_type: RUFF_FIX_MEDIA_TYPE.to_owned(),
        retained_bytes: bytes,
        observed_bytes: bytes,
        limit_bytes: 1_048_576,
        truncated: false,
        sha256: Sha256Digest::compute(content.as_bytes()),
        relative_path: None,
        content: Some(content),
    }
}

fn contract_inputs(path: &str, content: String) -> (Observation, FixCandidate, Evidence) {
    let observation_id = object_id("019f7e95-0000-7000-8000-000000000001");
    let evidence = source_evidence(content);
    let observation = Observation {
        schema_version: ObservationSchemaVersion::V1,
        observation_id: observation_id.clone(),
        tool: Tool {
            name: "ruff".to_owned(),
            version: "0.15.2".to_owned(),
            rule_id: Some("RUF100".to_owned()),
        },
        language: Language::from_str("python").expect("python language"),
        severity: Severity::Warning,
        origin: Origin::Normal,
        message: "canonical Ruff fix".to_owned(),
        location: Some(Location {
            path: RepoPath::from_str(path).expect("test RepoPath"),
            start: Position { line: 1, column: 1 },
            end: None,
        }),
        symbol: None,
        expected: None,
        observed: None,
        evidence_ids: Vec::new(),
    };
    let candidate = FixCandidate {
        schema_version: FixCandidateSchemaVersion::V1,
        fix_candidate_id: object_id("019f7e95-0000-7000-8000-000000000002"),
        observation_ids: vec![observation_id],
        applicability: Applicability::Safe,
        tool_native: true,
        patch_evidence_id: evidence.evidence_id.clone(),
    };
    (observation, candidate, evidence)
}

fn harness_with(
    path: &str,
    contents: &[u8],
    document: String,
    scratch_limits: ScratchLimits,
) -> Harness {
    let repo = tempdir().expect("temporary repository");
    write_target(&repo, path, contents);
    finish_harness(repo, path, document, scratch_limits)
}

fn finish_harness(
    repo: TempDir,
    path: &str,
    document: String,
    scratch_limits: ScratchLimits,
) -> Harness {
    let workspace = ScratchWorkspace::stage(repo.path(), &["."], scratch_limits)
        .expect("stage scratch workspace");
    let (observation, candidate, evidence) = contract_inputs(path, document);
    Harness {
        repo,
        workspace,
        observation,
        candidate,
        evidence,
    }
}

fn standard_harness() -> Harness {
    harness_with(
        TARGET,
        PREIMAGE,
        fixture_document(),
        ScratchLimits::default(),
    )
}

fn run(harness: &Harness, limits: RuffFixLimits) -> Result<CanonicalRuffFix, RuffFixError> {
    canonicalize_ruff_fix(
        &harness.workspace,
        &harness.observation,
        &harness.candidate,
        &harness.evidence,
        limits,
    )
}

fn set_document(harness: &mut Harness, document: &Value) {
    harness.evidence = source_evidence(serde_json::to_string(&document).expect("encode document"));
    harness.candidate.patch_evidence_id = harness.evidence.evidence_id.clone();
}

fn document_with_edits(edits: Value) -> String {
    let mut document = serde_json::from_str::<Value>(&fixture_document()).expect("fixture JSON");
    document["fix"]["edits"] = edits;
    serde_json::to_string(&document).expect("encode document")
}

fn document_with_raw_first_edit_content(raw_json_string: &str) -> String {
    let replacement = format!("\"content\":{raw_json_string}");
    fixture_document().replacen("\"content\":\"# \"", &replacement, 1)
}

#[test]
fn canonicalizes_unordered_deletion_replacement_and_insertion_exactly() {
    let harness = standard_harness();
    let original_before = fs::read(harness.repo.path().join(TARGET)).expect("original before");
    let scratch_before = fs::read(harness.workspace.path().join(TARGET)).expect("scratch before");

    let first = run(&harness, RuffFixLimits::default()).expect("canonical Ruff fix");
    let second = run(&harness, RuffFixLimits::default()).expect("repeat canonical Ruff fix");

    assert_eq!(first.patch, second.patch);
    assert_eq!(first.patch_evidence.content, second.patch_evidence.content);
    assert_eq!(first.patch_evidence.sha256, second.patch_evidence.sha256);
    assert_eq!(
        first.patch_evidence.content.as_deref(),
        Some(fixture_patch())
    );
    assert_eq!(first.patch_evidence.sha256.as_str(), PATCH_SHA256);
    assert_eq!(
        first.patch_evidence.media_type,
        "application/vnd.diagnostic-triage.patch+json"
    );
    assert_eq!(first.patch_evidence.source, EvidenceSource::Patch);
    assert!(!first.patch_evidence.truncated);
    assert_eq!(first.patch.changes().len(), 1);
    assert_eq!(
        first.patch.changes()[0],
        ScratchChange::Write {
            path: TARGET.to_owned(),
            contents: RESULT.to_vec(),
        }
    );
    assert_eq!(
        first.evidence_mapping.source_evidence_id,
        harness.evidence.evidence_id
    );
    assert_eq!(
        first.evidence_mapping.canonical_evidence_id,
        first.patch_evidence.evidence_id
    );
    assert_eq!(
        first.evidence_mapping.canonical_sha256,
        first.patch_evidence.sha256
    );
    assert_eq!(
        fs::read(harness.repo.path().join(TARGET)).expect("original after"),
        original_before
    );
    assert_eq!(
        fs::read(harness.workspace.path().join(TARGET)).expect("scratch after"),
        scratch_before
    );
}

#[test]
fn pins_lf_half_open_and_eof_insertion_coordinates() {
    let document = document_with_edits(json!([
        {
            "content": "",
            "location": {"row": 1, "column": 2},
            "end_location": {"row": 2, "column": 1}
        },
        {
            "content": "tail\n",
            "location": {"row": 3, "column": 1},
            "end_location": {"row": 3, "column": 1}
        }
    ]));
    let harness = harness_with(TARGET, b"a\nb\n", document, ScratchLimits::default());

    let canonical = run(&harness, RuffFixLimits::default()).expect("LF coordinates");

    assert_eq!(
        canonical.patch.changes(),
        &[ScratchChange::Write {
            path: TARGET.to_owned(),
            contents: b"ab\ntail\n".to_vec(),
        }]
    );
}

#[test]
fn rejects_wrong_media_identity_and_attribution() {
    let mut wrong_media = standard_harness();
    wrong_media.evidence.media_type = "application/json".to_owned();
    assert!(matches!(
        run(&wrong_media, RuffFixLimits::default()),
        Err(RuffFixError::InvalidEvidence { .. })
    ));

    let mut wrong_evidence_id = standard_harness();
    wrong_evidence_id.candidate.patch_evidence_id =
        object_id("019f7e95-0000-7000-8000-000000000099");
    assert!(matches!(
        run(&wrong_evidence_id, RuffFixLimits::default()),
        Err(RuffFixError::InvalidCandidate { .. })
    ));

    let mut multiple_observations = standard_harness();
    multiple_observations
        .candidate
        .observation_ids
        .push(object_id("019f7e95-0000-7000-8000-000000000098"));
    assert!(matches!(
        run(&multiple_observations, RuffFixLimits::default()),
        Err(RuffFixError::InvalidCandidate { .. })
    ));

    let mut wrong_tool = standard_harness();
    wrong_tool.observation.tool.name = "other".to_owned();
    assert!(matches!(
        run(&wrong_tool, RuffFixLimits::default()),
        Err(RuffFixError::ObservationMismatch { .. })
    ));

    for field in ["version", "rule_id", "filename"] {
        let mut harness = standard_harness();
        let mut document =
            serde_json::from_str::<Value>(&fixture_document()).expect("fixture JSON");
        document[field] = Value::String("mismatch".to_owned());
        set_document(&mut harness, &document);
        assert!(matches!(
            run(&harness, RuffFixLimits::default()),
            Err(RuffFixError::ObservationMismatch { .. })
        ));
    }
}

#[test]
fn rejects_truncated_unsafe_and_manual_sources() {
    let mut truncated = standard_harness();
    truncated.evidence.observed_bytes += 1;
    truncated.evidence.truncated = true;
    assert!(matches!(
        run(&truncated, RuffFixLimits::default()),
        Err(RuffFixError::InvalidEvidence { .. })
    ));

    for applicability in [Applicability::Unsafe, Applicability::Manual] {
        let mut harness = standard_harness();
        harness.candidate.applicability = applicability;
        assert!(matches!(
            run(&harness, RuffFixLimits::default()),
            Err(RuffFixError::InvalidCandidate { .. })
        ));
    }

    let mut native_unsafe = standard_harness();
    let mut document = serde_json::from_str::<Value>(&fixture_document()).expect("fixture JSON");
    document["fix"]["applicability"] = Value::String("unsafe".to_owned());
    set_document(&mut native_unsafe, &document);
    assert!(matches!(
        run(&native_unsafe, RuffFixLimits::default()),
        Err(RuffFixError::InvalidCandidate { .. })
    ));
}

#[test]
fn rejects_zero_out_of_range_reversed_overlapping_and_ambiguous_edits() {
    let invalid_edits = [
        json!([]),
        json!([{
            "content": "x",
            "location": {"row": 0, "column": 1},
            "end_location": {"row": 1, "column": 1}
        }]),
        json!([{
            "content": "x",
            "location": {"row": 1, "column": 99},
            "end_location": {"row": 1, "column": 99}
        }]),
        json!([{
            "content": "x",
            "location": {"row": 2, "column": 1},
            "end_location": {"row": 1, "column": 1}
        }]),
    ];
    for edits in invalid_edits {
        let harness = harness_with(
            TARGET,
            PREIMAGE,
            document_with_edits(edits),
            ScratchLimits::default(),
        );
        assert!(matches!(
            run(&harness, RuffFixLimits::default()),
            Err(RuffFixError::InvalidEdit { .. })
        ));
    }

    let ambiguous_edits = [
        json!([
            {"content": "x", "location": {"row": 2, "column": 1}, "end_location": {"row": 2, "column": 4}},
            {"content": "y", "location": {"row": 2, "column": 3}, "end_location": {"row": 2, "column": 5}}
        ]),
        json!([
            {"content": "x", "location": {"row": 2, "column": 1}, "end_location": {"row": 2, "column": 1}},
            {"content": "y", "location": {"row": 2, "column": 1}, "end_location": {"row": 2, "column": 1}}
        ]),
    ];
    for edits in ambiguous_edits {
        let harness = harness_with(
            TARGET,
            PREIMAGE,
            document_with_edits(edits),
            ScratchLimits::default(),
        );
        assert!(matches!(
            run(&harness, RuffFixLimits::default()),
            Err(RuffFixError::OverlappingEdits { .. })
        ));
    }
}

#[test]
fn rejects_crlf_non_ascii_and_non_utf8_preimages_without_mutation() {
    let cases = [
        (
            b"import os\r\nvalue = 1\r\nprint(value)\r\n".as_slice(),
            false,
        ),
        ("import os\nvalue = café\nprint(value)\n".as_bytes(), false),
        (b"import os\nvalue = \xff\nprint(value)\n".as_slice(), true),
    ];
    for (preimage, expect_non_utf8) in cases {
        let harness = harness_with(
            TARGET,
            preimage,
            fixture_document(),
            ScratchLimits::default(),
        );
        let scratch_before = fs::read(harness.workspace.path().join(TARGET)).expect("before");
        let error = run(&harness, RuffFixLimits::default()).expect_err("must reject");
        assert!(
            if expect_non_utf8 {
                matches!(error, RuffFixError::NonUtf8Target { .. })
            } else {
                matches!(error, RuffFixError::AmbiguousCoordinates { .. })
            },
            "unexpected error: {error}"
        );
        assert_eq!(
            fs::read(harness.workspace.path().join(TARGET)).expect("after"),
            scratch_before
        );
    }
}

#[test]
fn rejects_changed_missing_and_nonregular_staged_targets() {
    let changed = standard_harness();
    fs::write(changed.workspace.path().join(TARGET), b"changed\n").expect("change scratch");
    let changed_before = fs::read(changed.workspace.path().join(TARGET)).expect("changed before");
    assert!(matches!(
        run(&changed, RuffFixLimits::default()),
        Err(RuffFixError::BaseChanged)
    ));
    assert_eq!(
        fs::read(changed.workspace.path().join(TARGET)).expect("changed after"),
        changed_before
    );
    assert_eq!(
        fs::read(changed.repo.path().join(TARGET)).expect("original"),
        PREIMAGE
    );

    let mut missing = standard_harness();
    missing
        .observation
        .location
        .as_mut()
        .expect("location")
        .path = RepoPath::from_str("src/missing.py").expect("missing path");
    let mut document = serde_json::from_str::<Value>(&fixture_document()).expect("fixture JSON");
    document["filename"] = Value::String("src/missing.py".to_owned());
    set_document(&mut missing, &document);
    assert!(matches!(
        run(&missing, RuffFixLimits::default()),
        Err(RuffFixError::MissingTarget { .. })
    ));

    let repo = tempdir().expect("temporary repository");
    write_target(&repo, "src/directory/child.py", b"child = true\n");
    write_target(&repo, TARGET, PREIMAGE);
    let mut directory_document =
        serde_json::from_str::<Value>(&fixture_document()).expect("fixture JSON");
    directory_document["filename"] = Value::String("src/directory".to_owned());
    let nonregular = finish_harness(
        repo,
        "src/directory",
        serde_json::to_string(&directory_document).expect("encode document"),
        ScratchLimits::default(),
    );
    assert!(matches!(
        run(&nonregular, RuffFixLimits::default()),
        Err(RuffFixError::NonRegularTarget { .. })
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one boundary matrix keeps exact and minus-one limit cases together"
)]
fn enforces_ruff_and_workspace_hard_limits() {
    let harness = standard_harness();
    let limits = RuffFixLimits {
        max_edits: usize::MAX,
        ..RuffFixLimits::default()
    };
    assert!(matches!(
        run(&harness, limits),
        Err(RuffFixError::InvalidLimits {
            resource: "Ruff edit count",
            ..
        })
    ));

    let exact_edit_limit = RuffFixLimits {
        max_edits: 3,
        ..RuffFixLimits::default()
    };
    run(&harness, exact_edit_limit).expect("edit count at limit");
    let below_edit_limit = RuffFixLimits {
        max_edits: 2,
        ..RuffFixLimits::default()
    };
    assert!(matches!(
        run(&harness, below_edit_limit),
        Err(RuffFixError::BoundExceeded {
            resource: "Ruff edit count",
            ..
        })
    ));

    let exact_source_limit = RuffFixLimits {
        max_source_evidence_bytes: harness.evidence.retained_bytes,
        ..RuffFixLimits::default()
    };
    run(&harness, exact_source_limit).expect("source Evidence bytes at limit");
    let below_source_limit = RuffFixLimits {
        max_source_evidence_bytes: harness.evidence.retained_bytes - 1,
        ..RuffFixLimits::default()
    };
    assert!(matches!(
        run(&harness, below_source_limit),
        Err(RuffFixError::BoundExceeded {
            resource: "Ruff source Evidence bytes",
            ..
        })
    ));

    let target_bytes = u64::try_from(PREIMAGE.len()).expect("target length");
    let exact_target_limit = RuffFixLimits {
        max_target_bytes: target_bytes,
        ..RuffFixLimits::default()
    };
    run(&harness, exact_target_limit).expect("target bytes at limit");
    let below_target_limit = RuffFixLimits {
        max_target_bytes: u64::try_from(PREIMAGE.len() - 1).expect("target limit"),
        ..RuffFixLimits::default()
    };
    assert!(matches!(
        run(&harness, below_target_limit),
        Err(RuffFixError::BoundExceeded {
            resource: "staged Ruff target bytes",
            ..
        })
    ));

    let result_bytes = u64::try_from(RESULT.len()).expect("result length");
    let exact_result_limit = RuffFixLimits {
        max_result_bytes: result_bytes,
        ..RuffFixLimits::default()
    };
    run(&harness, exact_result_limit).expect("result bytes at limit");
    let below_result_limit = RuffFixLimits {
        max_result_bytes: u64::try_from(RESULT.len() - 1).expect("result limit"),
        ..RuffFixLimits::default()
    };
    assert!(matches!(
        run(&harness, below_result_limit),
        Err(RuffFixError::BoundExceeded {
            resource: "canonical full-file write bytes",
            ..
        })
    ));

    let patch_bytes = u64::try_from(fixture_patch().len()).expect("patch length");
    let exact_patch_limit = RuffFixLimits {
        max_patch_evidence_bytes: patch_bytes,
        ..RuffFixLimits::default()
    };
    run(&harness, exact_patch_limit).expect("patch Evidence bytes at limit");
    let below_patch_limit = RuffFixLimits {
        max_patch_evidence_bytes: u64::try_from(fixture_patch().len() - 1).expect("patch limit"),
        ..RuffFixLimits::default()
    };
    assert!(matches!(
        run(&harness, below_patch_limit),
        Err(RuffFixError::BoundExceeded {
            resource: "canonical patch Evidence bytes",
            ..
        })
    ));

    let mut large_preimage = PREIMAGE.to_vec();
    large_preimage.extend(std::iter::repeat_n(b'x', 512));
    let probe = harness_with(
        TARGET,
        &large_preimage,
        fixture_document(),
        ScratchLimits::default(),
    );
    let base_bound = probe.workspace.base_evidence().retained_bytes;
    let patch_bytes = run(&probe, RuffFixLimits::default())
        .expect("probe canonical patch")
        .patch_evidence
        .retained_bytes;
    assert!(patch_bytes > base_bound);
    let workspace_exact = harness_with(
        TARGET,
        &large_preimage,
        fixture_document(),
        ScratchLimits {
            max_evidence_bytes: u32::try_from(patch_bytes).expect("exact Evidence bound"),
            ..ScratchLimits::default()
        },
    );
    assert_eq!(
        run(&workspace_exact, RuffFixLimits::default())
            .expect("workspace Evidence bytes at limit")
            .patch_evidence
            .retained_bytes,
        patch_bytes
    );

    let workspace_below = harness_with(
        TARGET,
        &large_preimage,
        fixture_document(),
        ScratchLimits {
            max_evidence_bytes: u32::try_from(patch_bytes - 1).expect("below Evidence bound"),
            ..ScratchLimits::default()
        },
    );
    assert!(matches!(
        run(&workspace_below, RuffFixLimits::default()),
        Err(RuffFixError::Scratch {
            source: ScratchError::BoundExceeded {
                resource: "Evidence bytes",
                ..
            }
        })
    ));
}

#[test]
fn enforces_each_json_string_limit_at_exact_and_minus_one() {
    let harness = standard_harness();
    let exact_string_limit = RuffFixLimits {
        max_string_bytes: "src/example.py".len() as u64,
        ..RuffFixLimits::default()
    };
    run(&harness, exact_string_limit).expect("longest Ruff string at limit");

    let below_string_limit = RuffFixLimits {
        max_string_bytes: "src/example.py".len() as u64 - 1,
        ..RuffFixLimits::default()
    };
    assert!(matches!(
        run(&harness, below_string_limit),
        Err(RuffFixError::BoundExceeded {
            resource: "Ruff string bytes",
            ..
        })
    ));

    let invalid = RuffFixLimits {
        max_string_bytes: MAX_RUFF_FIX_STRING_BYTES + 1,
        ..RuffFixLimits::default()
    };
    assert!(matches!(
        run(&harness, invalid),
        Err(RuffFixError::InvalidLimits {
            resource: "Ruff string bytes",
            ..
        })
    ));

    let invalid_depth = RuffFixLimits {
        max_json_depth: usize::MAX,
        ..RuffFixLimits::default()
    };
    assert!(matches!(
        run(&harness, invalid_depth),
        Err(RuffFixError::InvalidLimits {
            resource: "Ruff JSON nesting depth",
            ..
        })
    ));
}

#[test]
fn canonicalize_rejects_escaped_over_limit_before_json_materialization() {
    let raw_content = r#""\u0061\u0061\u0061\u0061\u0061\u0061\u0061\u0061\u0061\u0061\u0061\u0061\u0061\u0061\u0061\x""#;
    let harness = harness_with(
        TARGET,
        PREIMAGE,
        document_with_raw_first_edit_content(raw_content),
        ScratchLimits::default(),
    );
    let limits = RuffFixLimits {
        max_string_bytes: "src/example.py".len() as u64,
        ..RuffFixLimits::default()
    };

    assert!(matches!(
        run(&harness, limits),
        Err(RuffFixError::BoundExceeded {
            resource: "Ruff string bytes",
            actual: 15,
            max: 14,
        })
    ));
}

#[test]
fn canonicalize_accepts_valid_unicode_surrogate_pair_through_real_path() {
    let raw_content = r#""\uD834\uDD1E""#;
    let harness = harness_with(
        TARGET,
        PREIMAGE,
        document_with_raw_first_edit_content(raw_content),
        ScratchLimits::default(),
    );
    let limits = RuffFixLimits {
        max_string_bytes: "src/example.py".len() as u64,
        ..RuffFixLimits::default()
    };

    let canonical = run(&harness, limits).expect("valid surrogate pair");
    let mut expected = b"\nvalue = 42\n".to_vec();
    expected.extend_from_slice("\u{1D11E}".as_bytes());
    expected.extend_from_slice(b"print(value)\n");
    assert_eq!(
        canonical.patch.changes(),
        &[ScratchChange::Write {
            path: TARGET.to_owned(),
            contents: expected,
        }]
    );
}
