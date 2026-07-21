use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};
#[cfg(unix)]
use std::{process::Child, time::Instant};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use diagnostic_triage_contracts::{
    Sha256Digest,
    model::{Applicability, EvidenceSource, ExecutionStatus},
    protocol::{Operation, ProtocolEnvelope},
};
#[cfg(unix)]
use diagnostic_triage_provider_python::ProviderSession;
use diagnostic_triage_provider_python::{
    CompletionBuilder, ProviderError, decode_request, emit_envelope, emit_manifest,
    normalize_ruff_json, run_ruff_session, validate_generated_session, validate_request,
};
#[cfg(unix)]
use wait_timeout::ChildExt;

const REQUEST: &[u8] = include_bytes!("golden/request.json");

#[cfg(unix)]
struct FakeRuff {
    root: PathBuf,
    program: PathBuf,
}

#[cfg(unix)]
impl FakeRuff {
    fn new(check_body: &str) -> Self {
        Self::with_version("printf 'ruff 0.15.2\\n'; exit 0", check_body)
    }

    fn with_version(version_body: &str, check_body: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "diagnostic-triage-ruff-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let program = root.join("ruff");
        fs::write(
            &program,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then {version_body}; fi\n{check_body}\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        Self { root, program }
    }
}

#[cfg(unix)]
impl Drop for FakeRuff {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
struct WatchdogChild {
    child: Child,
    fake_process_group: PathBuf,
    armed: bool,
}

#[cfg(unix)]
impl WatchdogChild {
    fn new(child: Child, fake_process_group: PathBuf) -> Self {
        Self {
            child,
            fake_process_group,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(unix)]
impl Drop for WatchdogChild {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ignored = self.child.kill();
        let _ignored = self.child.wait();
        let deadline = Instant::now() + Duration::from_secs(3);
        while marked_process_group_exists(&self.fake_process_group) != Some(false)
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(unix)]
fn marked_process_group_exists(marker: &Path) -> Option<bool> {
    let raw_pid = fs::read_to_string(marker).ok()?.parse::<i32>().ok()?;
    let process_group = rustix::process::Pid::from_raw(raw_pid)?;
    match rustix::process::test_kill_process_group(process_group) {
        Ok(()) => Some(true),
        Err(rustix::io::Errno::SRCH) => Some(false),
        Err(_) => None,
    }
}

fn request() -> diagnostic_triage_contracts::protocol::RequestEnvelope {
    decode_request(REQUEST, REQUEST.len()).unwrap()
}

#[test]
fn manifest_is_one_typed_golden_jsonl_line() {
    let mut actual = Vec::new();
    emit_manifest(&mut actual).unwrap();
    assert_eq!(actual, include_bytes!("golden/manifest.jsonl"));
}

#[test]
fn clean_ruff_output_has_zero_events_and_exact_completion_counts() {
    let request = decode_request(REQUEST, REQUEST.len()).unwrap();
    validate_request(&request).unwrap();
    let mut builder = CompletionBuilder::new(&request);
    let normalized = normalize_ruff_json(
        &request,
        "0.15.2",
        Path::new("/repo"),
        include_bytes!("golden/ruff-clean.json"),
        &[],
        &mut builder,
    )
    .unwrap();
    assert!(normalized.events.is_empty());
    let completion = builder.complete(0, 4).unwrap();
    assert_eq!(completion.sequence, 0);
    assert_eq!(completion.counts.observations, 0);
    assert_eq!(completion.status, ExecutionStatus::Complete);
}

#[test]
fn findings_match_golden_and_preserve_only_explicit_safe_unsafe_metadata() {
    let request = decode_request(REQUEST, REQUEST.len()).unwrap();
    let mut builder = CompletionBuilder::new(&request);
    let normalized = normalize_ruff_json(
        &request,
        "0.15.2",
        Path::new("/repo"),
        include_bytes!("golden/ruff-findings.json"),
        &[],
        &mut builder,
    )
    .unwrap();

    let mut actual = Vec::new();
    for event in &normalized.events {
        emit_envelope(&mut actual, event).unwrap();
    }
    assert_eq!(
        actual,
        include_bytes!("golden/ruff-findings.expected.jsonl")
    );
    let candidates = normalized
        .events
        .iter()
        .filter_map(|event| match event {
            ProtocolEnvelope::FixCandidate(value) => Some(&value.fix_candidate),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 3);
    assert_eq!(candidates[0].applicability, Applicability::Safe);
    assert_eq!(candidates[1].applicability, Applicability::Unsafe);
    assert_eq!(candidates[2].applicability, Applicability::Manual);

    let patches = normalized
        .events
        .iter()
        .filter_map(|event| match event {
            ProtocolEnvelope::Evidence(value) if value.evidence.source == EvidenceSource::Patch => {
                Some(&value.evidence)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(patches.len(), 3);
    let safe_patch: serde_json::Value =
        serde_json::from_str(patches[0].content.as_deref().unwrap()).unwrap();
    assert_eq!(safe_patch["version"], "0.15.2");
    assert_eq!(safe_patch["filename"], "src/a.py");
    assert_eq!(safe_patch["rule_id"], "F401");
    assert_eq!(safe_patch["fix"]["applicability"], "safe");
    assert_eq!(safe_patch["fix"]["message"], "Remove unused import: os");
    assert_eq!(safe_patch["fix"]["edits"][0]["content"], "");
    assert_eq!(safe_patch["fix"]["edits"][0]["location"]["row"], 1);
    assert_eq!(safe_patch["fix"]["edits"][0]["end_location"]["column"], 10);
    assert_eq!(
        safe_patch["fix"]["edits"][0]["future_edit_field"],
        "preserved"
    );
    assert_eq!(safe_patch["fix"]["future_fix_field"]["mode"], "strict");

    assert!(matches!(
        &normalized.events[0],
        ProtocolEnvelope::Observation(value) if value.observation.severity == diagnostic_triage_contracts::model::Severity::Error
    ));

    let completion = builder.complete(1, 7).unwrap();
    assert_eq!(completion.sequence, 9);
    assert_eq!(completion.counts.observations, 3);
    assert_eq!(completion.counts.evidence, 3);
    assert_eq!(completion.counts.fix_candidates, 3);
    assert_eq!(completion.counts.executions, 0);
    assert_eq!(
        completion.evidence_bytes,
        patches
            .iter()
            .map(|evidence| evidence.retained_bytes)
            .sum::<u64>()
    );
}

#[test]
fn ruff_locations_preserve_points_insertions_and_half_open_code_point_ranges() {
    let request = request();
    let mut builder = CompletionBuilder::new(&request);
    let input = r#"[
      {"code":"POINT","filename":"src/unicode.py","location":{"row":1,"column":2},"message":"point after α","severity":"warning","fix":null},
      {"code":"INSERT","filename":"src/unicode.py","location":{"row":2,"column":3},"end_location":{"row":2,"column":3},"message":"insertion","severity":"warning","fix":null},
      {"code":"SAME","filename":"src/unicode.py","location":{"row":3,"column":2},"end_location":{"row":3,"column":4},"message":"same line","severity":"warning","fix":null},
      {"code":"NEXT","filename":"src/unicode.py","location":{"row":4,"column":1},"end_location":{"row":5,"column":1},"message":"through newline","severity":"warning","fix":null}
    ]"#;
    let normalized = normalize_ruff_json(
        &request,
        "0.15.2",
        Path::new("/repo"),
        input.as_bytes(),
        &[],
        &mut builder,
    )
    .expect("Ruff Location v1 shapes normalize");
    let locations = normalized
        .events
        .iter()
        .filter_map(|event| match event {
            ProtocolEnvelope::Observation(value) => value.observation.location.as_ref(),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(locations.len(), 4);
    assert!(locations[0].end.is_none(), "absent end remains a point");
    assert_eq!(locations[1].start, locations[1].end.clone().unwrap());
    assert_eq!(locations[2].end.as_ref().unwrap().column, 4);
    assert_eq!(locations[3].end.as_ref().unwrap().line, 5);
    assert_eq!(locations[3].end.as_ref().unwrap().column, 1);
}

#[test]
fn ruff_non_bmp_fixture_proves_scalar_not_utf16_or_utf8_columns() {
    let provenance: serde_json::Value =
        serde_json::from_slice(include_bytes!("golden/ruff-unicode.provenance.json"))
            .expect("Ruff fixture provenance is JSON");
    assert_eq!(provenance["tool"], "ruff");
    assert_eq!(provenance["tool_version"], "ruff 0.15.14");
    assert_eq!(
        provenance["coordinate_probe"]["unicode_scalar_start_column"],
        10
    );
    assert_eq!(provenance["coordinate_probe"]["utf16_start_column"], 11);
    assert_eq!(provenance["coordinate_probe"]["utf8_byte_start_column"], 13);
    assert_eq!(
        provenance["source_sha256"],
        Sha256Digest::compute(include_bytes!("golden/ruff-unicode.py")).as_str()
    );
    assert_eq!(
        provenance["output_sha256"],
        Sha256Digest::compute(include_bytes!("golden/ruff-unicode.json")).as_str()
    );

    let request = request();
    let mut builder = CompletionBuilder::new(&request);
    let normalized = normalize_ruff_json(
        &request,
        "0.15.14",
        Path::new("/repo"),
        include_bytes!("golden/ruff-unicode.json"),
        &[],
        &mut builder,
    )
    .expect("pinned Ruff JSON fixture normalizes");
    let location = normalized
        .events
        .iter()
        .find_map(|event| match event {
            ProtocolEnvelope::Observation(value) => value.observation.location.as_ref(),
            _ => None,
        })
        .expect("fixture emits one location");
    assert_eq!(location.start.column, 10);
    assert_eq!(location.end.as_ref().expect("Ruff end_location").column, 11);
}

#[test]
fn unknown_severity_is_rejected_and_untrusted_edits_are_manual() {
    let request = request();
    let unknown_severity = br#"[{"code":"X","filename":"x.py","location":{"row":1,"column":1},"message":"x","severity":"fatal","fix":null}]"#;
    let mut builder = CompletionBuilder::new(&request);
    assert!(matches!(
        normalize_ruff_json(
            &request,
            "0.15.2",
            Path::new("/repo"),
            unknown_severity,
            &[],
            &mut builder,
        ),
        Err(ProviderError::RuffSeverity(value)) if value == "fatal"
    ));

    let unsafe_shapes = br#"[
      {"code":"A","filename":"a.py","location":{"row":1,"column":1},"message":"missing","severity":"warning","fix":{"applicability":"safe","message":"missing edits"}},
      {"code":"B","filename":"b.py","location":{"row":1,"column":1},"message":"overlap","severity":"warning","fix":{"applicability":"safe","message":"overlap","edits":[{"content":"x","location":{"row":1,"column":1},"end_location":{"row":1,"column":3}},{"content":"y","location":{"row":1,"column":2},"end_location":{"row":1,"column":4}}]}}
    ]"#;
    let mut builder = CompletionBuilder::new(&request);
    let normalized = normalize_ruff_json(
        &request,
        "0.15.2",
        Path::new("/repo"),
        unsafe_shapes,
        &[],
        &mut builder,
    )
    .unwrap();
    let candidates = normalized
        .events
        .iter()
        .filter_map(|event| match event {
            ProtocolEnvelope::FixCandidate(value) => Some(&value.fix_candidate),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 2);
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate.applicability == Applicability::Manual)
    );
    assert_eq!(
        normalized
            .events
            .iter()
            .filter(|event| matches!(event, ProtocolEnvelope::Evidence(_)))
            .count(),
        2
    );
}

#[test]
fn malformed_request_and_ruff_json_are_rejected() {
    let request = decode_request(REQUEST, REQUEST.len()).unwrap();
    let doubled = [REQUEST, REQUEST].concat();
    assert!(matches!(
        decode_request(&doubled, doubled.len()),
        Err(ProviderError::Request(_))
    ));
    let invalid_id = String::from_utf8(REQUEST.to_vec())
        .unwrap()
        .replace("019f7e95-0000-7000-8000-000000000001", "not-a-uuid");
    assert!(matches!(
        decode_request(invalid_id.as_bytes(), invalid_id.len()),
        Err(ProviderError::Request(_))
    ));
    let mut builder = CompletionBuilder::new(&request);
    assert!(matches!(
        normalize_ruff_json(
            &request,
            "0.15.2",
            Path::new("/repo"),
            include_bytes!("golden/ruff-malformed.json"),
            &[],
            &mut builder,
        ),
        Err(ProviderError::RuffJson(_))
    ));
}

#[test]
fn caller_bound_and_request_or_ruff_path_escape_are_rejected() {
    assert!(matches!(
        decode_request(REQUEST, REQUEST.len() - 1),
        Err(ProviderError::InputLimit { .. })
    ));
    let escaped = include_bytes!("golden/request-path-escape.json");
    assert!(matches!(
        decode_request(escaped, escaped.len()),
        Err(ProviderError::Request(_))
    ));

    let request = decode_request(REQUEST, REQUEST.len()).unwrap();
    let mut builder = CompletionBuilder::new(&request);
    assert!(matches!(
        normalize_ruff_json(
            &request,
            "0.15.2",
            Path::new("/repo"),
            include_bytes!("golden/ruff-path-escape.json"),
            &[],
            &mut builder,
        ),
        Err(ProviderError::PathEscape(_))
    ));
}

#[test]
fn capability_and_operation_mismatch_are_rejected() {
    let mismatch = include_bytes!("golden/request-capability-mismatch.json");
    let request = decode_request(mismatch, mismatch.len()).unwrap();
    assert!(matches!(
        validate_request(&request),
        Err(ProviderError::Unsupported(_))
    ));

    let mut request = decode_request(REQUEST, REQUEST.len()).unwrap();
    request.required_capabilities = vec![
        "diagnostic.check/v1".parse().unwrap(),
        "fix.propose/v1".parse().unwrap(),
    ];
    request.optional_capabilities = vec!["vendor.unknown/v1".parse().unwrap()];
    validate_request(&request).unwrap();

    let mut request = decode_request(REQUEST, REQUEST.len()).unwrap();
    request.operation = Operation::Fix;
    assert!(matches!(
        validate_request(&request),
        Err(ProviderError::Unsupported(_))
    ));
}

#[test]
fn unsupported_completion_preserves_the_protocol_terminal_state() {
    let request = request();
    let completion = CompletionBuilder::new(&request)
        .unsupported(0, "required capability is not advertised")
        .unwrap();

    assert_eq!(completion.status, ExecutionStatus::Unsupported);
    assert_eq!(completion.tool_exit_code.0, None);
    assert_eq!(completion.sequence, 0);
}

#[test]
fn fix_events_require_negotiated_fix_propose_capability() {
    let mut request = request();
    request
        .optional_capabilities
        .retain(|capability| capability.as_str() != "fix.propose/v1");
    validate_request(&request).unwrap();
    let mut builder = CompletionBuilder::new(&request);
    let normalized = normalize_ruff_json(
        &request,
        "0.15.2",
        Path::new("/repo"),
        include_bytes!("golden/ruff-findings.json"),
        &[],
        &mut builder,
    )
    .unwrap();

    assert_eq!(normalized.events.len(), 3);
    assert!(
        normalized
            .events
            .iter()
            .all(|event| matches!(event, ProtocolEnvelope::Observation(_)))
    );
    let completion = builder.complete(1, 1).unwrap();
    assert_eq!(completion.counts.fix_candidates, 0);
    assert_eq!(completion.counts.evidence, 0);
}

#[cfg(unix)]
#[test]
fn nonzero_findings_exit_is_complete_and_cross_field_valid() {
    let fake = FakeRuff::new(
        r#"printf '%s' '[{"code":"F401","filename":"src/a.py","location":{"row":1,"column":1},"end_location":{"row":1,"column":2},"message":"unused","severity":"error","fix":{"applicability":"safe","message":"remove","edits":[{"content":"","location":{"row":1,"column":1},"end_location":{"row":1,"column":2}}]}}]'; exit 1"#,
    );
    let request = request();
    let session = run_ruff_session(&request, &fake.root, &fake.program).unwrap();

    assert_eq!(session.completion.status, ExecutionStatus::Complete);
    assert_eq!(session.completion.tool_exit_code.0, Some(1));
    assert_eq!(session.completion.counts.observations, 1);
    assert_eq!(session.completion.counts.evidence, 2);
    assert_eq!(session.completion.counts.fix_candidates, 1);
    assert!(session.events.iter().any(|event| matches!(
        event,
        ProtocolEnvelope::FixCandidate(value)
            if value.fix_candidate.applicability == Applicability::Safe
    )));
    validate_generated_session(&request, &session).unwrap();
}

#[cfg(unix)]
#[test]
fn nested_workspace_targets_are_resolved_from_the_repository_root() {
    let mut fake = FakeRuff::new(
        r#"if [ ! -d "$5" ]; then printf 'missing target: %s' "$5" >&2; exit 2; fi
printf '%s' '[{"code":"F401","filename":"pkg/src/a.py","location":{"row":1,"column":1},"end_location":{"row":1,"column":2},"message":"unused","severity":"error","fix":null}]'; exit 1"#,
    );
    fs::create_dir_all(fake.root.join("tools")).unwrap();
    fs::rename(&fake.program, fake.root.join("tools/ruff")).unwrap();
    fake.program = PathBuf::from("tools/ruff");
    fs::create_dir_all(fake.root.join("pkg/src")).unwrap();
    let mut request = request();
    request.workspace = "pkg".parse().unwrap();
    request.targets = vec!["pkg/src".parse().unwrap()];

    let session = run_ruff_session(&request, &fake.root, &fake.program).unwrap();

    assert_eq!(session.completion.status, ExecutionStatus::Complete);
    assert!(session.events.iter().any(|event| matches!(
        event,
        ProtocolEnvelope::Observation(value)
            if value.observation.location.as_ref().is_some_and(|location| {
                location.path.as_str() == "pkg/src/a.py"
            })
    )));
    validate_generated_session(&request, &session).unwrap();
}

#[cfg(unix)]
#[test]
fn nested_workspace_rejects_sibling_and_symlink_targets_before_ruff() {
    use std::os::unix::fs::symlink;

    let fake = FakeRuff::new("printf '[]'; exit 0");
    fs::create_dir_all(fake.root.join("pkg")).unwrap();
    fs::create_dir_all(fake.root.join("sibling")).unwrap();
    symlink(fake.root.join("sibling"), fake.root.join("pkg/link")).unwrap();

    for target in ["sibling", "pkg/link", "pkg/link/new.py"] {
        let mut request = request();
        request.workspace = "pkg".parse().unwrap();
        request.targets = vec![target.parse().unwrap()];

        let session = run_ruff_session(&request, &fake.root, &fake.program).unwrap();

        assert_eq!(session.completion.status, ExecutionStatus::Incomplete);
        assert!(
            session
                .completion
                .message
                .as_deref()
                .is_some_and(|message| message.contains("path escapes"))
        );
        assert!(session.events.is_empty());
        validate_generated_session(&request, &session).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn nested_workspace_scope_is_revalidated_after_ruff() {
    let fake = FakeRuff::new("rmdir pkg/src; ln -s ../sibling pkg/src; printf '[]'; exit 0");
    fs::create_dir_all(fake.root.join("pkg/src")).unwrap();
    fs::create_dir_all(fake.root.join("sibling")).unwrap();
    let mut request = request();
    request.workspace = "pkg".parse().unwrap();
    request.targets = vec!["pkg/src".parse().unwrap()];

    let session = run_ruff_session(&request, &fake.root, &fake.program).unwrap();

    assert_eq!(session.completion.status, ExecutionStatus::Incomplete);
    assert!(
        session
            .completion
            .message
            .as_deref()
            .is_some_and(|message| message.contains("path escapes"))
    );
    validate_generated_session(&request, &session).unwrap();
}

#[cfg(unix)]
#[test]
fn root_workspace_preserves_missing_targets_and_rejects_escape_ancestors() {
    use std::os::unix::fs::symlink;

    let fake =
        FakeRuff::new(r#"if [ "$5" != "missing.py" ]; then exit 2; fi; printf '[]'; exit 0"#);
    let mut request = request();
    request.targets = vec!["missing.py".parse().unwrap()];

    let session = run_ruff_session(&request, &fake.root, &fake.program).unwrap();
    assert_eq!(session.completion.status, ExecutionStatus::Complete);
    validate_generated_session(&request, &session).unwrap();

    symlink(std::env::temp_dir(), fake.root.join("escape")).unwrap();
    request.targets = vec!["escape/missing.py".parse().unwrap()];
    let session = run_ruff_session(&request, &fake.root, &fake.program).unwrap();
    assert_eq!(session.completion.status, ExecutionStatus::Incomplete);
    assert!(
        session
            .completion
            .message
            .as_deref()
            .is_some_and(|message| message.contains("path escapes"))
    );
    validate_generated_session(&request, &session).unwrap();
}

#[cfg(unix)]
#[test]
fn clean_run_completes_when_caller_allows_no_payload_events() {
    let fake = FakeRuff::new("printf '[]'; exit 0");
    let mut request = request();
    request.limits.max_events = 0;
    let session = run_ruff_session(&request, &fake.root, &fake.program).unwrap();

    assert!(session.events.is_empty());
    assert_eq!(session.completion.status, ExecutionStatus::Complete);
    assert_eq!(session.completion.sequence, 0);
    validate_generated_session(&request, &session).unwrap();
}

#[cfg(unix)]
#[test]
fn tool_error_exit_is_incomplete_and_retains_stderr_evidence() {
    let fake = FakeRuff::new("printf 'configuration error' >&2; exit 2");
    let request = request();
    let session = run_ruff_session(&request, &fake.root, &fake.program).unwrap();

    assert_eq!(session.completion.status, ExecutionStatus::Incomplete);
    assert_eq!(session.completion.tool_exit_code.0, None);
    assert!(
        session
            .completion
            .message
            .as_deref()
            .is_some_and(|message| message.contains("Some(2)"))
    );
    assert!(session.events.iter().any(|event| matches!(
        event,
        ProtocolEnvelope::Evidence(value) if value.evidence.source == EvidenceSource::Stderr
    )));
    validate_generated_session(&request, &session).unwrap();
}

#[cfg(unix)]
#[test]
fn signal_crash_is_incomplete_without_inventing_an_exit_code() {
    let fake = FakeRuff::new("kill -TERM $$");
    let request = request();
    let session = run_ruff_session(&request, &fake.root, &fake.program).unwrap();

    assert_eq!(session.completion.status, ExecutionStatus::Incomplete);
    assert_eq!(session.completion.tool_exit_code.0, None);
    assert!(
        session
            .completion
            .message
            .as_deref()
            .is_some_and(|message| message.contains("TerminatedWithoutCode"))
    );
    validate_generated_session(&request, &session).unwrap();
}

#[cfg(unix)]
#[test]
fn malformed_version_is_text_evidence_not_json() {
    let fake = FakeRuff::with_version("printf 'not-ruff\\n'; exit 0", "printf '[]'; exit 0");
    let request = request();
    let session = run_ruff_session(&request, &fake.root, &fake.program).unwrap();

    assert_eq!(session.completion.status, ExecutionStatus::Incomplete);
    assert!(session.events.iter().any(|event| matches!(
        event,
        ProtocolEnvelope::Evidence(value)
            if value.evidence.source == EvidenceSource::Stdout
                && value.evidence.media_type == "text/plain"
    )));
    validate_generated_session(&request, &session).unwrap();
}

#[cfg(unix)]
#[test]
fn timeout_is_incomplete_and_retains_stderr_evidence() {
    let fake = FakeRuff::new(
        "(sleep 12; kill -KILL 0) & printf '%s' \"$$\" > \"$DT_RUFF_PID_MARKER\"; printf 'started' >&2; while :; do sleep 1; done",
    );
    let marker = fake.root.join("ruff-pgid");
    let mut request = request();
    // Give the spawned fixture a scheduling window before the timeout. The
    // contract under test is retention after output, not sub-50 ms startup.
    request.limits.timeout_ms = 500;
    let mut paths = vec![fake.root.clone()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let child = Command::new(env!("CARGO_BIN_EXE_diagnostic-triage-provider-python"))
        .current_dir(&fake.root)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("DT_RUFF_PID_MARKER", &marker)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = WatchdogChild::new(child, marker);
    let mut request_bytes = serde_json::to_vec(&request).unwrap();
    request_bytes.push(b'\n');
    child
        .child
        .stdin
        .take()
        .unwrap()
        .write_all(&request_bytes)
        .unwrap();

    let status = child.child.wait_timeout(Duration::from_secs(10)).unwrap();
    let status = status.expect("provider exceeded the independent 10 s watchdog");
    assert!(status.success());
    assert_eq!(
        marked_process_group_exists(&child.fake_process_group),
        Some(false),
        "provider returned before the Fake Ruff process group disappeared"
    );
    child.disarm();
    let mut output = String::new();
    child
        .child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    let mut lines = output.lines();
    let manifest = lines.next().expect("provider emits a manifest first");
    assert_eq!(
        format!("{manifest}\n").as_bytes(),
        include_bytes!("golden/manifest.jsonl")
    );
    let events = lines
        .map(|line| serde_json::from_str::<ProtocolEnvelope>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, ProtocolEnvelope::Completion(_)))
            .count(),
        1
    );
    let completion = events
        .iter()
        .find_map(|event| match event {
            ProtocolEnvelope::Completion(value) => Some(value.clone()),
            _ => None,
        })
        .expect("provider emits one completion");

    assert_eq!(completion.status, ExecutionStatus::Incomplete);
    assert_eq!(completion.tool_exit_code.0, None);
    assert!(events.iter().any(|event| matches!(
        event,
        ProtocolEnvelope::Evidence(value) if value.evidence.source == EvidenceSource::Stderr
    )));
    let session = ProviderSession {
        events: events
            .into_iter()
            .filter(|event| !matches!(event, ProtocolEnvelope::Completion(_)))
            .collect(),
        completion,
    };
    validate_generated_session(&request, &session).unwrap();
}

#[cfg(unix)]
#[test]
fn stdout_overflow_is_incomplete_with_truncated_evidence() {
    let fake =
        FakeRuff::new("i=0; while [ \"$i\" -lt 700 ]; do printf 'xxxxxxxx'; i=$((i + 1)); done");
    let mut request = request();
    request.limits.max_evidence_bytes = 512;
    let session = run_ruff_session(&request, &fake.root, &fake.program).unwrap();

    assert_eq!(session.completion.status, ExecutionStatus::Incomplete);
    assert!(session.events.iter().any(|event| matches!(
        event,
        ProtocolEnvelope::Evidence(value)
            if value.evidence.source == EvidenceSource::Stdout && value.evidence.truncated
    )));
    validate_generated_session(&request, &session).unwrap();
}

#[cfg(unix)]
#[test]
fn simultaneous_stdout_and_stderr_are_drained_without_deadlock() {
    let fake = FakeRuff::new(
        r#"i=0; while [ "$i" -lt 10000 ]; do printf '                '; printf 'yyyyyyyyyyyyyyyy' >&2; i=$((i + 1)); done; printf '[]'; exit 0"#,
    );
    let mut request = request();
    request.limits.timeout_ms = 5_000;
    request.limits.max_stdout_bytes = 512 * 1024;
    request.limits.max_stderr_bytes = 512 * 1024;
    request.limits.max_evidence_bytes = 256;
    let session = run_ruff_session(&request, &fake.root, &fake.program).unwrap();

    assert_eq!(session.completion.status, ExecutionStatus::Complete);
    assert!(session.events.iter().any(|event| matches!(
        event,
        ProtocolEnvelope::Evidence(value)
            if value.evidence.source == EvidenceSource::Stderr
                && value.evidence.observed_bytes == 160_000
                && value.evidence.truncated
    )));
    validate_generated_session(&request, &session).unwrap();
}

#[cfg(unix)]
#[test]
fn malformed_process_json_is_incomplete_with_stdout_evidence() {
    let fake = FakeRuff::new("printf '{'; exit 0");
    let request = request();
    let session = run_ruff_session(&request, &fake.root, &fake.program).unwrap();

    assert_eq!(session.completion.status, ExecutionStatus::Incomplete);
    assert_eq!(session.completion.counts.observations, 0);
    assert_eq!(session.completion.counts.evidence, 1);
    validate_generated_session(&request, &session).unwrap();
}

#[cfg(unix)]
#[test]
fn binary_emits_manifest_before_reading_then_runs_ruff() {
    let fake = FakeRuff::new(
        r#"if [ "$1" != "check" ] || [ "$2" != "--output-format" ] || [ "$3" != "json" ] || [ "$4" != "--" ] || [ "$5" != "src" ]; then printf 'bad argv' >&2; exit 2; fi
printf '%s' '[{"code":"F401","filename":"src/a.py","location":{"row":1,"column":1},"end_location":{"row":1,"column":2},"message":"unused","severity":"error","fix":{"applicability":"safe","message":"remove","edits":[{"content":"","location":{"row":1,"column":1},"end_location":{"row":1,"column":2}}]}}]'; exit 1"#,
    );
    let mut paths = vec![fake.root.clone()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let mut child = Command::new(env!("CARGO_BIN_EXE_diagnostic-triage-provider-python"))
        .current_dir(&fake.root)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut first_line = String::new();
    stdout.read_line(&mut first_line).unwrap();
    assert_eq!(
        first_line.as_bytes(),
        include_bytes!("golden/manifest.jsonl")
    );

    let mut request_writer = child.stdin.take().unwrap();
    request_writer.write_all(REQUEST).unwrap();
    let status = child.wait_timeout(Duration::from_secs(1)).unwrap();
    drop(request_writer);
    let Some(status) = status else {
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("provider waited for stdin EOF after one complete JSONL request");
    };
    assert!(status.success());
    let mut tail = String::new();
    stdout.read_to_string(&mut tail).unwrap();
    let events = tail
        .lines()
        .map(|line| serde_json::from_str::<ProtocolEnvelope>(line).unwrap())
        .collect::<Vec<_>>();
    let patch = events.iter().find_map(|event| match event {
        ProtocolEnvelope::Evidence(value) if value.evidence.source == EvidenceSource::Patch => {
            Some(&value.evidence)
        }
        _ => None,
    });
    let patch = patch.expect("binary transcript exposes Ruff patch evidence");
    let patch_json: serde_json::Value =
        serde_json::from_str(patch.content.as_deref().unwrap()).unwrap();
    assert_eq!(patch_json["filename"], "src/a.py");
    assert_eq!(patch_json["rule_id"], "F401");
    assert!(events.iter().any(|event| matches!(
        event,
        ProtocolEnvelope::FixCandidate(value)
            if value.fix_candidate.patch_evidence_id == patch.evidence_id
                && value.fix_candidate.applicability == Applicability::Safe
    )));
    let completion = events.last().unwrap();
    assert!(matches!(
        completion,
        ProtocolEnvelope::Completion(value)
            if value.status == ExecutionStatus::Complete
                && value.counts.fix_candidates == 1
                && value.counts.evidence == 2
    ));
}

#[cfg(unix)]
#[test]
fn manifest_first_stdio_completion_waits_for_closed_stdio_descendant_cleanup() {
    let fake = FakeRuff::new(
        r#"(sleep 1; printf 'late-descendant-write' > "$DIAGNOSTIC_TRIAGE_DELAYED_MARKER") </dev/null >/dev/null 2>&1 &
printf '[]'; exit 0"#,
    );
    let marker = fake.root.join("delayed-descendant-marker");
    let mut paths = vec![fake.root.clone()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let mut child = Command::new(env!("CARGO_BIN_EXE_diagnostic-triage-provider-python"))
        .current_dir(&fake.root)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("DIAGNOSTIC_TRIAGE_DELAYED_MARKER", &marker)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut manifest = String::new();
    stdout.read_line(&mut manifest).unwrap();
    assert_eq!(manifest.as_bytes(), include_bytes!("golden/manifest.jsonl"));

    child.stdin.take().unwrap().write_all(REQUEST).unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());

    let mut tail = String::new();
    stdout.read_to_string(&mut tail).unwrap();
    let events = tail
        .lines()
        .map(|line| serde_json::from_str::<ProtocolEnvelope>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(
        matches!(
            events.last(),
            Some(ProtocolEnvelope::Completion(value))
                if value.status == ExecutionStatus::Complete
                    && value.tool_exit_code.0 == Some(0)
        ),
        "unexpected process cleanup transcript: {events:?}"
    );

    // The child closes all captured streams, exits first, and attempts the
    // delayed write later. Completion is valid only after the dedicated
    // process group has been terminated and reaped.
    thread::sleep(Duration::from_millis(1_200));
    assert!(
        !marker.exists(),
        "Completion was published while a same-group descendant was still live"
    );
}

#[cfg(unix)]
#[test]
fn binary_emits_unsupported_for_unadvertised_required_capability() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_diagnostic-triage-provider-python"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut manifest = String::new();
    stdout.read_line(&mut manifest).unwrap();
    assert_eq!(manifest.as_bytes(), include_bytes!("golden/manifest.jsonl"));

    child
        .stdin
        .take()
        .unwrap()
        .write_all(include_bytes!("golden/request-capability-mismatch.json"))
        .unwrap();
    let mut tail = String::new();
    stdout.read_to_string(&mut tail).unwrap();
    assert!(child.wait().unwrap().success());
    let completion = serde_json::from_str::<ProtocolEnvelope>(tail.trim()).unwrap();
    assert!(matches!(
        completion,
        ProtocolEnvelope::Completion(value)
            if value.status == ExecutionStatus::Unsupported
                && value.tool_exit_code.0.is_none()
    ));
}
