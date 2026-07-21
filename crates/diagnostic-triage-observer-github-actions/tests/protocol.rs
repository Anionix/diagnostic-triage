//! Process-level JSON Lines protocol tests for the GitHub Actions Observer.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

use diagnostic_triage_contracts::{model::ExecutionStatus, protocol::ProtocolEnvelope};

fn invoke(input: &[u8]) -> Vec<ProtocolEnvelope> {
    let mut child = Command::new(env!(
        "CARGO_BIN_EXE_diagnostic-triage-observer-github-actions"
    ))
    .current_dir(env!("CARGO_MANIFEST_DIR"))
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("Observer binary must start");
    child
        .stdin
        .take()
        .expect("stdin must be piped")
        .write_all(input)
        .expect("request must be writable");
    let output = child
        .wait_with_output()
        .expect("Observer binary must terminate");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    String::from_utf8(output.stdout)
        .expect("stdout must be UTF-8 JSON Lines")
        .lines()
        .map(|line| serde_json::from_str(line).expect("line must be a protocol envelope"))
        .collect()
}

#[test]
fn manifest_is_flushed_before_the_observer_reads_a_request() {
    let mut child = Command::new(env!(
        "CARGO_BIN_EXE_diagnostic-triage-observer-github-actions"
    ))
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .spawn()
    .expect("Observer binary must start");
    let stdout = child.stdout.take().expect("stdout must be piped");
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line);
        sender
            .send((result, line))
            .expect("receiver must remain live");
    });
    let (result, line) = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("manifest must be emitted before any request arrives");
    result.expect("manifest line must be readable");
    let envelope = serde_json::from_str(&line).expect("manifest must be a protocol envelope");
    assert!(matches!(envelope, ProtocolEnvelope::Manifest(_)));

    child.kill().expect("blocked Observer must be terminable");
    child.wait().expect("terminated Observer must be reaped");
    reader.join().expect("manifest reader must terminate");
}

#[test]
fn binary_emits_manifest_first_and_exactly_one_completion_last() {
    let request = concat!(
        r#"{"protocol_version":"diagnostic-triage.protocol/v1","kind":"request","#,
        r#""request_id":"019f7e95-0000-7000-8000-000000000065","#,
        r#""operation":"OBSERVE","workspace":".","#,
        r#""targets":["tests/golden/workflow-success.json"],"#,
        r#""required_capabilities":["execution.observe/v1"],"#,
        r#""optional_capabilities":[],"limits":{"timeout_ms":1000,"#,
        r#""max_stdout_bytes":1048576,"max_stderr_bytes":65536,"#,
        r#""max_evidence_bytes":65536,"max_events":100}}"#,
        "\n"
    );
    let envelopes = invoke(request.as_bytes());

    assert!(matches!(
        envelopes.first(),
        Some(ProtocolEnvelope::Manifest(_))
    ));
    assert!(matches!(
        envelopes.last(),
        Some(ProtocolEnvelope::Completion(value))
            if value.status == ExecutionStatus::Complete
    ));
    assert_eq!(
        envelopes
            .iter()
            .filter(|value| matches!(value, ProtocolEnvelope::Completion(_)))
            .count(),
        1
    );
}

#[test]
fn malformed_request_still_gets_one_terminal_completion() {
    let envelopes = invoke(b"{}\n");

    assert_eq!(envelopes.len(), 2);
    assert!(matches!(envelopes[0], ProtocolEnvelope::Manifest(_)));
    assert!(matches!(
        &envelopes[1],
        ProtocolEnvelope::Completion(value)
            if value.status == ExecutionStatus::Incomplete
                && value.tool_exit_code.0.is_none()
    ));
}
