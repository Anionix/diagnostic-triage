use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use diagnostic_triage_contracts::{model::ExecutionStatus, protocol::ProtocolEnvelope};
use wait_timeout::ChildExt;

const REQUEST: &[u8] = include_bytes!("golden/request.jsonl");

#[cfg(unix)]
struct FakeCargo {
    root: PathBuf,
    program: PathBuf,
}

#[cfg(unix)]
impl FakeCargo {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "diagnostic-triage-rust-binary-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let program = root.join("cargo");
        fs::write(
            &program,
            concat!(
                "#!/bin/sh\n",
                "if [ \"$1\" = \"--version\" ]; then printf 'cargo 1.93.1 (fixture)\\n'; exit 0; fi\n",
                "if [ \"$1\" = \"clippy\" ] && [ \"$2\" = \"--version\" ]; then printf 'clippy 0.1.93 (fixture)\\n'; exit 0; fi\n",
                "if [ \"$1\" = \"check\" ] || [ \"$1\" = \"clippy\" ]; then printf '%s\\n' '{\"reason\":\"build-finished\",\"success\":true}'; exit 0; fi\n",
                "exit 91\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        Self { root, program }
    }
}

#[cfg(unix)]
impl Drop for FakeCargo {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
#[test]
fn binary_is_manifest_first_and_does_not_wait_for_stdin_eof() {
    let fake = FakeCargo::new();
    let mut child = Command::new(env!("CARGO_BIN_EXE_diagnostic-triage-provider-rust"))
        .current_dir(&fake.root)
        .env("DIAGNOSTIC_TRIAGE_CARGO_BIN", &fake.program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut first_line = String::new();
    stdout.read_line(&mut first_line).unwrap();
    let manifest = serde_json::from_str::<ProtocolEnvelope>(first_line.trim()).unwrap();
    assert!(matches!(manifest, ProtocolEnvelope::Manifest(_)));

    let mut request_writer = child.stdin.take().unwrap();
    request_writer.write_all(REQUEST).unwrap();
    let status = child.wait_timeout(Duration::from_secs(2)).unwrap();
    drop(request_writer);
    let Some(status) = status else {
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("Provider waited for stdin EOF after one complete request line");
    };
    assert!(status.success());

    let mut tail = String::new();
    stdout.read_to_string(&mut tail).unwrap();
    let events = tail
        .lines()
        .map(|line| serde_json::from_str::<ProtocolEnvelope>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(ProtocolEnvelope::Completion(value))
            if value.status == ExecutionStatus::Complete
                && value.tool_exit_code.0 == Some(0)
                && value.counts.observations == 0
                && value.counts.evidence == 2
    ));
}

#[cfg(unix)]
#[test]
fn malformed_request_gets_exactly_one_incomplete_completion() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_diagnostic-triage-provider-rust"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut manifest = String::new();
    stdout.read_line(&mut manifest).unwrap();
    child.stdin.take().unwrap().write_all(b"{}\n").unwrap();
    let mut tail = String::new();
    stdout.read_to_string(&mut tail).unwrap();
    assert!(child.wait().unwrap().success());
    let events = tail.lines().collect::<Vec<_>>();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        serde_json::from_str::<ProtocolEnvelope>(events[0]).unwrap(),
        ProtocolEnvelope::Completion(value)
            if value.status == ExecutionStatus::Incomplete
                && value.tool_exit_code.0.is_none()
    ));
}
