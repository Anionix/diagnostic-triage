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
struct FakeBiome {
    root: PathBuf,
    program: PathBuf,
}

#[cfg(unix)]
impl FakeBiome {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "diagnostic-triage-biome-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let program = root.join("biome");
        fs::write(
            &program,
            concat!(
                "#!/bin/sh\n",
                "if [ \"$1\" = \"--version\" ]; then printf 'Version: 2.4.15\\n'; exit 0; fi\n",
                "if [ \"$1\" != \"check\" ] || [ \"$2\" != \"--reporter=sarif\" ] || [ \"$3\" != \"--max-diagnostics=none\" ] || [ \"$4\" != \"--no-errors-on-unmatched\" ] || [ \"$5\" != \"--\" ] || [ \"$6\" != \"src/main.ts\" ]; then printf 'bad argv' >&2; exit 2; fi\n",
                "printf '%s' '{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"Biome\"}},\"results\":[{\"ruleId\":\"lint/suspicious/noDebugger\",\"level\":\"error\",\"message\":{\"text\":\"Unexpected debugger.\"},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"src/main.ts\"},\"region\":{\"startLine\":2,\"startColumn\":1,\"endLine\":2,\"endColumn\":9}}}]}]}]}'\n",
                "exit 1\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        Self { root, program }
    }
}

#[cfg(unix)]
impl Drop for FakeBiome {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
#[test]
fn binary_is_manifest_first_and_does_not_wait_for_stdin_eof() {
    let fake = FakeBiome::new();
    let mut child = Command::new(env!("CARGO_BIN_EXE_diagnostic-triage-provider-biome"))
        .current_dir(&fake.root)
        .env("DIAGNOSTIC_TRIAGE_BIOME_BIN", &fake.program)
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
    assert!(events.iter().any(|event| matches!(
        event,
        ProtocolEnvelope::Observation(value)
            if value.observation.tool.version == "2.4.15"
                && value.observation.tool.rule_id.as_deref()
                    == Some("lint/suspicious/noDebugger")
    )));
    assert!(matches!(
        events.last(),
        Some(ProtocolEnvelope::Completion(value))
            if value.status == ExecutionStatus::Complete
                && value.tool_exit_code.0 == Some(1)
                && value.counts.observations == 1
                && value.counts.fix_candidates == 0
    ));
}

#[cfg(unix)]
#[test]
fn malformed_request_still_gets_exactly_one_incomplete_completion() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_diagnostic-triage-provider-biome"))
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
    let completion = serde_json::from_str::<ProtocolEnvelope>(events[0]).unwrap();
    assert!(matches!(
        completion,
        ProtocolEnvelope::Completion(value)
            if value.status == ExecutionStatus::Incomplete
                && value.tool_exit_code.0.is_none()
    ));
}
