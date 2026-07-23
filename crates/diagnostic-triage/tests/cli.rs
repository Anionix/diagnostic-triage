use std::{
    fs,
    io::{self, Write},
    path::Path,
    process::Command,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use clap::Parser;
use diagnostic_triage::{Cli, CliError, execute};
use diagnostic_triage_runtime::FixCommandError;
use tempfile::tempdir;

const REVISION: &str = "a12b34c56d78e90f1234567890abcdef12345678";
const POLICY_FAIL_REPORT: &[u8] = include_bytes!("../../../tests/fixtures/v1/valid-report.json");

struct RejectWrites;

impl Write for RejectWrites {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected output failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct RejectFlush {
    bytes: Vec<u8>,
}

impl Write for RejectFlush {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("injected flush failure"))
    }
}

fn init_repository(repository: &Path) {
    fs::create_dir(repository.join("src")).expect("source directory");
    fs::write(
        repository.join("src/lib.rs"),
        b"pub fn value() -> u8 { 1 }\n",
    )
    .expect("source");
    fs::write(
        repository.join("diagnostic-triage.toml"),
        format!(
            "[engine]\nversion=\"0.1.0\"\nsource_revision=\"{REVISION}\"\n\
             [repository]\nworkspace=\".\"\ntargets=[\"src\"]\n"
        ),
    )
    .expect("config");
    for arguments in [
        &["init", "-q"][..],
        &["config", "user.name", "test"][..],
        &["config", "user.email", "test@example.invalid"][..],
        &["config", "commit.gpgsign", "false"][..],
        &["add", "-A"][..],
        &["commit", "-qm", "baseline"][..],
    ] {
        assert!(
            Command::new("git")
                .args(arguments)
                .current_dir(repository)
                .status()
                .expect("git")
                .success()
        );
    }
}

#[cfg(unix)]
fn configure_safe_fix_provider(repository: &Path) {
    fs::write(repository.join("src/a.py"), b"import os\nvalue = 1\n").expect("Python source");
    fs::create_dir(repository.join("bin")).expect("provider directory");
    let provider = r#"#!/bin/sh
set -eu
printf '%s\n' '{"protocol_version":"diagnostic-triage.protocol/v1","kind":"manifest","adapter":{"id":"ruff","version":"0.1.0","kind":"PROVIDER","capabilities":["diagnostic.check/v1","fix.propose/v1"],"languages":["python"]}}'
IFS= read -r request
request_id=$(printf '%s\n' "$request" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p')
test -n "$request_id"
emit() {
  printf '%s\n' "$1" | sed "s/__REQUEST_ID__/$request_id/g"
}
if grep -q '^import os$' src/a.py; then
  emit '{"protocol_version":"diagnostic-triage.protocol/v1","kind":"observation","request_id":"__REQUEST_ID__","sequence":0,"observation":{"schema_version":"diagnostic-triage.observation/v1","observation_id":"019f7e95-0000-7000-8000-000000000000","tool":{"name":"ruff","version":"0.15.2","rule_id":"F401"},"language":"python","severity":"ERROR","origin":"NORMAL","message":"os imported but unused","location":{"path":"src/a.py","start":{"line":1,"column":8},"end":{"line":1,"column":10}},"evidence_ids":[]}}'
  emit '{"protocol_version":"diagnostic-triage.protocol/v1","kind":"evidence","request_id":"__REQUEST_ID__","sequence":1,"evidence":{"schema_version":"diagnostic-triage.evidence/v1","evidence_id":"019f7e95-0000-7000-8000-000000000003","source":"PATCH","media_type":"application/vnd.ruff.fix+json","retained_bytes":290,"observed_bytes":290,"limit_bytes":4096,"truncated":false,"sha256":"396ba46fec5758c8222d129e37d5bbc07a621e0ba1a1d9697fe33c272bf02618","content":"{\"version\":\"0.15.2\",\"filename\":\"src/a.py\",\"rule_id\":\"F401\",\"fix\":{\"applicability\":\"safe\",\"edits\":[{\"content\":\"\",\"end_location\":{\"column\":10,\"row\":1},\"future_edit_field\":\"preserved\",\"location\":{\"column\":1,\"row\":1}}],\"future_fix_field\":{\"mode\":\"strict\"},\"message\":\"Remove unused import: os\"}}"}}'
  emit '{"protocol_version":"diagnostic-triage.protocol/v1","kind":"fix_candidate","request_id":"__REQUEST_ID__","sequence":2,"fix_candidate":{"schema_version":"diagnostic-triage.fix-candidate/v1","fix_candidate_id":"019f7e95-0000-7000-8000-000000000002","observation_ids":["019f7e95-0000-7000-8000-000000000000"],"applicability":"SAFE","tool_native":true,"patch_evidence_id":"019f7e95-0000-7000-8000-000000000003"}}'
  emit '{"protocol_version":"diagnostic-triage.protocol/v1","kind":"completion","request_id":"__REQUEST_ID__","sequence":3,"status":"COMPLETE","tool_exit_code":1,"tool_duration_ms":1,"counts":{"observations":1,"evidence":1,"fix_candidates":1,"executions":0},"evidence_bytes":290}'
else
  emit '{"protocol_version":"diagnostic-triage.protocol/v1","kind":"completion","request_id":"__REQUEST_ID__","sequence":0,"status":"COMPLETE","tool_exit_code":0,"tool_duration_ms":1,"counts":{"observations":0,"evidence":0,"fix_candidates":0,"executions":0},"evidence_bytes":0}'
fi
"#;
    let provider_path = repository.join("bin/provider.sh");
    fs::write(&provider_path, provider).expect("provider");
    let mut permissions = fs::metadata(&provider_path)
        .expect("provider metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider_path, permissions).expect("provider permissions");
    fs::OpenOptions::new()
        .append(true)
        .open(repository.join("diagnostic-triage.toml"))
        .expect("config")
        .write_all(
            b"\n[[providers]]\nadapter_id=\"ruff\"\nadapter_version=\"0.1.0\"\n\
              tool_name=\"ruff\"\ntool_version=\"0.15.2\"\nprogram=\"bin/provider.sh\"\n\
              required=true\nrequired_capabilities=[\"diagnostic.check/v1\"]\n\
              optional_capabilities=[\"fix.propose/v1\"]\n",
        )
        .expect("provider config");
    for arguments in [
        &["add", "-A"][..],
        &["commit", "-qm", "safe fix provider"][..],
    ] {
        assert!(
            Command::new("git")
                .args(arguments)
                .current_dir(repository)
                .status()
                .expect("git")
                .success()
        );
    }
}

#[test]
fn parser_exposes_public_commands_with_explicit_safe_apply_only() {
    assert!(Cli::try_parse_from(["diagnostic-triage", "check"]).is_ok());
    assert!(Cli::try_parse_from(["diagnostic-triage", "ci"]).is_ok());
    assert!(Cli::try_parse_from(["diagnostic-triage", "fix"]).is_ok());
    assert!(Cli::try_parse_from(["diagnostic-triage", "fix", "--apply-safe"]).is_ok());
    assert!(
        Cli::try_parse_from(["diagnostic-triage", "verify", "--patch", "candidate.patch",]).is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "diagnostic-triage",
            "observe",
            "--source",
            "github-actions",
            "--input",
            "run.json",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from(["diagnostic-triage", "issue-draft", "--input", "report.json",])
            .is_ok()
    );
    assert!(Cli::try_parse_from(["diagnostic-triage", "unknown"]).is_err());
}

#[test]
fn ci_emits_only_the_selected_report_and_returns_pass() {
    let repository = tempdir().expect("repository");
    init_repository(repository.path());
    let cli = Cli::try_parse_from([
        "diagnostic-triage",
        "--repository",
        repository.path().to_str().expect("utf-8 path"),
        "ci",
    ])
    .expect("CLI");
    let mut output = Vec::new();

    let status = execute(&cli, &mut output).expect("CI report");

    assert_eq!(status.code(), 0);
    assert!(
        std::str::from_utf8(&output)
            .expect("UTF-8 report")
            .contains("\"verdict\":\"PASS\"")
    );
}

#[test]
fn fix_without_a_safe_candidate_is_empty_and_read_only() {
    let repository = tempdir().expect("repository");
    init_repository(repository.path());
    let cli = Cli::try_parse_from([
        "diagnostic-triage",
        "--repository",
        repository.path().to_str().expect("utf-8 path"),
        "fix",
    ])
    .expect("CLI");
    let mut output = Vec::new();

    assert_eq!(execute(&cli, &mut output).expect("fix").code(), 0);
    assert!(output.is_empty());
    assert!(
        Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(repository.path())
            .output()
            .expect("git status")
            .stdout
            .is_empty()
    );
}

#[test]
fn apply_safe_without_an_authoritative_candidate_is_a_read_only_noop() {
    let repository = tempdir().expect("repository");
    init_repository(repository.path());
    let cli = Cli::try_parse_from([
        "diagnostic-triage",
        "--repository",
        repository.path().to_str().expect("utf-8 path"),
        "fix",
        "--apply-safe",
    ])
    .expect("CLI");

    let mut output = Vec::new();
    assert_eq!(execute(&cli, &mut output).expect("safe no-op").code(), 0);
    assert!(output.is_empty());
    assert!(
        Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(repository.path())
            .output()
            .expect("git status")
            .stdout
            .is_empty()
    );
}

#[cfg(unix)]
#[test]
fn apply_safe_publishes_only_the_verified_tool_native_result() {
    let repository = tempdir().expect("repository");
    init_repository(repository.path());
    configure_safe_fix_provider(repository.path());
    let cli = Cli::try_parse_from([
        "diagnostic-triage",
        "--repository",
        repository.path().to_str().expect("utf-8 path"),
        "fix",
        "--apply-safe",
    ])
    .expect("CLI");
    let mut output = Vec::new();

    assert_eq!(execute(&cli, &mut output).expect("apply safe").code(), 0);
    assert!(std::str::from_utf8(&output).unwrap().contains("-import os"));
    assert_eq!(
        fs::read(repository.path().join("src/a.py")).expect("published source"),
        b"\nvalue = 1\n"
    );
    assert_eq!(
        Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(repository.path())
            .output()
            .expect("git status")
            .stdout,
        b" M src/a.py\n"
    );

    let mut second_output = Vec::new();
    assert_eq!(
        execute(&cli, &mut second_output)
            .expect("safe no-op after publication")
            .code(),
        0
    );
    assert!(second_output.is_empty());
    assert_eq!(
        fs::read(repository.path().join("src/a.py")).expect("unchanged published source"),
        b"\nvalue = 1\n"
    );
}

#[cfg(unix)]
#[test]
fn apply_safe_output_failure_precedes_source_publication() {
    let repository = tempdir().expect("repository");
    init_repository(repository.path());
    configure_safe_fix_provider(repository.path());
    let cli = Cli::try_parse_from([
        "diagnostic-triage",
        "--repository",
        repository.path().to_str().expect("utf-8 path"),
        "fix",
        "--apply-safe",
    ])
    .expect("CLI");

    assert!(matches!(
        execute(&cli, &mut RejectWrites),
        Err(CliError::Fix(FixCommandError::PatchOutput(_)))
    ));
    assert_eq!(
        fs::read(repository.path().join("src/a.py")).expect("unpublished source"),
        b"import os\nvalue = 1\n"
    );
    assert!(
        Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(repository.path())
            .output()
            .expect("git status")
            .stdout
            .is_empty()
    );
}

#[cfg(unix)]
#[test]
fn apply_safe_flush_failure_precedes_source_publication() {
    let repository = tempdir().expect("repository");
    init_repository(repository.path());
    configure_safe_fix_provider(repository.path());
    let cli = Cli::try_parse_from([
        "diagnostic-triage",
        "--repository",
        repository.path().to_str().expect("utf-8 path"),
        "fix",
        "--apply-safe",
    ])
    .expect("CLI");
    let mut output = RejectFlush::default();

    assert!(matches!(
        execute(&cli, &mut output),
        Err(CliError::Fix(FixCommandError::PatchOutput(_)))
    ));
    assert!(!output.bytes.is_empty());
    assert_eq!(
        fs::read(repository.path().join("src/a.py")).expect("unpublished source"),
        b"import os\nvalue = 1\n"
    );
    assert!(
        Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(repository.path())
            .output()
            .expect("git status")
            .stdout
            .is_empty()
    );
}

#[test]
fn binary_help_and_invalid_arguments_use_separate_streams() {
    let binary = env!("CARGO_BIN_EXE_diagnostic-triage");
    let help = Command::new(binary).arg("--help").output().expect("help");
    assert!(help.status.success());
    let help_stdout = std::str::from_utf8(&help.stdout).expect("help UTF-8");
    assert!(help_stdout.contains("check"));
    assert!(help_stdout.contains("ci"));
    assert!(help_stdout.contains("fix"));
    assert!(help_stdout.contains("verify"));
    assert!(help.stderr.is_empty());

    let invalid = Command::new(binary)
        .arg("unknown")
        .output()
        .expect("invalid arguments");
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    assert!(!invalid.stderr.is_empty());
}

#[test]
fn broken_provider_is_incomplete_without_mutating_the_repository() {
    let repository = tempdir().expect("repository");
    init_repository(repository.path());
    let binary = env!("CARGO_BIN_EXE_diagnostic-triage");
    let escaped_binary = binary.replace('\\', "\\\\").replace('"', "\\\"");
    let provider = format!(
        "\n[[providers]]\nadapter_id=\"broken\"\nadapter_version=\"1\"\n\
         tool_name=\"broken\"\ntool_version=\"1\"\nprogram=\"{escaped_binary}\"\n\
         argv=[\"--help\"]\nrequired=true\n\
         required_capabilities=[\"diagnostic.check/v1\"]\n"
    );
    let config = repository.path().join("diagnostic-triage.toml");
    fs::OpenOptions::new()
        .append(true)
        .open(&config)
        .expect("open config")
        .write_all(provider.as_bytes())
        .expect("provider config");
    assert!(
        Command::new("git")
            .args(["add", "diagnostic-triage.toml"])
            .current_dir(repository.path())
            .status()
            .expect("git add")
            .success()
    );
    assert!(
        Command::new("git")
            .args(["commit", "-qm", "provider"])
            .current_dir(repository.path())
            .status()
            .expect("git commit")
            .success()
    );

    let result = Command::new(binary)
        .args(["--repository", repository.path().to_str().unwrap(), "ci"])
        .output()
        .expect("CI");

    assert_eq!(result.status.code(), Some(2));
    assert!(
        std::str::from_utf8(&result.stdout)
            .expect("report UTF-8")
            .contains("\"verdict\":\"INCOMPLETE\"")
    );
    assert!(result.stderr.is_empty());
    assert!(
        Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(repository.path())
            .output()
            .expect("git status")
            .stdout
            .is_empty()
    );
}

#[test]
fn ci_does_not_treat_config_pathspec_magic_as_a_tracked_literal() {
    let repository = tempdir().expect("repository");
    init_repository(repository.path());
    fs::copy(
        repository.path().join("diagnostic-triage.toml"),
        repository.path().join("*.toml"),
    )
    .expect("literal wildcard config");
    let cli = Cli::try_parse_from([
        "diagnostic-triage",
        "--repository",
        repository.path().to_str().expect("UTF-8 path"),
        "--config",
        "*.toml",
        "ci",
    ])
    .expect("CLI");

    assert!(matches!(
        execute(&cli, &mut Vec::new()),
        Err(CliError::ConfigUntracked(path)) if path == "*.toml"
    ));
}

#[test]
fn issue_draft_reads_a_repository_relative_report_and_never_posts_it() {
    let repository = tempdir().expect("repository");
    init_repository(repository.path());
    let check = Cli::try_parse_from([
        "diagnostic-triage",
        "--repository",
        repository.path().to_str().expect("UTF-8 path"),
        "check",
    ])
    .expect("check CLI");
    let mut report = Vec::new();
    execute(&check, &mut report).expect("check report");
    fs::write(repository.path().join("report.json"), report).expect("report file");

    let draft = Cli::try_parse_from([
        "diagnostic-triage",
        "--repository",
        repository.path().to_str().expect("UTF-8 path"),
        "issue-draft",
        "--input",
        "report.json",
        "--format",
        "json",
    ])
    .expect("issue-draft CLI");
    let mut output = Vec::new();

    assert_eq!(execute(&draft, &mut output).expect("draft").code(), 0);
    let output = std::str::from_utf8(&output).expect("UTF-8 draft");
    assert!(output.contains("\"labels\":[\"bug\"]"));
    assert!(!output.contains("api.github.com"));
}

#[test]
fn issue_draft_rejects_path_escape() {
    let repository = tempdir().expect("repository");
    init_repository(repository.path());
    let draft = Cli::try_parse_from([
        "diagnostic-triage",
        "--repository",
        repository.path().to_str().expect("UTF-8 path"),
        "issue-draft",
        "--input",
        "../report.json",
    ])
    .expect("issue-draft CLI");

    assert!(matches!(
        execute(&draft, &mut Vec::new()),
        Err(CliError::InputPath(path)) if path == "../report.json"
    ));
}

#[test]
fn issue_draft_markdown_preserves_policy_failure_exit_status() {
    let repository = tempdir().expect("repository");
    init_repository(repository.path());
    fs::write(repository.path().join("report.json"), POLICY_FAIL_REPORT).expect("report");
    let draft = Cli::try_parse_from([
        "diagnostic-triage",
        "--repository",
        repository.path().to_str().expect("UTF-8 path"),
        "issue-draft",
        "--input",
        "report.json",
        "--format",
        "markdown",
    ])
    .expect("issue-draft CLI");
    let mut output = Vec::new();

    assert_eq!(execute(&draft, &mut output).expect("draft").code(), 1);
    let output = std::str::from_utf8(&output).expect("UTF-8 draft");
    assert!(output.starts_with("# Diagnostic Triage bug issue draft\n\n"));
    assert!(output.contains("\"verdict\":\"POLICY_FAIL\""));
    assert!(!output.contains("\\n"));
}
