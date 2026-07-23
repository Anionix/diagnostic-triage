use std::{fs, io::Write, path::Path, process::Command};

use clap::Parser;
use diagnostic_triage::{Cli, execute};
use tempfile::tempdir;

const REVISION: &str = "a12b34c56d78e90f1234567890abcdef12345678";

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

#[test]
fn parser_exposes_check_and_ci_without_implicit_flags() {
    assert!(Cli::try_parse_from(["diagnostic-triage", "check"]).is_ok());
    assert!(Cli::try_parse_from(["diagnostic-triage", "ci"]).is_ok());
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

    let status = execute(cli, &mut output).expect("CI report");

    assert_eq!(status.code(), 0);
    assert!(
        std::str::from_utf8(&output)
            .expect("UTF-8 report")
            .contains("\"verdict\":\"PASS\"")
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
