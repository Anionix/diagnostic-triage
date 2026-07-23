use std::{fs, path::Path, process::Command};

use diagnostic_triage_contracts::model::Verdict;
use diagnostic_triage_runtime::{ReadOnlyCommandMode, RuntimeConfig, run_read_only_command};
use tempfile::tempdir;

const REVISION: &str = "a12b34c56d78e90f1234567890abcdef12345678";

fn config() -> RuntimeConfig {
    RuntimeConfig::from_toml(&format!(
        "[engine]\nversion=\"0.1.0\"\nsource_revision=\"{REVISION}\"\n\
         [repository]\nworkspace=\".\"\ntargets=[\"src\"]\n"
    ))
    .expect("valid config")
}

fn init_git(repository: &Path) {
    fs::create_dir(repository.join("src")).expect("source directory");
    fs::write(
        repository.join("src/lib.rs"),
        b"pub fn value() -> u8 { 1 }\n",
    )
    .expect("source");
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
fn read_only_command_assembles_a_pass_report_without_providers() {
    let repository = tempdir().expect("repository");
    init_git(repository.path());

    let report = run_read_only_command(
        &config(),
        repository.path(),
        ReadOnlyCommandMode::Check,
        None,
    )
    .expect("check report");

    assert_eq!(report.verdict, Verdict::Pass);
    assert!(report.executions.is_empty());
}

#[test]
fn read_only_command_identity_binds_the_complete_repository_state() {
    let repository = tempdir().expect("repository");
    init_git(repository.path());
    let baseline =
        run_read_only_command(&config(), repository.path(), ReadOnlyCommandMode::Ci, None)
            .expect("baseline report");

    fs::write(
        repository.path().join("src/lib.rs"),
        b"pub fn value() -> u8 { 2 }\n",
    )
    .expect("mutated source");
    let changed =
        run_read_only_command(&config(), repository.path(), ReadOnlyCommandMode::Ci, None)
            .expect("changed report");

    assert_ne!(baseline.session_id, changed.session_id);
}
