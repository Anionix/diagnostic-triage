//! Thin, testable command-line boundary for Diagnostic Triage.

use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::Command,
};

use clap::{Parser, Subcommand};
use diagnostic_triage_runtime::{
    ConfigError, ObserverCommandError, ReadOnlyCommandMode, ReporterError, RuntimeCommandError,
    RuntimeConfig, ValidatedSessionReport, config::OutputFormat, run_github_actions_observer,
    run_read_only_command, verdict_exit_code, write_bug_issue_draft_json,
    write_bug_issue_draft_markdown, write_canonical_json, write_tsv,
};
use thiserror::Error;

const DEFAULT_CONFIG: &str = "diagnostic-triage.toml";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const GITHUB_ACTIONS_OBSERVER: &str = "diagnostic-triage-observer-github-actions";

// LLM contract: DISCOVERED -> CONFIGURED -> EXECUTED -> REPORTED; invalid input -> INCOMPLETE.

/// Diagnostic Triage command-line arguments.
#[derive(Debug, Parser)]
#[command(name = "diagnostic-triage", version, about)]
pub struct Cli {
    /// Trusted Git repository root.
    #[arg(long, global = true, default_value = ".")]
    repository: PathBuf,
    /// Repository-relative checked-in runtime configuration.
    #[arg(long, global = true, default_value = DEFAULT_CONFIG)]
    config: PathBuf,
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Clone, Debug, Subcommand)]
enum CliCommand {
    /// Run local read-only diagnostics.
    Check,
    /// Run reproducible configured CI diagnostics.
    Ci,
    /// Run an offline Observer over completed CI data.
    Observe {
        /// Observer source implementation.
        #[arg(long, value_enum)]
        source: ObserveSource,
        /// Repository-relative completed-run JSON input.
        #[arg(long)]
        input: PathBuf,
    },
    /// Render a bug Issue draft from a validated report without posting it.
    IssueDraft {
        /// Repository-relative canonical report JSON.
        #[arg(long)]
        input: PathBuf,
        /// Draft representation written to stdout.
        #[arg(long, value_enum, default_value_t = IssueDraftFormat::Markdown)]
        format: IssueDraftFormat,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
enum ObserveSource {
    #[value(name = "github-actions")]
    GitHubActions,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
enum IssueDraftFormat {
    Markdown,
    Json,
}

/// Stable process status selected from a validated session verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandStatus(u8);

impl CommandStatus {
    /// Return the stable v1 process exit code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self.0
    }
}

/// Failures before a valid report can select a verdict-backed status.
#[derive(Debug, Error)]
pub enum CliError {
    #[error("repository root is unavailable: {0}")]
    Repository(String),
    #[error("configuration path must be repository-relative: {0}")]
    ConfigPath(String),
    #[error("configuration file was not found: {0}")]
    ConfigMissing(String),
    #[error("CI configuration is not tracked by Git: {0}")]
    ConfigUntracked(String),
    #[error("configuration exceeds the {MAX_CONFIG_BYTES}-byte limit")]
    ConfigLimit,
    #[error("configuration file could not be read: {0}")]
    ConfigIo(#[source] std::io::Error),
    #[error("input path must be a repository-relative regular file: {0}")]
    InputPath(String),
    #[error("input exceeds the {MAX_INPUT_BYTES}-byte limit")]
    InputLimit,
    #[error("input file could not be read: {0}")]
    InputIo(#[source] std::io::Error),
    #[error("GitHub Actions Observer executable was not found beside the CLI or on PATH: {0}")]
    ObserverMissing(String),
    #[error("Observer output could not be written: {0}")]
    ObserverIo(#[source] std::io::Error),
    #[error(transparent)]
    Observer(#[from] ObserverCommandError),
    #[error("configuration is invalid: {0}")]
    Config(#[from] ConfigError),
    #[error("output.path is unsupported by the stdout-only v1 CLI")]
    OutputPath,
    #[error(transparent)]
    Runtime(#[from] RuntimeCommandError),
    #[error(transparent)]
    Reporter(#[from] ReporterError),
}

/// Execute one parsed CLI command and write only its selected report to stdout.
///
/// # Errors
///
/// Returns [`CliError`] for repository, configuration, runtime, or reporter
/// failures. Callers map every such failure to exit code 2.
pub fn execute(cli: &Cli, output: &mut dyn Write) -> Result<CommandStatus, CliError> {
    let repository = canonical_repository(&cli.repository)?;
    match &cli.command {
        CliCommand::Observe { source, input } => {
            return execute_observe(&repository, *source, input, output);
        }
        CliCommand::IssueDraft { input, format } => {
            return execute_issue_draft(&repository, input, *format, output);
        }
        CliCommand::Check | CliCommand::Ci => {}
    }
    let config_path = resolve_config_path(&repository, &cli.config)?;
    if matches!(cli.command, CliCommand::Ci) {
        require_tracked_config(&repository, &cli.config)?;
    }
    let config = load_config(&config_path)?;
    if config.output.path.is_some() {
        return Err(CliError::OutputPath);
    }
    let mode = match cli.command {
        CliCommand::Check => ReadOnlyCommandMode::Check,
        CliCommand::Ci => ReadOnlyCommandMode::Ci,
        CliCommand::Observe { .. } | CliCommand::IssueDraft { .. } => unreachable!(),
    };
    let report = run_read_only_command(&config, &repository, mode, || {
        Some(jiff::Timestamp::now().to_string())
    })?;
    match config.output.format {
        OutputFormat::Json => write_canonical_json(&report, output)?,
        OutputFormat::Tsv => write_tsv(&report, output)?,
    }
    Ok(CommandStatus(verdict_exit_code(&report.verdict)))
}

fn execute_issue_draft(
    repository: &Path,
    input: &Path,
    format: IssueDraftFormat,
    output: &mut dyn Write,
) -> Result<CommandStatus, CliError> {
    let path = resolve_input_path(repository, input)?;
    let bytes = read_bounded(&path)?;
    let report = ValidatedSessionReport::from_json(&bytes)?;
    match format {
        IssueDraftFormat::Markdown => write_bug_issue_draft_markdown(report.as_report(), output)?,
        IssueDraftFormat::Json => write_bug_issue_draft_json(report.as_report(), output)?,
    }
    Ok(CommandStatus(verdict_exit_code(
        &report.as_report().verdict,
    )))
}

fn execute_observe(
    repository: &Path,
    source: ObserveSource,
    input: &Path,
    output: &mut dyn Write,
) -> Result<CommandStatus, CliError> {
    let input_path = resolve_input_path(repository, input)?;
    let input_bytes = read_bounded(&input_path)?;
    let program = observer_program(source)?;
    let result = run_github_actions_observer(&program, &input.to_string_lossy(), &input_bytes)?;
    output
        .write_all(&result.transcript)
        .map_err(CliError::ObserverIo)?;
    Ok(CommandStatus(result.exit_code))
}

fn observer_program(source: ObserveSource) -> Result<PathBuf, CliError> {
    let current = std::env::current_exe().map_err(CliError::InputIo)?;
    let search_path = std::env::var_os("PATH");
    observer_program_from(source, &current, search_path.as_deref())
}

fn observer_program_from(
    source: ObserveSource,
    current: &Path,
    search_path: Option<&OsStr>,
) -> Result<PathBuf, CliError> {
    let name = match source {
        ObserveSource::GitHubActions => {
            format!("{GITHUB_ACTIONS_OBSERVER}{}", std::env::consts::EXE_SUFFIX)
        }
    };
    let sibling = current
        .parent()
        .ok_or_else(|| CliError::ObserverMissing(name.clone()))?
        .join(&name);
    if sibling.is_file() {
        return Ok(sibling);
    }
    if let Some(program) = search_path
        .into_iter()
        .flat_map(std::env::split_paths)
        .map(|directory| directory.join(&name))
        .find(|candidate| candidate.is_file())
    {
        return Ok(program);
    }
    Err(CliError::ObserverMissing(name))
}

fn canonical_repository(path: &Path) -> Result<PathBuf, CliError> {
    let canonical =
        fs::canonicalize(path).map_err(|error| CliError::Repository(error.to_string()))?;
    if !canonical.is_dir() {
        return Err(CliError::Repository(format!(
            "{} is not a directory",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn resolve_config_path(repository: &Path, relative: &Path) -> Result<PathBuf, CliError> {
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative.components().any(|part| {
            matches!(
                part,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(CliError::ConfigPath(relative.display().to_string()));
    }
    let candidate = repository.join(relative);
    let metadata = fs::symlink_metadata(&candidate)
        .map_err(|_| CliError::ConfigMissing(relative.display().to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CliError::ConfigPath(relative.display().to_string()));
    }
    let canonical = fs::canonicalize(&candidate).map_err(CliError::ConfigIo)?;
    if !canonical.starts_with(repository) {
        return Err(CliError::ConfigPath(relative.display().to_string()));
    }
    Ok(canonical)
}

fn resolve_input_path(repository: &Path, relative: &Path) -> Result<PathBuf, CliError> {
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative.components().any(|part| {
            matches!(
                part,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(CliError::InputPath(relative.display().to_string()));
    }
    let candidate = repository.join(relative);
    let metadata = fs::symlink_metadata(&candidate)
        .map_err(|_| CliError::InputPath(relative.display().to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CliError::InputPath(relative.display().to_string()));
    }
    let canonical = fs::canonicalize(&candidate).map_err(CliError::InputIo)?;
    if !canonical.starts_with(repository) {
        return Err(CliError::InputPath(relative.display().to_string()));
    }
    Ok(canonical)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, CliError> {
    read_bounded_with_limit(path, MAX_INPUT_BYTES)
}

fn read_bounded_with_limit(path: &Path, limit: u64) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(CliError::InputIo)?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(CliError::InputIo)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(CliError::InputLimit);
    }
    Ok(bytes)
}

fn require_tracked_config(repository: &Path, relative: &Path) -> Result<(), CliError> {
    let status = Command::new("git")
        .args(["--literal-pathspecs", "ls-files", "--error-unmatch", "--"])
        .arg(relative)
        .current_dir(repository)
        .output()
        .map_err(|error| CliError::Repository(error.to_string()))?
        .status;
    if !status.success() {
        return Err(CliError::ConfigUntracked(relative.display().to_string()));
    }
    Ok(())
}

fn load_config(path: &Path) -> Result<RuntimeConfig, CliError> {
    let metadata = fs::metadata(path).map_err(CliError::ConfigIo)?;
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(CliError::ConfigLimit);
    }
    let input = fs::read_to_string(path).map_err(CliError::ConfigIo)?;
    RuntimeConfig::from_toml(&input).map_err(CliError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn bounded_reader_rejects_bytes_beyond_the_stream_limit() {
        let directory = tempdir().expect("temporary directory");
        let input = directory.path().join("input.json");
        fs::write(&input, b"1234").expect("input");

        assert!(matches!(
            read_bounded_with_limit(&input, 3),
            Err(CliError::InputLimit)
        ));
    }

    #[test]
    fn observer_discovery_falls_back_to_an_explicit_search_path() {
        let directory = tempdir().expect("temporary directory");
        let current = directory.path().join("nested/diagnostic-triage");
        let observer = directory.path().join(format!(
            "{GITHUB_ACTIONS_OBSERVER}{}",
            std::env::consts::EXE_SUFFIX
        ));
        fs::write(&observer, b"observer").expect("observer");

        assert_eq!(
            observer_program_from(
                ObserveSource::GitHubActions,
                &current,
                Some(directory.path().as_os_str())
            )
            .expect("PATH observer"),
            observer
        );
    }
}
