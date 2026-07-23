//! Thin, testable command-line boundary for Diagnostic Triage.

use std::{
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    process::Command,
};

use clap::{Parser, Subcommand};
use diagnostic_triage_runtime::{
    ConfigError, ReadOnlyCommandMode, ReporterError, RuntimeCommandError, RuntimeConfig,
    config::OutputFormat, run_read_only_command, verdict_exit_code, write_canonical_json,
    write_tsv,
};
use thiserror::Error;

const DEFAULT_CONFIG: &str = "diagnostic-triage.toml";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

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

#[derive(Clone, Copy, Debug, Subcommand)]
enum CliCommand {
    /// Run local read-only diagnostics.
    Check,
    /// Run reproducible configured CI diagnostics.
    Ci,
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
pub fn execute(cli: Cli, output: &mut dyn Write) -> Result<CommandStatus, CliError> {
    let repository = canonical_repository(&cli.repository)?;
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
    let canonical = fs::canonicalize(&candidate).map_err(|error| CliError::ConfigIo(error))?;
    if !canonical.starts_with(repository) {
        return Err(CliError::ConfigPath(relative.display().to_string()));
    }
    Ok(canonical)
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
