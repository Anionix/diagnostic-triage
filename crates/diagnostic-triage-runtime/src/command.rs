//! Narrow command facade used by the unpublished CLI crate.

use std::path::Path;

use diagnostic_triage_contracts::model::{SessionReport, Verdict};
use thiserror::Error;

use crate::RuntimeConfig;
use crate::orchestration::{
    ReadOnlyMode, assemble_read_only_report, execute_current_read_only_plan,
    project_executed_read_only_plan,
};

// LLM contract: CONFIGURED -> EXECUTED -> NORMALIZED -> REPORTED; runtime failure -> INCOMPLETE.

/// Read-only command selected by the CLI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOnlyCommandMode {
    Check,
    Ci,
}

/// Opaque failure from the internal runtime command pipeline.
#[derive(Debug, Error)]
pub enum RuntimeCommandError {
    #[error("read-only execution failed: {0}")]
    Execution(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("runtime projection failed: {0}")]
    Projection(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("report assembly failed: {0}")]
    Report(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Execute one complete read-only command and assemble its v1 report.
///
/// The repository identity is derived from the exact state snapshot checked
/// again after every Provider exits. No caller-selected digest can enter the
/// command path.
///
/// # Errors
///
/// Returns a typed command-boundary error when execution, normalization, or
/// report assembly fails.
pub fn run_read_only_command(
    config: &RuntimeConfig,
    repository_root: &Path,
    mode: ReadOnlyCommandMode,
    evaluation_time: Option<String>,
) -> Result<SessionReport, RuntimeCommandError> {
    let mode = match mode {
        ReadOnlyCommandMode::Check => ReadOnlyMode::Check,
        ReadOnlyCommandMode::Ci => ReadOnlyMode::Ci,
    };
    let executed = execute_current_read_only_plan(config, repository_root, mode)
        .map_err(|error| RuntimeCommandError::Execution(Box::new(error)))?;
    let projection = project_executed_read_only_plan(executed)
        .map_err(|error| RuntimeCommandError::Projection(Box::new(error)))?;
    let evaluation_time = projection
        .requires_evaluation_time()
        .then_some(evaluation_time)
        .flatten();
    assemble_read_only_report(projection, evaluation_time)
        .map_err(|error| RuntimeCommandError::Report(Box::new(error)))
}

/// Map a validated v1 verdict to its stable process exit code.
#[must_use]
pub const fn verdict_exit_code(verdict: &Verdict) -> u8 {
    match verdict {
        Verdict::Pass => 0,
        Verdict::PolicyFail => 1,
        Verdict::Incomplete | Verdict::Unsupported => 2,
    }
}
