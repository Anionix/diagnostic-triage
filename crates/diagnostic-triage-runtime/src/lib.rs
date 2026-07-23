//! Runtime configuration, bounded process orchestration, and deterministic output boundaries for Diagnostic Triage.

mod command;
#[allow(
    dead_code,
    reason = "typed constructor consumed by #223 runtime projection"
)]
mod execution;
#[allow(dead_code, reason = "#223 consumer")]
mod execution_identity;
mod issue_draft;
#[allow(
    dead_code,
    reason = "private kernel consumed by follow-up issue-draft reporter slices"
)]
mod issue_draft_sanitize;
#[allow(dead_code, reason = "planning kernel consumed by #77 orchestration")]
mod orchestration;
mod ruff_fix;
mod scratch;

pub use ruff_fix::{
    CanonicalRuffFix, MAX_RUFF_FIX_EDITS, MAX_RUFF_FIX_EVIDENCE_BYTES, MAX_RUFF_FIX_FILE_BYTES,
    MAX_RUFF_FIX_JSON_DEPTH, MAX_RUFF_FIX_STRING_BYTES, RUFF_FIX_MEDIA_TYPE, RuffFixError,
    RuffFixEvidenceMapping, RuffFixLimits, canonicalize_ruff_fix,
};
pub use scratch::{
    PATCH_MEDIA_TYPE, RESULT_MEDIA_TYPE, SNAPSHOT_MEDIA_TYPE, SafeFixAuthorization, ScratchChange,
    ScratchError, ScratchEvidence, ScratchLimits, ScratchPatch, ScratchWorkspace,
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

pub mod config;
pub mod github_annotations;
pub mod process;
pub mod reporters;
pub mod sarif;
pub mod session;

pub use command::{
    ObserverCommandError, ObserverCommandResult, ReadOnlyCommandMode, RuntimeCommandError,
    run_github_actions_observer, run_read_only_command, verdict_exit_code,
};
pub use config::{ConfigError, RuntimeConfig};
pub use github_annotations::{
    GitHubAnnotationReporter, github_annotations_bytes, write_github_annotations,
};
pub use issue_draft::{
    BUG_ISSUE_DRAFT_SCHEMA_VERSION, BUG_ISSUE_LABEL, BugIssueDraftJsonReporter,
    BugIssueDraftMarkdownReporter, MAX_ISSUE_DRAFT_OUTPUT_BYTES, bug_issue_draft_json_bytes,
    bug_issue_draft_markdown_bytes, write_bug_issue_draft_json, write_bug_issue_draft_markdown,
};
pub use reporters::{
    CanonicalJsonReporter, MAX_REPORT_OUTPUT_BYTES, ReportFormat, Reporter, ReporterError,
    TSV_HEADER, TsvReporter, ValidatedSessionReport, canonical_json_bytes, tsv_bytes,
    write_canonical_json, write_tsv,
};
pub use sarif::{SarifReporter, sarif_bytes, write_sarif};
pub use session::{
    ProviderSessionError, ProviderSessionOutcome, ProviderSessionState, run_provider_session,
};
