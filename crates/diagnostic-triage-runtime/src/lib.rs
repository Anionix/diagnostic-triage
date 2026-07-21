//! Runtime configuration, bounded process orchestration, and deterministic output boundaries for Diagnostic Triage.

mod scratch;

pub use scratch::{
    PATCH_MEDIA_TYPE, RESULT_MEDIA_TYPE, SNAPSHOT_MEDIA_TYPE, SafeFixAuthorization, ScratchChange,
    ScratchError, ScratchEvidence, ScratchLimits, ScratchPatch, ScratchWorkspace,
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

pub mod config;
pub mod github_annotations;
pub mod process;
pub mod reporters;
pub mod session;

pub use config::{ConfigError, RuntimeConfig};
pub use github_annotations::{
    GitHubAnnotationReporter, github_annotations_bytes, write_github_annotations,
};
pub use reporters::{
    CanonicalJsonReporter, MAX_REPORT_OUTPUT_BYTES, ReportFormat, Reporter, ReporterError,
    TSV_HEADER, TsvReporter, ValidatedSessionReport, canonical_json_bytes, tsv_bytes,
    write_canonical_json, write_tsv,
};
pub use session::{
    ProviderSessionError, ProviderSessionOutcome, ProviderSessionState, run_provider_session,
};
