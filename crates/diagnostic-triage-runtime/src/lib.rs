//! Runtime configuration, bounded process orchestration, and deterministic output boundaries for Diagnostic Triage.

mod scratch;

pub use scratch::{
    PATCH_MEDIA_TYPE, RESULT_MEDIA_TYPE, SNAPSHOT_MEDIA_TYPE, SafeFixAuthorization, ScratchChange,
    ScratchError, ScratchEvidence, ScratchLimits, ScratchPatch, ScratchWorkspace,
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

pub mod config;
pub mod process;
pub mod reporters;

pub use config::{ConfigError, RuntimeConfig};
pub use reporters::{
    CanonicalJsonReporter, MAX_REPORT_OUTPUT_BYTES, ReportFormat, Reporter, ReporterError,
    TSV_HEADER, TsvReporter, ValidatedSessionReport, canonical_json_bytes, tsv_bytes,
    write_canonical_json, write_tsv,
};
