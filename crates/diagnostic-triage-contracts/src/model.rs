//! Typed, policy-independent Diagnostic Triage model objects.

#![allow(
    clippy::missing_errors_doc,
    reason = "model validators uniformly return ContractError for local invariant violations"
)]

use std::collections::HashSet;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use sha2::{Digest, Sha256};

use crate::{
    AdapterId, ContractError, Fingerprint, Language, Nullable, ObjectId, RepoPath, Sha256Digest,
    SourceRevision,
};
use crate::{jsonl::deserialize_strict_value, wire::deserialize_optional};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

macro_rules! schema_version {
    ($name:ident, $wire:literal) => {
        #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
        pub enum $name {
            #[serde(rename = $wire)]
            #[schemars(rename = $wire)]
            V1,
        }
    };
}

schema_version!(ObservationSchemaVersion, "diagnostic-triage.observation/v1");
schema_version!(FindingSchemaVersion, "diagnostic-triage.finding/v1");
schema_version!(DecisionSchemaVersion, "diagnostic-triage.decision/v1");
schema_version!(EvidenceSchemaVersion, "diagnostic-triage.evidence/v1");
schema_version!(
    FixCandidateSchemaVersion,
    "diagnostic-triage.fix-candidate/v1"
);
schema_version!(ExecutionSchemaVersion, "diagnostic-triage.execution/v1");
schema_version!(
    SessionReportSchemaVersion,
    "diagnostic-triage.session-report/v1"
);

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Origin {
    Normal,
    Boundary,
    Malformed,
    Fuzz,
    Generated,
    Unknown,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Position {
    pub line: u32,
    pub column: u32,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    pub path: RepoPath,
    pub start: Position,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub end: Option<Position>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub name: String,
    pub version: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub rule_id: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Syntax,
    Type,
    Correctness,
    Runtime,
    Build,
    Test,
    Resource,
    Concurrency,
    Security,
    Environment,
    Tooling,
    Style,
    Robustness,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MicroCategory {
    #[serde(rename = "parse-error")]
    ParseError,
    #[serde(rename = "invalid-token")]
    InvalidToken,
    #[serde(rename = "invalid-structure")]
    InvalidStructure,
    #[serde(rename = "incompatible-type")]
    IncompatibleType,
    #[serde(rename = "missing-type")]
    MissingType,
    Nullability,
    #[serde(rename = "unresolved-symbol")]
    UnresolvedSymbol,
    #[serde(rename = "invalid-call")]
    InvalidCall,
    #[serde(rename = "contract-mismatch")]
    ContractMismatch,
    Assertion,
    Invariant,
    #[serde(rename = "wrong-result")]
    WrongResult,
    #[serde(rename = "data-loss")]
    DataLoss,
    #[serde(rename = "state-transition")]
    StateTransition,
    Nondeterminism,
    Exception,
    Panic,
    Abort,
    Signal,
    #[serde(rename = "import-failure")]
    ImportFailure,
    Initialization,
    Compile,
    Link,
    #[serde(rename = "dependency-resolution")]
    DependencyResolution,
    #[serde(rename = "code-generation")]
    CodeGeneration,
    Configuration,
    Collection,
    Setup,
    Teardown,
    Flaky,
    #[serde(rename = "coverage-gate")]
    CoverageGate,
    Timeout,
    #[serde(rename = "memory-limit")]
    MemoryLimit,
    #[serde(rename = "disk-limit")]
    DiskLimit,
    #[serde(rename = "output-limit")]
    OutputLimit,
    #[serde(rename = "file-descriptor-limit")]
    FileDescriptorLimit,
    Race,
    Deadlock,
    Livelock,
    Ordering,
    Atomicity,
    #[serde(rename = "input-validation")]
    InputValidation,
    #[serde(rename = "path-escape")]
    PathEscape,
    Injection,
    #[serde(rename = "unsafe-deserialization")]
    UnsafeDeserialization,
    Permission,
    #[serde(rename = "secret-exposure")]
    SecretExposure,
    #[serde(rename = "tool-missing")]
    ToolMissing,
    #[serde(rename = "version-mismatch")]
    VersionMismatch,
    Platform,
    Locale,
    Timezone,
    Network,
    Filesystem,
    Protocol,
    #[serde(rename = "malformed-output")]
    MalformedOutput,
    #[serde(rename = "provider-crash")]
    ProviderCrash,
    #[serde(rename = "unsupported-version")]
    UnsupportedVersion,
    Format,
    Lint,
    Documentation,
    Complexity,
    Deprecation,
    #[serde(rename = "boundary-input")]
    BoundaryInput,
    #[serde(rename = "malformed-input")]
    MalformedInput,
    #[serde(rename = "crash-resistance")]
    CrashResistance,
    #[serde(rename = "roundtrip-mismatch")]
    RoundtripMismatch,
    #[serde(rename = "fuzz-finding")]
    FuzzFinding,
    #[serde(rename = "unknown")]
    Unknown,
}

/// A category and its category-specific micro-category.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Taxonomy {
    pub category: Category,
    pub micro_category: MicroCategory,
}

/// Backwards-readable name for the taxonomy object used by Findings.
pub type Classification = Taxonomy;

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingState {
    Discovered,
    Normalized,
    Classified,
    FixProposed,
    Verified,
    Reported,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PreReportState {
    Classified,
    FixProposed,
    Verified,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema_version: ObservationSchemaVersion,
    pub observation_id: ObjectId,
    pub tool: Tool,
    pub language: Language,
    pub severity: Severity,
    pub origin: Origin,
    pub message: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub location: Option<Location>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub symbol: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub observed: Option<String>,
    pub evidence_ids: Vec<ObjectId>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema_version: FindingSchemaVersion,
    pub finding_id: ObjectId,
    pub fingerprint: Fingerprint,
    pub observation_ids: Vec<ObjectId>,
    pub tool: Tool,
    pub language: Language,
    pub severity: Severity,
    pub classification: Taxonomy,
    pub message: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub location: Option<Location>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub symbol: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub observed: Option<String>,
    pub state: FindingState,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub pre_report_state: Option<PreReportState>,
    pub evidence_ids: Vec<ObjectId>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub fix_candidate_id: Option<ObjectId>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub verification_execution_ids: Option<Vec<ObjectId>>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DecisionAction {
    Observe,
    Warn,
    Block,
    Waive,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum WaivedAction {
    Warn,
    Block,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Waiver {
    pub fingerprint: Fingerprint,
    pub waived_action: WaivedAction,
    pub reason: String,
    pub owner: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub schema_version: DecisionSchemaVersion,
    pub decision_id: ObjectId,
    pub finding_id: ObjectId,
    pub action: DecisionAction,
    pub evaluated_at: String,
    pub policy_digest: Sha256Digest,
    pub matched_rule_id: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub waiver: Option<Waiver>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EvidenceSource {
    Stdout,
    Stderr,
    Diagnostic,
    Patch,
    Artifact,
    Traceback,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub schema_version: EvidenceSchemaVersion,
    pub evidence_id: ObjectId,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub execution_id: Option<ObjectId>,
    pub source: EvidenceSource,
    pub media_type: String,
    pub retained_bytes: u64,
    pub observed_bytes: u64,
    pub limit_bytes: u32,
    pub truncated: bool,
    pub sha256: Sha256Digest,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub relative_path: Option<RepoPath>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub content: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Applicability {
    Safe,
    Unsafe,
    Manual,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixCandidate {
    pub schema_version: FixCandidateSchemaVersion,
    pub fix_candidate_id: ObjectId,
    pub observation_ids: Vec<ObjectId>,
    pub applicability: Applicability,
    pub tool_native: bool,
    pub patch_evidence_id: ObjectId,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AdapterKind {
    Engine,
    Provider,
    Observer,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ExecutionStatus {
    Complete,
    Incomplete,
    Unsupported,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolchainFingerprint {
    Digest(Sha256Digest),
    Unavailable(Unavailable),
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum Unavailable {
    #[serde(rename = "UNAVAILABLE")]
    Value,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PhaseDuration {
    Milliseconds(u32),
    NotApplicable(NotApplicable),
    Unavailable(Unavailable),
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum NotApplicable {
    #[serde(rename = "NOT_APPLICABLE")]
    Value,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPhases {
    pub queue: PhaseDuration,
    pub setup: PhaseDuration,
    pub run: PhaseDuration,
    pub normalize: PhaseDuration,
    pub total: PhaseDuration,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PerformanceStatus {
    NotEvaluated,
    WithinBudget,
    ImprovementCandidate,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Performance {
    pub status: PerformanceStatus,
    pub budget_ms: u32,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CacheStatus {
    Hit,
    Miss,
    NotApplicable,
    Unavailable,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cache {
    pub status: CacheStatus,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub restore_ms: Option<u32>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub save_ms: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetryStatus {
    Recorded,
    NotApplicable,
    Unavailable,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retry {
    pub status: RetryStatus,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub attempt: Option<u32>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub same_revision: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub group_id: Option<ObjectId>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunnerStatus {
    Recorded,
    Unavailable,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runner {
    pub status: RunnerStatus,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub os: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub arch: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub image: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub fingerprint: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationAttribution {
    pub fix_candidate_id: ObjectId,
    pub patch_sha256: Sha256Digest,
    pub base_snapshot_sha256: Sha256Digest,
    pub base_snapshot_evidence_id: ObjectId,
    pub target_fingerprints: Vec<Fingerprint>,
    pub result_evidence_id: ObjectId,
}

impl VerificationAttribution {
    fn validate(&self) -> Result<(), ContractError> {
        check_unique(&self.target_fingerprints, "target_fingerprints", 1024, 1)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub schema_version: ExecutionSchemaVersion,
    pub execution_id: ObjectId,
    pub adapter_id: AdapterId,
    pub adapter_kind: AdapterKind,
    pub tool: Tool,
    pub toolchain_fingerprint: ToolchainFingerprint,
    pub required: bool,
    pub status: ExecutionStatus,
    pub exit_code: Nullable<u8>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub message: Option<String>,
    pub phases_ms: ExecutionPhases,
    pub performance: Performance,
    pub cache: Cache,
    pub retry: Retry,
    pub runner: Runner,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub verification: Option<Box<VerificationAttribution>>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineIdentity {
    pub version: String,
    pub source_revision: SourceRevision,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Pass,
    PolicyFail,
    Incomplete,
    Unsupported,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionReport {
    pub schema_version: SessionReportSchemaVersion,
    pub session_id: ObjectId,
    pub engine: EngineIdentity,
    pub contract_sha256: Sha256Digest,
    pub policy_digest: Sha256Digest,
    pub verdict: Verdict,
    pub observations: Vec<Observation>,
    pub findings: Vec<Finding>,
    pub decisions: Vec<Decision>,
    pub evidence: Vec<Evidence>,
    pub fix_candidates: Vec<FixCandidate>,
    pub executions: Vec<Execution>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionReportRaw {
    schema_version: SessionReportSchemaVersion,
    session_id: ObjectId,
    engine: EngineIdentity,
    contract_sha256: Sha256Digest,
    policy_digest: Sha256Digest,
    verdict: Verdict,
    observations: Vec<Observation>,
    findings: Vec<Finding>,
    decisions: Vec<Decision>,
    evidence: Vec<Evidence>,
    fix_candidates: Vec<FixCandidate>,
    executions: Vec<Execution>,
}

impl From<SessionReportRaw> for SessionReport {
    fn from(raw: SessionReportRaw) -> Self {
        Self {
            schema_version: raw.schema_version,
            session_id: raw.session_id,
            engine: raw.engine,
            contract_sha256: raw.contract_sha256,
            policy_digest: raw.policy_digest,
            verdict: raw.verdict,
            observations: raw.observations,
            findings: raw.findings,
            decisions: raw.decisions,
            evidence: raw.evidence,
            fix_candidates: raw.fix_candidates,
            executions: raw.executions,
        }
    }
}

impl<'de> Deserialize<'de> for SessionReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = deserialize_strict_value(deserializer)?;
        let raw = serde_json::from_value::<SessionReportRaw>(value).map_err(D::Error::custom)?;
        let report = Self::from(raw);
        crate::validate::validate_report(&report).map_err(D::Error::custom)?;
        Ok(report)
    }
}

fn model_error(message: impl Into<String>) -> ContractError {
    ContractError::Model(message.into())
}

fn check_string(value: &str, field: &str, max: usize, nonempty: bool) -> Result<(), ContractError> {
    let length = value.chars().count();
    if (nonempty && length == 0) || length > max {
        return Err(model_error(format!(
            "{field} must contain 1..={max} characters"
        )));
    }
    Ok(())
}

fn check_unique<T>(values: &[T], field: &str, max: usize, min: usize) -> Result<(), ContractError>
where
    T: Eq + std::hash::Hash,
{
    if values.len() < min || values.len() > max {
        return Err(model_error(format!(
            "{field} must contain {min}..={max} items"
        )));
    }
    if values.iter().collect::<HashSet<_>>().len() != values.len() {
        return Err(model_error(format!("{field} must contain unique items")));
    }
    Ok(())
}

fn validate_position(position: &Position) -> Result<(), ContractError> {
    if position.line == 0 || position.column == 0 {
        return Err(model_error("position line and column must be positive"));
    }
    Ok(())
}

fn validate_location(location: &Location) -> Result<(), ContractError> {
    validate_position(&location.start)?;
    if let Some(end) = &location.end {
        validate_position(end)?;
        if (end.line, end.column) < (location.start.line, location.start.column) {
            return Err(model_error("location end precedes start"));
        }
    }
    Ok(())
}

fn validate_tool(tool: &Tool) -> Result<(), ContractError> {
    check_string(&tool.name, "tool.name", 64, true)?;
    check_string(&tool.version, "tool.version", 64, true)?;
    if let Some(rule_id) = &tool.rule_id {
        check_string(rule_id, "tool.rule_id", 128, true)?;
    }
    Ok(())
}

fn validate_optional_text(
    value: Option<&str>,
    field: &str,
    max: usize,
) -> Result<(), ContractError> {
    if let Some(value) = value {
        check_string(value, field, max, true)?;
    }
    Ok(())
}

fn validate_common_texts(
    message: &str,
    symbol: Option<&str>,
    expected: Option<&str>,
    observed: Option<&str>,
) -> Result<(), ContractError> {
    check_string(message, "message", 8192, true)?;
    validate_optional_text(symbol, "symbol", 512)?;
    validate_optional_text(expected, "expected", 8192)?;
    validate_optional_text(observed, "observed", 8192)
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive taxonomy-to-micro-category table mirrors the v1 schema"
)]
fn micro_matches(category: &Category, micro: &MicroCategory) -> bool {
    match category {
        Category::Syntax => matches!(
            micro,
            MicroCategory::ParseError
                | MicroCategory::InvalidToken
                | MicroCategory::InvalidStructure
                | MicroCategory::Unknown
        ),
        Category::Type => matches!(
            micro,
            MicroCategory::IncompatibleType
                | MicroCategory::MissingType
                | MicroCategory::Nullability
                | MicroCategory::UnresolvedSymbol
                | MicroCategory::InvalidCall
                | MicroCategory::ContractMismatch
                | MicroCategory::Unknown
        ),
        Category::Correctness => matches!(
            micro,
            MicroCategory::Assertion
                | MicroCategory::Invariant
                | MicroCategory::WrongResult
                | MicroCategory::DataLoss
                | MicroCategory::StateTransition
                | MicroCategory::Nondeterminism
                | MicroCategory::Unknown
        ),
        Category::Runtime => matches!(
            micro,
            MicroCategory::Exception
                | MicroCategory::Panic
                | MicroCategory::Abort
                | MicroCategory::Signal
                | MicroCategory::ImportFailure
                | MicroCategory::Initialization
                | MicroCategory::Unknown
        ),
        Category::Build => matches!(
            micro,
            MicroCategory::Compile
                | MicroCategory::Link
                | MicroCategory::DependencyResolution
                | MicroCategory::CodeGeneration
                | MicroCategory::Configuration
                | MicroCategory::Unknown
        ),
        Category::Test => matches!(
            micro,
            MicroCategory::Collection
                | MicroCategory::Setup
                | MicroCategory::Assertion
                | MicroCategory::Teardown
                | MicroCategory::Flaky
                | MicroCategory::CoverageGate
                | MicroCategory::Unknown
        ),
        Category::Resource => matches!(
            micro,
            MicroCategory::Timeout
                | MicroCategory::MemoryLimit
                | MicroCategory::DiskLimit
                | MicroCategory::OutputLimit
                | MicroCategory::FileDescriptorLimit
                | MicroCategory::Unknown
        ),
        Category::Concurrency => matches!(
            micro,
            MicroCategory::Race
                | MicroCategory::Deadlock
                | MicroCategory::Livelock
                | MicroCategory::Ordering
                | MicroCategory::Atomicity
                | MicroCategory::Unknown
        ),
        Category::Security => matches!(
            micro,
            MicroCategory::InputValidation
                | MicroCategory::PathEscape
                | MicroCategory::Injection
                | MicroCategory::UnsafeDeserialization
                | MicroCategory::Permission
                | MicroCategory::SecretExposure
                | MicroCategory::Unknown
        ),
        Category::Environment => matches!(
            micro,
            MicroCategory::ToolMissing
                | MicroCategory::VersionMismatch
                | MicroCategory::Platform
                | MicroCategory::Locale
                | MicroCategory::Timezone
                | MicroCategory::Network
                | MicroCategory::Filesystem
                | MicroCategory::Unknown
        ),
        Category::Tooling => matches!(
            micro,
            MicroCategory::Protocol
                | MicroCategory::MalformedOutput
                | MicroCategory::ProviderCrash
                | MicroCategory::UnsupportedVersion
                | MicroCategory::Configuration
                | MicroCategory::Unknown
        ),
        Category::Style => matches!(
            micro,
            MicroCategory::Format
                | MicroCategory::Lint
                | MicroCategory::Documentation
                | MicroCategory::Complexity
                | MicroCategory::Deprecation
                | MicroCategory::Unknown
        ),
        Category::Robustness => matches!(
            micro,
            MicroCategory::BoundaryInput
                | MicroCategory::MalformedInput
                | MicroCategory::CrashResistance
                | MicroCategory::RoundtripMismatch
                | MicroCategory::FuzzFinding
                | MicroCategory::Unknown
        ),
    }
}

impl Position {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_position(self)
    }
}

impl Location {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_location(self)
    }
}

impl Tool {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_tool(self)
    }
}

impl Taxonomy {
    pub fn validate(&self) -> Result<(), ContractError> {
        if micro_matches(&self.category, &self.micro_category) {
            Ok(())
        } else {
            Err(model_error("micro_category is not valid for category"))
        }
    }
}

impl Observation {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_tool(&self.tool)?;
        validate_common_texts(
            &self.message,
            self.symbol.as_deref(),
            self.expected.as_deref(),
            self.observed.as_deref(),
        )?;
        if let Some(location) = &self.location {
            validate_location(location)?;
        }
        check_unique(&self.evidence_ids, "evidence_ids", 64, 0)
    }
}

impl Finding {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_tool(&self.tool)?;
        self.classification.validate()?;
        validate_common_texts(
            &self.message,
            self.symbol.as_deref(),
            self.expected.as_deref(),
            self.observed.as_deref(),
        )?;
        if let Some(location) = &self.location {
            validate_location(location)?;
        }
        check_unique(&self.observation_ids, "observation_ids", 1024, 1)?;
        check_unique(&self.evidence_ids, "evidence_ids", 64, 0)?;
        if let Some(ids) = &self.verification_execution_ids {
            check_unique(ids, "verification_execution_ids", 64, 1)?;
        }
        match (self.state, self.pre_report_state) {
            (FindingState::Reported, None) => {
                return Err(model_error(
                    "pre_report_state is required for REPORTED findings",
                ));
            }
            (FindingState::Reported, Some(_)) | (_, None) => {}
            (_, Some(_)) => {
                return Err(model_error(
                    "pre_report_state is allowed only for REPORTED findings",
                ));
            }
        }
        let effective_state = match self.pre_report_state {
            Some(PreReportState::Classified) => FindingState::Classified,
            Some(PreReportState::FixProposed) => FindingState::FixProposed,
            Some(PreReportState::Verified) => FindingState::Verified,
            None => self.state,
        };
        if matches!(
            effective_state,
            FindingState::Discovered | FindingState::Normalized | FindingState::Classified
        ) && (self.fix_candidate_id.is_some() || self.verification_execution_ids.is_some())
        {
            return Err(model_error(
                "pre-fix findings cannot contain fix or verification references",
            ));
        }
        if matches!(
            effective_state,
            FindingState::FixProposed | FindingState::Verified
        ) && self.fix_candidate_id.is_none()
        {
            return Err(model_error(
                "fix_candidate_id is required for this finding state",
            ));
        }
        if effective_state == FindingState::Verified && self.verification_execution_ids.is_none() {
            return Err(model_error(
                "verification_execution_ids is required for verified findings",
            ));
        }
        Ok(())
    }

    /// Preserve the last material lifecycle state while entering `REPORTED`.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::Model`] when the Finding is invalid or has not
    /// reached `CLASSIFIED`.
    pub fn into_reported(mut self) -> Result<Self, ContractError> {
        self.validate()?;
        self.pre_report_state = Some(match self.state {
            FindingState::Classified => PreReportState::Classified,
            FindingState::FixProposed => PreReportState::FixProposed,
            FindingState::Verified => PreReportState::Verified,
            _ => {
                return Err(model_error(
                    "only CLASSIFIED, FIX_PROPOSED, or VERIFIED findings may be reported",
                ));
            }
        });
        self.state = FindingState::Reported;
        self.validate()?;
        Ok(self)
    }
}

/// Return whether a wire timestamp satisfies the v1 RFC 3339 profile.
///
/// This lexical guard intentionally narrows Jiff's broader Temporal/ISO 8601
/// parser before using Jiff for calendar and instant semantics. The v1 wire
/// profile uses one to nine fractional digits and excludes leap seconds so
/// every accepted value maps losslessly to the engine's nanosecond timestamp.
/// Years are bounded to 0000 through 9998 because Jiff's instant range does
/// not contain every offset-adjusted civil time in year 9999.
///
/// This function is public only for sibling unpublished workspace crates; it
/// is not part of a supported Rust SDK.
#[doc(hidden)]
#[must_use]
pub fn is_valid_rfc3339_datetime(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || !matches!(bytes[10], b'T' | b't')
        || ![4, 7].iter().all(|&index| bytes[index] == b'-')
        || ![13, 16].iter().all(|&index| bytes[index] == b':')
        || !bytes[..19]
            .iter()
            .enumerate()
            .all(|(index, byte)| [4, 7, 10, 13, 16].contains(&index) || byte.is_ascii_digit())
    {
        return false;
    }
    if &bytes[..4] == b"9999" {
        return false;
    }

    let mut zone_start = 19;
    if bytes[zone_start] == b'.' {
        zone_start += 1;
        let fraction_start = zone_start;
        while bytes.get(zone_start).is_some_and(u8::is_ascii_digit) {
            zone_start += 1;
        }
        if zone_start == fraction_start || zone_start - fraction_start > 9 {
            return false;
        }
    }
    if (bytes[17] - b'0') * 10 + (bytes[18] - b'0') > 59 {
        return false;
    }

    // Jiff's Temporal parser intentionally accepts wider ISO 8601 offsets;
    // RFC 3339 fixes numeric offset hours to 00..=23 and minutes to 00..=59.
    match bytes.get(zone_start..) {
        Some([b'Z' | b'z']) => {}
        Some(
            [
                b'+' | b'-',
                hour_tens,
                hour_ones,
                b':',
                minute_tens,
                minute_ones,
            ],
        ) if hour_tens.is_ascii_digit()
            && hour_ones.is_ascii_digit()
            && minute_tens.is_ascii_digit()
            && minute_ones.is_ascii_digit()
            && (hour_tens - b'0') * 10 + (hour_ones - b'0') <= 23
            && (minute_tens - b'0') * 10 + (minute_ones - b'0') <= 59 => {}
        _ => return false,
    }

    value.parse::<jiff::Timestamp>().is_ok()
}

impl Waiver {
    pub fn validate(&self) -> Result<(), ContractError> {
        check_string(&self.reason, "waiver.reason", 2048, true)?;
        check_string(&self.owner, "waiver.owner", 256, true)?;
        if is_valid_rfc3339_datetime(&self.expires_at) {
            Ok(())
        } else {
            Err(model_error(
                "waiver.expires_at must be an RFC 3339 date-time",
            ))
        }
    }
}

impl Decision {
    pub fn validate(&self) -> Result<(), ContractError> {
        check_string(&self.matched_rule_id, "matched_rule_id", 128, true)?;
        if !is_valid_rfc3339_datetime(&self.evaluated_at) {
            return Err(model_error(
                "decision.evaluated_at must be an RFC 3339 date-time",
            ));
        }
        match (&self.action, &self.waiver) {
            (DecisionAction::Waive, Some(waiver)) => {
                waiver.validate()?;
                let evaluated_at = self.evaluated_at.parse::<jiff::Timestamp>().map_err(|_| {
                    model_error("decision.evaluated_at must be an RFC 3339 date-time")
                })?;
                let expires_at = waiver
                    .expires_at
                    .parse::<jiff::Timestamp>()
                    .map_err(|_| model_error("waiver.expires_at must be an RFC 3339 date-time"))?;
                if expires_at <= evaluated_at {
                    return Err(model_error(
                        "WAIVE decisions require expiry strictly after evaluation",
                    ));
                }
                Ok(())
            }
            (DecisionAction::Waive, None) => Err(model_error("WAIVE decisions require waiver")),
            (_, Some(_)) => Err(model_error("only WAIVE decisions may contain waiver")),
            (_, None) => Ok(()),
        }
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

impl Evidence {
    pub fn validate(&self) -> Result<(), ContractError> {
        check_string(&self.media_type, "media_type", 128, true)?;
        if self.retained_bytes > 1_048_576 || self.limit_bytes > 1_048_576 {
            return Err(model_error("evidence byte limit exceeds 1048576"));
        }
        if self.retained_bytes > self.observed_bytes
            || self.retained_bytes > u64::from(self.limit_bytes)
        {
            return Err(model_error(
                "retained bytes exceed observed bytes or evidence limit",
            ));
        }
        if self.truncated != (self.observed_bytes > self.retained_bytes) {
            return Err(model_error("evidence truncation metadata is inconsistent"));
        }
        match (&self.relative_path, &self.content) {
            (Some(_), Some(_)) | (None, None) => Err(model_error(
                "evidence requires exactly one storage location",
            )),
            (Some(_), None) => Ok(()),
            (None, Some(content)) => {
                if u64::try_from(content.len()).unwrap_or(u64::MAX) != self.retained_bytes {
                    return Err(model_error(
                        "retained byte count mismatches evidence content",
                    ));
                }
                if sha256(content.as_bytes()) != self.sha256.as_str() {
                    return Err(model_error("evidence digest mismatch"));
                }
                Ok(())
            }
        }
    }
}

impl FixCandidate {
    pub fn validate(&self) -> Result<(), ContractError> {
        check_unique(&self.observation_ids, "observation_ids", 1024, 1)?;
        match (self.applicability, self.tool_native) {
            (Applicability::Safe, false) => Err(model_error("SAFE fixes must be tool_native")),
            (Applicability::Unsafe, false) => {
                Err(model_error("non-tool-native fixes must be MANUAL"))
            }
            (Applicability::Manual | Applicability::Safe | Applicability::Unsafe, true)
            | (Applicability::Manual, false) => Ok(()),
        }
    }
}

fn validate_phase_duration(value: &PhaseDuration, field: &str) -> Result<(), ContractError> {
    if let PhaseDuration::Milliseconds(value) = value {
        if *value > 600_000 {
            return Err(model_error(format!("{field} exceeds 600000 ms")));
        }
    }
    Ok(())
}

impl ExecutionPhases {
    pub fn validate(&self) -> Result<(), ContractError> {
        let values = [
            (&self.queue, "queue"),
            (&self.setup, "setup"),
            (&self.run, "run"),
            (&self.normalize, "normalize"),
            (&self.total, "total"),
        ];
        for (value, field) in values {
            validate_phase_duration(value, field)?;
        }
        if let PhaseDuration::Milliseconds(total) = &self.total {
            if ![&self.queue, &self.setup, &self.run, &self.normalize]
                .iter()
                .any(|value| matches!(value, PhaseDuration::Unavailable(_)))
            {
                let sum: u32 = [&self.queue, &self.setup, &self.run, &self.normalize]
                    .iter()
                    .filter_map(|value| match value {
                        PhaseDuration::Milliseconds(value) => Some(*value),
                        _ => None,
                    })
                    .sum();
                if *total != sum {
                    return Err(model_error("execution phase total is inconsistent"));
                }
            }
        } else if matches!(&self.total, PhaseDuration::NotApplicable(_))
            && [&self.queue, &self.setup, &self.run, &self.normalize]
                .iter()
                .any(|value| !matches!(value, PhaseDuration::NotApplicable(_)))
        {
            return Err(model_error(
                "non-applicable total has recorded execution phases",
            ));
        }
        Ok(())
    }
}

impl Performance {
    pub fn validate(&self, run: &PhaseDuration) -> Result<(), ContractError> {
        if self.budget_ms == 0 || self.budget_ms > 600_000 {
            return Err(model_error("performance budget must be 1..=600000 ms"));
        }
        if let PhaseDuration::Milliseconds(run) = run {
            let expected = if *run > self.budget_ms {
                PerformanceStatus::ImprovementCandidate
            } else {
                PerformanceStatus::WithinBudget
            };
            if self.status != PerformanceStatus::NotEvaluated && self.status != expected {
                return Err(model_error("execution performance status is inconsistent"));
            }
        }
        Ok(())
    }
}

impl Cache {
    pub fn validate(&self) -> Result<(), ContractError> {
        if matches!(self.status, CacheStatus::Hit | CacheStatus::Miss) && self.restore_ms.is_none()
        {
            return Err(model_error("cache HIT/MISS requires restore_ms"));
        }
        if matches!(
            self.status,
            CacheStatus::NotApplicable | CacheStatus::Unavailable
        ) && (self.restore_ms.is_some() || self.save_ms.is_some())
        {
            return Err(model_error("cache timings require HIT or MISS"));
        }
        if self.restore_ms.is_some_and(|value| value > 600_000)
            || self.save_ms.is_some_and(|value| value > 600_000)
        {
            return Err(model_error("cache timing exceeds 600000 ms"));
        }
        Ok(())
    }
}

impl Retry {
    pub fn validate(&self) -> Result<(), ContractError> {
        match self.status {
            RetryStatus::Recorded => {
                let attempt = self
                    .attempt
                    .ok_or_else(|| model_error("recorded retry requires attempt"))?;
                if !(1..=100).contains(&attempt) || self.same_revision.is_none() {
                    return Err(model_error(
                        "recorded retry requires attempt 1..=100 and same_revision",
                    ));
                }
                Ok(())
            }
            RetryStatus::NotApplicable | RetryStatus::Unavailable
                if self.attempt.is_some()
                    || self.same_revision.is_some()
                    || self.group_id.is_some() =>
            {
                Err(model_error("retry details require RECORDED status"))
            }
            RetryStatus::NotApplicable | RetryStatus::Unavailable => Ok(()),
        }
    }
}

impl Runner {
    pub fn validate(&self) -> Result<(), ContractError> {
        match self.status {
            RunnerStatus::Recorded => {
                check_string(
                    self.os
                        .as_deref()
                        .ok_or_else(|| model_error("recorded runner requires os"))?,
                    "runner.os",
                    64,
                    true,
                )?;
                check_string(
                    self.arch
                        .as_deref()
                        .ok_or_else(|| model_error("recorded runner requires arch"))?,
                    "runner.arch",
                    64,
                    true,
                )?;
                if self.fingerprint.is_none() {
                    return Err(model_error("recorded runner requires fingerprint"));
                }
                if let Some(image) = &self.image {
                    check_string(image, "runner.image", 256, true)?;
                }
                Ok(())
            }
            RunnerStatus::Unavailable
                if self.os.is_some()
                    || self.arch.is_some()
                    || self.image.is_some()
                    || self.fingerprint.is_some() =>
            {
                Err(model_error("runner details require RECORDED status"))
            }
            RunnerStatus::Unavailable => Ok(()),
        }
    }
}

impl Execution {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_tool(&self.tool)?;
        if let Some(verification) = &self.verification {
            if self.adapter_kind != AdapterKind::Provider {
                return Err(model_error(
                    "verification attribution is valid only for Provider executions",
                ));
            }
            verification.validate()?;
        }
        if self.status != ExecutionStatus::Complete
            && (self.exit_code.0.is_some() || self.message.is_none())
        {
            return Err(model_error(
                "incomplete or unsupported execution requires message and null exit_code",
            ));
        }
        if self.status == ExecutionStatus::Complete
            && matches!(
                &self.adapter_kind,
                AdapterKind::Engine | AdapterKind::Provider
            )
            && self.exit_code.0.is_none()
        {
            return Err(model_error(
                "complete engine/provider execution requires exit_code",
            ));
        }
        if let Some(message) = &self.message {
            check_string(message, "message", 8192, true)?;
        }
        self.phases_ms.validate()?;
        self.performance.validate(&self.phases_ms.run)?;
        self.cache.validate()?;
        self.retry.validate()?;
        self.runner.validate()
    }
}

impl EngineIdentity {
    pub fn validate(&self) -> Result<(), ContractError> {
        check_string(&self.version, "engine.version", 64, true)
    }
}

impl SessionReport {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.engine.validate()?;
        for collection in [
            self.observations.len(),
            self.findings.len(),
            self.decisions.len(),
            self.evidence.len(),
            self.fix_candidates.len(),
            self.executions.len(),
        ] {
            if collection > 10_000 {
                return Err(model_error("session report collection exceeds 10000 items"));
            }
        }
        for observation in &self.observations {
            observation.validate()?;
        }
        for finding in &self.findings {
            finding.validate()?;
        }
        for decision in &self.decisions {
            decision.validate()?;
        }
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        for candidate in &self.fix_candidates {
            candidate.validate()?;
        }
        for execution in &self.executions {
            execution.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Evidence, EvidenceSchemaVersion, PhaseDuration, SessionReport, Sha256Digest,
        ToolchainFingerprint, Unavailable, VerificationAttribution, is_valid_rfc3339_datetime,
    };

    #[test]
    fn schema_version_is_exact_and_optional_null_is_rejected() {
        let wrong = r#"{"schema_version":"diagnostic-triage.evidence/v2","evidence_id":"019f7e95-0000-7000-8000-000000000001","source":"STDOUT","media_type":"text/plain","retained_bytes":0,"observed_bytes":0,"limit_bytes":0,"truncated":false,"sha256":"0000000000000000000000000000000000000000000000000000000000000000","relative_path":"x.txt"}"#;
        assert!(serde_json::from_str::<Evidence>(wrong).is_err());

        let null_optional = r#"{"schema_version":"diagnostic-triage.evidence/v1","evidence_id":"019f7e95-0000-7000-8000-000000000001","source":"STDOUT","media_type":"text/plain","retained_bytes":0,"observed_bytes":0,"limit_bytes":0,"truncated":false,"sha256":"0000000000000000000000000000000000000000000000000000000000000000","relative_path":null}"#;
        assert!(serde_json::from_str::<Evidence>(null_optional).is_err());
    }

    #[test]
    fn phase_duration_preserves_scalar_and_terminal_strings() {
        assert_eq!(
            serde_json::to_string(&PhaseDuration::Milliseconds(7)).unwrap(),
            "7"
        );
        assert_eq!(
            serde_json::to_string(&PhaseDuration::Unavailable(Unavailable::Value)).unwrap(),
            "\"UNAVAILABLE\""
        );
    }

    #[test]
    fn evidence_validation_checks_utf8_bytes_and_digest() {
        let evidence = Evidence {
            schema_version: EvidenceSchemaVersion::V1,
            evidence_id: "019f7e95-0000-7000-8000-000000000001".parse().unwrap(),
            execution_id: None,
            source: super::EvidenceSource::Stdout,
            media_type: "text/plain".to_owned(),
            retained_bytes: 5,
            observed_bytes: 5,
            limit_bytes: 5,
            truncated: false,
            sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                .parse::<Sha256Digest>()
                .unwrap(),
            relative_path: None,
            content: Some("hello".to_owned()),
        };
        assert!(evidence.validate().is_ok());
    }

    #[test]
    fn waiver_datetime_uses_strict_rfc3339_shape_and_timestamp_semantics() {
        for value in [
            "2024-02-29T23:59:59Z",
            "0000-01-01T00:00:00+23:59",
            "9998-12-31T23:59:59-23:59",
            "2000-02-29T23:59:59Z",
            "2400-02-29T23:59:59Z",
            "2024-02-29t23:59:59z",
            "2024-02-29T23:59:59.123456789+09:00",
            "2024-02-29T23:59:59+23:59",
            "2024-02-29T23:59:59-23:59",
        ] {
            assert!(
                is_valid_rfc3339_datetime(value),
                "expected valid date-time: {value}"
            );
        }

        for value in [
            "2023-02-29T23:59:59Z",
            "9999-01-01T00:00:00Z",
            "1900-02-29T23:59:59Z",
            "2100-02-29T23:59:59Z",
            "2024-02-29T23:59Z",
            "2024-02-29T23:59:59+0900",
            "2024-02-29T23:59:59Z[Asia/Tokyo]",
            "2024-02-29T23:59:59.+09:00",
            "2024-02-29T23:59:59.1234567890Z",
            "2024-02-29T23:59:60Z",
            "2024-02-29T23:59:59+24:00",
            "2024-02-29T23:59:59-24:00",
            "2024-02-29T23:59:59+23:60",
            "2024-02-29T23:59:59-23:60",
        ] {
            assert!(
                !is_valid_rfc3339_datetime(value),
                "expected invalid date-time: {value}"
            );
        }
    }

    #[test]
    fn toolchain_fingerprint_accepts_only_digest_or_unavailable() {
        let unavailable = serde_json::from_str::<ToolchainFingerprint>(r#""UNAVAILABLE""#).unwrap();
        assert_eq!(
            unavailable,
            ToolchainFingerprint::Unavailable(Unavailable::Value)
        );
        assert!(serde_json::from_str::<ToolchainFingerprint>(r#""available""#).is_err());
    }

    #[test]
    fn verification_attribution_is_optional_and_omits_null() {
        let mut report = serde_json::from_str::<SessionReport>(include_str!(
            "../../../tests/fixtures/v1/valid-report.json"
        ))
        .unwrap();
        let without_verification = serde_json::to_value(&report).unwrap();
        assert!(
            without_verification["executions"][0]
                .get("verification")
                .is_none()
        );

        report.executions[0].verification = Some(Box::new(VerificationAttribution {
            fix_candidate_id: "019f7e95-0000-7000-8000-000000000202".parse().unwrap(),
            patch_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
            base_snapshot_sha256:
                "1111111111111111111111111111111111111111111111111111111111111111"
                    .parse()
                    .unwrap(),
            base_snapshot_evidence_id: "019f7e95-0000-7000-8000-000000000204".parse().unwrap(),
            target_fingerprints: vec![
                "dtfp1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .parse()
                    .unwrap(),
            ],
            result_evidence_id: "019f7e95-0000-7000-8000-000000000203".parse().unwrap(),
        }));
        assert!(report.executions[0].validate().is_ok());
        let with_verification = serde_json::to_value(&report).unwrap();
        assert_eq!(
            with_verification["executions"][0]["verification"],
            serde_json::json!({
                "fix_candidate_id": "019f7e95-0000-7000-8000-000000000202",
                "patch_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "base_snapshot_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
                "base_snapshot_evidence_id": "019f7e95-0000-7000-8000-000000000204",
                "target_fingerprints": [
                    "dtfp1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ],
                "result_evidence_id": "019f7e95-0000-7000-8000-000000000203"
            })
        );

        report.executions[0]
            .verification
            .as_mut()
            .unwrap()
            .target_fingerprints
            .clear();
        assert!(report.executions[0].validate().is_err());

        report.executions[0]
            .verification
            .as_mut()
            .unwrap()
            .target_fingerprints = vec![
            "dtfp1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .unwrap(),
            "dtfp1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .unwrap(),
        ];
        assert!(report.executions[0].validate().is_err());

        report.executions[0]
            .verification
            .as_mut()
            .unwrap()
            .target_fingerprints = vec![
            "dtfp1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .unwrap();
            1025
        ];
        assert!(report.executions[0].validate().is_err());

        let mut null_verification = with_verification["executions"][0].clone();
        null_verification["verification"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<super::Execution>(null_verification).is_err());

        report.executions[0].adapter_kind = super::AdapterKind::Observer;
        assert!(report.executions[0].validate().is_err());
    }
}
