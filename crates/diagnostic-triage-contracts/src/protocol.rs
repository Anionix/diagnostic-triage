//! Typed JSON Lines envelopes for the Diagnostic Triage Provider Protocol v1.

use std::collections::HashSet;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{
    error::ContractError,
    jsonl::deserialize_strict_value,
    model::{AdapterKind, Evidence, Execution, ExecutionStatus, FixCandidate, Observation},
    scalar::{AdapterId, Capability, Language, ObjectId, RepoPath},
    wire::{Nullable, deserialize_optional},
};

const PROTOCOL_VERSION: &str = "diagnostic-triage.protocol/v1";
const MAX_SEQUENCE: u64 = 10_000;
const MAX_TIMEOUT_MS: u64 = 600_000;
const MAX_STDOUT_BYTES: u64 = 16_777_216;
const MAX_STDERR_BYTES: u64 = 4_194_304;
const MAX_EVIDENCE_BYTES: u64 = 1_048_576;
const MAX_EVENTS: u64 = 10_000;
const MAX_COMPLETION_EVIDENCE_BYTES: u64 = 10_485_760_000;

/// The only protocol version understood by this crate.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum ProtocolVersion {
    #[serde(rename = "diagnostic-triage.protocol/v1")]
    #[schemars(rename = "diagnostic-triage.protocol/v1")]
    V1,
}

/// The discriminator carried by every v1 envelope.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum EnvelopeKind {
    #[serde(rename = "manifest")]
    Manifest,
    #[serde(rename = "request")]
    Request,
    #[serde(rename = "observation")]
    Observation,
    #[serde(rename = "evidence")]
    Evidence,
    #[serde(rename = "fix_candidate")]
    FixCandidate,
    #[serde(rename = "execution")]
    Execution,
    #[serde(rename = "completion")]
    Completion,
}

/// An operation requested from an adapter.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum Operation {
    #[serde(rename = "CHECK")]
    Check,
    #[serde(rename = "FIX")]
    Fix,
    #[serde(rename = "VERIFY")]
    Verify,
    #[serde(rename = "OBSERVE")]
    Observe,
}

/// Adapter identity and capabilities advertised during the handshake.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterManifest {
    pub id: AdapterId,
    pub version: String,
    pub kind: AdapterKind,
    pub capabilities: Vec<Capability>,
    pub languages: Vec<Language>,
}

/// Limits imposed on one adapter invocation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestLimits {
    pub timeout_ms: u64,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub max_evidence_bytes: u64,
    pub max_events: u64,
}

/// The adapter-to-engine handshake envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEnvelope {
    pub protocol_version: ProtocolVersion,
    pub kind: EnvelopeKind,
    pub adapter: AdapterManifest,
}

/// The engine-to-adapter request envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub protocol_version: ProtocolVersion,
    pub kind: EnvelopeKind,
    pub request_id: ObjectId,
    pub operation: Operation,
    pub workspace: RepoPath,
    pub targets: Vec<RepoPath>,
    pub required_capabilities: Vec<Capability>,
    pub optional_capabilities: Vec<Capability>,
    pub limits: RequestLimits,
}

/// An observation emitted by an adapter.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationEnvelope {
    pub protocol_version: ProtocolVersion,
    pub kind: EnvelopeKind,
    pub request_id: ObjectId,
    pub sequence: u64,
    pub observation: Observation,
}

/// Evidence emitted by an adapter.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEnvelope {
    pub protocol_version: ProtocolVersion,
    pub kind: EnvelopeKind,
    pub request_id: ObjectId,
    pub sequence: u64,
    pub evidence: Evidence,
}

/// A proposed fix emitted by an adapter.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixCandidateEnvelope {
    pub protocol_version: ProtocolVersion,
    pub kind: EnvelopeKind,
    pub request_id: ObjectId,
    pub sequence: u64,
    pub fix_candidate: FixCandidate,
}

/// An execution record emitted by an adapter.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEnvelope {
    pub protocol_version: ProtocolVersion,
    pub kind: EnvelopeKind,
    pub request_id: ObjectId,
    pub sequence: u64,
    pub execution: Execution,
}

/// Counts reported by the final completion envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionCounts {
    pub observations: u64,
    pub evidence: u64,
    pub fix_candidates: u64,
    pub executions: u64,
}

/// The final adapter-to-engine completion envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionEnvelope {
    pub protocol_version: ProtocolVersion,
    pub kind: EnvelopeKind,
    pub request_id: ObjectId,
    pub sequence: u64,
    pub status: ExecutionStatus,
    pub tool_exit_code: Nullable<u8>,
    pub tool_duration_ms: u64,
    pub counts: CompletionCounts,
    pub evidence_bytes: u64,
    #[serde(
        default,
        deserialize_with = "deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub message: Option<String>,
}

/// One complete v1 JSON Lines envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ProtocolEnvelope {
    Manifest(ManifestEnvelope),
    Request(RequestEnvelope),
    Observation(ObservationEnvelope),
    Evidence(EvidenceEnvelope),
    FixCandidate(FixCandidateEnvelope),
    Execution(ExecutionEnvelope),
    Completion(CompletionEnvelope),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawProtocolEnvelope {
    Manifest(ManifestEnvelopeRaw),
    Request(RequestEnvelopeRaw),
    Observation(ObservationEnvelopeRaw),
    Evidence(EvidenceEnvelopeRaw),
    FixCandidate(FixCandidateEnvelopeRaw),
    Execution(ExecutionEnvelopeRaw),
    Completion(CompletionEnvelopeRaw),
}

#[derive(Debug, JsonSchema, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEnvelopeRaw {
    protocol_version: ProtocolVersion,
    kind: EnvelopeKind,
    adapter: AdapterManifest,
}

#[derive(Debug, JsonSchema, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelopeRaw {
    protocol_version: ProtocolVersion,
    kind: EnvelopeKind,
    request_id: ObjectId,
    operation: Operation,
    workspace: RepoPath,
    targets: Vec<RepoPath>,
    required_capabilities: Vec<Capability>,
    optional_capabilities: Vec<Capability>,
    limits: RequestLimits,
}

#[derive(Debug, JsonSchema, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationEnvelopeRaw {
    protocol_version: ProtocolVersion,
    kind: EnvelopeKind,
    request_id: ObjectId,
    sequence: u64,
    observation: Observation,
}

#[derive(Debug, JsonSchema, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceEnvelopeRaw {
    protocol_version: ProtocolVersion,
    kind: EnvelopeKind,
    request_id: ObjectId,
    sequence: u64,
    evidence: Evidence,
}

#[derive(Debug, JsonSchema, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixCandidateEnvelopeRaw {
    protocol_version: ProtocolVersion,
    kind: EnvelopeKind,
    request_id: ObjectId,
    sequence: u64,
    fix_candidate: FixCandidate,
}

#[derive(Debug, JsonSchema, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionEnvelopeRaw {
    protocol_version: ProtocolVersion,
    kind: EnvelopeKind,
    request_id: ObjectId,
    sequence: u64,
    execution: Execution,
}

#[derive(Debug, JsonSchema, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionEnvelopeRaw {
    protocol_version: ProtocolVersion,
    kind: EnvelopeKind,
    request_id: ObjectId,
    sequence: u64,
    status: ExecutionStatus,
    tool_exit_code: Nullable<u8>,
    tool_duration_ms: u64,
    counts: CompletionCounts,
    evidence_bytes: u64,
    #[serde(default, deserialize_with = "deserialize_optional")]
    message: Option<String>,
}

macro_rules! impl_envelope_try_from {
    ($raw_var:ident, $raw:ident, $envelope:ident, $build:expr, $validate:ident) => {
        impl TryFrom<$raw> for $envelope {
            type Error = ContractError;

            fn try_from($raw_var: $raw) -> Result<Self, Self::Error> {
                let value = $build;
                $validate(&value)?;
                Ok(value)
            }
        }
    };
}

impl_envelope_try_from!(
    raw,
    ManifestEnvelopeRaw,
    ManifestEnvelope,
    Self {
        protocol_version: raw.protocol_version,
        kind: raw.kind,
        adapter: raw.adapter,
    },
    validate_manifest
);
impl_envelope_try_from!(
    raw,
    RequestEnvelopeRaw,
    RequestEnvelope,
    Self {
        protocol_version: raw.protocol_version,
        kind: raw.kind,
        request_id: raw.request_id,
        operation: raw.operation,
        workspace: raw.workspace,
        targets: raw.targets,
        required_capabilities: raw.required_capabilities,
        optional_capabilities: raw.optional_capabilities,
        limits: raw.limits,
    },
    validate_request
);
impl_envelope_try_from!(
    raw,
    ObservationEnvelopeRaw,
    ObservationEnvelope,
    Self {
        protocol_version: raw.protocol_version,
        kind: raw.kind,
        request_id: raw.request_id,
        sequence: raw.sequence,
        observation: raw.observation,
    },
    validate_observation
);
impl_envelope_try_from!(
    raw,
    EvidenceEnvelopeRaw,
    EvidenceEnvelope,
    Self {
        protocol_version: raw.protocol_version,
        kind: raw.kind,
        request_id: raw.request_id,
        sequence: raw.sequence,
        evidence: raw.evidence,
    },
    validate_evidence
);
impl_envelope_try_from!(
    raw,
    FixCandidateEnvelopeRaw,
    FixCandidateEnvelope,
    Self {
        protocol_version: raw.protocol_version,
        kind: raw.kind,
        request_id: raw.request_id,
        sequence: raw.sequence,
        fix_candidate: raw.fix_candidate,
    },
    validate_fix_candidate
);
impl_envelope_try_from!(
    raw,
    ExecutionEnvelopeRaw,
    ExecutionEnvelope,
    Self {
        protocol_version: raw.protocol_version,
        kind: raw.kind,
        request_id: raw.request_id,
        sequence: raw.sequence,
        execution: raw.execution,
    },
    validate_execution
);
impl_envelope_try_from!(
    raw,
    CompletionEnvelopeRaw,
    CompletionEnvelope,
    Self {
        protocol_version: raw.protocol_version,
        kind: raw.kind,
        request_id: raw.request_id,
        sequence: raw.sequence,
        status: raw.status,
        tool_exit_code: raw.tool_exit_code,
        tool_duration_ms: raw.tool_duration_ms,
        counts: raw.counts,
        evidence_bytes: raw.evidence_bytes,
        message: raw.message,
    },
    validate_completion
);

impl<'de> Deserialize<'de> for ProtocolEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = deserialize_strict_value(deserializer)?;
        let raw = serde_json::from_value::<RawProtocolEnvelope>(value).map_err(D::Error::custom)?;
        let envelope = match raw {
            RawProtocolEnvelope::Manifest(value) => {
                Self::Manifest(value.try_into().map_err(D::Error::custom)?)
            }
            RawProtocolEnvelope::Request(value) => {
                Self::Request(value.try_into().map_err(D::Error::custom)?)
            }
            RawProtocolEnvelope::Observation(value) => {
                Self::Observation(value.try_into().map_err(D::Error::custom)?)
            }
            RawProtocolEnvelope::Evidence(value) => {
                Self::Evidence(value.try_into().map_err(D::Error::custom)?)
            }
            RawProtocolEnvelope::FixCandidate(value) => {
                Self::FixCandidate(value.try_into().map_err(D::Error::custom)?)
            }
            RawProtocolEnvelope::Execution(value) => {
                Self::Execution(value.try_into().map_err(D::Error::custom)?)
            }
            RawProtocolEnvelope::Completion(value) => {
                Self::Completion(value.try_into().map_err(D::Error::custom)?)
            }
        };
        envelope.validate().map_err(D::Error::custom)?;
        Ok(envelope)
    }
}

impl ProtocolEnvelope {
    /// Validate the local v1 schema shape represented by this envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::Protocol`] for a protocol-shape violation or
    /// propagates a model validation error from an event payload.
    pub fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Manifest(value) => validate_manifest(value),
            Self::Request(value) => validate_request(value),
            Self::Observation(value) => validate_observation(value),
            Self::Evidence(value) => validate_evidence(value),
            Self::FixCandidate(value) => validate_fix_candidate(value),
            Self::Execution(value) => validate_execution(value),
            Self::Completion(value) => validate_completion(value),
        }
    }
}

fn validate_manifest(value: &ManifestEnvelope) -> Result<(), ContractError> {
    validate_header(value.protocol_version, value.kind, EnvelopeKind::Manifest)?;
    if matches!(value.adapter.kind, AdapterKind::Engine) {
        return Err(protocol_error("manifest adapter kind cannot be ENGINE"));
    }
    validate_string("adapter.version", &value.adapter.version, 1, 64)?;
    validate_array(
        "adapter.capabilities",
        &value.adapter.capabilities,
        1,
        64,
        true,
    )?;
    validate_array("adapter.languages", &value.adapter.languages, 0, 64, true)
}

fn validate_request(value: &RequestEnvelope) -> Result<(), ContractError> {
    validate_header(value.protocol_version, value.kind, EnvelopeKind::Request)?;
    validate_array("targets", &value.targets, 1, 256, true)?;
    validate_array(
        "required_capabilities",
        &value.required_capabilities,
        0,
        64,
        true,
    )?;
    validate_array(
        "optional_capabilities",
        &value.optional_capabilities,
        0,
        64,
        true,
    )?;
    validate_limits(&value.limits)
}

fn validate_observation(value: &ObservationEnvelope) -> Result<(), ContractError> {
    value.observation.validate()?;
    validate_event_header(
        value.protocol_version,
        value.kind,
        EnvelopeKind::Observation,
        value.sequence,
    )
}

fn validate_evidence(value: &EvidenceEnvelope) -> Result<(), ContractError> {
    value.evidence.validate()?;
    validate_event_header(
        value.protocol_version,
        value.kind,
        EnvelopeKind::Evidence,
        value.sequence,
    )
}

fn validate_fix_candidate(value: &FixCandidateEnvelope) -> Result<(), ContractError> {
    value.fix_candidate.validate()?;
    validate_event_header(
        value.protocol_version,
        value.kind,
        EnvelopeKind::FixCandidate,
        value.sequence,
    )
}

fn validate_execution(value: &ExecutionEnvelope) -> Result<(), ContractError> {
    value.execution.validate()?;
    validate_event_header(
        value.protocol_version,
        value.kind,
        EnvelopeKind::Execution,
        value.sequence,
    )
}

fn validate_limits(value: &RequestLimits) -> Result<(), ContractError> {
    if !(1..=MAX_TIMEOUT_MS).contains(&value.timeout_ms) {
        return Err(protocol_error(
            "limits.timeout_ms exceeds the v1 hard maximum",
        ));
    }
    if value.max_stdout_bytes > MAX_STDOUT_BYTES {
        return Err(protocol_error(
            "limits.max_stdout_bytes exceeds the v1 hard maximum",
        ));
    }
    if value.max_stderr_bytes > MAX_STDERR_BYTES {
        return Err(protocol_error(
            "limits.max_stderr_bytes exceeds the v1 hard maximum",
        ));
    }
    if value.max_evidence_bytes > MAX_EVIDENCE_BYTES {
        return Err(protocol_error(
            "limits.max_evidence_bytes exceeds the v1 hard maximum",
        ));
    }
    if value.max_events > MAX_EVENTS {
        return Err(protocol_error(
            "limits.max_events exceeds the v1 hard maximum",
        ));
    }
    Ok(())
}

fn validate_event_header(
    protocol_version: ProtocolVersion,
    kind: EnvelopeKind,
    expected_kind: EnvelopeKind,
    sequence: u64,
) -> Result<(), ContractError> {
    validate_header(protocol_version, kind, expected_kind)?;
    if sequence > MAX_SEQUENCE {
        return Err(protocol_error("event sequence exceeds the v1 hard maximum"));
    }
    Ok(())
}

fn validate_completion(value: &CompletionEnvelope) -> Result<(), ContractError> {
    validate_event_header(
        value.protocol_version,
        value.kind,
        EnvelopeKind::Completion,
        value.sequence,
    )?;
    if value.tool_duration_ms > MAX_TIMEOUT_MS {
        return Err(protocol_error(
            "tool_duration_ms exceeds the v1 hard maximum",
        ));
    }
    validate_count("counts.observations", value.counts.observations)?;
    validate_count("counts.evidence", value.counts.evidence)?;
    validate_count("counts.fix_candidates", value.counts.fix_candidates)?;
    validate_count("counts.executions", value.counts.executions)?;
    if value.evidence_bytes > MAX_COMPLETION_EVIDENCE_BYTES {
        return Err(protocol_error("evidence_bytes exceeds the v1 hard maximum"));
    }
    if let Some(message) = &value.message {
        validate_string("message", message, 1, 8192)?;
    }

    match value.status {
        ExecutionStatus::Complete if value.tool_exit_code.0.is_none() => Err(protocol_error(
            "COMPLETE completion requires an integer tool_exit_code",
        )),
        ExecutionStatus::Incomplete | ExecutionStatus::Unsupported
            if value.tool_exit_code.0.is_some() =>
        {
            Err(protocol_error(
                "INCOMPLETE and UNSUPPORTED completions require a null tool_exit_code",
            ))
        }
        ExecutionStatus::Incomplete | ExecutionStatus::Unsupported if value.message.is_none() => {
            Err(protocol_error(
                "INCOMPLETE and UNSUPPORTED completions require message",
            ))
        }
        _ => Ok(()),
    }
}

fn validate_header(
    protocol_version: ProtocolVersion,
    kind: EnvelopeKind,
    expected_kind: EnvelopeKind,
) -> Result<(), ContractError> {
    if protocol_version != ProtocolVersion::V1 {
        return Err(protocol_error(&format!(
            "protocol_version must be {PROTOCOL_VERSION}"
        )));
    }
    if kind != expected_kind {
        return Err(protocol_error(
            "envelope kind does not match its typed envelope",
        ));
    }
    Ok(())
}

fn validate_array<T>(
    name: &str,
    values: &[T],
    minimum: usize,
    maximum: usize,
    require_unique: bool,
) -> Result<(), ContractError>
where
    T: Eq + std::hash::Hash,
{
    if values.len() < minimum {
        return Err(protocol_error(&format!(
            "{name} has fewer than {minimum} items"
        )));
    }
    if values.len() > maximum {
        return Err(protocol_error(&format!("{name} exceeds {maximum} items")));
    }
    if require_unique {
        let mut seen = HashSet::with_capacity(values.len());
        if values.iter().any(|value| !seen.insert(value)) {
            return Err(protocol_error(&format!("{name} must contain unique items")));
        }
    }
    Ok(())
}

fn validate_count(name: &str, value: u64) -> Result<(), ContractError> {
    if value > MAX_EVENTS {
        Err(protocol_error(&format!(
            "{name} exceeds the v1 hard maximum"
        )))
    } else {
        Ok(())
    }
}

fn validate_string(
    name: &str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), ContractError> {
    let length = value.chars().count();
    if !(minimum..=maximum).contains(&length) {
        return Err(protocol_error(&format!(
            "{name} must contain between {minimum} and {maximum} characters"
        )));
    }
    Ok(())
}

fn protocol_error(message: &str) -> ContractError {
    ContractError::Protocol(message.to_owned())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{EnvelopeKind, ProtocolEnvelope, ProtocolVersion};

    const REQUEST_ID: &str = "019f7e95-0000-7000-8000-000000000001";

    fn valid_manifest() -> serde_json::Value {
        json!({
            "protocol_version": "diagnostic-triage.protocol/v1",
            "kind": "manifest",
            "adapter": {
                "id": "python-provider",
                "version": "1.0.0",
                "kind": "PROVIDER",
                "capabilities": ["diagnostic.check/v1"],
                "languages": ["python"]
            }
        })
    }

    fn valid_request() -> serde_json::Value {
        json!({
            "protocol_version": "diagnostic-triage.protocol/v1",
            "kind": "request",
            "request_id": REQUEST_ID,
            "operation": "CHECK",
            "workspace": ".",
            "targets": ["src/lib.rs"],
            "required_capabilities": ["diagnostic.check/v1"],
            "optional_capabilities": [],
            "limits": {
                "timeout_ms": 600_000,
                "max_stdout_bytes": 16_777_216,
                "max_stderr_bytes": 4_194_304,
                "max_evidence_bytes": 1_048_576,
                "max_events": 10_000
            }
        })
    }

    fn valid_completion() -> serde_json::Value {
        json!({
            "protocol_version": "diagnostic-triage.protocol/v1",
            "kind": "completion",
            "request_id": REQUEST_ID,
            "sequence": 0,
            "status": "COMPLETE",
            "tool_exit_code": 0,
            "tool_duration_ms": 0,
            "counts": {
                "observations": 0,
                "evidence": 0,
                "fix_candidates": 0,
                "executions": 0
            },
            "evidence_bytes": 0
        })
    }

    #[test]
    fn accepts_each_basic_handshake_shape() {
        let manifest: ProtocolEnvelope = serde_json::from_value(valid_manifest()).unwrap();
        let request: ProtocolEnvelope = serde_json::from_value(valid_request()).unwrap();
        let completion: ProtocolEnvelope = serde_json::from_value(valid_completion()).unwrap();

        assert!(matches!(manifest, ProtocolEnvelope::Manifest(_)));
        assert!(matches!(request, ProtocolEnvelope::Request(_)));
        assert!(matches!(completion, ProtocolEnvelope::Completion(_)));
    }

    #[test]
    fn rejects_wrong_version_and_unknown_fields() {
        let mut wrong_version = valid_manifest();
        wrong_version["protocol_version"] = json!("diagnostic-triage.protocol/v2");
        assert!(serde_json::from_value::<ProtocolEnvelope>(wrong_version).is_err());

        let mut unknown = valid_manifest();
        unknown["adapter"]["unexpected"] = json!(true);
        assert!(serde_json::from_value::<ProtocolEnvelope>(unknown).is_err());
    }

    #[test]
    fn rejects_duplicate_keys_during_direct_deserialization() {
        let input = r#"{"protocol_version":"diagnostic-triage.protocol/v1","kind":"manifest","adapter":{"id":"ruff","version":"1","version":"2","kind":"PROVIDER","capabilities":["diagnostic.check/v1"],"languages":[]}}"#;
        assert!(serde_json::from_str::<ProtocolEnvelope>(input).is_err());
    }

    #[test]
    fn rejects_duplicate_arrays_and_excessive_limits() {
        let mut duplicate_targets = valid_request();
        duplicate_targets["targets"] = json!(["src/lib.rs", "src/lib.rs"]);
        assert!(serde_json::from_value::<ProtocolEnvelope>(duplicate_targets).is_err());

        let mut excessive_timeout = valid_request();
        excessive_timeout["limits"]["timeout_ms"] = json!(600_001);
        assert!(serde_json::from_value::<ProtocolEnvelope>(excessive_timeout).is_err());
    }

    #[test]
    fn enforces_completion_exit_code_and_message_rules() {
        let mut missing_exit_code = valid_completion();
        missing_exit_code
            .as_object_mut()
            .unwrap()
            .remove("tool_exit_code");
        assert!(serde_json::from_value::<ProtocolEnvelope>(missing_exit_code).is_err());

        let mut explicit_null_message = valid_completion();
        explicit_null_message["message"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<ProtocolEnvelope>(explicit_null_message).is_err());

        let mut incomplete = valid_completion();
        incomplete["status"] = json!("INCOMPLETE");
        incomplete["tool_exit_code"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<ProtocolEnvelope>(incomplete).is_err());

        let mut valid_incomplete = valid_completion();
        valid_incomplete["status"] = json!("INCOMPLETE");
        valid_incomplete["tool_exit_code"] = serde_json::Value::Null;
        valid_incomplete["message"] = json!("timed out");
        assert!(serde_json::from_value::<ProtocolEnvelope>(valid_incomplete).is_ok());
    }

    #[test]
    fn serializes_exact_header_spellings() {
        assert_eq!(
            serde_json::to_value(ProtocolVersion::V1).unwrap(),
            json!("diagnostic-triage.protocol/v1")
        );
        assert_eq!(
            serde_json::to_value(EnvelopeKind::FixCandidate).unwrap(),
            json!("fix_candidate")
        );
    }
}

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.
