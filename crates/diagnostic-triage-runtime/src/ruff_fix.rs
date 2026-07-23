//! Bounded canonicalization of authoritative Ruff safe-fix evidence.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use diagnostic_triage_contracts::model::{
    Applicability, Evidence, EvidenceSource, FixCandidate, Observation,
};
use diagnostic_triage_contracts::{ObjectId, Sha256Digest};
use serde::Deserialize;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use thiserror::Error;

use crate::{PATCH_MEDIA_TYPE, ScratchChange, ScratchError, ScratchPatch, ScratchWorkspace};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// Authoritative inline media emitted by the Python Provider for one Ruff fix.
pub const RUFF_FIX_MEDIA_TYPE: &str = "application/vnd.ruff.fix+json";

/// Absolute edit-count ceiling for one Ruff fix document.
pub const MAX_RUFF_FIX_EDITS: usize = 4_096;
/// Absolute nesting-depth ceiling for one Ruff fix JSON document.
pub const MAX_RUFF_FIX_JSON_DEPTH: usize = 128;
/// Absolute source or canonical Evidence ceiling for Ruff canonicalization.
pub const MAX_RUFF_FIX_EVIDENCE_BYTES: u64 = 1_048_576;
/// Absolute bound for each retained Ruff JSON string value.
pub const MAX_RUFF_FIX_STRING_BYTES: u64 = 256 * 1_024;
/// Absolute staged target or canonical full-file write ceiling.
pub const MAX_RUFF_FIX_FILE_BYTES: u64 = 64 * 1_024 * 1_024;

/// Ruff-specific limits checked in addition to the staged [`ScratchWorkspace`] limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuffFixLimits {
    /// Maximum number of edits accepted from one Ruff fix.
    pub max_edits: usize,
    /// Maximum object/array nesting depth accepted in the Ruff JSON document.
    pub max_json_depth: usize,
    /// Maximum retained bytes accepted from the Ruff source Evidence.
    pub max_source_evidence_bytes: u64,
    /// Maximum UTF-8 bytes accepted in each retained Ruff JSON string.
    pub max_string_bytes: u64,
    /// Maximum bytes read from the staged target preimage.
    pub max_target_bytes: u64,
    /// Maximum bytes materialized in the canonical full-file write.
    pub max_result_bytes: u64,
    /// Maximum bytes retained by the canonical patch Evidence.
    pub max_patch_evidence_bytes: u64,
}

impl Default for RuffFixLimits {
    fn default() -> Self {
        Self {
            max_edits: MAX_RUFF_FIX_EDITS,
            max_json_depth: MAX_RUFF_FIX_JSON_DEPTH,
            max_source_evidence_bytes: MAX_RUFF_FIX_EVIDENCE_BYTES,
            max_string_bytes: MAX_RUFF_FIX_STRING_BYTES,
            max_target_bytes: MAX_RUFF_FIX_FILE_BYTES,
            max_result_bytes: MAX_RUFF_FIX_FILE_BYTES,
            max_patch_evidence_bytes: MAX_RUFF_FIX_EVIDENCE_BYTES,
        }
    }
}

/// Auditable linkage from authoritative Ruff Evidence to its canonical patch Evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuffFixEvidenceMapping {
    /// Exact `FixCandidate` validated while canonicalizing the Ruff source.
    pub candidate: FixCandidate,
    /// Complete Ruff Evidence snapshot supplied by the Provider.
    pub source_evidence: Evidence,
    /// Runtime-created canonical patch Evidence identifier.
    pub canonical_evidence_id: ObjectId,
    /// Digest of the deterministic canonical patch JSON.
    pub canonical_sha256: Sha256Digest,
}

/// One validated canonical full-file patch and its runtime-owned Evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalRuffFix {
    /// Deterministic one-file scratch patch.
    pub patch: ScratchPatch,
    /// Complete inline `application/vnd.diagnostic-triage.patch+json` Evidence.
    pub patch_evidence: Evidence,
    /// Source-to-canonical Evidence lineage.
    evidence_mapping: RuffFixEvidenceMapping,
}

impl CanonicalRuffFix {
    /// Return the immutable Provider-source to runtime-patch provenance.
    #[must_use]
    pub fn evidence_mapping(&self) -> &RuffFixEvidenceMapping {
        &self.evidence_mapping
    }
}

/// Typed fail-closed rejection from Ruff fix canonicalization.
#[derive(Debug, Error)]
pub enum RuffFixError {
    /// Source Evidence metadata or storage does not satisfy the Ruff boundary.
    #[error("invalid Ruff fix Evidence: {reason}")]
    InvalidEvidence { reason: &'static str },
    /// Candidate identity or applicability is not exactly authorized by the source objects.
    #[error("invalid Ruff fix candidate binding: {reason}")]
    InvalidCandidate { reason: &'static str },
    /// Observation identity or Ruff attribution does not match the source Evidence.
    #[error("Ruff fix does not match its Observation: {reason}")]
    ObservationMismatch { reason: &'static str },
    /// The staged scratch preimage no longer equals its immutable base snapshot.
    #[error("scratch workspace changed after staging")]
    BaseChanged,
    /// The Ruff target is absent from the staged workspace.
    #[error("Ruff fix target is missing from the staged workspace: {path}")]
    MissingTarget { path: String },
    /// The Ruff target is not a regular staged file.
    #[error("Ruff fix target is not a regular staged file: {path}")]
    NonRegularTarget { path: String },
    /// The Ruff target is not valid UTF-8.
    #[error("Ruff fix target is not UTF-8: {path}")]
    NonUtf8Target { path: String },
    /// Ruff coordinate units are ambiguous for this staged preimage.
    #[error("Ruff coordinate semantics are not pinned for {kind}")]
    AmbiguousCoordinates { kind: &'static str },
    /// One source edit has invalid one-based half-open coordinates.
    #[error("invalid Ruff edit {index}: {reason}")]
    InvalidEdit { index: usize, reason: &'static str },
    /// Two edits cannot be ordered into one unambiguous disjoint application.
    #[error("Ruff edits {first} and {second} overlap or share a start position")]
    OverlappingEdits { first: usize, second: usize },
    /// A Ruff-specific hard limit was exceeded.
    #[error("{resource} bound exceeded: {actual} > {max}")]
    BoundExceeded {
        resource: &'static str,
        actual: u64,
        max: u64,
    },
    /// The recursive JSON scanner reached a configured nesting-depth ceiling.
    #[error("Ruff JSON nesting depth exceeded: {depth} > {max}")]
    JsonNestingDepthExceeded { depth: usize, max: usize },
    /// A caller attempted to weaken a compile-time Ruff hard ceiling.
    #[error("invalid Ruff fix limit for {resource}: {configured} > {hard_max}")]
    InvalidLimits {
        resource: &'static str,
        configured: u64,
        hard_max: u64,
    },
    /// The complete inline Ruff document is malformed.
    #[error("malformed Ruff fix JSON: {source}")]
    Json {
        #[source]
        source: serde_json::Error,
    },
    /// A contract object failed its own model validation.
    #[error("invalid Ruff canonicalization contract object: {source}")]
    Contract {
        #[source]
        source: diagnostic_triage_contracts::ContractError,
    },
    /// The scratch runtime rejected a bounded snapshot or canonical patch.
    #[error("scratch runtime rejected Ruff canonicalization: {source}")]
    Scratch {
        #[source]
        source: ScratchError,
    },
}

/// Convert one complete authoritative Ruff safe fix into a canonical full-file scratch patch.
///
/// The conversion is pure with respect to both the original repository and the staged workspace.
/// Every edit is resolved against the same byte-identical staged preimage. The workspace is
/// scanned before reading and again while canonical patch Evidence is captured, so stale bases
/// are rejected without partial application.
///
/// # Errors
///
/// Returns a typed [`RuffFixError`] for malformed or mismatched source objects, unsupported
/// applicability, ambiguous coordinates, stale or invalid staged targets, overlapping edits, and
/// any Ruff, Evidence, patch, or workspace hard-limit violation.
pub fn canonicalize_ruff_fix(
    workspace: &ScratchWorkspace,
    observation: &Observation,
    candidate: &FixCandidate,
    source_evidence: &Evidence,
    limits: RuffFixLimits,
) -> Result<CanonicalRuffFix, RuffFixError> {
    validate_limits(limits)?;
    validate_bindings(observation, candidate, source_evidence, limits)?;
    let document = parse_document(source_evidence, limits)?;
    validate_attribution(observation, &document)?;
    ensure_unchanged_base(workspace)?;

    let preimage = read_target(workspace, &document.filename, limits.max_target_bytes)?;
    let preimage_text =
        std::str::from_utf8(&preimage).map_err(|_| RuffFixError::NonUtf8Target {
            path: document.filename.clone(),
        })?;
    if !preimage_text.is_ascii() {
        return Err(RuffFixError::AmbiguousCoordinates {
            kind: "non-ASCII staged preimages",
        });
    }
    if preimage.contains(&b'\r') {
        return Err(RuffFixError::AmbiguousCoordinates {
            kind: "CR or CRLF staged preimages",
        });
    }

    let resolved = resolve_edits(&preimage, document.fix.edits)?;
    let result_bytes = materialized_len(&preimage, &resolved, limits.max_result_bytes)?;
    let expected_patch_bytes = preflight_patch_evidence(
        workspace,
        &document.filename,
        u64::try_from(result_bytes).unwrap_or(u64::MAX),
        limits.max_patch_evidence_bytes,
    )?;
    let result = materialize(&preimage, &resolved, limits.max_result_bytes)?;
    let patch = ScratchPatch::new(vec![ScratchChange::Write {
        path: document.filename,
        contents: result,
    }])
    .map_err(|source| RuffFixError::Scratch { source })?;
    let captured = workspace
        .capture(&patch, None)
        .map_err(|source| RuffFixError::Scratch { source })?;
    if captured.result.sha256 != workspace.base_evidence().sha256 {
        return Err(RuffFixError::BaseChanged);
    }
    debug_assert_eq!(captured.patch.retained_bytes, expected_patch_bytes);
    debug_assert_eq!(captured.patch.media_type, PATCH_MEDIA_TYPE);

    let evidence_mapping = RuffFixEvidenceMapping {
        candidate: candidate.clone(),
        source_evidence: source_evidence.clone(),
        canonical_evidence_id: captured.patch.evidence_id.clone(),
        canonical_sha256: captured.patch.sha256.clone(),
    };
    Ok(CanonicalRuffFix {
        patch,
        patch_evidence: captured.patch,
        evidence_mapping,
    })
}

fn validate_bindings(
    observation: &Observation,
    candidate: &FixCandidate,
    source: &Evidence,
    limits: RuffFixLimits,
) -> Result<(), RuffFixError> {
    if let Some(content) = source.content.as_deref() {
        enforce_bound(
            "Ruff source Evidence bytes",
            u64::try_from(content.len()).unwrap_or(u64::MAX),
            limits.max_source_evidence_bytes,
        )?;
    }
    enforce_bound(
        "Ruff source Evidence bytes",
        source.retained_bytes,
        limits.max_source_evidence_bytes,
    )?;
    observation
        .validate()
        .map_err(|source| RuffFixError::Contract { source })?;
    candidate
        .validate()
        .map_err(|source| RuffFixError::Contract { source })?;
    source
        .validate()
        .map_err(|source| RuffFixError::Contract { source })?;

    if source.source != EvidenceSource::Patch
        || source.media_type != RUFF_FIX_MEDIA_TYPE
        || source.truncated
        || source.relative_path.is_some()
        || source.content.is_none()
    {
        return Err(RuffFixError::InvalidEvidence {
            reason: "expected complete inline untruncated application/vnd.ruff.fix+json PATCH Evidence",
        });
    }
    if candidate.applicability != Applicability::Safe || !candidate.tool_native {
        return Err(RuffFixError::InvalidCandidate {
            reason: "candidate must be tool-native SAFE",
        });
    }
    if candidate.patch_evidence_id != source.evidence_id {
        return Err(RuffFixError::InvalidCandidate {
            reason: "patch_evidence_id does not identify the Ruff Evidence",
        });
    }
    if candidate.observation_ids.as_slice() != [observation.observation_id.clone()] {
        return Err(RuffFixError::InvalidCandidate {
            reason: "candidate must identify exactly the supplied Observation",
        });
    }
    if observation.tool.name != "ruff" {
        return Err(RuffFixError::ObservationMismatch {
            reason: "tool name is not ruff",
        });
    }
    if observation.language.as_str() != "python" {
        return Err(RuffFixError::ObservationMismatch {
            reason: "language is not python",
        });
    }
    Ok(())
}

fn parse_document(
    source: &Evidence,
    limits: RuffFixLimits,
) -> Result<RuffFixDocument, RuffFixError> {
    let content = source
        .content
        .as_deref()
        .ok_or(RuffFixError::InvalidEvidence {
            reason: "inline content is missing",
        })?;
    // The aggregate source cap is checked before deserialization and therefore also bounds every
    // decoded JSON string. The custom seed stops before allocating a Vec entry beyond max_edits.
    enforce_bound(
        "Ruff source Evidence bytes",
        u64::try_from(content.len()).unwrap_or(u64::MAX),
        limits.max_source_evidence_bytes,
    )?;
    preflight_json_string_bounds(content, limits.max_string_bytes, limits.max_json_depth)?;
    let exceeded_edit_count = Cell::new(None);
    let exceeded_string_bytes = Cell::new(None);
    let mut deserializer = serde_json::Deserializer::from_str(content);
    let parsed = RuffFixDocumentSeed {
        max_edits: limits.max_edits,
        exceeded_edit_count: &exceeded_edit_count,
        max_string_bytes: limits.max_string_bytes,
        exceeded_string_bytes: &exceeded_string_bytes,
    }
    .deserialize(&mut deserializer);
    if let Some(actual) = exceeded_edit_count.get() {
        return Err(RuffFixError::BoundExceeded {
            resource: "Ruff edit count",
            actual,
            max: u64::try_from(limits.max_edits).unwrap_or(u64::MAX),
        });
    }
    if let Some(actual) = exceeded_string_bytes.get() {
        return Err(RuffFixError::BoundExceeded {
            resource: "Ruff string bytes",
            actual,
            max: limits.max_string_bytes,
        });
    }
    let document = parsed.map_err(|source| RuffFixError::Json { source })?;
    deserializer
        .end()
        .map_err(|source| RuffFixError::Json { source })?;
    if document.fix.applicability != "safe" {
        return Err(RuffFixError::InvalidCandidate {
            reason: "Ruff applicability is not safe",
        });
    }
    Ok(document)
}

/// Check JSON string lengths from the wire representation before `serde_json` can materialize them.
///
/// `serde_json` must allocate an escaped JSON string before calling a visitor's `visit_string`.
/// This preflight therefore counts the decoded UTF-8 bytes directly from the raw JSON lexemes.
/// Malformed lexemes are left to `serde_json` for the authoritative syntax error; a bound violation
/// found before malformed input is still rejected fail-closed.
fn preflight_json_string_bounds(
    content: &str,
    max_bytes: u64,
    max_depth: usize,
) -> Result<(), RuffFixError> {
    let bytes = content.as_bytes();
    let mut scanner = JsonBoundScanner {
        bytes,
        max_bytes,
        max_depth,
    };
    let Some(next_offset) = scanner.scan_value(0, JsonContext::Root, 0)? else {
        return Ok(());
    };
    if bytes[next_offset..]
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
    {
        return Ok(());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum JsonContext {
    Root,
    Fix,
    Edits,
    Edit,
    RetainedString,
    Unknown,
}

struct JsonBoundScanner<'a> {
    bytes: &'a [u8],
    max_bytes: u64,
    max_depth: usize,
}

impl JsonBoundScanner<'_> {
    fn scan_value(
        &mut self,
        offset: usize,
        context: JsonContext,
        depth: usize,
    ) -> Result<Option<usize>, RuffFixError> {
        let Some(offset) = self.skip_whitespace(offset) else {
            return Ok(None);
        };
        if matches!(context, JsonContext::Unknown) {
            return self.skip_value(offset, depth);
        }
        match self.bytes.get(offset) {
            Some(b'"') => {
                let Some(scan) = scan_json_string(self.bytes, offset, self.max_bytes) else {
                    return Ok(None);
                };
                if matches!(context, JsonContext::RetainedString) {
                    if let Some(actual) = scan.decoded_bytes {
                        return Err(RuffFixError::BoundExceeded {
                            resource: "Ruff string bytes",
                            actual,
                            max: self.max_bytes,
                        });
                    }
                }
                Ok(Some(scan.next_offset))
            }
            Some(b'{') => {
                let depth = self.enter_container(depth)?;
                self.scan_object(offset + 1, context, depth)
            }
            Some(b'[') => {
                let depth = self.enter_container(depth)?;
                self.scan_array(offset + 1, context, depth)
            }
            Some(_) => Ok(Some(self.skip_primitive(offset))),
            None => Ok(None),
        }
    }

    fn scan_object(
        &mut self,
        mut offset: usize,
        context: JsonContext,
        depth: usize,
    ) -> Result<Option<usize>, RuffFixError> {
        loop {
            let Some(next) = self.skip_whitespace(offset) else {
                return Ok(None);
            };
            offset = next;
            if self.bytes.get(offset) == Some(&b'}') {
                return Ok(Some(offset + 1));
            }
            if self.bytes.get(offset) != Some(&b'"') {
                return Ok(None);
            }
            let Some(key) = scan_json_string(self.bytes, offset, u64::MAX) else {
                return Ok(None);
            };
            let child_context = object_child_context(self.bytes, offset, key.next_offset, context);
            let Some(colon) = self.skip_whitespace(key.next_offset) else {
                return Ok(None);
            };
            if self.bytes.get(colon) != Some(&b':') {
                return Ok(None);
            }
            let Some(value_end) = self.scan_value(colon + 1, child_context, depth)? else {
                return Ok(None);
            };
            offset = value_end;
            let Some(separator) = self.skip_whitespace(offset) else {
                return Ok(None);
            };
            match self.bytes.get(separator) {
                Some(b',') => offset = separator + 1,
                Some(b'}') => return Ok(Some(separator + 1)),
                _ => return Ok(None),
            }
        }
    }

    fn scan_array(
        &mut self,
        mut offset: usize,
        context: JsonContext,
        depth: usize,
    ) -> Result<Option<usize>, RuffFixError> {
        loop {
            let Some(next) = self.skip_whitespace(offset) else {
                return Ok(None);
            };
            offset = next;
            if self.bytes.get(offset) == Some(&b']') {
                return Ok(Some(offset + 1));
            }
            let child_context = if matches!(context, JsonContext::Edits) {
                JsonContext::Edit
            } else {
                JsonContext::Unknown
            };
            let Some(value_end) = self.scan_value(offset, child_context, depth)? else {
                return Ok(None);
            };
            let Some(separator) = self.skip_whitespace(value_end) else {
                return Ok(None);
            };
            match self.bytes.get(separator) {
                Some(b',') => offset = separator + 1,
                Some(b']') => return Ok(Some(separator + 1)),
                _ => return Ok(None),
            }
        }
    }

    fn skip_value(&mut self, offset: usize, depth: usize) -> Result<Option<usize>, RuffFixError> {
        match self.bytes.get(offset) {
            Some(b'"') => {
                Ok(scan_json_string(self.bytes, offset, u64::MAX).map(|scan| scan.next_offset))
            }
            Some(b'{') => {
                let depth = self.enter_container(depth)?;
                self.skip_object(offset + 1, depth)
            }
            Some(b'[') => {
                let depth = self.enter_container(depth)?;
                self.skip_array(offset + 1, depth)
            }
            Some(_) => Ok(Some(self.skip_primitive(offset))),
            None => Ok(None),
        }
    }

    fn skip_object(
        &mut self,
        mut offset: usize,
        depth: usize,
    ) -> Result<Option<usize>, RuffFixError> {
        loop {
            let Some(next) = self.skip_whitespace(offset) else {
                return Ok(None);
            };
            offset = next;
            if self.bytes.get(offset) == Some(&b'}') {
                return Ok(Some(offset + 1));
            }
            let Some(key) = scan_json_string(self.bytes, offset, u64::MAX) else {
                return Ok(None);
            };
            let Some(colon) = self.skip_whitespace(key.next_offset) else {
                return Ok(None);
            };
            if self.bytes.get(colon) != Some(&b':') {
                return Ok(None);
            }
            let Some(value) = self.skip_whitespace(colon + 1) else {
                return Ok(None);
            };
            let Some(value_end) = self.skip_value(value, depth)? else {
                return Ok(None);
            };
            let Some(separator) = self.skip_whitespace(value_end) else {
                return Ok(None);
            };
            match self.bytes.get(separator) {
                Some(b',') => offset = separator + 1,
                Some(b'}') => return Ok(Some(separator + 1)),
                _ => return Ok(None),
            }
        }
    }

    fn skip_array(
        &mut self,
        mut offset: usize,
        depth: usize,
    ) -> Result<Option<usize>, RuffFixError> {
        loop {
            let Some(next) = self.skip_whitespace(offset) else {
                return Ok(None);
            };
            offset = next;
            if self.bytes.get(offset) == Some(&b']') {
                return Ok(Some(offset + 1));
            }
            let Some(value_end) = self.skip_value(offset, depth)? else {
                return Ok(None);
            };
            let Some(separator) = self.skip_whitespace(value_end) else {
                return Ok(None);
            };
            match self.bytes.get(separator) {
                Some(b',') => offset = separator + 1,
                Some(b']') => return Ok(Some(separator + 1)),
                _ => return Ok(None),
            }
        }
    }

    fn enter_container(&self, depth: usize) -> Result<usize, RuffFixError> {
        let next_depth = depth.saturating_add(1);
        if next_depth > self.max_depth {
            return Err(RuffFixError::JsonNestingDepthExceeded {
                depth: next_depth,
                max: self.max_depth,
            });
        }
        Ok(next_depth)
    }

    fn skip_primitive(&self, mut offset: usize) -> usize {
        while let Some(byte) = self.bytes.get(offset) {
            if byte.is_ascii_whitespace() || matches!(byte, b',' | b']' | b'}') {
                return offset;
            }
            offset += 1;
        }
        offset
    }

    fn skip_whitespace(&self, mut offset: usize) -> Option<usize> {
        while self.bytes.get(offset).is_some_and(u8::is_ascii_whitespace) {
            offset += 1;
        }
        (offset <= self.bytes.len()).then_some(offset)
    }
}

fn object_child_context(
    bytes: &[u8],
    key_start: usize,
    key_end: usize,
    context: JsonContext,
) -> JsonContext {
    if matches!(context, JsonContext::Unknown) {
        return JsonContext::Unknown;
    }
    match context {
        JsonContext::Root if json_key_matches(bytes, key_start, key_end, "version") => {
            JsonContext::RetainedString
        }
        JsonContext::Root if json_key_matches(bytes, key_start, key_end, "filename") => {
            JsonContext::RetainedString
        }
        JsonContext::Root if json_key_matches(bytes, key_start, key_end, "rule_id") => {
            JsonContext::RetainedString
        }
        JsonContext::Root if json_key_matches(bytes, key_start, key_end, "fix") => JsonContext::Fix,
        JsonContext::Fix => {
            if json_key_matches(bytes, key_start, key_end, "applicability") {
                JsonContext::RetainedString
            } else if json_key_matches(bytes, key_start, key_end, "edits") {
                JsonContext::Edits
            } else {
                JsonContext::Unknown
            }
        }
        JsonContext::Edit => {
            if json_key_matches(bytes, key_start, key_end, "content") {
                JsonContext::RetainedString
            } else {
                JsonContext::Unknown
            }
        }
        _ => JsonContext::Unknown,
    }
}

fn json_key_matches(bytes: &[u8], start: usize, end: usize, expected: &str) -> bool {
    let Some(inner) = bytes.get(start + 1..end.saturating_sub(1)) else {
        return false;
    };
    if inner == expected.as_bytes() {
        return true;
    }
    let mut decoded = Vec::with_capacity(expected.len());
    let mut offset = 0;
    while offset < inner.len() {
        let byte = inner[offset];
        if byte == b'\\' {
            let Some(escape) = inner.get(offset + 1) else {
                return false;
            };
            let (code_point, consumed) = match escape {
                b'"' => (u32::from(b'"'), 2),
                b'\\' => (u32::from(b'\\'), 2),
                b'/' => (u32::from(b'/'), 2),
                b'b' => (8, 2),
                b'f' => (12, 2),
                b'n' => (10, 2),
                b'r' => (13, 2),
                b't' => (9, 2),
                b'u' => {
                    let Some(code_unit) = parse_json_hex(inner, offset + 2) else {
                        return false;
                    };
                    if (0xD800..=0xDBFF).contains(&code_unit) {
                        return false;
                    }
                    (u32::from(code_unit), 6)
                }
                _ => return false,
            };
            let Some(character) = char::from_u32(code_point) else {
                return false;
            };
            let mut encoded = [0; 4];
            let encoded = character.encode_utf8(&mut encoded).as_bytes();
            decoded.extend_from_slice(encoded);
            offset += consumed;
        } else {
            if byte >= 0x80 {
                return false;
            }
            decoded.push(byte);
            offset += 1;
        }
        if decoded.len() > expected.len() {
            return false;
        }
    }
    decoded == expected.as_bytes()
}

struct JsonStringScan {
    next_offset: usize,
    decoded_bytes: Option<u64>,
}

/// Scan one JSON string without allocating its decoded representation.
fn scan_json_string(bytes: &[u8], start: usize, max_bytes: u64) -> Option<JsonStringScan> {
    let mut offset = start.checked_add(1)?;
    let mut decoded = 0_u64;
    while offset < bytes.len() {
        match bytes[offset] {
            b'"' => {
                return Some(JsonStringScan {
                    next_offset: offset + 1,
                    decoded_bytes: None,
                });
            }
            b'\\' => {
                let escape = *bytes.get(offset.checked_add(1)?)?;
                let (decoded_width, consumed) = match escape {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => (1, 2),
                    b'u' => {
                        let code_unit = parse_json_hex(bytes, offset.checked_add(2)?)?;
                        if (0xD800..=0xDBFF).contains(&code_unit)
                            && bytes.get(offset.checked_add(6)?) == Some(&b'\\')
                            && bytes.get(offset.checked_add(7)?) == Some(&b'u')
                        {
                            let low = parse_json_hex(bytes, offset.checked_add(8)?)?;
                            if (0xDC00..=0xDFFF).contains(&low) {
                                (4, 12)
                            } else {
                                (3, 6)
                            }
                        } else {
                            (json_code_unit_utf8_width(code_unit), 6)
                        }
                    }
                    _ => return None,
                };
                decoded = decoded.saturating_add(decoded_width);
                if decoded > max_bytes {
                    return Some(JsonStringScan {
                        next_offset: offset,
                        decoded_bytes: Some(decoded),
                    });
                }
                offset = offset.checked_add(consumed)?;
            }
            byte if byte < 0x20 => return None,
            _ => {
                // Raw UTF-8 contributes exactly its wire byte length to the decoded String.
                decoded = decoded.saturating_add(1);
                if decoded > max_bytes {
                    return Some(JsonStringScan {
                        next_offset: offset,
                        decoded_bytes: Some(decoded),
                    });
                }
                offset += 1;
            }
        }
    }
    None
}

fn parse_json_hex(bytes: &[u8], start: usize) -> Option<u16> {
    let digits = bytes.get(start..start.checked_add(4)?)?;
    let mut value = 0_u16;
    for &digit in digits {
        value = value.checked_mul(16)?.checked_add(match digit {
            b'0'..=b'9' => u16::from(digit - b'0'),
            b'a'..=b'f' => u16::from(digit - b'a' + 10),
            b'A'..=b'F' => u16::from(digit - b'A' + 10),
            _ => return None,
        })?;
    }
    Some(value)
}

fn json_code_unit_utf8_width(code_unit: u16) -> u64 {
    match code_unit {
        0..=0x7F => 1,
        0x80..=0x7FF => 2,
        _ => 3,
    }
}

fn validate_attribution(
    observation: &Observation,
    document: &RuffFixDocument,
) -> Result<(), RuffFixError> {
    if document.version != observation.tool.version {
        return Err(RuffFixError::ObservationMismatch {
            reason: "tool version differs",
        });
    }
    if document.rule_id.as_deref() != observation.tool.rule_id.as_deref() {
        return Err(RuffFixError::ObservationMismatch {
            reason: "rule ID differs",
        });
    }
    let path = observation
        .location
        .as_ref()
        .ok_or(RuffFixError::ObservationMismatch {
            reason: "Observation location is missing",
        })?
        .path
        .as_str();
    if document.filename != path {
        return Err(RuffFixError::ObservationMismatch {
            reason: "repository-relative filename differs",
        });
    }
    Ok(())
}

fn ensure_unchanged_base(workspace: &ScratchWorkspace) -> Result<(), RuffFixError> {
    let empty = ScratchPatch::new(Vec::new()).map_err(|source| RuffFixError::Scratch { source })?;
    let current = workspace
        .capture(&empty, None)
        .map_err(|source| RuffFixError::Scratch { source })?;
    if current.result.sha256 == workspace.base_evidence().sha256 {
        Ok(())
    } else {
        Err(RuffFixError::BaseChanged)
    }
}

fn read_target(
    workspace: &ScratchWorkspace,
    relative: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, RuffFixError> {
    match workspace.read_immutable_base_file(relative, max_bytes) {
        Ok(contents) => Ok(contents),
        Err(ScratchError::BoundExceeded { actual, max, .. }) if max == max_bytes => {
            Err(RuffFixError::BoundExceeded {
                resource: "staged Ruff target bytes",
                actual,
                max,
            })
        }
        Err(ScratchError::MissingPath { .. }) => Err(RuffFixError::MissingTarget {
            path: relative.to_owned(),
        }),
        Err(
            ScratchError::SymlinkPath { .. }
            | ScratchError::UnsupportedEntry { .. }
            | ScratchError::NotDirectory { .. },
        ) => Err(RuffFixError::NonRegularTarget {
            path: relative.to_owned(),
        }),
        Err(ScratchError::BaseChanged | ScratchError::SourceChanged { .. }) => {
            Err(RuffFixError::BaseChanged)
        }
        Err(source) => Err(RuffFixError::Scratch { source }),
    }
}

#[derive(Debug)]
struct RuffFixDocument {
    version: String,
    filename: String,
    rule_id: Option<String>,
    fix: RuffFix,
}

#[derive(Debug)]
struct RuffFix {
    applicability: String,
    edits: Vec<RuffEdit>,
}

#[derive(Debug, Deserialize)]
struct RuffEdit {
    content: String,
    location: RuffPosition,
    end_location: RuffPosition,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct RuffPosition {
    row: u32,
    column: u32,
}

struct RuffFixDocumentSeed<'a> {
    max_edits: usize,
    exceeded_edit_count: &'a Cell<Option<u64>>,
    max_string_bytes: u64,
    exceeded_string_bytes: &'a Cell<Option<u64>>,
}

impl<'de> DeserializeSeed<'de> for RuffFixDocumentSeed<'_> {
    type Value = RuffFixDocument;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_map(RuffFixDocumentVisitor {
            max_edits: self.max_edits,
            exceeded_edit_count: self.exceeded_edit_count,
            max_string_bytes: self.max_string_bytes,
            exceeded_string_bytes: self.exceeded_string_bytes,
        })
    }
}

struct RuffFixDocumentVisitor<'a> {
    max_edits: usize,
    exceeded_edit_count: &'a Cell<Option<u64>>,
    max_string_bytes: u64,
    exceeded_string_bytes: &'a Cell<Option<u64>>,
}

impl<'de> Visitor<'de> for RuffFixDocumentVisitor<'_> {
    type Value = RuffFixDocument;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Ruff fix document")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut version = None;
        let mut filename = None;
        let mut rule_id = None;
        let mut fix = None;
        while let Some(field) = map.next_key::<&str>()? {
            match field {
                "version" => {
                    if version.is_some() {
                        return Err(de::Error::duplicate_field("version"));
                    }
                    version = Some(map.next_value_seed(BoundedStringSeed {
                        max_bytes: self.max_string_bytes,
                        exceeded_bytes: self.exceeded_string_bytes,
                    })?);
                }
                "filename" => {
                    if filename.is_some() {
                        return Err(de::Error::duplicate_field("filename"));
                    }
                    filename = Some(map.next_value_seed(BoundedStringSeed {
                        max_bytes: self.max_string_bytes,
                        exceeded_bytes: self.exceeded_string_bytes,
                    })?);
                }
                "rule_id" => {
                    if rule_id.is_some() {
                        return Err(de::Error::duplicate_field("rule_id"));
                    }
                    rule_id = Some(map.next_value_seed(BoundedOptionalStringSeed {
                        max_bytes: self.max_string_bytes,
                        exceeded_bytes: self.exceeded_string_bytes,
                    })?);
                }
                "fix" => {
                    if fix.is_some() {
                        return Err(de::Error::duplicate_field("fix"));
                    }
                    fix = Some(map.next_value_seed(RuffFixSeed {
                        max_edits: self.max_edits,
                        exceeded_edit_count: self.exceeded_edit_count,
                        max_string_bytes: self.max_string_bytes,
                        exceeded_string_bytes: self.exceeded_string_bytes,
                    })?);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(RuffFixDocument {
            version: version.ok_or_else(|| de::Error::missing_field("version"))?,
            filename: filename.ok_or_else(|| de::Error::missing_field("filename"))?,
            rule_id: rule_id.ok_or_else(|| de::Error::missing_field("rule_id"))?,
            fix: fix.ok_or_else(|| de::Error::missing_field("fix"))?,
        })
    }
}

struct RuffFixSeed<'a> {
    max_edits: usize,
    exceeded_edit_count: &'a Cell<Option<u64>>,
    max_string_bytes: u64,
    exceeded_string_bytes: &'a Cell<Option<u64>>,
}

impl<'de> DeserializeSeed<'de> for RuffFixSeed<'_> {
    type Value = RuffFix;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_map(RuffFixVisitor {
            max_edits: self.max_edits,
            exceeded_edit_count: self.exceeded_edit_count,
            max_string_bytes: self.max_string_bytes,
            exceeded_string_bytes: self.exceeded_string_bytes,
        })
    }
}

struct RuffFixVisitor<'a> {
    max_edits: usize,
    exceeded_edit_count: &'a Cell<Option<u64>>,
    max_string_bytes: u64,
    exceeded_string_bytes: &'a Cell<Option<u64>>,
}

impl<'de> Visitor<'de> for RuffFixVisitor<'_> {
    type Value = RuffFix;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Ruff fix object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut applicability = None;
        let mut edits = None;
        while let Some(field) = map.next_key::<&str>()? {
            match field {
                "applicability" => {
                    if applicability.is_some() {
                        return Err(de::Error::duplicate_field("applicability"));
                    }
                    applicability = Some(map.next_value_seed(BoundedStringSeed {
                        max_bytes: self.max_string_bytes,
                        exceeded_bytes: self.exceeded_string_bytes,
                    })?);
                }
                "edits" => {
                    if edits.is_some() {
                        return Err(de::Error::duplicate_field("edits"));
                    }
                    edits = Some(map.next_value_seed(RuffEditsSeed {
                        max_edits: self.max_edits,
                        exceeded_edit_count: self.exceeded_edit_count,
                        max_string_bytes: self.max_string_bytes,
                        exceeded_string_bytes: self.exceeded_string_bytes,
                    })?);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(RuffFix {
            applicability: applicability
                .ok_or_else(|| de::Error::missing_field("applicability"))?,
            edits: edits.ok_or_else(|| de::Error::missing_field("edits"))?,
        })
    }
}

struct RuffEditsSeed<'a> {
    max_edits: usize,
    exceeded_edit_count: &'a Cell<Option<u64>>,
    max_string_bytes: u64,
    exceeded_string_bytes: &'a Cell<Option<u64>>,
}

impl<'de> DeserializeSeed<'de> for RuffEditsSeed<'_> {
    type Value = Vec<RuffEdit>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_seq(RuffEditsVisitor {
            max_edits: self.max_edits,
            exceeded_edit_count: self.exceeded_edit_count,
            max_string_bytes: self.max_string_bytes,
            exceeded_string_bytes: self.exceeded_string_bytes,
        })
    }
}

struct RuffEditsVisitor<'a> {
    max_edits: usize,
    exceeded_edit_count: &'a Cell<Option<u64>>,
    max_string_bytes: u64,
    exceeded_string_bytes: &'a Cell<Option<u64>>,
}

impl<'de> Visitor<'de> for RuffEditsVisitor<'_> {
    type Value = Vec<RuffEdit>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded Ruff edit array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let capacity = sequence.size_hint().unwrap_or(0).min(self.max_edits);
        let mut edits = Vec::with_capacity(capacity);
        while edits.len() < self.max_edits {
            let Some(edit) = sequence.next_element_seed(RuffEditSeed {
                max_string_bytes: self.max_string_bytes,
                exceeded_string_bytes: self.exceeded_string_bytes,
            })?
            else {
                return Ok(edits);
            };
            edits.push(edit);
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            let actual = u64::try_from(self.max_edits)
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            self.exceeded_edit_count.set(Some(actual));
            return Err(de::Error::custom(
                "Ruff edit count exceeds configured bound",
            ));
        }
        Ok(edits)
    }
}

struct RuffEditSeed<'a> {
    max_string_bytes: u64,
    exceeded_string_bytes: &'a Cell<Option<u64>>,
}

impl<'de> DeserializeSeed<'de> for RuffEditSeed<'_> {
    type Value = RuffEdit;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_map(RuffEditVisitor {
            max_string_bytes: self.max_string_bytes,
            exceeded_string_bytes: self.exceeded_string_bytes,
        })
    }
}

struct RuffEditVisitor<'a> {
    max_string_bytes: u64,
    exceeded_string_bytes: &'a Cell<Option<u64>>,
}

impl<'de> Visitor<'de> for RuffEditVisitor<'_> {
    type Value = RuffEdit;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Ruff edit object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut content = None;
        let mut location = None;
        let mut end_location = None;
        while let Some(field) = map.next_key::<&str>()? {
            match field {
                "content" => {
                    if content.is_some() {
                        return Err(de::Error::duplicate_field("content"));
                    }
                    content = Some(map.next_value_seed(BoundedStringSeed {
                        max_bytes: self.max_string_bytes,
                        exceeded_bytes: self.exceeded_string_bytes,
                    })?);
                }
                "location" => {
                    if location.is_some() {
                        return Err(de::Error::duplicate_field("location"));
                    }
                    location = Some(map.next_value()?);
                }
                "end_location" => {
                    if end_location.is_some() {
                        return Err(de::Error::duplicate_field("end_location"));
                    }
                    end_location = Some(map.next_value()?);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(RuffEdit {
            content: content.ok_or_else(|| de::Error::missing_field("content"))?,
            location: location.ok_or_else(|| de::Error::missing_field("location"))?,
            end_location: end_location.ok_or_else(|| de::Error::missing_field("end_location"))?,
        })
    }
}

struct BoundedStringSeed<'a> {
    max_bytes: u64,
    exceeded_bytes: &'a Cell<Option<u64>>,
}

impl<'de> DeserializeSeed<'de> for BoundedStringSeed<'_> {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_string(BoundedStringVisitor {
            max_bytes: self.max_bytes,
            exceeded_bytes: self.exceeded_bytes,
        })
    }
}

struct BoundedOptionalStringSeed<'a> {
    max_bytes: u64,
    exceeded_bytes: &'a Cell<Option<u64>>,
}

impl<'de> DeserializeSeed<'de> for BoundedOptionalStringSeed<'_> {
    type Value = Option<String>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_option(BoundedOptionalStringVisitor {
            max_bytes: self.max_bytes,
            exceeded_bytes: self.exceeded_bytes,
        })
    }
}

struct BoundedOptionalStringVisitor<'a> {
    max_bytes: u64,
    exceeded_bytes: &'a Cell<Option<u64>>,
}

impl<'de> Visitor<'de> for BoundedOptionalStringVisitor<'_> {
    type Value = Option<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded optional string")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        BoundedStringSeed {
            max_bytes: self.max_bytes,
            exceeded_bytes: self.exceeded_bytes,
        }
        .deserialize(deserializer)
        .map(Some)
    }
}

struct BoundedStringVisitor<'a> {
    max_bytes: u64,
    exceeded_bytes: &'a Cell<Option<u64>>,
}

impl<'de> Visitor<'de> for BoundedStringVisitor<'_> {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded string")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(value)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let actual = u64::try_from(value.len()).unwrap_or(u64::MAX);
        if actual > self.max_bytes {
            self.exceeded_bytes.set(Some(actual));
            return Err(E::custom("Ruff JSON string exceeds configured bound"));
        }
        Ok(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let actual = u64::try_from(value.len()).unwrap_or(u64::MAX);
        if actual > self.max_bytes {
            self.exceeded_bytes.set(Some(actual));
            return Err(E::custom("Ruff JSON string exceeds configured bound"));
        }
        Ok(value)
    }
}

struct ResolvedEdit {
    source_index: usize,
    start: usize,
    end: usize,
    content: String,
}

fn resolve_edits(preimage: &[u8], edits: Vec<RuffEdit>) -> Result<Vec<ResolvedEdit>, RuffFixError> {
    if edits.is_empty() {
        return Err(RuffFixError::InvalidEdit {
            index: 0,
            reason: "at least one edit is required",
        });
    }
    let preimage_text = std::str::from_utf8(preimage).map_err(|_| RuffFixError::InvalidEdit {
        index: 0,
        reason: "staged preimage is not UTF-8",
    })?;
    let mut required_rows = BTreeSet::new();
    for (source_index, edit) in edits.iter().enumerate() {
        for position in [edit.location, edit.end_location] {
            if position.row == 0 || position.column == 0 {
                return Err(RuffFixError::InvalidEdit {
                    index: source_index,
                    reason: "row and column must be one-based",
                });
            }
            required_rows.insert(position.row);
        }
    }
    let line_ranges = selected_line_ranges(preimage, &required_rows);
    let mut resolved = Vec::with_capacity(edits.len());
    for (source_index, edit) in edits.into_iter().enumerate() {
        let start = resolve_position(&line_ranges, edit.location, source_index)?;
        let end = resolve_position(&line_ranges, edit.end_location, source_index)?;
        if end < start {
            return Err(RuffFixError::InvalidEdit {
                index: source_index,
                reason: "half-open end precedes start",
            });
        }
        if !preimage_text.is_char_boundary(start) || !preimage_text.is_char_boundary(end) {
            return Err(RuffFixError::InvalidEdit {
                index: source_index,
                reason: "coordinate is not a UTF-8 boundary",
            });
        }
        resolved.push(ResolvedEdit {
            source_index,
            start,
            end,
            content: edit.content,
        });
    }
    resolved.sort_by_key(|edit| (edit.start, edit.end, edit.source_index));
    for pair in resolved.windows(2) {
        let previous = &pair[0];
        let next = &pair[1];
        if previous.end > next.start || previous.start == next.start {
            return Err(RuffFixError::OverlappingEdits {
                first: previous.source_index,
                second: next.source_index,
            });
        }
    }
    Ok(resolved)
}

fn preflight_patch_evidence(
    workspace: &ScratchWorkspace,
    path: &str,
    contents_bytes: u64,
    max_bytes: u64,
) -> Result<u64, RuffFixError> {
    match workspace.preflight_write_patch_evidence(path, contents_bytes, max_bytes) {
        Ok(encoded_bytes) => Ok(encoded_bytes),
        Err(ScratchError::BoundExceeded {
            resource: "Evidence bytes",
            actual,
            max,
        }) if max == max_bytes => Err(RuffFixError::BoundExceeded {
            resource: "canonical patch Evidence bytes",
            actual,
            max,
        }),
        Err(source) => Err(RuffFixError::Scratch { source }),
    }
}

fn selected_line_ranges(
    preimage: &[u8],
    required_rows: &BTreeSet<u32>,
) -> BTreeMap<u32, (usize, usize)> {
    let mut ranges = BTreeMap::new();
    let mut row = 1_u32;
    let mut line_start = 0_usize;
    for (index, byte) in preimage.iter().enumerate() {
        if *byte == b'\n' {
            if required_rows.contains(&row) {
                ranges.insert(row, (line_start, index));
            }
            row = row.saturating_add(1);
            line_start = index + 1;
        }
    }
    if required_rows.contains(&row) {
        ranges.insert(row, (line_start, preimage.len()));
    }
    ranges
}

fn resolve_position(
    line_ranges: &BTreeMap<u32, (usize, usize)>,
    position: RuffPosition,
    edit_index: usize,
) -> Result<usize, RuffFixError> {
    let &(line_start, line_end) =
        line_ranges
            .get(&position.row)
            .ok_or(RuffFixError::InvalidEdit {
                index: edit_index,
                reason: "row is outside the staged preimage",
            })?;
    let column = usize::try_from(position.column - 1).unwrap_or(usize::MAX);
    if column > line_end.saturating_sub(line_start) {
        return Err(RuffFixError::InvalidEdit {
            index: edit_index,
            reason: "column is outside the staged preimage line",
        });
    }
    Ok(line_start + column)
}

fn validate_limits(limits: RuffFixLimits) -> Result<(), RuffFixError> {
    for (resource, configured, hard_max) in [
        (
            "Ruff edit count",
            u64::try_from(limits.max_edits).unwrap_or(u64::MAX),
            u64::try_from(MAX_RUFF_FIX_EDITS).unwrap_or(u64::MAX),
        ),
        (
            "Ruff JSON nesting depth",
            u64::try_from(limits.max_json_depth).unwrap_or(u64::MAX),
            u64::try_from(MAX_RUFF_FIX_JSON_DEPTH).unwrap_or(u64::MAX),
        ),
        (
            "Ruff source Evidence bytes",
            limits.max_source_evidence_bytes,
            MAX_RUFF_FIX_EVIDENCE_BYTES,
        ),
        (
            "Ruff string bytes",
            limits.max_string_bytes,
            MAX_RUFF_FIX_STRING_BYTES,
        ),
        (
            "staged Ruff target bytes",
            limits.max_target_bytes,
            MAX_RUFF_FIX_FILE_BYTES,
        ),
        (
            "canonical full-file write bytes",
            limits.max_result_bytes,
            MAX_RUFF_FIX_FILE_BYTES,
        ),
        (
            "canonical patch Evidence bytes",
            limits.max_patch_evidence_bytes,
            MAX_RUFF_FIX_EVIDENCE_BYTES,
        ),
    ] {
        if configured > hard_max {
            return Err(RuffFixError::InvalidLimits {
                resource,
                configured,
                hard_max,
            });
        }
    }
    Ok(())
}

fn materialize(
    preimage: &[u8],
    edits: &[ResolvedEdit],
    max_result_bytes: u64,
) -> Result<Vec<u8>, RuffFixError> {
    let final_len = materialized_len(preimage, edits, max_result_bytes)?;

    let mut result = Vec::with_capacity(final_len);
    let mut cursor = 0;
    for edit in edits {
        result.extend_from_slice(&preimage[cursor..edit.start]);
        result.extend_from_slice(edit.content.as_bytes());
        cursor = edit.end;
    }
    result.extend_from_slice(&preimage[cursor..]);
    debug_assert_eq!(result.len(), final_len);
    Ok(result)
}

fn materialized_len(
    preimage: &[u8],
    edits: &[ResolvedEdit],
    max_result_bytes: u64,
) -> Result<usize, RuffFixError> {
    let final_len = edits.iter().try_fold(preimage.len(), |length, edit| {
        length
            .checked_sub(edit.end - edit.start)
            .and_then(|value| value.checked_add(edit.content.len()))
            .ok_or(RuffFixError::BoundExceeded {
                resource: "canonical full-file write bytes",
                actual: u64::MAX,
                max: max_result_bytes,
            })
    })?;
    enforce_bound(
        "canonical full-file write bytes",
        u64::try_from(final_len).unwrap_or(u64::MAX),
        max_result_bytes,
    )?;
    Ok(final_len)
}

fn enforce_bound(resource: &'static str, actual: u64, max: u64) -> Result<(), RuffFixError> {
    if actual > max {
        Err(RuffFixError::BoundExceeded {
            resource,
            actual,
            max,
        })
    } else {
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use tempfile::tempdir;

    use super::*;
    use crate::scratch::{inject_immutable_base_read_failure, inject_open_entry_race};

    #[test]
    fn preflight_rejects_escaped_over_limit_before_string_materialization() {
        let content = r#"{"fix":{"edits":[{"content":"\u0061\u0061\u0061\u0061\u0061"}]}}"#;

        let result = preflight_json_string_bounds(content, 4, MAX_RUFF_FIX_JSON_DEPTH);
        assert!(matches!(
            result,
            Err(RuffFixError::BoundExceeded {
                resource: "Ruff string bytes",
                actual: 5,
                max: 4,
            })
        ));
    }

    #[test]
    fn preflight_counts_unicode_surrogate_pair_as_four_utf8_bytes() {
        let content = r#"{"fix":{"edits":[{"content":"\uD834\uDD1E"}]}}"#;

        assert!(matches!(
            preflight_json_string_bounds(content, 3, MAX_RUFF_FIX_JSON_DEPTH),
            Err(RuffFixError::BoundExceeded {
                resource: "Ruff string bytes",
                actual: 4,
                max: 3,
            })
        ));
    }

    #[test]
    fn preflight_rejects_json_nesting_depth_with_typed_error() {
        let mut content = String::from("null");
        for _ in 0..3 {
            content = format!(r#"{{"nested":{content}}}"#);
        }

        assert!(matches!(
            preflight_json_string_bounds(&content, 64, 2),
            Err(RuffFixError::JsonNestingDepthExceeded { depth: 3, max: 2 })
        ));
    }

    #[test]
    fn immutable_base_read_rejects_symlink_swap_between_stat_and_open() {
        let repository = tempdir().expect("repository");
        let outside = tempdir().expect("outside");
        let target = "example.py";
        fs::write(repository.path().join(target), b"base\n").expect("base target");
        fs::write(outside.path().join(target), b"outside\n").expect("outside target");
        let workspace = ScratchWorkspace::stage(
            repository.path(),
            &[target],
            crate::ScratchLimits::default(),
        )
        .expect("stage workspace");
        let workspace_target = workspace.path().join(target);
        let retained_target = workspace.path().join("retained.py");
        let outside_target = outside.path().join(target);
        let raced_target = workspace_target.clone();
        inject_open_entry_race(move || {
            fs::rename(&raced_target, retained_target).expect("retain staged inode");
            symlink(outside_target, &raced_target).expect("install raced symlink");
        });

        let error = read_target(&workspace, target, 64).expect_err("symlink race must reject");

        assert!(matches!(
            error,
            RuffFixError::Scratch {
                source: ScratchError::Io {
                    operation: "open descriptor-relative entry without following symlinks",
                    ..
                }
            }
        ));
        assert_eq!(
            fs::read(repository.path().join(target)).expect("original repository target"),
            b"base\n"
        );
        assert_eq!(
            fs::read(outside.path().join(target)).expect("outside target"),
            b"outside\n"
        );
    }

    #[test]
    fn immutable_base_read_fault_is_fail_closed_without_mutation() {
        let repository = tempdir().expect("repository");
        let target = "example.py";
        fs::write(repository.path().join(target), b"base\n").expect("base target");
        let workspace = ScratchWorkspace::stage(
            repository.path(),
            &[target],
            crate::ScratchLimits::default(),
        )
        .expect("stage workspace");
        let before = fs::read(workspace.path().join(target)).expect("read before");
        inject_immutable_base_read_failure();

        let error = read_target(&workspace, target, 64).expect_err("read fault must reject");

        assert!(matches!(
            error,
            RuffFixError::Scratch {
                source: ScratchError::Io {
                    operation: "read immutable scratch base file",
                    ..
                }
            }
        ));
        assert_eq!(
            fs::read(workspace.path().join(target)).expect("read after"),
            before
        );
        assert_eq!(
            fs::read(repository.path().join(target)).expect("original target"),
            b"base\n"
        );
    }

    #[test]
    fn immutable_base_read_rejects_content_changed_after_staging() {
        let repository = tempdir().expect("repository");
        let target = "example.py";
        fs::write(repository.path().join(target), b"base\n").expect("base target");
        let workspace = ScratchWorkspace::stage(
            repository.path(),
            &[target],
            crate::ScratchLimits::default(),
        )
        .expect("stage workspace");
        fs::write(workspace.path().join(target), b"changed\n").expect("change staged target");

        let error = workspace
            .read_immutable_base_file(target, 64)
            .expect_err("content proof must reject the changed target");

        assert!(matches!(error, ScratchError::BaseChanged));
    }
}
