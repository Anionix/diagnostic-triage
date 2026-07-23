//! Manifest-first Provider Protocol session orchestration.

use std::{cell::RefCell, time::Duration};

use diagnostic_triage_contracts::{
    AdapterId, Capability, ContractError, ObjectId, ValidatedSession,
    model::{AdapterKind, ExecutionStatus},
    protocol::{CompletionCounts, ManifestEnvelope, Operation, ProtocolEnvelope, RequestEnvelope},
    validate_session_jsonl,
};
use thiserror::Error;

use crate::process::{
    ProcessError, ProcessLimits, ProcessOutcome, ProcessSpec, ProcessState, StreamLineDecision,
    run_bounded_manifest_first,
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// Provider handshake deadline required by protocol v1.
pub const PROVIDER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Final runtime disposition of one Provider Protocol session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderSessionState {
    Complete(Box<ValidatedSession>),
    Incomplete {
        reason: String,
        validated_session: Option<Box<ValidatedSession>>,
    },
    Unsupported {
        missing_required: Vec<Capability>,
        reason: String,
        validated_session: Option<Box<ValidatedSession>>,
    },
}

/// Bounded process evidence plus the validated protocol disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSessionOutcome {
    pub state: ProviderSessionState,
    pub manifest: Option<ManifestEnvelope>,
    pub process: ProcessOutcome,
    /// Exact count written after successful manifest validation.
    pub request_bytes_written: usize,
}

/// Failures that prevent a trustworthy bounded session outcome.
#[derive(Debug, Error)]
pub enum ProviderSessionError {
    #[error("request envelope is invalid")]
    InvalidRequest(#[source] ContractError),
    #[error("request envelope could not be serialized")]
    SerializeRequest(#[source] serde_json::Error),
    #[error("provider process could not be executed")]
    Process(#[from] ProcessError),
}

/// Execute one Provider Protocol request after a validated manifest handshake.
///
/// The process receives no stdin bytes until its first complete stdout line is
/// a valid manifest for `expected_adapter` and `expected_adapter_version`.
/// Protocol, EOF, crash, and limit failures become
/// [`ProviderSessionState::Incomplete`]; missing required capabilities become
/// [`ProviderSessionState::Unsupported`] without sending the request.
///
/// # Errors
///
/// Returns an error only when the caller supplies an invalid request or the
/// bounded process substrate cannot create a trustworthy process outcome.
pub fn run_provider_session(
    spec: ProcessSpec,
    expected_adapter: &AdapterId,
    expected_adapter_version: &str,
    request: &RequestEnvelope,
) -> Result<ProviderSessionOutcome, ProviderSessionError> {
    run_provider_session_with_handshake_timeout(
        spec,
        expected_adapter,
        expected_adapter_version,
        request,
        PROVIDER_HANDSHAKE_TIMEOUT,
    )
}

fn run_provider_session_with_handshake_timeout(
    spec: ProcessSpec,
    expected_adapter: &AdapterId,
    expected_adapter_version: &str,
    request: &RequestEnvelope,
    handshake_timeout: Duration,
) -> Result<ProviderSessionOutcome, ProviderSessionError> {
    ProtocolEnvelope::Request(request.clone())
        .validate()
        .map_err(ProviderSessionError::InvalidRequest)?;
    let limits = ProcessLimits::try_from(&request.limits)?;
    let handshake_timeout = handshake_timeout.min(limits.timeout);
    let mut request_line = serde_json::to_vec(&ProtocolEnvelope::Request(request.clone()))
        .map_err(ProviderSessionError::SerializeRequest)?;
    request_line.push(b'\n');

    let handshake = RefCell::new(None);
    let stream = RefCell::new(StreamValidator::new(request));
    let transport = run_bounded_manifest_first(
        &spec.stdin(request_line.clone()),
        limits,
        handshake_timeout,
        |line| {
            let result =
                validate_handshake(line, expected_adapter, expected_adapter_version, request);
            let accepted = matches!(result, HandshakeResult::Accepted(_));
            handshake.replace(Some(result));
            accepted
        },
        |line| {
            let handshake = handshake.borrow();
            let Some(HandshakeResult::Accepted(manifest)) = handshake.as_ref() else {
                return StreamLineDecision::Reject;
            };
            stream.borrow_mut().accept_line(line, manifest)
        },
    )?;
    let process = transport.process;
    let request_bytes_written = transport.request_bytes_written;
    let stream_error = stream.into_inner().error;
    let handshake = handshake.into_inner();

    match handshake {
        Some(HandshakeResult::Unsupported {
            manifest,
            missing_required,
            reason,
        }) => Ok(ProviderSessionOutcome {
            state: ProviderSessionState::Unsupported {
                missing_required,
                reason,
                validated_session: None,
            },
            manifest: Some(manifest),
            process,
            request_bytes_written,
        }),
        Some(HandshakeResult::Incomplete { manifest, reason }) => Ok(ProviderSessionOutcome {
            state: ProviderSessionState::Incomplete {
                reason,
                validated_session: None,
            },
            manifest,
            process,
            request_bytes_written,
        }),
        None => Ok(ProviderSessionOutcome {
            state: ProviderSessionState::Incomplete {
                reason: process_reason(&process),
                validated_session: None,
            },
            manifest: None,
            process,
            request_bytes_written,
        }),
        Some(HandshakeResult::Accepted(manifest)) => Ok(finish_accepted(
            process,
            manifest,
            request,
            &request_line,
            request_bytes_written,
            transport.handshake_accepted,
            stream_error,
        )),
    }
}

fn finish_accepted(
    process: ProcessOutcome,
    manifest: ManifestEnvelope,
    request: &RequestEnvelope,
    request_line: &[u8],
    request_bytes_written: usize,
    handshake_accepted: bool,
    stream_error: Option<String>,
) -> ProviderSessionOutcome {
    if !handshake_accepted
        || process.state != ProcessState::Complete
        || process.exit_code != Some(0)
        || request_bytes_written != request_line.len()
    {
        return ProviderSessionOutcome {
            state: ProviderSessionState::Incomplete {
                reason: stream_error.unwrap_or_else(|| process_reason(&process)),
                validated_session: None,
            },
            manifest: Some(manifest),
            process,
            request_bytes_written,
        };
    }

    let Some(manifest_end) = process.stdout.bytes.iter().position(|byte| *byte == b'\n') else {
        return ProviderSessionOutcome {
            state: ProviderSessionState::Incomplete {
                reason: "manifest line disappeared from captured stdout".to_owned(),
                validated_session: None,
            },
            manifest: Some(manifest),
            process,
            request_bytes_written,
        };
    };
    let manifest_end = manifest_end.saturating_add(1);
    let mut transcript = Vec::with_capacity(
        process
            .stdout
            .bytes
            .len()
            .saturating_add(request_line.len()),
    );
    transcript.extend_from_slice(&process.stdout.bytes[..manifest_end]);
    transcript.extend_from_slice(request_line);
    transcript.extend_from_slice(&process.stdout.bytes[manifest_end..]);

    let session = match validate_session_jsonl(&transcript) {
        Ok(session) => session,
        Err(error) => {
            return ProviderSessionOutcome {
                state: ProviderSessionState::Incomplete {
                    reason: format!("provider protocol is incomplete: {error}"),
                    validated_session: None,
                },
                manifest: Some(manifest),
                process,
                request_bytes_written,
            };
        }
    };
    debug_assert_eq!(&session.request, request);
    let state = match session.completion.status {
        ExecutionStatus::Complete => ProviderSessionState::Complete(Box::new(session)),
        ExecutionStatus::Incomplete => {
            let reason = session
                .completion
                .message
                .clone()
                .unwrap_or_else(|| "provider reported INCOMPLETE".to_owned());
            ProviderSessionState::Incomplete {
                reason,
                validated_session: Some(Box::new(session)),
            }
        }
        ExecutionStatus::Unsupported => {
            let reason = session
                .completion
                .message
                .clone()
                .unwrap_or_else(|| "provider reported UNSUPPORTED".to_owned());
            ProviderSessionState::Unsupported {
                missing_required: Vec::new(),
                reason,
                validated_session: Some(Box::new(session)),
            }
        }
    };
    ProviderSessionOutcome {
        state,
        manifest: Some(manifest),
        process,
        request_bytes_written,
    }
}

enum HandshakeResult {
    Accepted(ManifestEnvelope),
    Incomplete {
        manifest: Option<ManifestEnvelope>,
        reason: String,
    },
    Unsupported {
        manifest: ManifestEnvelope,
        missing_required: Vec<Capability>,
        reason: String,
    },
}

struct StreamValidator<'a> {
    request: &'a RequestEnvelope,
    next_sequence: u64,
    counts: CompletionCounts,
    evidence_bytes: u64,
    error: Option<String>,
}

impl<'a> StreamValidator<'a> {
    fn new(request: &'a RequestEnvelope) -> Self {
        Self {
            request,
            next_sequence: 0,
            counts: CompletionCounts {
                observations: 0,
                evidence: 0,
                fix_candidates: 0,
                executions: 0,
            },
            evidence_bytes: 0,
            error: None,
        }
    }

    fn accept_line(&mut self, line: &[u8], manifest: &ManifestEnvelope) -> StreamLineDecision {
        let envelope = match serde_json::from_slice::<ProtocolEnvelope>(line) {
            Ok(envelope) => envelope,
            Err(error) => return self.reject(format!("stream line is malformed: {error}")),
        };
        match envelope {
            ProtocolEnvelope::Observation(value) => self.accept_event(
                &value.request_id,
                value.sequence,
                StreamEventKind::Observation,
                None,
                manifest,
            ),
            ProtocolEnvelope::Evidence(value) => self.accept_event(
                &value.request_id,
                value.sequence,
                StreamEventKind::Evidence,
                Some(value.evidence.retained_bytes),
                manifest,
            ),
            ProtocolEnvelope::FixCandidate(value) => self.accept_event(
                &value.request_id,
                value.sequence,
                StreamEventKind::FixCandidate,
                None,
                manifest,
            ),
            ProtocolEnvelope::Execution(value) => self.accept_event(
                &value.request_id,
                value.sequence,
                StreamEventKind::Execution,
                None,
                manifest,
            ),
            ProtocolEnvelope::Completion(value) => {
                if value.request_id != self.request.request_id
                    || value.sequence != self.next_sequence
                    || value.counts != self.counts
                    || value.evidence_bytes != self.evidence_bytes
                {
                    return self.reject(
                        "completion does not match streamed request, sequence, or counts"
                            .to_owned(),
                    );
                }
                StreamLineDecision::Complete
            }
            ProtocolEnvelope::Manifest(_) | ProtocolEnvelope::Request(_) => {
                self.reject("manifest or request appeared in provider event stream".to_owned())
            }
        }
    }

    fn accept_event(
        &mut self,
        request_id: &ObjectId,
        sequence: u64,
        kind: StreamEventKind,
        retained_evidence_bytes: Option<u64>,
        manifest: &ManifestEnvelope,
    ) -> StreamLineDecision {
        if request_id != &self.request.request_id || sequence != self.next_sequence {
            return self.reject("event request_id or sequence is invalid".to_owned());
        }
        let event_count = self
            .counts
            .observations
            .saturating_add(self.counts.evidence)
            .saturating_add(self.counts.fix_candidates)
            .saturating_add(self.counts.executions);
        if event_count >= self.request.limits.max_events {
            return self.reject("configured event limit exceeded".to_owned());
        }
        if !kind.allowed_for(&manifest.adapter.kind) {
            return self.reject("adapter role cannot emit this event kind".to_owned());
        }
        if let Some(capability) = kind.capability() {
            let provided = manifest
                .adapter
                .capabilities
                .iter()
                .any(|provided| provided.as_str() == capability);
            let requested = self
                .request
                .required_capabilities
                .iter()
                .chain(&self.request.optional_capabilities)
                .any(|requested| requested.as_str() == capability);
            if !provided || !requested {
                return self.reject("event capability was not negotiated".to_owned());
            }
        }
        if let Some(retained) = retained_evidence_bytes {
            if retained > self.request.limits.max_evidence_bytes {
                return self.reject("configured evidence limit exceeded".to_owned());
            }
            let Some(total) = self.evidence_bytes.checked_add(retained) else {
                return self.reject("evidence byte count overflowed".to_owned());
            };
            self.evidence_bytes = total;
        }
        self.next_sequence = self.next_sequence.saturating_add(1);
        match kind {
            StreamEventKind::Observation => {
                self.counts.observations = self.counts.observations.saturating_add(1);
            }
            StreamEventKind::Evidence => {
                self.counts.evidence = self.counts.evidence.saturating_add(1);
            }
            StreamEventKind::FixCandidate => {
                self.counts.fix_candidates = self.counts.fix_candidates.saturating_add(1);
            }
            StreamEventKind::Execution => {
                self.counts.executions = self.counts.executions.saturating_add(1);
            }
        }
        StreamLineDecision::Continue
    }

    fn reject(&mut self, reason: String) -> StreamLineDecision {
        self.error.get_or_insert(reason);
        StreamLineDecision::Reject
    }
}

#[derive(Clone, Copy)]
enum StreamEventKind {
    Observation,
    Evidence,
    FixCandidate,
    Execution,
}

impl StreamEventKind {
    fn allowed_for(self, adapter_kind: &AdapterKind) -> bool {
        matches!(
            (adapter_kind, self),
            (
                AdapterKind::Provider,
                Self::Observation | Self::Evidence | Self::FixCandidate
            ) | (AdapterKind::Observer, Self::Evidence | Self::Execution)
        )
    }

    fn capability(self) -> Option<&'static str> {
        match self {
            Self::Observation => Some("diagnostic.check/v1"),
            Self::FixCandidate => Some("fix.propose/v1"),
            Self::Execution => Some("execution.observe/v1"),
            Self::Evidence => None,
        }
    }
}

fn validate_handshake(
    line: &[u8],
    expected_adapter: &AdapterId,
    expected_adapter_version: &str,
    request: &RequestEnvelope,
) -> HandshakeResult {
    let envelope = match serde_json::from_slice::<ProtocolEnvelope>(line) {
        Ok(envelope) => envelope,
        Err(error) => {
            return HandshakeResult::Incomplete {
                manifest: None,
                reason: format!("manifest is malformed: {error}"),
            };
        }
    };
    let ProtocolEnvelope::Manifest(manifest) = envelope else {
        return HandshakeResult::Incomplete {
            manifest: None,
            reason: "first provider line is not a manifest".to_owned(),
        };
    };
    if &manifest.adapter.id != expected_adapter {
        return HandshakeResult::Incomplete {
            manifest: Some(manifest),
            reason: "manifest adapter id does not match configured adapter".to_owned(),
        };
    }
    if manifest.adapter.version != expected_adapter_version {
        return HandshakeResult::Incomplete {
            manifest: Some(manifest),
            reason: "manifest adapter version does not match configured adapter".to_owned(),
        };
    }
    let role_supported = matches!(
        (&manifest.adapter.kind, request.operation),
        (
            AdapterKind::Provider,
            Operation::Check | Operation::Fix | Operation::Verify
        ) | (AdapterKind::Observer, Operation::Observe)
    );
    if !role_supported {
        // LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.
        // LLM contract: MANIFEST_VALIDATED -> UNSUPPORTED; request remains UNSENT.
        return HandshakeResult::Unsupported {
            manifest,
            missing_required: Vec::new(),
            reason: "adapter role does not support the requested operation".to_owned(),
        };
    }
    let mut missing_required = request
        .required_capabilities
        .iter()
        .filter(|capability| !manifest.adapter.capabilities.contains(capability))
        .cloned()
        .collect::<Vec<_>>();
    missing_required.sort();
    if missing_required.is_empty() {
        HandshakeResult::Accepted(manifest)
    } else {
        HandshakeResult::Unsupported {
            manifest,
            missing_required,
            reason: "required capability is unsupported".to_owned(),
        }
    }
}

fn process_reason(process: &ProcessOutcome) -> String {
    match process.state {
        ProcessState::Complete => format!(
            "provider process exited with code {}",
            process
                .exit_code
                .map_or_else(|| "unavailable".to_owned(), |code| code.to_string())
        ),
        ProcessState::Incomplete(reason) => format!("provider process is incomplete: {reason:?}"),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Duration};

    use diagnostic_triage_contracts::{
        AdapterId,
        model::ExecutionStatus,
        protocol::{ProtocolEnvelope, RequestEnvelope},
    };
    use tempfile::tempdir;

    use super::{
        ProviderSessionState, run_provider_session, run_provider_session_with_handshake_timeout,
    };
    use crate::process::{IncompleteReason, ProcessSpec, ProcessState};

    const REQUEST_ID: &str = "019f7e95-0000-7000-8000-000000000001";
    const ADAPTER_VERSION: &str = "1.0.0";

    fn request(required: &str, optional: &[&str], stdout: u64) -> RequestEnvelope {
        request_for("CHECK", required, optional, stdout)
    }

    fn request_for(
        operation: &str,
        required: &str,
        optional: &[&str],
        stdout: u64,
    ) -> RequestEnvelope {
        let value = serde_json::json!({
            "protocol_version": "diagnostic-triage.protocol/v1",
            "kind": "request",
            "request_id": REQUEST_ID,
            "operation": operation,
            "workspace": ".",
            "targets": ["src/lib.rs"],
            "required_capabilities": [required],
            "optional_capabilities": optional,
            "limits": {
                "timeout_ms": 2_000,
                "max_stdout_bytes": stdout,
                "max_stderr_bytes": 4_096,
                "max_evidence_bytes": 1_048_576,
                "max_events": 10
            }
        });
        let envelope: ProtocolEnvelope = serde_json::from_value(value).unwrap();
        let ProtocolEnvelope::Request(request) = envelope else {
            panic!("request fixture must decode as request")
        };
        request
    }

    fn manifest(capabilities: &[&str]) -> String {
        manifest_for("PROVIDER", capabilities)
    }

    fn manifest_for(kind: &str, capabilities: &[&str]) -> String {
        manifest_for_adapter("test-provider", kind, capabilities)
    }

    fn manifest_for_adapter(adapter_id: &str, kind: &str, capabilities: &[&str]) -> String {
        serde_json::json!({
            "protocol_version": "diagnostic-triage.protocol/v1",
            "kind": "manifest",
            "adapter": {
                "id": adapter_id,
                "version": "1.0.0",
                "kind": kind,
                "capabilities": capabilities,
                "languages": ["python"]
            }
        })
        .to_string()
    }

    fn completion(sequence: u64) -> String {
        terminal_completion(sequence, &ExecutionStatus::Complete, None)
    }

    fn terminal_completion(
        sequence: u64,
        status: &ExecutionStatus,
        message: Option<&str>,
    ) -> String {
        let complete = status == &ExecutionStatus::Complete;
        let mut completion = serde_json::json!({
            "protocol_version": "diagnostic-triage.protocol/v1",
            "kind": "completion",
            "request_id": REQUEST_ID,
            "sequence": sequence,
            "status": status,
            "tool_exit_code": if complete { Some(0) } else { None },
            "tool_duration_ms": if complete { 1 } else { 37 },
            "counts": {
                "observations": 0,
                "evidence": 0,
                "fix_candidates": 0,
                "executions": 0
            },
            "evidence_bytes": 0
        });
        if let Some(message) = message {
            completion["message"] = message.into();
        }
        completion.to_string()
    }

    fn evidence(sequence: u64, id: &str) -> String {
        serde_json::json!({
            "protocol_version": "diagnostic-triage.protocol/v1",
            "kind": "evidence",
            "request_id": REQUEST_ID,
            "sequence": sequence,
            "evidence": {
                "schema_version": "diagnostic-triage.evidence/v1",
                "evidence_id": id,
                "source": "PATCH",
                "media_type": "text/x-diff",
                "retained_bytes": 0,
                "observed_bytes": 0,
                "limit_bytes": 1_048_576,
                "truncated": false,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "content": ""
            }
        })
        .to_string()
    }

    fn provider_script(manifest: &str, tail: &str) -> ProcessSpec {
        ProcessSpec::new("/bin/sh").args([
            "-c",
            "printf '%s\\n' \"$1\"; IFS= read -r request; printf '%s' \"$2\"",
            "sh",
            manifest,
            tail,
        ])
    }

    fn adapter_id() -> AdapterId {
        "test-provider".parse().unwrap()
    }

    #[test]
    fn validates_manifest_before_request_and_completes() {
        let request = request("diagnostic.check/v1", &[], 16_384);
        let outcome = run_provider_session(
            provider_script(&manifest(&["diagnostic.check/v1"]), &completion(0)),
            &adapter_id(),
            ADAPTER_VERSION,
            &request,
        )
        .unwrap();

        assert!(matches!(outcome.state, ProviderSessionState::Complete(_)));
        assert!(outcome.request_bytes_written > 0);
        assert_eq!(outcome.process.exit_code, Some(0));
    }

    #[test]
    fn validated_terminal_states_retain_the_session() {
        for (status, expected_reason) in [
            (ExecutionStatus::Incomplete, "provider stopped early"),
            (
                ExecutionStatus::Unsupported,
                "provider cannot perform request",
            ),
        ] {
            let request = request("diagnostic.check/v1", &[], 16_384);
            let outcome = run_provider_session(
                provider_script(
                    &manifest(&["diagnostic.check/v1"]),
                    &terminal_completion(0, &status, Some(expected_reason)),
                ),
                &adapter_id(),
                ADAPTER_VERSION,
                &request,
            )
            .unwrap();

            let (reason, validated_session) = match outcome.state {
                ProviderSessionState::Incomplete {
                    reason,
                    validated_session,
                }
                | ProviderSessionState::Unsupported {
                    reason,
                    validated_session,
                    ..
                } => (reason, validated_session),
                ProviderSessionState::Complete(_) => panic!("expected terminal state"),
            };
            let session = validated_session.expect("validated terminal session must be retained");
            assert_eq!(reason, expected_reason);
            assert_eq!(session.request.request_id, request.request_id);
            assert_eq!(session.completion.tool_duration_ms, 37);
            assert_eq!(session.completion.tool_exit_code.0, None);
            assert_eq!(session.completion.message.as_deref(), Some(expected_reason));
        }
    }

    #[test]
    fn adapter_version_mismatch_is_incomplete_without_request_bytes() {
        let directory = tempdir().unwrap();
        let marker = directory.path().join("request-received");
        let mut wrong: serde_json::Value =
            serde_json::from_str(&manifest(&["diagnostic.check/v1"])).unwrap();
        wrong["adapter"]["version"] = "2.0.0".into();
        let script = ProcessSpec::new("/bin/sh").args([
            "-c",
            "printf '%s\n' \"$1\"; if IFS= read -r request; then : > \"$2\"; fi",
            "sh",
            &wrong.to_string(),
            marker.to_str().unwrap(),
        ]);
        let outcome = run_provider_session(
            script,
            &adapter_id(),
            ADAPTER_VERSION,
            &request("diagnostic.check/v1", &[], 16_384),
        )
        .unwrap();

        assert!(matches!(
            outcome.state,
            ProviderSessionState::Incomplete {
                ref reason,
                validated_session: None,
            } if reason == "manifest adapter version does not match configured adapter"
        ));
        assert_eq!(outcome.request_bytes_written, 0);
        assert!(!marker.exists());
    }

    #[test]
    fn ignores_unknown_optional_capability() {
        let request = request("diagnostic.check/v1", &["provider.future/v9"], 16_384);
        let outcome = run_provider_session(
            provider_script(&manifest(&["diagnostic.check/v1"]), &completion(0)),
            &adapter_id(),
            ADAPTER_VERSION,
            &request,
        )
        .unwrap();
        assert!(matches!(outcome.state, ProviderSessionState::Complete(_)));
    }

    #[test]
    fn unsupported_required_capability_receives_no_request_bytes() {
        let directory = tempdir().unwrap();
        let marker = directory.path().join("request-received");
        let script = ProcessSpec::new("/bin/sh").args([
            "-c",
            "printf '%s\\n' \"$1\"; if IFS= read -r request; then : > \"$2\"; fi",
            "sh",
            &manifest(&["diagnostic.check/v1"]),
            marker.to_str().unwrap(),
        ]);
        let request = request_for("FIX", "fix.propose/v1", &[], 16_384);
        let outcome =
            run_provider_session(script, &adapter_id(), ADAPTER_VERSION, &request).unwrap();

        assert!(matches!(
            outcome.state,
            ProviderSessionState::Unsupported {
                validated_session: None,
                ..
            }
        ));
        assert_eq!(outcome.request_bytes_written, 0);
        assert!(!marker.exists());
    }

    #[test]
    fn handshake_mismatch_role_is_unsupported_without_request_bytes() {
        for (kind, operation, capability) in [
            ("PROVIDER", "OBSERVE", "execution.observe/v1"),
            ("OBSERVER", "CHECK", "diagnostic.check/v1"),
            ("OBSERVER", "FIX", "fix.propose/v1"),
            ("OBSERVER", "VERIFY", "diagnostic.check/v1"),
        ] {
            let directory = tempdir().unwrap();
            let marker = directory.path().join("request-received");
            let script = ProcessSpec::new("/bin/sh").args([
                "-c",
                "printf '%s\\n' \"$1\"; if IFS= read -r request; then : > \"$2\"; fi",
                "sh",
                &manifest_for(kind, &[capability]),
                marker.to_str().unwrap(),
            ]);
            let request = request_for(operation, capability, &[], 16_384);
            let outcome =
                run_provider_session(script, &adapter_id(), ADAPTER_VERSION, &request).unwrap();

            assert!(matches!(
                outcome.state,
                ProviderSessionState::Unsupported {
                    ref missing_required,
                    ..
                } if missing_required.is_empty()
            ));
            assert_eq!(outcome.request_bytes_written, 0);
            assert!(!marker.exists());
        }
    }

    #[test]
    fn handshake_mismatch_adapter_id_remains_incomplete_without_request_bytes() {
        let directory = tempdir().unwrap();
        let marker = directory.path().join("request-received");
        let script = ProcessSpec::new("/bin/sh").args([
            "-c",
            "printf '%s\\n' \"$1\"; if IFS= read -r request; then : > \"$2\"; fi",
            "sh",
            &manifest_for_adapter("other-provider", "PROVIDER", &["diagnostic.check/v1"]),
            marker.to_str().unwrap(),
        ]);
        let request = request("diagnostic.check/v1", &[], 16_384);
        let outcome =
            run_provider_session(script, &adapter_id(), ADAPTER_VERSION, &request).unwrap();

        assert!(matches!(
            outcome.state,
            ProviderSessionState::Incomplete { ref reason, .. }
                if reason == "manifest adapter id does not match configured adapter"
        ));
        assert_eq!(outcome.request_bytes_written, 0);
        assert!(!marker.exists());
    }

    #[test]
    fn rejects_payload_output_before_request_delivery() {
        let manifest = manifest(&["diagnostic.check/v1"]);
        let completion = completion(0);
        let script = ProcessSpec::new("/bin/sh").args([
            "-c",
            "printf '%s\\n%s' \"$1\" \"$2\"; IFS= read -r request",
            "sh",
            &manifest,
            &completion,
        ]);
        let request = request("diagnostic.check/v1", &[], 16_384);
        let outcome =
            run_provider_session(script, &adapter_id(), ADAPTER_VERSION, &request).unwrap();

        assert!(matches!(
            outcome.state,
            ProviderSessionState::Incomplete { .. }
        ));
        assert_eq!(outcome.request_bytes_written, 0);
        assert_eq!(
            outcome.process.state,
            ProcessState::Incomplete(IncompleteReason::RequestOrderViolation)
        );
    }

    #[test]
    fn malformed_manifest_is_incomplete_without_request() {
        let request = request("diagnostic.check/v1", &[], 16_384);
        let outcome = run_provider_session(
            provider_script("{not-json", &completion(0)),
            &adapter_id(),
            ADAPTER_VERSION,
            &request,
        )
        .unwrap();
        assert!(matches!(
            outcome.state,
            ProviderSessionState::Incomplete { .. }
        ));
        assert_eq!(outcome.request_bytes_written, 0);
    }

    #[test]
    fn handshake_timeout_is_incomplete_and_bounded() {
        let request = request("diagnostic.check/v1", &[], 16_384);
        let outcome = run_provider_session_with_handshake_timeout(
            ProcessSpec::new("/bin/sh").args(["-c", "sleep 2"]),
            &adapter_id(),
            ADAPTER_VERSION,
            &request,
            Duration::from_millis(40),
        )
        .unwrap();
        assert_eq!(
            outcome.process.state,
            ProcessState::Incomplete(IncompleteReason::HandshakeTimeout)
        );
        assert_eq!(outcome.request_bytes_written, 0);
    }

    #[test]
    fn late_manifest_cannot_cross_the_handshake_deadline() {
        let directory = tempdir().unwrap();
        let marker = directory.path().join("late-request-received");
        let manifest = manifest(&["diagnostic.check/v1"]);
        let script = ProcessSpec::new("/bin/sh").args([
            "-c",
            "sleep 0.08; printf '%s\\n' \"$1\"; if IFS= read -r request; then : > \"$2\"; fi",
            "sh",
            &manifest,
            marker.to_str().unwrap(),
        ]);
        let request = request("diagnostic.check/v1", &[], 16_384);
        let outcome = run_provider_session_with_handshake_timeout(
            script,
            &adapter_id(),
            ADAPTER_VERSION,
            &request,
            Duration::from_millis(40),
        )
        .unwrap();

        assert_eq!(outcome.request_bytes_written, 0);
        assert!(!marker.exists());
        assert_eq!(
            outcome.process.state,
            ProcessState::Incomplete(IncompleteReason::HandshakeTimeout)
        );
    }

    #[test]
    fn event_overflow_is_rejected_while_provider_is_still_running() {
        let mut request = request("diagnostic.check/v1", &[], 16_384);
        request.limits.max_events = 1;
        let first = evidence(0, "019f7e95-0000-7000-8000-000000000101");
        let second = evidence(1, "019f7e95-0000-7000-8000-000000000102");
        let script = ProcessSpec::new("/bin/sh").args([
            "-c",
            "printf '%s\\n' \"$1\"; IFS= read -r request; printf '%s\\n%s\\n' \"$2\" \"$3\"; sleep 2",
            "sh",
            &manifest(&["diagnostic.check/v1"]),
            &first,
            &second,
        ]);
        let outcome =
            run_provider_session(script, &adapter_id(), ADAPTER_VERSION, &request).unwrap();

        assert_eq!(
            outcome.process.state,
            ProcessState::Incomplete(IncompleteReason::ProtocolViolation)
        );
        assert!(outcome.process.duration < Duration::from_secs(1));
        assert!(matches!(
            outcome.state,
            ProviderSessionState::Incomplete { ref reason, .. }
                if reason.contains("event limit")
        ));
    }

    #[test]
    fn malformed_and_post_completion_output_are_rejected_while_streaming() {
        let request = request("diagnostic.check/v1", &[], 16_384);
        let manifest = manifest(&["diagnostic.check/v1"]);
        let tails = ["{bad\n".to_owned(), format!("{}\nextra", completion(0))];
        for tail in tails {
            let script = ProcessSpec::new("/bin/sh").args([
                "-c",
                "printf '%s\\n' \"$1\"; IFS= read -r request; printf '%s' \"$2\"; sleep 2",
                "sh",
                &manifest,
                &tail,
            ]);
            let outcome =
                run_provider_session(script, &adapter_id(), ADAPTER_VERSION, &request).unwrap();
            assert_eq!(
                outcome.process.state,
                ProcessState::Incomplete(IncompleteReason::ProtocolViolation)
            );
            assert!(outcome.process.duration < Duration::from_secs(1));
        }
    }

    #[test]
    fn eof_malformed_tail_crash_and_post_completion_are_incomplete() {
        let request = request("diagnostic.check/v1", &[], 16_384);
        let manifest = manifest(&["diagnostic.check/v1"]);
        let cases = [
            provider_script(&manifest, ""),
            provider_script(&manifest, "{bad"),
            provider_script(&manifest, &format!("{}\\n{{}}", completion(0))),
            ProcessSpec::new("/bin/sh").args([
                "-c",
                "printf '%s\\n' \"$1\"; IFS= read -r request; exit 7",
                "sh",
                &manifest,
            ]),
        ];
        for spec in cases {
            let outcome =
                run_provider_session(spec, &adapter_id(), ADAPTER_VERSION, &request).unwrap();
            assert!(
                matches!(outcome.state, ProviderSessionState::Incomplete { .. }),
                "unexpected state: {:?}",
                outcome.state
            );
        }
    }

    #[test]
    fn stdout_overflow_is_incomplete() {
        let request = request("diagnostic.check/v1", &[], 1_024);
        let tail = "x".repeat(2_048);
        let outcome = run_provider_session(
            provider_script(&manifest(&["diagnostic.check/v1"]), &tail),
            &adapter_id(),
            ADAPTER_VERSION,
            &request,
        )
        .unwrap();
        assert!(matches!(
            outcome.state,
            ProviderSessionState::Incomplete { .. }
        ));
        assert!(outcome.process.stdout.truncated);
    }

    #[test]
    fn request_is_never_materialized_by_the_runtime() {
        let directory = tempdir().unwrap();
        let before = fs::read_dir(directory.path()).unwrap().count();
        let request = request("diagnostic.check/v1", &[], 16_384);
        let _outcome = run_provider_session(
            provider_script(&manifest(&["diagnostic.check/v1"]), &completion(0)),
            &adapter_id(),
            ADAPTER_VERSION,
            &request,
        )
        .unwrap();
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), before);
    }
}
