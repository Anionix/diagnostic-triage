//! Pure identity validation for projected Provider sessions.

use diagnostic_triage_contracts::{
    AdapterId, ValidatedSession,
    model::{AdapterKind, ExecutionStatus},
    protocol::{ProtocolEnvelope, RequestEnvelope},
};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderExecutionIdentity<'a> {
    pub request: &'a RequestEnvelope,
    pub adapter_id: &'a AdapterId,
    pub adapter_version: &'a str,
    pub adapter_kind: AdapterKind,
    pub tool_name: &'a str,
    pub tool_version: &'a str,
    pub completion: ExpectedCompletion<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExpectedCompletion<'a> {
    Complete,
    Incomplete(&'a str),
    Unsupported(&'a str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderIdentityMismatch {
    Request,
    AdapterId,
    AdapterVersion,
    AdapterKind,
    CompletionStatus,
    TerminalReason,
    ObservationToolName,
    ObservationToolVersion,
    ExecutionEvent,
}

pub(crate) fn validate_provider_execution_identity(
    expected: &ProviderExecutionIdentity<'_>,
    session: &ValidatedSession,
) -> Result<(), ProviderIdentityMismatch> {
    let adapter = &session.manifest.adapter;
    if &session.request != expected.request {
        return Err(ProviderIdentityMismatch::Request);
    }
    if &adapter.id != expected.adapter_id {
        return Err(ProviderIdentityMismatch::AdapterId);
    }
    if adapter.version != expected.adapter_version {
        return Err(ProviderIdentityMismatch::AdapterVersion);
    }
    if adapter.kind != expected.adapter_kind {
        return Err(ProviderIdentityMismatch::AdapterKind);
    }
    let (status, reason) = match expected.completion {
        ExpectedCompletion::Complete => (ExecutionStatus::Complete, None),
        ExpectedCompletion::Incomplete(reason) => (ExecutionStatus::Incomplete, Some(reason)),
        ExpectedCompletion::Unsupported(reason) => (ExecutionStatus::Unsupported, Some(reason)),
    };
    if session.completion.status != status {
        return Err(ProviderIdentityMismatch::CompletionStatus);
    }
    if reason.is_some() && session.completion.message.as_deref() != reason {
        return Err(ProviderIdentityMismatch::TerminalReason);
    }
    for event in &session.events {
        match event {
            ProtocolEnvelope::Observation(value) => {
                if value.observation.tool.name != expected.tool_name {
                    return Err(ProviderIdentityMismatch::ObservationToolName);
                }
                if value.observation.tool.version != expected.tool_version {
                    return Err(ProviderIdentityMismatch::ObservationToolVersion);
                }
            }
            ProtocolEnvelope::Execution(_) => return Err(ProviderIdentityMismatch::ExecutionEvent),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ProviderIdentityMismatch as Mismatch;
    use diagnostic_triage_contracts::validate_session_jsonl;

    fn session() -> ValidatedSession {
        validate_session_jsonl(include_bytes!(
            "../../../tests/fixtures/v1/valid-session.jsonl"
        ))
        .unwrap()
    }

    fn expected(session: &ValidatedSession) -> ProviderExecutionIdentity<'_> {
        ProviderExecutionIdentity {
            request: &session.request,
            adapter_id: &session.manifest.adapter.id,
            adapter_version: &session.manifest.adapter.version,
            adapter_kind: AdapterKind::Provider,
            tool_name: "ruff",
            tool_version: "0.12.4",
            completion: ExpectedCompletion::Complete,
        }
    }

    #[test]
    fn accepts_complete_and_terminal_identity() {
        let mut complete = session();
        complete.completion.message = Some("informational".to_owned());
        validate_provider_execution_identity(&expected(&complete), &complete).unwrap();
        for (status, completion) in [
            ("INCOMPLETE", ExpectedCompletion::Incomplete("stopped")),
            ("UNSUPPORTED", ExpectedCompletion::Unsupported("stopped")),
        ] {
            let input = include_str!("../../../tests/fixtures/v1/valid-session.jsonl").replace(
                "\"status\":\"COMPLETE\",\"tool_exit_code\":1",
                &format!("\"status\":\"{status}\",\"tool_exit_code\":null,\"message\":\"stopped\""),
            );
            let terminal = validate_session_jsonl(input.as_bytes()).unwrap();
            let mut identity = expected(&terminal);
            identity.completion = completion;
            validate_provider_execution_identity(&identity, &terminal).unwrap();
        }
    }

    #[test]
    fn rejects_each_identity_mismatch() {
        let base = session();
        let assert = |identity, session: &ValidatedSession, mismatch| {
            assert_eq!(
                validate_provider_execution_identity(&identity, session),
                Err(mismatch)
            );
        };
        let mut changed = base.clone();
        changed.request.targets.clear();
        assert(expected(&base), &changed, Mismatch::Request);
        changed = base.clone();
        changed.manifest.adapter.id = "other".parse().unwrap();
        assert(expected(&base), &changed, Mismatch::AdapterId);
        changed = base.clone();
        changed.manifest.adapter.version.push('x');
        assert(expected(&base), &changed, Mismatch::AdapterVersion);
        changed = base.clone();
        changed.manifest.adapter.kind = AdapterKind::Observer;
        assert(expected(&base), &changed, Mismatch::AdapterKind);
        let mut identity = expected(&base);
        identity.completion = ExpectedCompletion::Incomplete("provider reported INCOMPLETE");
        assert(identity, &base, Mismatch::CompletionStatus);
        changed = base.clone();
        changed.completion.status = ExecutionStatus::Incomplete;
        changed.completion.message = Some("actual".to_owned());
        identity = expected(&changed);
        identity.completion = ExpectedCompletion::Incomplete("expected");
        assert(identity, &changed, Mismatch::TerminalReason);
        identity = expected(&base);
        identity.tool_name = "other";
        assert(identity, &base, Mismatch::ObservationToolName);
        identity = expected(&base);
        identity.tool_version = "other";
        assert(identity, &base, Mismatch::ObservationToolVersion);
        let mut execution_session = base.clone();
        let line = include_str!("../../../tests/fixtures/v1/valid-observer-session.jsonl")
            .lines()
            .nth(2)
            .unwrap();
        execution_session
            .events
            .push(serde_json::from_str(line).unwrap());
        assert(
            expected(&base),
            &execution_session,
            Mismatch::ExecutionEvent,
        );
    }
}
