//! Python diagnostic provider entry point.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    path::Path,
};

use diagnostic_triage_contracts::ObjectId;
use diagnostic_triage_provider_python::{
    CompletionBuilder, MAX_REQUEST_BYTES, ProviderError, ProviderSession, decode_request,
    emit_manifest, emit_session_tail, empty_incomplete, run_ruff_session,
    validate_generated_session, validate_request,
};

const FALLBACK_REQUEST_ID: &str = "00000000-0000-4000-8000-000000000000";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut stdout = io::stdout().lock();
    emit_manifest(&mut stdout)?;
    stdout.flush()?;

    let mut input = Vec::new();
    BufReader::new(io::stdin().lock())
        .take(u64::try_from(MAX_REQUEST_BYTES)? + 1)
        .read_until(b'\n', &mut input)?;

    let session = match decode_request(&input, MAX_REQUEST_BYTES) {
        Ok(request) => match validate_request(&request) {
            Ok(()) => {
                let launch_root = std::env::current_dir()?;
                let session = run_ruff_session(&request, &launch_root, Path::new("ruff"))
                    .or_else(|error| incomplete_for_request(&request, error.to_string()))?;
                match validate_generated_session(&request, &session) {
                    Ok(()) => session,
                    Err(error) => incomplete_for_request(&request, error.to_string())?,
                }
            }
            Err(error @ ProviderError::Unsupported(_)) => {
                unsupported_for_request(&request, error.to_string())?
            }
            Err(error) => incomplete_for_request(&request, error.to_string())?,
        },
        Err(error) => ProviderSession {
            events: Vec::new(),
            completion: empty_incomplete(recover_request_id(&input), error.to_string())?,
        },
    };
    emit_session_tail(&mut stdout, &session)?;
    Ok(())
}

fn incomplete_for_request(
    request: &diagnostic_triage_contracts::protocol::RequestEnvelope,
    message: String,
) -> Result<ProviderSession, diagnostic_triage_provider_python::ProviderError> {
    Ok(ProviderSession {
        events: Vec::new(),
        completion: CompletionBuilder::new(request).incomplete(0, message)?,
    })
}

fn unsupported_for_request(
    request: &diagnostic_triage_contracts::protocol::RequestEnvelope,
    message: String,
) -> Result<ProviderSession, ProviderError> {
    Ok(ProviderSession {
        events: Vec::new(),
        completion: CompletionBuilder::new(request).unsupported(0, message)?,
    })
}

fn recover_request_id(input: &[u8]) -> ObjectId {
    serde_json::from_slice::<serde_json::Value>(input)
        .ok()
        .and_then(|value| value.get("request_id")?.as_str()?.parse().ok())
        .unwrap_or_else(|| {
            FALLBACK_REQUEST_ID
                .parse()
                .expect("static fallback request id is valid")
        })
}
