//! Rust diagnostic Provider entry point.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use std::process::ExitCode;

fn main() -> ExitCode {
    match diagnostic_triage_provider_rust::run_stdio() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("diagnostic-triage-provider-rust: {error}");
            ExitCode::FAILURE
        }
    }
}
