//! GitHub Actions execution Observer entry point.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use std::process::ExitCode;

fn main() -> ExitCode {
    match diagnostic_triage_observer_github_actions::run_stdio() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("diagnostic-triage-observer-github-actions: {error}");
            ExitCode::FAILURE
        }
    }
}
