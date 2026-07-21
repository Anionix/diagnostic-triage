//! Biome diagnostic provider entry point.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use std::process::ExitCode;

fn main() -> ExitCode {
    match diagnostic_triage_provider_biome::run_stdio() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("diagnostic-triage-provider-biome: {error}");
            ExitCode::FAILURE
        }
    }
}
