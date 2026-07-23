//! Diagnostic Triage CLI entry point.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use std::{io, process::ExitCode};

use clap::Parser;

fn main() -> ExitCode {
    let cli = diagnostic_triage::Cli::parse();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match diagnostic_triage::execute(cli, &mut output) {
        Ok(status) => ExitCode::from(status.code()),
        Err(error) => {
            eprintln!("diagnostic-triage: {error}");
            ExitCode::from(2)
        }
    }
}
