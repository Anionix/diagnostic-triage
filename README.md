# Diagnostic Triage

Diagnostic Triage is a policy-aware Rust CLI that normalizes diagnostics from
language tools, classifies and deduplicates findings, verifies tool-native
fixes, and reports reproducible results to people and CI systems.

It is an orchestration layer, not a replacement for Ruff, ty, Pyright, pytest,
Biome, Cargo, or Clippy. Those tools remain authoritative for collection and
fix safety.

## Status

The project is establishing its versioned contracts. The stable v1 interfaces
will be the `diagnostic-triage` command, `diagnostic-triage.toml`, JSON/JSONL
schemas, and exit codes. Rust workspace crates are internal and will not be
published during v1 development. No alpha contract has been published yet.
Before that first alpha, checked-in config shapes are revision-specific and
consumers must pin the full commit object ID. Missing Provider identity fields
are rejected with a migration error; the runtime never guesses identity data.

The canonical architecture and terminology are recorded in [CONTEXT.md](CONTEXT.md)
and [ADR 0001](docs/adr/0001-standalone-canonical-engine.md).

## Running from source

`observe --source github-actions` requires the first-party
`diagnostic-triage-observer-github-actions` binary. Release archives place it
beside `diagnostic-triage`; source installs must install both packages to the
same Cargo `--root`, or put the Observer on `PATH`.

## License

Apache-2.0.
