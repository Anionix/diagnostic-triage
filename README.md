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

The public command surface is:

```text
diagnostic-triage check
diagnostic-triage ci
diagnostic-triage fix
diagnostic-triage fix --apply-safe
diagnostic-triage verify --patch <repo-relative-path>
diagnostic-triage observe --source github-actions --input <repo-relative-path>
diagnostic-triage issue-draft --input <repo-relative-path>
```

`fix` writes a patch to stdout and leaves the repository unchanged.
`fix --apply-safe` is the only source-writing command; it applies only one
canonical Ruff SAFE candidate for an existing regular file after isolated
before/after verification succeeds. The v1 publication path supports Linux and
macOS. The verified patch is written and flushed before descriptor-bound source
publication, so output failure leaves source untouched. A post-publication
cleanup or final-state failure exits 2 with the patch already available on
stdout and an explicit applied-state error.

`observe --source github-actions` requires the first-party
`diagnostic-triage-observer-github-actions` binary. Release archives place it
beside `diagnostic-triage`; source installs must install both packages to the
same Cargo `--root`, or put the Observer on `PATH`.

## License

Apache-2.0.
