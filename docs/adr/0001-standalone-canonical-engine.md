# ADR 0001: Standalone Canonical Diagnostic Engine

## Status

Accepted

## Context

Python, web, and Rust tools expose incompatible diagnostics and fix contracts.
A consumer-specific implementation would duplicate classification, policy,
fingerprinting, process limits, and verification across repositories. It would
also make generic contract changes depend on an unrelated benchmark domain.

## Decision

Diagnostic Triage is an independent Rust CLI and the single canonical owner of
its generic contracts and implementation. Consumer repositories pin an
immutable source revision and retain only repository-specific policy and
integration fixtures.

The public seam is intentionally small: CLI commands, configuration,
versioned JSON/JSONL schemas, and exit codes. Internal Rust crates are separate
compilation modules but remain unpublished during v1. The dependency direction
is `contracts <- engine <- runtime <- cli`; Provider and Observer binaries
depend on contracts and use the same process protocol as third-party adapters.

The Engine separates policy-independent Observation and Finding data from
repository-specific Decision data. Operational `INCOMPLETE` and `UNSUPPORTED`
states belong to Execution and session verdicts, not individual Findings.

Performance evidence is represented by Execution. A 60-second execution is an
improvement candidate by default, not a correctness failure. GitHub-specific
metadata is imported by an optional Observer. Test selection and scheduling are
outside v1.

## Consequences

- Consumer repositories cannot fork the generic schema or taxonomy.
- First-party adapters pay process startup cost in exchange for fault isolation
  and one real protocol seam.
- Rust implementation details may change without a public crate migration.
- After the first alpha, a breaking contract change requires a new
  schema/protocol major version.
- The prototype in `Anionix/data-format-lab` is provenance, not a compatibility
  commitment; this repository's first published contracts define v1.
