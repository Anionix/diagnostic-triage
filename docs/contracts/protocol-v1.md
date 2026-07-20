# Diagnostic Triage Provider Protocol v1

The v1 protocol is a bounded JSON Lines transcript between the Engine and one
Provider or Observer process. Each line is one UTF-8 JSON object. Blank lines,
duplicate object keys, trailing data, and non-UTF-8 input are invalid.

## Direction and order

1. The adapter writes one `manifest` line to stdout before reading stdin.
2. The Engine validates its version and required capabilities, then writes one
   `request` line to stdin.
3. The adapter writes zero or more `observation`, `evidence`, `fix_candidate`,
   or `execution` lines to stdout.
4. The adapter writes exactly one final `completion` line and exits.

The transcript fixtures interleave both directions to make the full session
contract testable. A runtime must still enforce the direction above.

Event `sequence` starts at zero and increments by one. Every post-manifest line
uses the request's UUID. Completion counts must equal the emitted event counts,
and `evidence_bytes` must equal the sum of retained evidence bytes.

Providers may emit `observation`, `evidence`, and `fix_candidate`; Observers may
emit `evidence` and `execution`. An `observation`, `fix_candidate`, or
`execution` event respectively requires negotiated `diagnostic.check/v1`,
`fix.propose/v1`, or `execution.observe/v1`. First-party adapters use this same
boundary and cannot emit Engine-owned Findings or Decisions. Providers accept
`CHECK`, `FIX`, and `VERIFY`; Observers accept only `OBSERVE`.

## Capabilities and versions

`protocol_version` is exactly `diagnostic-triage.protocol/v1`. Capabilities are
namespaced identifiers ending in `/v1`, for example `diagnostic.check/v1` and
`execution.observe/v1`. An unsupported required capability terminates the
session as `UNSUPPORTED`; unsupported optional capabilities are ignored. Since
capability negotiation precedes the Request, the Engine does not send a Request
when a required capability is absent. It records the `UNSUPPORTED` execution
and session outcome itself; a transcript containing such a Request is invalid.
The manifest-only outcome is fixed by `handshake-unsupported.json` and its
referenced `valid-unsupported-report.json` golden fixture.

Schema v1 is additive only. Changing an existing field's meaning, accepted
value set, ordering rule, error rule, or default requires protocol v2.

JSON Schema validates each envelope's shape. Transcript and report validators
add cross-object semantics that Draft 2020-12 cannot express portably: adapter
role and operation, negotiated event capabilities, manifest attribution,
sequence and count agreement, unique IDs, references, byte/digest consistency,
location ordering, waiver binding, and verified-execution status. Passing the
schema alone is therefore necessary but not a valid Diagnostic Triage session.

## Limits and paths

The request always carries limits. v1 hard maxima are 600,000 ms total runtime,
16 MiB aggregate adapter stdout, 4 MiB aggregate adapter stderr, 1 MiB per
Evidence, and 10,000 events. A runtime must enforce limits while streaming,
before buffering the full value. The transcript validator covers representable
stdout and duration overruns; stderr and process termination remain runtime
boundaries because they are not JSON Lines events.

Workspace and target paths are repository-relative POSIX paths. `.` is allowed
for the workspace root. Absolute paths, Windows drive paths, backslashes, NUL,
and a `..` segment are invalid. An Evidence path is validated by the same rule.

## Completion semantics

- `COMPLETE` means the adapter finished its requested operation and has an
  integer exit code. A diagnostic tool's nonzero code may still be complete.
- `INCOMPLETE` means malformed output, timeout, truncation, crash, or another
  operational failure. It requires a message and null exit code.
- `UNSUPPORTED` means the protocol, capability, language, or operation cannot
  be honored. It requires a message and null exit code.

No partial session is promoted to PASS. Providers emit Observations, not
Findings, fingerprints, Decisions, or final policy Verdicts.

Execution records name both the adapter and invoked tool. Queue, setup, run,
normalize, cache, retry, runner, and toolchain identity are explicit; unavailable
measurements use the contract's `UNAVAILABLE` value instead of inferred data.
