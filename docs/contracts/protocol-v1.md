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

### Pre-v1 release compatibility note

Before the first alpha release, consumers pin the exact contract SHA-256 digest
that they validate against. Strict validators pinned to an earlier v1 digest
may reject additive fields; pre-alpha v1 therefore does not claim old-reader
compatibility.

JSON Schema validates each envelope's shape. Transcript and report validators
add cross-object semantics that Draft 2020-12 cannot express portably: adapter
role and operation, negotiated event capabilities, manifest attribution,
sequence and count agreement, unique IDs, references, byte/digest consistency,
location ordering, waiver binding, and verified-execution status. Passing the
schema alone is therefore necessary but not a valid Diagnostic Triage session.

### Timestamp profile

Waiver timestamps use a deterministic RFC 3339 subset: calendar-valid years
0000 through 9998, seconds 00 through 59, optional fractional seconds of one
through nine digits, and either Z/z or a numeric offset whose hour is 00
through 23 and minute is 00 through 59. Year 9999, leap seconds, and precision
finer than one nanosecond are unsupported in v1 so every accepted value maps
losslessly to the Engine timestamp used for expiry comparisons.

The schema pattern enforces both the lexical profile and Gregorian month,
day, and leap-year bounds without lookaround extensions. The Draft 2020-12
date-time format remains a semantic annotation and optional second assertion;
correctness does not depend on a validator enabling format assertions.

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

## Verification and evidence attribution

A `FixCandidate.observation_ids` list defines the candidate's observation
scope. Every Finding with a `fix_candidate_id` must have all of its observations
covered by that scope. A Finding that cites verification
(`verification_execution_ids`) must also cite a `fix_candidate_id`. Each source Observation
and its Finding must use the same complete tool identity, including `rule_id`.
A candidate must not span different `tool.name`/`tool.version` identities, but
it may cover observations from multiple `rule_id` values for that one tool
version.

Execution records name both the adapter and invoked tool. Queue, setup, run,
normalize, cache, retry, runner, and toolchain identity are explicit; unavailable
measurements use the contract's `UNAVAILABLE` value instead of inferred data.
Runtime-synthesized Provider executions may include `verification`, a
structural receipt containing the `fix_candidate_id`, `patch_sha256`,
`base_snapshot_sha256`, `base_snapshot_evidence_id`, nonempty unique
`target_fingerprints`, and `result_evidence_id` for the verification result.
`base_snapshot_evidence_id` must identify dedicated `ARTIFACT` evidence with
media type `application/vnd.diagnostic-triage.snapshot+json` whose `sha256`
matches `base_snapshot_sha256`. Verification PATCH evidence must be complete,
not truncated, and inline. Snapshot Evidence must also use inline `content` so
its digest is recomputed during contract validation; a `relative_path` PATCH or
snapshot is not proof.
Snapshot and result evidence IDs must be distinct. Snapshot evidence must never
be truncated: `truncated` is `false` and `observed_bytes` equals
`retained_bytes`. A verification result Evidence
must set its optional `execution_id` to the owning verification execution; a
`COMPLETE` verification execution's result evidence must likewise never be
truncated and must be inline. Evidence omits `execution_id` unless it is owned
by an execution.
Any execution-owned Evidence must resolve to an Execution in the same complete
`SessionReport`. In a protocol transcript it must resolve to an Execution event
in that transcript, which remains subject to the normal final `completion`
requirement. These are structural links and
digest bindings in the SessionReport, not cryptographic attestations; they do
not by themselves prove patch provenance, execution integrity, or result
correctness. Request IDs are intentionally excluded because SessionReport has
no validated request collection. Observer and Engine executions cannot carry
it. The field is omitted when absent, never serialized as `null`; the Request
envelope does not carry a fix candidate, including for `VERIFY --patch`.
