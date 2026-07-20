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

A `REPORTED` Finding records its last material lifecycle state in mandatory
`pre_report_state`: `CLASSIFIED`, `FIX_PROPOSED`, or `VERIFIED`. The field is
absent before `REPORTED`. Reporting a Finding does not erase its proof status:
`pre_report_state: VERIFIED` retains the same fix candidate and verification
execution references and remains subject to every VERIFIED invariant. This is
a structural lifecycle claim, not an append-only history or attestation.
`verification_execution_ids` record verification attempts, not success by
themselves. A `FIX_PROPOSED` Finding may retain failed or incomplete attempt
receipts. Every verification-attributed execution is still Provider-owned;
only an effective `VERIFIED` state additionally turns those references into a
verified-proof claim requiring a SAFE candidate and COMPLETE execution.

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

### Contract version compatibility

No alpha contract has been published. Before the first alpha release, v1
identifiers are provisional: contract corrections may add, remove, or require
fields and may change validation semantics. Pre-alpha consumers must pin the
immutable, full commit object ID from the canonical
`Anionix/diagnostic-triage` Git repository. A produced
`SessionReport.engine.source_revision` must equal that pin. The corresponding
`SessionReport.contract_sha256` is the lowercase SHA-256 of the revision's
lowercase ASCII object ID with no prefix, newline, or other terminator. Contract
validation checks this pair; consumers additionally compare `source_revision`
with their external source pin through `validate_report_for_revision` or an
equivalent runtime boundary. The pin itself supplies the expected bytes, so no
separate digest publication is required before release manifests exist. Golden
fixtures carry a fixed example identity and are contract examples, not release
reports. A different source revision or contract digest is a different
pre-alpha contract.

This comparison binds a report's claimed contract identity; it is not an
attestation that an untrusted producer ran that revision, and hashing a Git
object ID does not strengthen its provenance. Consumers that require producer
or artifact authenticity must separately verify the release manifest, artifact
digest, and signature once those release artifacts exist.

### Deterministic `SessionReport` assembly

`SessionReport` assembly is a pure function of its explicit inputs. Before
cloning or sorting any top-level collection, and before Decision materialization,
the Engine checks that every top-level collection it will emit contains at most
10,000 items; an over-limit collection is rejected at that boundary. The
Engine also streams its explicit input through a bounded JSON writer before
Decision materialization and checks the final encoded report after contract
validation; both enforce the 64 MiB v1 report limit without allocating an
aggregate JSON buffer. The Engine performs no filesystem or process I/O and
reads no clock or randomness source. `session_id` and `engine.source_revision`
are caller-owned inputs and are validated, not regenerated. `contract_sha256`,
`policy_digest`, and `verdict` are Engine-derived values and are not
caller-selected.

The canonical top-level order is ascending by canonical wire value of the
object ID for `observations`, `evidence`, `fix_candidates`, and `executions`;
ascending by `(fingerprint, finding_id)` for `findings`; and ascending by
`(finding_id, decision_id)` for `decisions`. Every nested array of identifier
or fingerprint references is sorted ascending by its canonical wire value.
For a nonempty `findings` collection, the caller supplies one validated
evaluation timestamp and every materialized Decision carries that timestamp;
with no Findings, no Decisions or evaluation timestamp is emitted.

Starting with the first alpha release, the whole published v1 boundary becomes
additive-only: schemas, protocol identifiers and events, taxonomy values, and
cross-object validation rules may gain only optional surface. Changing an
existing field's meaning, accepted value set, ordering rule, error rule,
required status, or default then requires protocol v2. Validators remain pinned
to an exact contract digest. Any additive v1 change creates a new digest and
requires an explicit consumer pin refresh; an older pinned validator may reject
members or events absent from its contract. Additive-only constrains evolution
between published v1 digests and is not an unknown-field fallback rule. Only
negotiated unknown optional capabilities are ignored.

JSON Schema validates each envelope's shape. Transcript and report validators
add cross-object semantics that Draft 2020-12 cannot express portably: adapter
role and operation, negotiated event capabilities, manifest attribution,
sequence and count agreement, unique IDs, references, byte/digest consistency,
location ordering, waiver binding, and verified-execution status. Passing the
schema alone is therefore necessary but not a valid Diagnostic Triage session.

### Timestamp profile

Waiver and policy-evaluation timestamps use a deterministic RFC 3339 subset:
calendar-valid years 0000 through 9998, seconds 00 through 59, optional
fractional seconds of one through nine digits, and either Z/z or a numeric
offset whose hour is 00 through 23 and minute is 00 through 59. Year 9999,
leap seconds, and precision finer than one nanosecond are unsupported in v1 so
every accepted value maps losslessly to the Engine timestamp used for expiry
comparisons. Every Decision records `evaluated_at` in this strict v1 RFC 3339
profile. All Decisions in one SessionReport represent the same parsed
evaluation instant; Engine producers reuse one `evaluated_at` wire value for
the entire report. Expiry comparison is by parsed instant, not by textual
ordering or offset spelling, and an active waiver expires strictly after
`evaluated_at`.

A report without Findings has no Decisions and therefore no policy-evaluation
instant. Its `PASS`, `INCOMPLETE`, or `UNSUPPORTED` verdict is determined from
the required Execution results; no placeholder Decision is emitted.

### Policy evaluation

Policy accepts valid Findings whose effective lifecycle is `CLASSIFIED`,
`FIX_PROPOSED`, or `VERIFIED`; a `REPORTED` Finding uses its mandatory
`pre_report_state`. Rules may match severity, taxonomy, fingerprint, language,
tool name, opaque case-sensitive tool version, and native rule ID. The highest
matching action wins under `OBSERVE < WARN < BLOCK`, with the lexicographically
smallest rule ID breaking equal-action ties across configured and implicit
default rules. A configured rule cannot weaken the default block for ERROR
Findings in `syntax`, `type`, `correctness`, `build`, or `test`.

One v1 policy snapshot contains at most 4,096 rules and 10,000 waivers. Bounds
are checked before Finding validation and before cloning, sorting, or hashing
the snapshot. For bounded input, Finding integrity precedes detailed policy
validation. Rule validation, waiver selection, policy digesting, and Decision
materialization form one atomic Engine boundary: exposing only a subset would
permit a Decision whose attribution is not bound to the exact validated policy
result.

Default Decisions use `default.observe` or the category-specific IDs
`default.error.syntax`, `default.error.type`, `default.error.correctness`,
`default.error.build`, and `default.error.test`; consumer rules cannot reserve
these IDs. Waivers match one exact fingerprint and one exact WARN or BLOCK
action. They require canonical nonblank reason and owner text and an expiry
strictly after the evaluation instant. Exact duplicate waivers are invalid.
If several active waivers match, the earliest expiry wins, followed by reason,
owner, and expiry wire text; input order never selects the winner.

The policy digest is versioned and independent of rule and waiver order.
Decision identity binds the Finding ID, policy digest, matched rule, action,
exact `evaluated_at` wire value, and optional waiver. Equivalent timestamp
spellings compare as the same instant for expiry but remain distinct Decision
identities.

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

The SessionReport verdict is derived, not caller-selected. Required executions
take precedence over policy: any required `INCOMPLETE` yields `INCOMPLETE`;
otherwise any required `UNSUPPORTED` yields `UNSUPPORTED`; otherwise any
`BLOCK` Decision yields `POLICY_FAIL`; otherwise the verdict is `PASS`.
Optional incomplete or unsupported executions do not affect the verdict, and
`OBSERVE`, `WARN`, and `WAIVE` Decisions are nonblocking.

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
