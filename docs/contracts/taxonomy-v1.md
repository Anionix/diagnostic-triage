# Diagnostic Triage Taxonomy v1

The taxonomy classifies evidence-backed Findings; it does not infer root cause
from prose alone. Category and micro-category identifiers are stable and never
renamed or reused. Additive identifiers require compatible schema and fixture
updates; semantic changes require taxonomy v2.

Every Finding has one primary classification. When structured evidence cannot
support a specific micro-category, use that category's `unknown` member.

| Category | Stable micro-categories |
|---|---|
| `syntax` | `parse-error`, `invalid-token`, `invalid-structure`, `unknown` |
| `type` | `incompatible-type`, `missing-type`, `nullability`, `unresolved-symbol`, `invalid-call`, `contract-mismatch`, `unknown` |
| `correctness` | `assertion`, `invariant`, `wrong-result`, `data-loss`, `state-transition`, `nondeterminism`, `unknown` |
| `runtime` | `exception`, `panic`, `abort`, `signal`, `import-failure`, `initialization`, `unknown` |
| `build` | `compile`, `link`, `dependency-resolution`, `code-generation`, `configuration`, `unknown` |
| `test` | `collection`, `setup`, `assertion`, `teardown`, `flaky`, `coverage-gate`, `unknown` |
| `resource` | `timeout`, `memory-limit`, `disk-limit`, `output-limit`, `file-descriptor-limit`, `unknown` |
| `concurrency` | `race`, `deadlock`, `livelock`, `ordering`, `atomicity`, `unknown` |
| `security` | `input-validation`, `path-escape`, `injection`, `unsafe-deserialization`, `permission`, `secret-exposure`, `unknown` |
| `environment` | `tool-missing`, `version-mismatch`, `platform`, `locale`, `timezone`, `network`, `filesystem`, `unknown` |
| `tooling` | `protocol`, `malformed-output`, `provider-crash`, `unsupported-version`, `configuration`, `unknown` |
| `style` | `format`, `lint`, `documentation`, `complexity`, `deprecation`, `unknown` |
| `robustness` | `boundary-input`, `malformed-input`, `crash-resistance`, `roundtrip-mismatch`, `fuzz-finding`, `unknown` |

## Classification rules

1. Preserve native tool, version, and rule identity; taxonomy does not replace
   authoritative identifiers.
2. Prefer the direct defect. A test exposing a type defect is `type`; failure to
   collect the test is `test.collection`.
3. Provider/protocol failure is an Execution status. Use `tooling` only when a
   completed tool diagnostic reports a tooling/configuration defect.
4. Use `resource` only when a declared bound is reached. An unexplained exit is
   `runtime.unknown` until evidence improves.
5. Use `security` only for a stated security invariant, never as severity.
6. CI latency and cache state belong to Execution, not this taxonomy.
7. `unknown` remains publishable and cannot be silently promoted.

Initial blocking policy is limited to ERROR Findings in `syntax`, `type`,
`correctness`, `build`, and `test`. Policy is consumer-owned and is not encoded
in the Finding contract.
