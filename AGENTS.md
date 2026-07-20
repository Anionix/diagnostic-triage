# Repository Instructions

## GitHub workflow

- This is an owner-original repository. Never stack pull requests.
- Start every branch from the latest `origin/main` and use one PR per task.
- Treat about 250 human-authored lines as a review-risk signal, not a target.
- Isolate generated lockfiles in a dedicated PR.
- Follow the review closeout procedure in `docs/agents/issue-tracker.md`.

## Architecture

- Keep the stable public interface to the CLI, config, JSON/JSONL contracts,
  and exit codes. Rust crates remain `publish = false` for v1.
- Keep dependencies directed as `contracts <- engine <- runtime <- cli`.
- Providers and observers depend on contracts and communicate over versioned
  JSON Lines. Do not bypass that seam for first-party implementations.
- Validate all provider, observer, config, path, and patch input at the system
  edge. Enforce time, byte, item, and event-count limits before buffering or
  processing untrusted input. Never execute shell command strings or accept
  absolute repository paths.
- Put this exact contract beside diagnostic lifecycle transitions:
  `// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.`

## Safety and reproducibility

- `check` and `ci` must not modify tracked files.
- Generate fixes in a scratch copy. Apply only authoritative safe fixes after
  before/after verification and only with an explicit flag.
- Keep `flake.nix`, `flake.lock`, Cargo manifests, and `Cargo.lock` current.
- Pin GitHub Actions by immutable commit and releases by source revision.
- Do not commit tool output, tokens, benchmark artifacts, or machine-specific
  absolute paths.

## Required checks

- Before each PR, use the code-review skill against `origin/main` for both
  repository standards and the originating issue/specification.
- Run `cargo fmt --check`, Clippy with warnings denied, tests, schema/fixture
  contract tests, and `nix flake check` as soon as those gates exist.

## Domain and tracking

- Use the single domain context in `CONTEXT.md` and ADRs under `docs/adr/`.
- GitHub Issues are the canonical tracker. See `docs/agents/issue-tracker.md`.
- Use the canonical triage roles in `docs/agents/triage-labels.md`.
