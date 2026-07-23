# Diagnostic Triage v0.1.0-alpha.1

This is the first pre-alpha release of the standalone Diagnostic Triage engine.
The CLI, configuration, JSON/JSONL schemas, and exit-code contract are the
intended public surfaces. Compatibility may still change before the first alpha;
consumers must pin the release commit SHA or a Nix lock.

The release contains native macOS binaries and static-musl Linux binaries for
x86_64 and aarch64, the first-party Providers and GitHub Actions Observer,
schemas, golden fixtures, provenance, the Nix flake, a deterministic release
manifest, SHA-256 checksums, and Sigstore keyless bundles.

Unsupported or intentionally limited surfaces:

- There is no public Rust SDK; all Rust crates remain `publish = false`.
- Diagnostic Triage does not implicitly connect to GitHub or post Issues.
- `fix --apply-safe` v1 publishes only one canonical Ruff SAFE edit to an
  existing regular file on Linux or macOS.
- Unsupported adapters, preview/style rules, and performance improvement
  candidates do not become blocking failures by default.
- Test selection, scheduling, skipping, and OTLP export are not included.

Verify a downloaded asset with its adjacent bundle:

```text
identity='^https://github.com/Anionix/diagnostic-triage/'\
'.github/workflows/release.yml@'
cosign verify-blob \
  --bundle <asset>.sigstore.json \
  --certificate-identity-regexp "${identity}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  <asset>
```

Then verify `SHA256SUMS`, extract the platform archive, and run:

```text
bin/diagnostic-triage --version
```

Nix consumers should pin this repository in `flake.lock` and use
`packages.<system>.diagnostic-triage`; normal CI never downloads schemas from
the network.
