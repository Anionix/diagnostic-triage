# Diagnostic Triage Context

Diagnostic Triage converts heterogeneous tool output into policy-independent
observations, normalized findings, repository decisions, and reproducible
session reports.

## Canonical terms

- **Provider**: an executable adapter that collects tool-native diagnostics.
- **Observer**: an executable adapter that imports execution metadata without
  selecting, skipping, or scheduling tests.
- **Observation**: untrusted, policy-independent input emitted by a Provider.
- **Finding**: an Engine-normalized and fingerprinted diagnostic.
- **Decision**: a repository Policy result for one Finding.
- **Evidence**: bounded raw or derived material supporting an Observation.
- **Execution**: bounded process and CI timing/status evidence.
- **Session report**: the deterministic aggregate and final Verdict.

## Ownership

This repository is the only owner of the generic taxonomy, schemas, protocol,
Engine, first-party adapters, fixtures, and release artifacts. Consumer
repositories own only their config, policy, integration fixtures, and immutable
source pin. Generic contracts must not be copied and edited in consumers.

## Non-goals for v1

- Replacing language tools or inventing independent AST rewrites.
- Public Rust SDK or stable crate interfaces.
- Remote execution, test selection, test skipping, or scheduling.
- Automatic Issue creation or implicit network access.
