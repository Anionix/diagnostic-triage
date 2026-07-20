from __future__ import annotations

import copy
import hashlib
import json
import re
import unittest
from collections import Counter
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from jsonschema.protocols import Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas" / "diagnostic-triage" / "v1"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "v1"

VALID_SESSION_FIXTURES = {
    "valid-empty-session.jsonl",
    "valid-observer-session.jsonl",
    "valid-session.jsonl",
    "valid-unknown-optional-capability.jsonl",
}
VALID_REPORT_FIXTURES = {
    "valid-report.json",
    "valid-unsupported-report.json",
}
INVALID_SESSION_FIXTURES = {
    "invalid-completion-count.jsonl",
    "invalid-completion-nonfinal.jsonl",
    "invalid-duplicate-completion.jsonl",
    "invalid-duplicate-object-id.jsonl",
    "invalid-evidence-metadata.jsonl",
    "invalid-execution-attribution.jsonl",
    "invalid-fix-nonpatch-evidence.jsonl",
    "invalid-malformed-line.jsonl",
    "invalid-output-overflow.jsonl",
    "invalid-path-escape.jsonl",
    "invalid-provider-policy-event.jsonl",
    "invalid-protocol-version.jsonl",
    "invalid-required-capability.jsonl",
    "invalid-request-id.jsonl",
    "invalid-role-operation.jsonl",
    "invalid-sequence-gap.jsonl",
    "invalid-timeout-overrun.jsonl",
    "invalid-truncated-session.jsonl",
    "invalid-unnegotiated-event.jsonl",
}
EVENT_CAPABILITIES = {
    "observation": "diagnostic.check/v1",
    "fix_candidate": "fix.propose/v1",
    "execution": "execution.observe/v1",
}
ADAPTER_EVENTS = {
    "PROVIDER": {"observation", "evidence", "fix_candidate"},
    "OBSERVER": {"evidence", "execution"},
}
ADAPTER_OPERATIONS = {
    "PROVIDER": {"CHECK", "FIX", "VERIFY"},
    "OBSERVER": {"OBSERVE"},
}
EVENT_IDENTIFIERS = {
    "observation": ("observation", "observation_id"),
    "evidence": ("evidence", "evidence_id"),
    "fix_candidate": ("fix_candidate", "fix_candidate_id"),
    "execution": ("execution", "execution_id"),
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


class ContractSchemas:
    def __init__(self) -> None:
        self.schemas: dict[str, dict[str, Any]] = {
            path.name: load_json(path) for path in sorted(SCHEMA_DIR.glob("*.json"))
        }
        resources: list[tuple[str, Resource[Any]]] = [
            (cast(str, schema["$id"]), Resource.from_contents(schema))
            for schema in self.schemas.values()
        ]
        self.registry = Registry[Any]().with_resources(resources)
        self.format_checker = FormatChecker()

    def validator(self, name: str) -> Validator:
        return Draft202012Validator(
            self.schemas[name],
            registry=self.registry,
            format_checker=self.format_checker,
        )


class ContractError(ValueError):
    pass


class SessionError(ContractError):
    pass


def load_session(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or any(not line for line in lines):
        raise SessionError("session must contain non-empty JSON lines")
    parsed: list[dict[str, Any]] = []
    for number, line in enumerate(lines, start=1):
        try:
            event = json.loads(line, object_pairs_hook=reject_duplicate_keys)
            parsed.append(cast(dict[str, Any], event))
        except (json.JSONDecodeError, ValueError) as error:
            raise SessionError(f"line {number}: {error}") from error
    return parsed


def validate_location(location: dict[str, Any] | None) -> None:
    if location is None or "end" not in location:
        return
    start = location["start"]
    end = location["end"]
    if (end["line"], end["column"]) < (start["line"], start["column"]):
        raise ContractError("location end precedes start")


def validate_evidence(
    evidence: dict[str, Any], max_retained_bytes: int | None = None
) -> None:
    retained_bytes = evidence["retained_bytes"]
    if max_retained_bytes is not None and retained_bytes > max_retained_bytes:
        raise ContractError("evidence limit exceeded")
    if retained_bytes > evidence["observed_bytes"]:
        raise ContractError("retained bytes exceed observed bytes")
    if retained_bytes > evidence["limit_bytes"]:
        raise ContractError("retained bytes exceed evidence limit")
    expected_truncation = evidence["observed_bytes"] > retained_bytes
    if evidence["truncated"] != expected_truncation:
        raise ContractError("evidence truncation metadata is inconsistent")
    if "content" in evidence:
        content = evidence["content"].encode("utf-8")
        if retained_bytes != len(content):
            raise ContractError("retained byte count mismatch")
        if evidence["sha256"] != hashlib.sha256(content).hexdigest():
            raise ContractError("evidence digest mismatch")


def validate_execution(execution: dict[str, Any]) -> None:
    phases = execution["phases_ms"]
    components = [phases[name] for name in ("queue", "setup", "run", "normalize")]
    total = phases["total"]
    if isinstance(total, int) and "UNAVAILABLE" not in components:
        expected_total = sum(value for value in components if isinstance(value, int))
        if total != expected_total:
            raise ContractError("execution phase total is inconsistent")
    elif total == "NOT_APPLICABLE" and any(
        value != "NOT_APPLICABLE" for value in components
    ):
        raise ContractError("non-applicable total has recorded execution phases")

    run_duration = phases["run"]
    performance = execution["performance"]
    if isinstance(run_duration, int) and performance["status"] != "NOT_EVALUATED":
        expected_status = (
            "IMPROVEMENT_CANDIDATE"
            if run_duration > performance["budget_ms"]
            else "WITHIN_BUDGET"
        )
        if performance["status"] != expected_status:
            raise ContractError("execution performance status is inconsistent")


# LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED ->
# VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.
def validate_report(report: dict[str, Any], contracts: ContractSchemas) -> None:
    try:
        contracts.validator("model.schema.json").validate(report)
    except ValidationError as error:
        raise ContractError(error.message) from error
    groups = {
        "observations": "observation_id",
        "findings": "finding_id",
        "decisions": "decision_id",
        "evidence": "evidence_id",
        "fix_candidates": "fix_candidate_id",
        "executions": "execution_id",
    }
    indexed: dict[str, dict[str, dict[str, Any]]] = {}
    all_ids: set[str] = set()
    for group, identifier_key in groups.items():
        values: dict[str, dict[str, Any]] = {}
        for value in report[group]:
            identifier = value[identifier_key]
            if identifier in all_ids:
                raise ContractError(f"duplicate report object id: {identifier}")
            all_ids.add(identifier)
            values[identifier] = value
        indexed[group] = values

    evidence_by_id = indexed["evidence"]
    evidence_ids = set(evidence_by_id)
    for evidence in evidence_by_id.values():
        validate_evidence(evidence)

    observation_by_id = indexed["observations"]
    observation_ids = set(observation_by_id)
    for observation in observation_by_id.values():
        validate_location(observation.get("location"))
        if not set(observation["evidence_ids"]) <= evidence_ids:
            raise ContractError("observation references unknown evidence")

    finding_by_id = indexed["findings"]
    finding_ids = set(finding_by_id)
    fix_ids = set(indexed["fix_candidates"])
    execution_by_id = indexed["executions"]
    execution_ids = set(execution_by_id)
    for finding in finding_by_id.values():
        validate_location(finding.get("location"))
        if not set(finding["observation_ids"]) <= observation_ids:
            raise ContractError("finding references unknown observation")
        if not set(finding["evidence_ids"]) <= evidence_ids:
            raise ContractError("finding references unknown evidence")
        if finding.get("fix_candidate_id") not in (None, *fix_ids):
            raise ContractError("finding references unknown fix candidate")
        if not set(finding.get("verification_execution_ids", ())) <= execution_ids:
            raise ContractError("finding references unknown verification execution")
        if finding["state"] == "VERIFIED" and any(
            execution_by_id[identifier]["status"] != "COMPLETE"
            for identifier in finding["verification_execution_ids"]
        ):
            raise ContractError("verified finding cites incomplete execution")

    decision_findings: list[str] = []
    for decision in indexed["decisions"].values():
        finding_id = decision["finding_id"]
        if finding_id not in finding_ids:
            raise ContractError("decision references unknown finding")
        decision_findings.append(finding_id)
        if decision["policy_digest"] != report["policy_digest"]:
            raise ContractError("decision policy digest differs from report")
        if "waiver" in decision:
            expected = finding_by_id[finding_id]["fingerprint"]
            if decision["waiver"]["fingerprint"] != expected:
                raise ContractError("waiver fingerprint differs from finding")
    if len(decision_findings) != len(set(decision_findings)):
        raise ContractError("finding has multiple policy decisions")
    if set(decision_findings) != finding_ids:
        raise ContractError("every finding requires one policy decision")

    for candidate in indexed["fix_candidates"].values():
        if not set(candidate["observation_ids"]) <= observation_ids:
            raise ContractError("fix references unknown observation")
        patch_id = candidate["patch_evidence_id"]
        if patch_id not in evidence_ids:
            raise ContractError("fix references unknown patch evidence")
        if evidence_by_id[patch_id]["source"] != "PATCH":
            raise ContractError("fix evidence is not a patch")

    for execution in indexed["executions"].values():
        validate_execution(execution)


def validate_session(path: Path, contracts: ContractSchemas) -> None:
    events = load_session(path)
    validator = contracts.validator("protocol.schema.json")
    for event in events:
        errors = sorted(
            validator.iter_errors(event),
            key=lambda error: list(error.path),
        )
        if errors:
            raise SessionError(errors[0].message)

    if len(events) < 3 or events[0]["kind"] != "manifest":
        raise SessionError("manifest must be first")
    if events[1]["kind"] != "request":
        raise SessionError("exactly one request must follow manifest")
    if events[-1]["kind"] != "completion":
        raise SessionError("completion must be final")

    manifest = events[0]
    request = events[1]
    completion = events[-1]
    request_id = request["request_id"]
    adapter_kind = manifest["adapter"]["kind"]
    if request["operation"] not in ADAPTER_OPERATIONS[adapter_kind]:
        raise SessionError("adapter role does not support the requested operation")
    capabilities = set(manifest["adapter"]["capabilities"])
    required_capabilities = set(request["required_capabilities"])
    if not required_capabilities <= capabilities:
        raise SessionError("required capability is unsupported")

    requested_capabilities = required_capabilities | set(
        request["optional_capabilities"]
    )
    negotiated_capabilities = capabilities & requested_capabilities

    payload_events = events[2:-1]
    if len(payload_events) > request["limits"]["max_events"]:
        raise SessionError("event limit exceeded")

    sequenced = [*payload_events, completion]
    for expected_sequence, event in enumerate(sequenced):
        if event["request_id"] != request_id:
            raise SessionError("request_id mismatch")
        if event["sequence"] != expected_sequence:
            raise SessionError("non-contiguous sequence")

    counts = Counter(event["kind"] for event in payload_events)
    expected_counts = {
        "observations": counts["observation"],
        "evidence": counts["evidence"],
        "fix_candidates": counts["fix_candidate"],
        "executions": counts["execution"],
    }
    if completion["counts"] != expected_counts:
        raise SessionError("completion counts do not match events")
    if completion["tool_duration_ms"] > request["limits"]["timeout_ms"]:
        raise SessionError("adapter exceeded the requested timeout")

    raw_lines = path.read_bytes().splitlines(keepends=True)
    provider_stdout_bytes = sum(
        len(line)
        for line, event in zip(raw_lines, events, strict=True)
        if event["kind"] != "request"
    )
    if provider_stdout_bytes > request["limits"]["max_stdout_bytes"]:
        raise SessionError("adapter stdout limit exceeded")

    evidence_by_id: dict[str, dict[str, Any]] = {}
    observations: set[str] = set()
    object_ids: set[str] = set()
    retained_bytes = 0
    for event in payload_events:
        event_kind = event["kind"]
        if event_kind not in ADAPTER_EVENTS[adapter_kind]:
            raise SessionError(f"{adapter_kind.lower()} cannot emit {event_kind}")
        required_capability = EVENT_CAPABILITIES.get(event_kind)
        if (
            required_capability is not None
            and required_capability not in negotiated_capabilities
        ):
            raise SessionError(f"event capability was not negotiated: {event_kind}")

        identifier_path = EVENT_IDENTIFIERS[event_kind]
        identifier = event[identifier_path[0]][identifier_path[1]]
        if identifier in object_ids:
            raise SessionError(f"duplicate object id: {identifier}")
        object_ids.add(identifier)

        if event["kind"] == "evidence":
            evidence = event["evidence"]
            evidence_by_id[evidence["evidence_id"]] = evidence
            retained_bytes += evidence["retained_bytes"]
            validate_evidence(evidence, request["limits"]["max_evidence_bytes"])
        elif event["kind"] == "observation":
            observation = event["observation"]
            observations.add(observation["observation_id"])
            validate_location(observation.get("location"))
        elif event["kind"] == "execution":
            execution = event["execution"]
            if execution["adapter_id"] != manifest["adapter"]["id"]:
                raise SessionError("execution adapter id differs from manifest")
            if execution["adapter_kind"] != adapter_kind:
                raise SessionError("execution adapter kind differs from manifest")
            validate_execution(execution)

    if completion["evidence_bytes"] != retained_bytes:
        raise SessionError("completion evidence byte count mismatch")

    evidence_ids = set(evidence_by_id)
    for event in payload_events:
        if event["kind"] == "observation":
            if not set(event["observation"]["evidence_ids"]) <= evidence_ids:
                raise SessionError("observation references unknown evidence")
        elif event["kind"] == "fix_candidate":
            candidate = event["fix_candidate"]
            if not set(candidate["observation_ids"]) <= observations:
                raise SessionError("fix references unknown observation")
            if candidate["patch_evidence_id"] not in evidence_ids:
                raise SessionError("fix references unknown patch evidence")
            if evidence_by_id[candidate["patch_evidence_id"]]["source"] != "PATCH":
                raise SessionError("fix evidence is not a patch")


class ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contracts = ContractSchemas()

    def test_schemas_are_valid_and_ids_are_unique(self) -> None:
        identifiers: list[str] = []
        for schema in self.contracts.schemas.values():
            Draft202012Validator.check_schema(schema)
            identifiers.append(cast(str, schema["$id"]))
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_valid_sessions(self) -> None:
        actual = {path.name for path in FIXTURE_DIR.glob("valid-*.jsonl")}
        self.assertEqual(actual, VALID_SESSION_FIXTURES)
        for name in sorted(VALID_SESSION_FIXTURES):
            with self.subTest(name=name):
                validate_session(FIXTURE_DIR / name, self.contracts)

    def test_invalid_sessions(self) -> None:
        paths = sorted(FIXTURE_DIR.glob("invalid-*.jsonl"))
        self.assertEqual({path.name for path in paths}, INVALID_SESSION_FIXTURES)
        for path in paths:
            with self.subTest(name=path.name), self.assertRaises(ContractError):
                validate_session(path, self.contracts)

    def test_session_report(self) -> None:
        actual = {path.name for path in FIXTURE_DIR.glob("valid-*.json")}
        self.assertEqual(actual, VALID_REPORT_FIXTURES)
        for name in sorted(VALID_REPORT_FIXTURES):
            with self.subTest(name=name):
                validate_report(load_json(FIXTURE_DIR / name), self.contracts)

    def test_missing_required_capability_becomes_unsupported(self) -> None:
        handshake = load_json(FIXTURE_DIR / "handshake-unsupported.json")
        self.assertEqual(
            set(handshake),
            {
                "schema_version",
                "manifest",
                "required_capabilities",
                "session_report_fixture",
            },
        )
        self.contracts.validator("protocol.schema.json").validate(
            handshake["manifest"]
        )
        capabilities = set(handshake["manifest"]["adapter"]["capabilities"])
        required = set(handshake["required_capabilities"])
        self.assertFalse(required <= capabilities)
        report = load_json(FIXTURE_DIR / handshake["session_report_fixture"])
        validate_report(report, self.contracts)
        self.assertEqual(report["verdict"], "UNSUPPORTED")
        required_executions = [
            execution for execution in report["executions"] if execution["required"]
        ]
        self.assertTrue(required_executions)
        self.assertTrue(
            all(
                execution["status"] == "UNSUPPORTED"
                for execution in required_executions
            )
        )

    def test_report_semantic_invariants(self) -> None:
        report = load_json(FIXTURE_DIR / "valid-report.json")
        candidates: dict[str, dict[str, Any]] = {}

        dangling = copy.deepcopy(report)
        dangling["findings"][0]["observation_ids"] = [
            "019f7e95-0000-7000-8000-000000009999"
        ]
        candidates["dangling reference"] = dangling

        duplicate = copy.deepcopy(report)
        duplicate["evidence"].append(copy.deepcopy(duplicate["evidence"][0]))
        candidates["duplicate id"] = duplicate

        corrupt_evidence = copy.deepcopy(report)
        corrupt_evidence["evidence"][0]["sha256"] = "f" * 64
        candidates["evidence digest"] = corrupt_evidence

        reversed_location = copy.deepcopy(report)
        reversed_location["findings"][0]["location"]["end"] = {
            "line": 6,
            "column": 1,
        }
        candidates["reversed location"] = reversed_location

        inconsistent_timing = copy.deepcopy(report)
        inconsistent_timing["executions"][0]["phases_ms"]["total"] = 185
        candidates["phase total"] = inconsistent_timing

        inconsistent_performance = copy.deepcopy(report)
        inconsistent_performance["executions"][0]["performance"]["budget_ms"] = 100
        candidates["performance status"] = inconsistent_performance

        inconsistent_cache = copy.deepcopy(report)
        inconsistent_cache["executions"][0]["cache"]["restore_ms"] = 1
        candidates["cache availability"] = inconsistent_cache

        inconsistent_retry = copy.deepcopy(report)
        inconsistent_retry["executions"][0]["retry"] = {
            "status": "UNAVAILABLE",
            "attempt": 1,
            "same_revision": True,
        }
        candidates["retry availability"] = inconsistent_retry

        inconsistent_runner = copy.deepcopy(report)
        inconsistent_runner["executions"][0]["runner"] = {
            "status": "UNAVAILABLE",
            "os": "linux",
        }
        candidates["runner availability"] = inconsistent_runner

        invalid_tool = copy.deepcopy(report)
        invalid_tool["executions"][0]["tool"]["name"] = ""
        candidates["tool identity"] = invalid_tool

        failed_verification = copy.deepcopy(report)
        failed_verification["evidence"][0]["source"] = "PATCH"
        failed_verification["fix_candidates"] = [
            {
                "schema_version": "diagnostic-triage.fix-candidate/v1",
                "fix_candidate_id": "019f7e95-0000-7000-8000-000000000107",
                "observation_ids": [
                    failed_verification["observations"][0]["observation_id"]
                ],
                "applicability": "SAFE",
                "tool_native": True,
                "patch_evidence_id": failed_verification["evidence"][0][
                    "evidence_id"
                ],
            }
        ]
        finding = failed_verification["findings"][0]
        finding["state"] = "VERIFIED"
        finding["fix_candidate_id"] = failed_verification["fix_candidates"][0][
            "fix_candidate_id"
        ]
        finding["verification_execution_ids"] = [
            failed_verification["executions"][0]["execution_id"]
        ]
        execution = failed_verification["executions"][0]
        execution["status"] = "INCOMPLETE"
        execution["exit_code"] = None
        execution["message"] = "verification provider timed out"
        candidates["failed verification"] = failed_verification

        missing_decision = copy.deepcopy(report)
        missing_decision["decisions"] = []
        candidates["missing decision"] = missing_decision

        for name, candidate in candidates.items():
            with self.subTest(name=name), self.assertRaises(ContractError):
                validate_report(candidate, self.contracts)

    def test_request_rejects_noncanonical_paths(self) -> None:
        request = load_session(
            FIXTURE_DIR / "valid-empty-session.jsonl"
        )[1]
        validator = self.contracts.validator("protocol.schema.json")
        invalid_paths = (
            "/absolute",
            "../escape",
            "nested/../escape",
            "C:drive-relative",
            "C:/absolute",
            "windows\\path",
            "nul\x00path",
            "double//separator",
            "dot/./segment",
            "trailing/",
        )
        for invalid_path in invalid_paths:
            candidate = copy.deepcopy(request)
            candidate["targets"] = [invalid_path]
            with self.subTest(path=repr(invalid_path)):
                self.assertTrue(list(validator.iter_errors(candidate)))

    def test_model_schema_matches_rust_wire_boundaries(self) -> None:
        validator = self.contracts.validator("model.schema.json")
        report = load_json(FIXTURE_DIR / "valid-report.json")
        protocol_validator = self.contracts.validator("protocol.schema.json")
        manifest = load_session(FIXTURE_DIR / "valid-empty-session.jsonl")[0]

        for valid_id in ("a", "github-actions", "a" * 128):
            report["executions"][0]["adapter_id"] = valid_id
            manifest["adapter"]["id"] = valid_id
            validator.validate(report)
            protocol_validator.validate(manifest)

        invalid_ids = (
            "",
            "GitHub Actions",
            "abc\n",
            "abc\r",
            "abc\r\n",
            "abc\u2028",
            "a" * 129,
        )
        for invalid_id in invalid_ids:
            report["executions"][0]["adapter_id"] = invalid_id
            manifest["adapter"]["id"] = invalid_id
            with self.subTest(adapter_id=repr(invalid_id)):
                self.assertTrue(list(validator.iter_errors(report)))
                self.assertTrue(list(protocol_validator.iter_errors(manifest)))

        for field in ("line", "column"):
            report = load_json(FIXTURE_DIR / "valid-report.json")
            position = report["observations"][0]["location"]["start"]
            for valid_value in (1, 4_294_967_295):
                position[field] = valid_value
                validator.validate(report)
            for invalid_value in (0, 4_294_967_296):
                position[field] = invalid_value
                with self.subTest(field=field, value=invalid_value):
                    self.assertTrue(list(validator.iter_errors(report)))

    def test_finding_rejects_policy_verdict(self) -> None:
        report = load_json(FIXTURE_DIR / "valid-report.json")
        finding = copy.deepcopy(report["findings"][0])
        finding["verdict"] = "POLICY_FAIL"
        errors = list(
            self.contracts.validator("model.schema.json").iter_errors(finding)
        )
        self.assertTrue(errors)

    def test_waiver_is_bound_to_a_fingerprint(self) -> None:
        report = load_json(FIXTURE_DIR / "valid-report.json")
        decision = copy.deepcopy(report["decisions"][0])
        decision["action"] = "WAIVE"
        decision["waiver"] = {
            "waived_action": "BLOCK",
            "reason": "accepted until the upstream fix lands",
            "owner": "maintainers",
            "expires_at": "2026-08-20T00:00:00Z",
        }
        validator = self.contracts.validator("model.schema.json")
        self.assertTrue(list(validator.iter_errors(decision)))
        decision["waiver"]["fingerprint"] = "dtfp1:" + "f" * 64
        report["decisions"][0] = decision
        with self.assertRaises(ContractError):
            validate_report(report, self.contracts)
        decision["waiver"]["fingerprint"] = report["findings"][0]["fingerprint"]
        validate_report(report, self.contracts)

    def test_taxonomy_document_matches_schema(self) -> None:
        taxonomy = self.contracts.schemas["taxonomy.schema.json"]
        schema_pairs = {
            branch["properties"]["category"]["const"]: set(
                branch["properties"]["micro_category"]["enum"]
            )
            for branch in taxonomy["oneOf"]
        }
        text = (ROOT / "docs" / "contracts" / "taxonomy-v1.md").read_text(
            encoding="utf-8"
        )
        document_pairs: dict[str, set[str]] = {}
        for line in text.splitlines():
            if not line.startswith("| `"):
                continue
            values = re.findall(r"`([^`]+)`", line)
            document_pairs[values[0]] = set(values[1:])
        self.assertEqual(schema_pairs, document_pairs)

    def test_prototype_provenance_is_pinned(self) -> None:
        provenance = load_json(
            ROOT
            / "provenance"
            / "imports"
            / "data-format-lab-diagnostic-triage-v0.json"
        )
        self.assertEqual(
            provenance["source_main_revision"],
            "f582eb40732a492841fd816dda3bfa13663a96a2",
        )
        self.assertEqual(provenance["license"], "Apache-2.0")
        expected_artifacts = {
            "docs/adr/0004-diagnostic-triage-contracts.md": (
                "1dd4b1f8aa31fd8dec1c20565d46365002bf7e92",
                "26b4981097f45a001c478537509f6b0fadaadb912017aa82ce2c04b7411fecd6",
            ),
            "docs/diagnostic-triage/taxonomy.md": (
                "b278f96f80d49822b20ab70de7e191fa1f64188e",
                "b5e7ec134aed6fd589db69d93960e06d9f2708520953cbdf0f0e3305da39192b",
            ),
            "schemas/diagnostic-triage/v1/finding.schema.json": (
                "9bd507074e96b426c12a1ef84f275f3049714753",
                "09f42be98a55abd7b165bdd30e6671b08abcf7bc5579ca8ba5dff5930d50d4ca",
            ),
            "tests/test_diagnostic_triage_contracts.py": (
                "08e2ece8d8fffe44fbb6f648a045105dbe14bcfa",
                "aaf039ec79fc6fe0227e97ac18dbf0067c3712f0b2b0a8565b7bd0799d130b89",
            ),
        }
        actual_artifacts = {
            artifact["path"]: (artifact["git_blob_oid"], artifact["sha256"])
            for artifact in provenance["committed_artifacts"]
        }
        self.assertEqual(actual_artifacts, expected_artifacts)
        self.assertTrue(
            all(
                artifact["source_revision"] == provenance["source_main_revision"]
                for artifact in provenance["committed_artifacts"]
            )
        )


if __name__ == "__main__":
    unittest.main()
