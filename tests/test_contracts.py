from __future__ import annotations

import copy
import hashlib
import json
import re
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from jsonschema.protocols import Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

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
    "valid-verified-report.json",
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
RESULT_EVIDENCE_SOURCES = {"STDOUT", "DIAGNOSTIC", "ARTIFACT"}
SNAPSHOT_MEDIA_TYPE = "application/vnd.diagnostic-triage.snapshot+json"
DRAFT202012_DIALECT = "https://json-schema.org/draft/2020-12/schema"


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
            (
                cast(str, schema["$id"]),
                schema_resource(schema),
            )
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


def schema_resource(schema: dict[str, Any]) -> Resource[Any]:
    # Sources: https://json-schema.org/draft/2020-12/json-schema-core#section-8.1.1,
    # https://referencing.readthedocs.io/en/stable/api/#referencing.Specification.create_resource.
    # LLM contract: LOADED -> DIALECT_VERIFIED -> REGISTERED | REJECTED.
    if schema.get("$schema") != DRAFT202012_DIALECT:
        raise ContractError("schema dialect must be Draft 2020-12")
    return DRAFT202012.create_resource(schema)


class SessionError(ContractError):
    pass


_RFC3339_TIMESTAMP = re.compile(
    r"(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"[Tt](?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?"
    r"(?P<zone>[Zz]|(?P<sign>[+-])(?P<offset_hour>[0-9]{2})"
    r":(?P<offset_minute>[0-9]{2}))"
)


def parse_rfc3339_instant(value: str) -> int:
    """Return a v1 RFC 3339 timestamp as nanoseconds from year 0000-01-01."""
    match = _RFC3339_TIMESTAMP.fullmatch(value)
    if match is None:
        raise ContractError("decision timestamp must be an RFC 3339 date-time")

    parts = {
        name: int(match.group(name))
        for name in ("year", "month", "day", "hour", "minute", "second")
    }
    year = parts["year"]
    month = parts["month"]
    day = parts["day"]
    if year > 9998 or not 1 <= month <= 12 or not 0 <= parts["second"] <= 59:
        raise ContractError("decision timestamp must be an RFC 3339 date-time")
    if not 0 <= parts["hour"] <= 23 or not 0 <= parts["minute"] <= 59:
        raise ContractError("decision timestamp must be an RFC 3339 date-time")

    leap_year = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    month_lengths = (
        31,
        29 if leap_year else 28,
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    )
    if not 1 <= day <= month_lengths[month - 1]:
        raise ContractError("decision timestamp must be an RFC 3339 date-time")

    completed_years = 0 if year == 0 else year - 1
    leap_years = sum(
        completed_years // period + 1 if year else 0 for period in (4, 400)
    )
    leap_years -= 0 if year == 0 else completed_years // 100 + 1
    days_before_year = 365 * year + leap_years
    days_before_month = sum(month_lengths[: month - 1])
    local_seconds = (
        (days_before_year + days_before_month + day - 1) * 86_400
        + parts["hour"] * 3_600
        + parts["minute"] * 60
        + parts["second"]
    )
    fraction = match.group("fraction") or ""
    nanoseconds = int(fraction.ljust(9, "0") or "0")

    zone = match.group("zone")
    offset_seconds = 0
    if zone not in "Zz":
        offset_hour = int(match.group("offset_hour"))
        offset_minute = int(match.group("offset_minute"))
        if offset_hour > 23 or offset_minute > 59:
            raise ContractError("decision timestamp must be an RFC 3339 date-time")
        offset_seconds = (offset_hour * 60 + offset_minute) * 60
        if match.group("sign") == "-":
            offset_seconds = -offset_seconds
    return (local_seconds - offset_seconds) * 1_000_000_000 + nanoseconds


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


def validate_execution_attribution(
    execution: dict[str, Any],
    candidates: dict[str, dict[str, Any]],
    evidence_by_id: dict[str, dict[str, Any]],
) -> None:
    verification = execution.get("verification")
    if verification is None:
        return
    if execution["adapter_kind"] != "PROVIDER":
        raise ContractError(
            "verification attribution is valid only for Provider executions"
        )
    candidate_id = verification["fix_candidate_id"]
    candidate = candidates.get(candidate_id)
    if candidate is None:
        raise ContractError("execution verification references unknown fix candidate")
    patch = evidence_by_id.get(candidate["patch_evidence_id"])
    if patch is None:
        raise ContractError("execution verification references unknown patch evidence")
    if patch["source"] != "PATCH":
        raise ContractError("execution verification patch evidence is not a patch")
    if patch["truncated"]:
        raise ContractError("execution verification patch evidence is truncated")
    if "content" not in patch:
        raise ContractError("execution verification patch evidence must be inline")
    if verification["patch_sha256"] != patch["sha256"]:
        raise ContractError(
            "execution verification patch digest differs from patch evidence"
        )

    base_snapshot = evidence_by_id.get(verification["base_snapshot_evidence_id"])
    if base_snapshot is None:
        raise ContractError(
            "execution verification references unknown base snapshot evidence"
        )
    if base_snapshot["source"] != "ARTIFACT":
        raise ContractError(
            "execution verification base snapshot evidence is not an artifact"
        )
    if "content" not in base_snapshot:
        raise ContractError(
            "execution verification base snapshot evidence must be inline"
        )
    if base_snapshot["media_type"] != SNAPSHOT_MEDIA_TYPE:
        raise ContractError(
            "execution verification base snapshot evidence has an invalid media type"
        )
    if base_snapshot["truncated"]:
        raise ContractError(
            "execution verification base snapshot evidence is truncated"
        )
    if verification["base_snapshot_sha256"] != base_snapshot["sha256"]:
        raise ContractError(
            "execution verification base snapshot digest differs from snapshot evidence"
        )

    if verification["base_snapshot_evidence_id"] == verification["result_evidence_id"]:
        raise ContractError(
            "execution verification base and result evidence must be distinct"
        )
    result = evidence_by_id.get(verification["result_evidence_id"])
    if result is None:
        raise ContractError("execution verification references unknown result evidence")
    if result["source"] not in RESULT_EVIDENCE_SOURCES:
        raise ContractError(
            "execution verification result evidence has an invalid source"
        )
    if result["media_type"] == SNAPSHOT_MEDIA_TYPE:
        raise ContractError(
            "execution verification result evidence cannot use snapshot media type"
        )
    if execution["status"] == "COMPLETE" and result["truncated"]:
        raise ContractError("complete execution result evidence must not be truncated")
    if execution["status"] == "COMPLETE" and "content" not in result:
        raise ContractError("complete verification result evidence must be inline")
    if result.get("execution_id") != execution["execution_id"]:
        raise ContractError(
            "execution verification result evidence belongs to a different execution"
        )


def verified_report_with_attribution() -> dict[str, Any]:
    report = load_json(FIXTURE_DIR / "valid-verified-report.json")
    alternate = copy.deepcopy(report["fix_candidates"][0])
    alternate["fix_candidate_id"] = "019f7e95-0000-7000-8000-000000000111"
    report["fix_candidates"].append(alternate)
    return report


# LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED ->
# VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.
def validate_report(
    report: dict[str, Any],
    contracts: ContractSchemas,
    expected_source_revision: str | None = None,
) -> None:
    try:
        contracts.validator("model.schema.json").validate(report)
    except ValidationError as error:
        raise ContractError(error.message) from error
    expected_contract_digest = hashlib.sha256(
        report["engine"]["source_revision"].encode("ascii")
    ).hexdigest()
    if report["contract_sha256"] != expected_contract_digest:
        raise ContractError("contract digest differs from engine source revision")
    if (
        expected_source_revision is not None
        and report["engine"]["source_revision"] != expected_source_revision
    ):
        raise ContractError("engine source revision differs from consumer pin")
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

    execution_by_id = indexed["executions"]
    execution_ids = set(execution_by_id)
    evidence_by_id = indexed["evidence"]
    evidence_ids = set(evidence_by_id)
    for evidence in evidence_by_id.values():
        validate_evidence(evidence)
        if (
            execution_id := evidence.get("execution_id")
        ) is not None and execution_id not in execution_ids:
            raise ContractError("evidence references unknown execution")

    observation_by_id = indexed["observations"]
    observation_ids = set(observation_by_id)
    for observation in observation_by_id.values():
        validate_location(observation.get("location"))
        if not set(observation["evidence_ids"]) <= evidence_ids:
            raise ContractError("observation references unknown evidence")

    finding_by_id = indexed["findings"]
    finding_ids = set(finding_by_id)
    fix_ids = set(indexed["fix_candidates"])
    cited_fingerprints_by_execution: dict[str, set[str]] = {}
    fingerprints: set[str] = set()
    for finding in finding_by_id.values():
        if finding["fingerprint"] in fingerprints:
            raise ContractError("duplicate report finding fingerprint")
        fingerprints.add(finding["fingerprint"])
        validate_location(finding.get("location"))
        if not set(finding["observation_ids"]) <= observation_ids:
            raise ContractError("finding references unknown observation")
        if not set(finding["evidence_ids"]) <= evidence_ids:
            raise ContractError("finding references unknown evidence")
        fix_candidate_id = finding.get("fix_candidate_id")
        effective_state = finding.get("pre_report_state", finding["state"])
        if effective_state in ("DISCOVERED", "NORMALIZED", "CLASSIFIED") and (
            fix_candidate_id is not None or "verification_execution_ids" in finding
        ):
            raise ContractError(
                "pre-fix findings cannot contain fix or verification references"
            )
        if fix_candidate_id not in (None, *fix_ids):
            raise ContractError("finding references unknown fix candidate")
        for observation_id in finding["observation_ids"]:
            if finding["tool"] != observation_by_id[observation_id]["tool"]:
                raise ContractError("finding tool differs from source observation tool")
        cited_execution_ids = finding.get("verification_execution_ids", ())
        if not set(cited_execution_ids) <= execution_ids:
            raise ContractError("finding references unknown verification execution")
        if cited_execution_ids and fix_candidate_id is None:
            raise ContractError("citing findings require a fix candidate")
        if fix_candidate_id is not None:
            candidate = indexed["fix_candidates"][fix_candidate_id]
            if not set(finding["observation_ids"]) <= set(candidate["observation_ids"]):
                raise ContractError(
                    "citing finding observations are outside the fix candidate scope"
                )
        for identifier in cited_execution_ids:
            execution = execution_by_id[identifier]
            verification = execution.get("verification")
            if verification is None:
                raise ContractError(
                    "citing findings reference execution without "
                    "verification attribution"
                )
            if verification["fix_candidate_id"] != finding["fix_candidate_id"]:
                raise ContractError(
                    "citing findings execution attribution differs from fix candidate"
                )
            if (
                execution["tool"]["name"] != finding["tool"]["name"]
                or execution["tool"]["version"] != finding["tool"]["version"]
            ):
                raise ContractError("citing findings tool differs from execution tool")
            cited_fingerprints_by_execution.setdefault(identifier, set()).add(
                finding["fingerprint"]
            )
        if effective_state == "VERIFIED":
            fix_candidate = indexed["fix_candidates"][finding["fix_candidate_id"]]
            if fix_candidate["applicability"] != "SAFE":
                raise ContractError(
                    "verified finding references a non-safe fix candidate"
                )
            for identifier in cited_execution_ids:
                execution = execution_by_id[identifier]
                if execution["status"] != "COMPLETE":
                    raise ContractError("verified finding cites incomplete execution")
                if execution["adapter_kind"] != "PROVIDER":
                    raise ContractError(
                        "verified finding cites a non-provider execution"
                    )

    referenced_observations = {
        observation_id
        for finding in finding_by_id.values()
        for observation_id in finding["observation_ids"]
    }
    if referenced_observations != observation_ids:
        raise ContractError("observation is not referenced by a finding")

    decision_findings: list[str] = []
    evaluation_instant: int | None = None
    for decision in indexed["decisions"].values():
        finding_id = decision["finding_id"]
        if finding_id not in finding_ids:
            raise ContractError("decision references unknown finding")
        decision_findings.append(finding_id)
        if decision["policy_digest"] != report["policy_digest"]:
            raise ContractError("decision policy digest differs from report")
        decision_instant = parse_rfc3339_instant(decision["evaluated_at"])
        if evaluation_instant is not None and decision_instant != evaluation_instant:
            raise ContractError(
                "report decisions use different policy evaluation instants"
            )
        evaluation_instant = decision_instant
        if "waiver" in decision:
            expected = finding_by_id[finding_id]["fingerprint"]
            if decision["waiver"]["fingerprint"] != expected:
                raise ContractError("waiver fingerprint differs from finding")
            expires_at = parse_rfc3339_instant(decision["waiver"]["expires_at"])
            if expires_at <= decision_instant:
                raise ContractError(
                    "WAIVE decisions require expiry strictly after evaluation"
                )
    if len(decision_findings) != len(set(decision_findings)):
        raise ContractError("finding has multiple policy decisions")
    if set(decision_findings) != finding_ids:
        raise ContractError("every finding requires one policy decision")

    for candidate in indexed["fix_candidates"].values():
        if not set(candidate["observation_ids"]) <= observation_ids:
            raise ContractError("fix references unknown observation")
        candidate_tools = {
            (
                observation_by_id[observation_id]["tool"]["name"],
                observation_by_id[observation_id]["tool"]["version"],
            )
            for observation_id in candidate["observation_ids"]
        }
        if len(candidate_tools) > 1:
            raise ContractError(
                "fix candidate observations must share tool name and version"
            )
        patch_id = candidate["patch_evidence_id"]
        if patch_id not in evidence_ids:
            raise ContractError("fix references unknown patch evidence")
        if evidence_by_id[patch_id]["source"] != "PATCH":
            raise ContractError("fix evidence is not a patch")

    base_snapshot_by_candidate: dict[str, str] = {}
    for execution in indexed["executions"].values():
        validate_execution_attribution(
            execution, indexed["fix_candidates"], evidence_by_id
        )
        validate_execution(execution)
        verification = execution.get("verification")
        if verification is not None:
            candidate_id = verification["fix_candidate_id"]
            previous = base_snapshot_by_candidate.setdefault(
                candidate_id, verification["base_snapshot_sha256"]
            )
            if previous != verification["base_snapshot_sha256"]:
                raise ContractError(
                    "execution verification base snapshot differs for fix candidate"
                )

    for execution in execution_by_id.values():
        verification = execution.get("verification")
        if verification is None:
            continue
        expected = cited_fingerprints_by_execution.get(execution["execution_id"], set())
        if set(verification["target_fingerprints"]) != expected:
            raise ContractError(
                "execution verification target fingerprints do not match "
                "citing findings"
            )

    if any(
        execution["required"] and execution["status"] == "INCOMPLETE"
        for execution in execution_by_id.values()
    ):
        expected_verdict = "INCOMPLETE"
    elif any(
        execution["required"] and execution["status"] == "UNSUPPORTED"
        for execution in execution_by_id.values()
    ):
        expected_verdict = "UNSUPPORTED"
    elif any(
        decision["action"] == "BLOCK" for decision in indexed["decisions"].values()
    ):
        expected_verdict = "POLICY_FAIL"
    else:
        expected_verdict = "PASS"
    if report["verdict"] != expected_verdict:
        raise ContractError(
            "report verdict differs from required executions and decisions"
        )


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
    observation_tools: dict[str, tuple[str, str]] = {}
    execution_ids: set[str] = set()
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
            observation_tools[observation["observation_id"]] = (
                observation["tool"]["name"],
                observation["tool"]["version"],
            )
            validate_location(observation.get("location"))
        elif event["kind"] == "execution":
            execution = event["execution"]
            execution_ids.add(execution["execution_id"])
            if execution["adapter_id"] != manifest["adapter"]["id"]:
                raise SessionError("execution adapter id differs from manifest")
            if execution["adapter_kind"] != adapter_kind:
                raise SessionError("execution adapter kind differs from manifest")
            validate_execution(execution)

    if completion["evidence_bytes"] != retained_bytes:
        raise SessionError("completion evidence byte count mismatch")

    for evidence in evidence_by_id.values():
        if (
            execution_id := evidence.get("execution_id")
        ) is not None and execution_id not in execution_ids:
            raise SessionError("evidence references unknown execution")

    evidence_ids = set(evidence_by_id)
    for event in payload_events:
        if event["kind"] == "observation":
            if not set(event["observation"]["evidence_ids"]) <= evidence_ids:
                raise SessionError("observation references unknown evidence")
        elif event["kind"] == "fix_candidate":
            candidate = event["fix_candidate"]
            if not set(candidate["observation_ids"]) <= observations:
                raise SessionError("fix references unknown observation")
            candidate_tools = {
                observation_tools[observation_id]
                for observation_id in candidate["observation_ids"]
            }
            if len(candidate_tools) > 1:
                raise SessionError(
                    "fix candidate observations must share tool name and version"
                )
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

    def test_schema_dialect_is_required_and_exact(self) -> None:
        canonical = self.contracts.schemas["common.schema.json"]
        invalid_dialects = (
            ("missing", None),
            ("mistyped", "https://json-schema.org/draft/2020-12/scheme"),
            ("different draft", "https://json-schema.org/draft/2019-09/schema"),
        )
        for name, dialect in invalid_dialects:
            schema = copy.deepcopy(canonical)
            if dialect is None:
                del schema["$schema"]
            else:
                schema["$schema"] = dialect
            with self.subTest(name=name), self.assertRaises(ContractError):
                schema_resource(schema)

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

    def test_verified_finding_requires_safe_matching_attribution(self) -> None:
        report = verified_report_with_attribution()
        validate_report(report, self.contracts)

        invalid_reports: dict[str, dict[str, Any]] = {}

        missing_attribution = copy.deepcopy(report)
        del missing_attribution["executions"][0]["verification"]
        invalid_reports["missing attribution"] = missing_attribution

        stale_same_tool_candidate = copy.deepcopy(report)
        stale_same_tool_candidate["executions"][0]["verification"][
            "fix_candidate_id"
        ] = stale_same_tool_candidate["fix_candidates"][1]["fix_candidate_id"]
        invalid_reports["stale same-tool candidate"] = stale_same_tool_candidate

        dangling_candidate = copy.deepcopy(report)
        dangling_candidate["executions"][0]["verification"]["fix_candidate_id"] = (
            "019f7e95-0000-7000-8000-000000000109"
        )
        invalid_reports["dangling candidate"] = dangling_candidate

        wrong_patch_digest = copy.deepcopy(report)
        wrong_patch_digest["executions"][0]["verification"]["patch_sha256"] = "f" * 64
        invalid_reports["wrong patch digest"] = wrong_patch_digest

        wrong_target = copy.deepcopy(report)
        wrong_target["executions"][0]["verification"]["target_fingerprints"] = [
            "dtfp1:" + "f" * 64
        ]
        invalid_reports["wrong target"] = wrong_target

        missing_target = copy.deepcopy(report)
        del missing_target["executions"][0]["verification"]["target_fingerprints"]
        invalid_reports["missing target"] = missing_target

        wrong_result_evidence = copy.deepcopy(report)
        wrong_result_evidence["executions"][0]["verification"]["result_evidence_id"] = (
            "019f7e95-0000-8000-8000-000000000999"
        )
        invalid_reports["wrong result evidence"] = wrong_result_evidence

        existing_wrong_result_evidence = copy.deepcopy(report)
        existing_wrong_result_evidence["executions"][0]["verification"][
            "result_evidence_id"
        ] = existing_wrong_result_evidence["evidence"][0]["evidence_id"]
        invalid_reports["existing but wrong result evidence"] = (
            existing_wrong_result_evidence
        )

        dangling_evidence_execution = copy.deepcopy(report)
        dangling_evidence_execution["evidence"][0]["execution_id"] = (
            "019f7e95-0000-8000-8000-000000000999"
        )
        invalid_reports["dangling evidence execution"] = dangling_evidence_execution

        wrong_result_execution = copy.deepcopy(report)
        result_evidence_id = wrong_result_execution["executions"][0]["verification"][
            "result_evidence_id"
        ]
        for evidence in wrong_result_execution["evidence"]:
            if evidence["evidence_id"] == result_evidence_id:
                evidence["execution_id"] = "019f7e95-0000-8000-8000-000000000999"
                break
        invalid_reports["wrong result execution ownership"] = wrong_result_execution

        missing_result_execution = copy.deepcopy(report)
        result_evidence_id = missing_result_execution["executions"][0]["verification"][
            "result_evidence_id"
        ]
        for evidence in missing_result_execution["evidence"]:
            if evidence["evidence_id"] == result_evidence_id:
                del evidence["execution_id"]
                break
        invalid_reports["missing result execution ownership"] = missing_result_execution

        unrelated_finding_observation = copy.deepcopy(report)
        unrelated_observation = copy.deepcopy(
            unrelated_finding_observation["observations"][0]
        )
        unrelated_observation["observation_id"] = "019f7e95-0000-7000-8000-000000000113"
        unrelated_finding_observation["observations"].append(unrelated_observation)
        unrelated_finding_observation["findings"][0]["observation_ids"].append(
            unrelated_observation["observation_id"]
        )
        invalid_reports["unrelated candidate observation"] = (
            unrelated_finding_observation
        )

        arbitrary_base_snapshot_digest = copy.deepcopy(report)
        arbitrary_base_snapshot_digest["executions"][0]["verification"][
            "base_snapshot_sha256"
        ] = "f" * 64
        invalid_reports["arbitrary base snapshot digest"] = (
            arbitrary_base_snapshot_digest
        )

        mismatched_base_snapshot_evidence = copy.deepcopy(report)
        mismatched_base_snapshot_evidence["executions"][0]["verification"][
            "base_snapshot_evidence_id"
        ] = mismatched_base_snapshot_evidence["fix_candidates"][0]["patch_evidence_id"]
        invalid_reports["mismatched base snapshot evidence"] = (
            mismatched_base_snapshot_evidence
        )

        missing_base_snapshot_evidence = copy.deepcopy(report)
        missing_base_snapshot_evidence["executions"][0]["verification"][
            "base_snapshot_evidence_id"
        ] = "019f7e95-0000-8000-8000-000000000999"
        invalid_reports["missing base snapshot evidence"] = (
            missing_base_snapshot_evidence
        )

        invalid_result_source = copy.deepcopy(report)
        result_evidence_id = invalid_result_source["executions"][0]["verification"][
            "result_evidence_id"
        ]
        for evidence in invalid_result_source["evidence"]:
            if evidence["evidence_id"] == result_evidence_id:
                evidence["source"] = "PATCH"
                break
        invalid_reports["invalid result evidence source"] = invalid_result_source

        for field, value in (("name", "black"), ("version", "0.12.3")):
            wrong_tool = copy.deepcopy(report)
            wrong_tool["executions"][0]["tool"][field] = value
            invalid_reports[f"wrong execution tool {field}"] = wrong_tool

        for applicability in ("MANUAL", "UNSAFE"):
            non_safe_candidate = copy.deepcopy(report)
            non_safe_candidate["fix_candidates"][0]["applicability"] = applicability
            invalid_reports[f"{applicability.lower()} candidate"] = non_safe_candidate

        for adapter_kind in ("ENGINE", "OBSERVER"):
            non_provider_execution = copy.deepcopy(report)
            non_provider_execution["executions"][0]["adapter_kind"] = adapter_kind
            invalid_reports[f"{adapter_kind.lower()} execution"] = (
                non_provider_execution
            )

        for name, candidate in invalid_reports.items():
            with self.subTest(name=name), self.assertRaises(ContractError):
                validate_report(candidate, self.contracts)

    def test_receipt_targets_include_non_verified_citing_findings(self) -> None:
        for status in ("INCOMPLETE", "UNSUPPORTED"):
            report = verified_report_with_attribution()
            report["findings"][0]["state"] = "FIX_PROPOSED"
            report["findings"][0].pop("pre_report_state", None)
            execution = report["executions"][0]
            execution["status"] = status
            execution["exit_code"] = None
            execution["message"] = f"verification execution is {status.lower()}"
            report["verdict"] = status
            with self.subTest(status=status):
                validate_report(report, self.contracts)

        missing_candidate = verified_report_with_attribution()
        missing_candidate["findings"][0]["state"] = "DISCOVERED"
        missing_candidate["findings"][0].pop("pre_report_state", None)
        del missing_candidate["findings"][0]["fix_candidate_id"]
        with self.assertRaises(ContractError):
            validate_report(missing_candidate, self.contracts)

        missing_attribution = verified_report_with_attribution()
        missing_attribution["findings"][0]["state"] = "FIX_PROPOSED"
        missing_attribution["findings"][0].pop("pre_report_state", None)
        del missing_attribution["executions"][0]["verification"]
        with self.assertRaises(ContractError):
            validate_report(missing_attribution, self.contracts)

    def test_reported_verified_finding_preserves_proof(self) -> None:
        verified = load_json(FIXTURE_DIR / "valid-verified-report.json")
        reported = copy.deepcopy(verified)
        reported["findings"][0]["state"] = "REPORTED"
        reported["findings"][0]["pre_report_state"] = "VERIFIED"
        validate_report(reported, self.contracts)

        invalid_reports: dict[str, dict[str, Any]] = {}

        missing_pre_state = copy.deepcopy(reported)
        del missing_pre_state["findings"][0]["pre_report_state"]
        invalid_reports["missing pre-report state"] = missing_pre_state

        missing_candidate = copy.deepcopy(reported)
        del missing_candidate["findings"][0]["fix_candidate_id"]
        invalid_reports["missing fix candidate"] = missing_candidate

        missing_executions = copy.deepcopy(reported)
        del missing_executions["findings"][0]["verification_execution_ids"]
        invalid_reports["missing verification executions"] = missing_executions

        incomplete = copy.deepcopy(reported)
        incomplete["executions"][0]["status"] = "INCOMPLETE"
        incomplete["executions"][0]["exit_code"] = None
        incomplete["executions"][0]["message"] = "verification timed out"
        incomplete["verdict"] = "INCOMPLETE"
        invalid_reports["incomplete verification"] = incomplete

        unsafe_candidate = copy.deepcopy(reported)
        unsafe_candidate["fix_candidates"][0]["applicability"] = "UNSAFE"
        invalid_reports["unsafe candidate"] = unsafe_candidate

        non_provider = copy.deepcopy(reported)
        non_provider["executions"][0]["adapter_kind"] = "OBSERVER"
        invalid_reports["non-provider verification"] = non_provider

        downgraded_claim = copy.deepcopy(reported)
        downgraded_claim["findings"][0]["pre_report_state"] = "CLASSIFIED"
        invalid_reports["classified claim with verified references"] = downgraded_claim

        pre_state_before_report = copy.deepcopy(verified)
        pre_state_before_report["findings"][0]["pre_report_state"] = "VERIFIED"
        invalid_reports["pre-report state before REPORTED"] = pre_state_before_report

        for name, candidate in invalid_reports.items():
            with self.subTest(name=name), self.assertRaises(ContractError):
                validate_report(candidate, self.contracts)

        unsafe_receipt = verified_report_with_attribution()
        unsafe_receipt["findings"][0]["state"] = "FIX_PROPOSED"
        unsafe_receipt["findings"][0].pop("pre_report_state", None)
        unsafe_receipt["fix_candidates"][0]["applicability"] = "UNSAFE"
        validate_report(unsafe_receipt, self.contracts)

        unsafe_receipt["findings"][0]["state"] = "REPORTED"
        unsafe_receipt["findings"][0]["pre_report_state"] = "FIX_PROPOSED"
        validate_report(unsafe_receipt, self.contracts)

        non_provider_receipt = copy.deepcopy(unsafe_receipt)
        non_provider_receipt["executions"][0]["adapter_kind"] = "OBSERVER"
        with self.assertRaises(ContractError):
            validate_report(non_provider_receipt, self.contracts)
        with self.assertRaisesRegex(ContractError, "only for Provider"):
            validate_execution_attribution(
                non_provider_receipt["executions"][0],
                {
                    unsafe_receipt["fix_candidates"][0]["fix_candidate_id"]:
                        unsafe_receipt["fix_candidates"][0]
                },
                {
                    evidence["evidence_id"]: evidence
                    for evidence in unsafe_receipt["evidence"]
                },
            )

        unsafe_receipt["findings"][0]["pre_report_state"] = "VERIFIED"
        with self.assertRaises(ContractError):
            validate_report(unsafe_receipt, self.contracts)

    def test_findings_and_candidates_preserve_tool_scope(self) -> None:
        outside_candidate_scope = verified_report_with_attribution()
        finding = outside_candidate_scope["findings"][0]
        finding["state"] = "FIX_PROPOSED"
        finding.pop("pre_report_state", None)
        del finding["verification_execution_ids"]
        del outside_candidate_scope["executions"][0]["verification"]
        unrelated_observation = copy.deepcopy(
            outside_candidate_scope["observations"][0]
        )
        unrelated_observation["observation_id"] = "019f7e95-0000-7000-8000-000000000113"
        outside_candidate_scope["observations"].append(unrelated_observation)
        finding["observation_ids"].append(unrelated_observation["observation_id"])
        with self.assertRaises(ContractError):
            validate_report(outside_candidate_scope, self.contracts)

        mismatched_finding_tool = verified_report_with_attribution()
        mismatched_finding_tool["observations"][0]["tool"]["rule_id"] = "E501"
        with self.assertRaises(ContractError):
            validate_report(mismatched_finding_tool, self.contracts)

        mixed_candidate_tools = verified_report_with_attribution()
        second_observation = copy.deepcopy(mixed_candidate_tools["observations"][0])
        second_observation["observation_id"] = "019f7e95-0000-7000-8000-000000000114"
        second_observation["tool"] = {"name": "black", "version": "25.1.0"}
        mixed_candidate_tools["observations"].append(second_observation)
        mixed_candidate_tools["fix_candidates"][0]["observation_ids"].append(
            second_observation["observation_id"]
        )
        with self.assertRaises(ContractError):
            validate_report(mixed_candidate_tools, self.contracts)

    def test_candidate_allows_same_tool_version_with_multiple_rule_ids(self) -> None:
        report = verified_report_with_attribution()
        second_observation = copy.deepcopy(report["observations"][0])
        second_observation["observation_id"] = "019f7e95-0000-7000-8000-000000000113"
        second_observation["tool"]["rule_id"] = "E501"
        report["observations"].append(second_observation)
        report["fix_candidates"][0]["observation_ids"].append(
            second_observation["observation_id"]
        )
        second_finding = copy.deepcopy(report["findings"][0])
        second_finding["finding_id"] = "019f7e95-0000-7000-8000-000000000114"
        second_finding["fingerprint"] = "dtfp1:" + "e" * 64
        second_finding["observation_ids"] = [second_observation["observation_id"]]
        second_finding["tool"]["rule_id"] = "E501"
        second_finding["state"] = "FIX_PROPOSED"
        second_finding.pop("verification_execution_ids", None)
        report["findings"].append(second_finding)
        second_decision = copy.deepcopy(report["decisions"][0])
        second_decision["decision_id"] = "019f7e95-0000-7000-8000-000000000115"
        second_decision["finding_id"] = second_finding["finding_id"]
        report["decisions"].append(second_decision)
        validate_report(report, self.contracts)

    def test_report_rejects_duplicate_finding_fingerprints(self) -> None:
        report = load_json(FIXTURE_DIR / "valid-report.json")
        duplicate_finding = copy.deepcopy(report["findings"][0])
        duplicate_finding["finding_id"] = "019f7e95-0000-7000-8000-000000000113"
        duplicate_decision = copy.deepcopy(report["decisions"][0])
        duplicate_decision["decision_id"] = "019f7e95-0000-7000-8000-000000000114"
        duplicate_decision["finding_id"] = duplicate_finding["finding_id"]
        report["findings"].append(duplicate_finding)
        report["decisions"].append(duplicate_decision)
        with self.assertRaises(ContractError):
            validate_report(report, self.contracts)

    def test_verification_evidence_boundaries_are_explicit(self) -> None:
        valid = verified_report_with_attribution()
        verification = valid["executions"][0]["verification"]
        base_snapshot_id = verification["base_snapshot_evidence_id"]
        result_id = verification["result_evidence_id"]

        invalid_reports: dict[str, dict[str, Any]] = {}

        truncated_base = copy.deepcopy(valid)
        base_snapshot = next(
            evidence
            for evidence in truncated_base["evidence"]
            if evidence["evidence_id"] == base_snapshot_id
        )
        base_snapshot["observed_bytes"] += 1
        base_snapshot["truncated"] = True
        invalid_reports["truncated base snapshot"] = truncated_base

        truncated_patch = copy.deepcopy(valid)
        patch = next(
            evidence
            for evidence in truncated_patch["evidence"]
            if evidence["evidence_id"]
            == truncated_patch["fix_candidates"][0]["patch_evidence_id"]
        )
        patch["observed_bytes"] += 1
        patch["truncated"] = True
        invalid_reports["truncated patch"] = truncated_patch

        relative_path_base = copy.deepcopy(valid)
        base_snapshot = next(
            evidence
            for evidence in relative_path_base["evidence"]
            if evidence["evidence_id"] == base_snapshot_id
        )
        del base_snapshot["content"]
        base_snapshot["relative_path"] = "snapshots/base.json"
        invalid_reports["relative_path base snapshot"] = relative_path_base

        relative_path_patch = copy.deepcopy(valid)
        patch = next(
            evidence
            for evidence in relative_path_patch["evidence"]
            if evidence["evidence_id"]
            == relative_path_patch["fix_candidates"][0]["patch_evidence_id"]
        )
        del patch["content"]
        patch["relative_path"] = "patches/fix.diff"
        invalid_reports["relative_path patch"] = relative_path_patch

        truncated_complete_result = copy.deepcopy(valid)
        complete_result = next(
            evidence
            for evidence in truncated_complete_result["evidence"]
            if evidence["evidence_id"] == result_id
        )
        complete_result["observed_bytes"] = 1
        complete_result["truncated"] = True
        invalid_reports["truncated complete result"] = truncated_complete_result

        relative_path_complete_result = copy.deepcopy(valid)
        complete_result = next(
            evidence
            for evidence in relative_path_complete_result["evidence"]
            if evidence["evidence_id"] == result_id
        )
        del complete_result["content"]
        complete_result["relative_path"] = "results/verification.txt"
        invalid_reports["relative_path complete result"] = relative_path_complete_result

        same_evidence = copy.deepcopy(valid)
        same_evidence["executions"][0]["verification"]["result_evidence_id"] = (
            base_snapshot_id
        )
        invalid_reports["same base and result evidence"] = same_evidence

        snapshot_result = copy.deepcopy(valid)
        snapshot_result_evidence = next(
            evidence
            for evidence in snapshot_result["evidence"]
            if evidence["evidence_id"] == result_id
        )
        snapshot_result_evidence["media_type"] = SNAPSHOT_MEDIA_TYPE
        invalid_reports["snapshot media type result"] = snapshot_result

        for name, report in invalid_reports.items():
            with self.subTest(name=name), self.assertRaises(ContractError):
                validate_report(report, self.contracts)

        for status in ("INCOMPLETE", "UNSUPPORTED"):
            non_inline_result = copy.deepcopy(valid)
            non_inline_result["verdict"] = status
            non_inline_result["findings"][0]["state"] = "FIX_PROPOSED"
            non_inline_result["findings"][0].pop("pre_report_state", None)
            non_inline_result["executions"][0]["status"] = status
            non_inline_result["executions"][0]["exit_code"] = None
            non_inline_result["executions"][0]["message"] = (
                f"verification {status.lower()}"
            )
            result = next(
                evidence
                for evidence in non_inline_result["evidence"]
                if evidence["evidence_id"] == result_id
            )
            del result["content"]
            result["relative_path"] = f"results/{status.lower()}.txt"
            result["observed_bytes"] = 1
            result["truncated"] = True
            with self.subTest(status=status):
                validate_report(non_inline_result, self.contracts)

            non_inline_result["findings"][0]["state"] = "REPORTED"
            non_inline_result["findings"][0]["pre_report_state"] = "FIX_PROPOSED"
            with self.subTest(status=status, state="REPORTED"):
                validate_report(non_inline_result, self.contracts)

    def test_session_evidence_execution_id_must_resolve(self) -> None:
        events = load_session(FIXTURE_DIR / "valid-session.jsonl")
        events[2]["evidence"]["execution_id"] = "019f7e95-0000-7000-8000-000000000999"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid-execution-evidence.jsonl"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(SessionError):
                validate_session(path, self.contracts)

    def test_provider_jsonl_rejects_execution_event(self) -> None:
        events = load_session(FIXTURE_DIR / "valid-session.jsonl")
        execution_event = copy.deepcopy(
            load_session(FIXTURE_DIR / "valid-observer-session.jsonl")[2]
        )
        execution_event["request_id"] = events[1]["request_id"]
        execution_event["sequence"] = 2
        execution = execution_event["execution"]
        execution["adapter_id"] = events[0]["adapter"]["id"]
        execution["adapter_kind"] = "PROVIDER"
        execution["tool"] = {"name": "ruff", "version": "0.12.4"}
        execution["exit_code"] = 0
        report = load_json(FIXTURE_DIR / "valid-verified-report.json")
        execution["verification"] = copy.deepcopy(
            report["executions"][0]["verification"]
        )
        events.insert(4, execution_event)
        events[-1]["sequence"] = 3
        events[-1]["counts"]["executions"] = 1

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid-provider-execution.jsonl"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(SessionError):
                validate_session(path, self.contracts)

    def test_observer_jsonl_rejects_verification_receipt(self) -> None:
        events = load_session(FIXTURE_DIR / "valid-observer-session.jsonl")
        report = load_json(FIXTURE_DIR / "valid-verified-report.json")
        events[2]["execution"]["verification"] = copy.deepcopy(
            report["executions"][0]["verification"]
        )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid-observer-verification.jsonl"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(SessionError):
                validate_session(path, self.contracts)

    def test_observer_evidence_may_resolve_to_its_execution_event(self) -> None:
        events = load_session(FIXTURE_DIR / "valid-observer-session.jsonl")
        execution_id = events[2]["execution"]["execution_id"]
        events.insert(
            3,
            {
                "protocol_version": "diagnostic-triage.protocol/v1",
                "kind": "evidence",
                "request_id": events[1]["request_id"],
                "sequence": 1,
                "evidence": {
                    "schema_version": "diagnostic-triage.evidence/v1",
                    "evidence_id": "019f7e95-0000-7000-8000-000000000203",
                    "execution_id": execution_id,
                    "source": "STDOUT",
                    "media_type": "text/plain",
                    "retained_bytes": 0,
                    "observed_bytes": 0,
                    "limit_bytes": 1048576,
                    "truncated": False,
                    "sha256": (
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca"
                        "495991b7852b855"
                    ),
                    "content": "",
                },
            },
        )
        events[-1]["sequence"] = 2
        events[-1]["counts"]["evidence"] = 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "valid-observer-evidence.jsonl"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )
            validate_session(path, self.contracts)

    def test_session_candidate_rejects_mixed_tool_versions(self) -> None:
        events = load_session(FIXTURE_DIR / "valid-session.jsonl")
        second_observation = copy.deepcopy(events[3])
        second_observation["observation"]["observation_id"] = (
            "019f7e95-0000-7000-8000-000000000005"
        )
        second_observation["observation"]["tool"]["rule_id"] = "E501"

        patch_evidence = copy.deepcopy(events[2])
        patch_evidence["evidence"]["evidence_id"] = (
            "019f7e95-0000-7000-8000-000000000004"
        )
        patch_evidence["evidence"]["source"] = "PATCH"
        candidate = {
            "protocol_version": "diagnostic-triage.protocol/v1",
            "kind": "fix_candidate",
            "request_id": events[1]["request_id"],
            "sequence": 3,
            "fix_candidate": {
                "schema_version": "diagnostic-triage.fix-candidate/v1",
                "fix_candidate_id": "019f7e95-0000-7000-8000-000000000006",
                "observation_ids": [
                    events[3]["observation"]["observation_id"],
                    second_observation["observation"]["observation_id"],
                ],
                "applicability": "MANUAL",
                "tool_native": False,
                "patch_evidence_id": patch_evidence["evidence"]["evidence_id"],
            },
        }
        events[2:4] = [
            events[2],
            events[3],
            second_observation,
            patch_evidence,
            candidate,
        ]
        payload_events = events[2:-1]
        for sequence, event in enumerate(payload_events):
            event["sequence"] = sequence
        events[-1]["sequence"] = len(payload_events)
        events[-1]["counts"] = {
            "observations": 2,
            "evidence": 2,
            "fix_candidates": 1,
            "executions": 0,
        }
        events[-1]["evidence_bytes"] = 8

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid-candidate-tools.jsonl"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )
            validate_session(path, self.contracts)

            second_observation["observation"]["tool"]["version"] = "0.12.5"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(SessionError):
                validate_session(path, self.contracts)

    def test_receipts_share_one_base_snapshot_per_candidate(self) -> None:
        report = verified_report_with_attribution()
        first_execution = report["executions"][0]
        second_execution = copy.deepcopy(first_execution)
        second_execution["execution_id"] = "019f7e95-0000-8000-8000-000000000112"
        second_execution["adapter_id"] = "ruff-secondary"
        second_result_evidence = next(
            copy.deepcopy(evidence)
            for evidence in report["evidence"]
            if evidence["evidence_id"]
            == second_execution["verification"]["result_evidence_id"]
        )
        second_result_evidence["evidence_id"] = "019f7e95-0000-8000-8000-000000000114"
        second_result_evidence["execution_id"] = second_execution["execution_id"]
        report["evidence"].append(second_result_evidence)
        second_execution["verification"]["result_evidence_id"] = second_result_evidence[
            "evidence_id"
        ]
        report["executions"].append(second_execution)
        report["findings"][0]["verification_execution_ids"].append(
            second_execution["execution_id"]
        )
        validate_report(report, self.contracts)

        second_execution["verification"]["base_snapshot_sha256"] = "a" * 64
        with self.assertRaises(ContractError):
            validate_report(report, self.contracts)

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
        self.contracts.validator("protocol.schema.json").validate(handshake["manifest"])
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

        wrong_contract_digest = copy.deepcopy(report)
        wrong_contract_digest["contract_sha256"] = "f" * 64
        candidates["contract identity"] = wrong_contract_digest

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
                "patch_evidence_id": failed_verification["evidence"][0]["evidence_id"],
            }
        ]
        finding = failed_verification["findings"][0]
        finding["state"] = "VERIFIED"
        finding.pop("pre_report_state", None)
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
        failed_verification["verdict"] = "INCOMPLETE"
        candidates["failed verification"] = failed_verification

        missing_decision = copy.deepcopy(report)
        missing_decision["decisions"] = []
        candidates["missing decision"] = missing_decision

        orphan_observation = copy.deepcopy(report)
        orphan_observation["findings"] = []
        orphan_observation["decisions"] = []
        orphan_observation["verdict"] = "PASS"
        candidates["orphan observation"] = orphan_observation

        for name, candidate in candidates.items():
            with self.subTest(name=name), self.assertRaises(ContractError):
                validate_report(candidate, self.contracts)

    def test_report_verdict_follows_execution_and_policy_precedence(self) -> None:
        def set_execution_status(
            report: dict[str, Any], index: int, status: str, required: bool
        ) -> None:
            execution = report["executions"][index]
            execution["required"] = required
            execution["status"] = status
            if status == "COMPLETE":
                execution["exit_code"] = 0
                execution.pop("message", None)
            else:
                execution["exit_code"] = None
                execution["message"] = f"required execution ended as {status}"

        def assert_only_verdict(
            name: str, report: dict[str, Any], expected: str
        ) -> None:
            for actual in ("PASS", "POLICY_FAIL", "INCOMPLETE", "UNSUPPORTED"):
                candidate = copy.deepcopy(report)
                candidate["verdict"] = actual
                if actual == expected:
                    with self.subTest(name=name, actual=actual):
                        validate_report(candidate, self.contracts)
                else:
                    with self.subTest(name=name, actual=actual), self.assertRaises(
                        ContractError
                    ):
                        validate_report(candidate, self.contracts)

        block = load_json(FIXTURE_DIR / "valid-report.json")
        assert_only_verdict("required complete with BLOCK", block, "POLICY_FAIL")

        for action in ("OBSERVE", "WARN"):
            report = load_json(FIXTURE_DIR / "valid-report.json")
            report["decisions"][0]["action"] = action
            assert_only_verdict(action, report, "PASS")

        waived = load_json(FIXTURE_DIR / "valid-report.json")
        waived["decisions"][0]["action"] = "WAIVE"
        waived["decisions"][0]["waiver"] = {
            "fingerprint": waived["findings"][0]["fingerprint"],
            "waived_action": "BLOCK",
            "reason": "accepted until the upstream fix lands",
            "owner": "maintainers",
            "expires_at": "2026-08-20T00:00:00Z",
        }
        assert_only_verdict("WAIVE", waived, "PASS")

        incomplete = load_json(FIXTURE_DIR / "valid-report.json")
        set_execution_status(incomplete, 0, "INCOMPLETE", True)
        assert_only_verdict(
            "required INCOMPLETE with BLOCK", incomplete, "INCOMPLETE"
        )

        unsupported = load_json(FIXTURE_DIR / "valid-report.json")
        set_execution_status(unsupported, 0, "UNSUPPORTED", True)
        assert_only_verdict(
            "required UNSUPPORTED with BLOCK", unsupported, "UNSUPPORTED"
        )

        mixed = copy.deepcopy(unsupported)
        second = copy.deepcopy(mixed["executions"][0])
        second["execution_id"] = "019f7e95-0000-7000-8000-000000000199"
        mixed["executions"].append(second)
        set_execution_status(mixed, 1, "INCOMPLETE", True)
        assert_only_verdict(
            "required INCOMPLETE and UNSUPPORTED", mixed, "INCOMPLETE"
        )

        for status in ("INCOMPLETE", "UNSUPPORTED"):
            optional = load_json(FIXTURE_DIR / "valid-unsupported-report.json")
            set_execution_status(optional, 0, status, False)
            assert_only_verdict(f"optional {status}", optional, "PASS")

        empty = load_json(FIXTURE_DIR / "valid-unsupported-report.json")
        empty["executions"] = []
        assert_only_verdict("empty report", empty, "PASS")

    def test_request_rejects_noncanonical_paths(self) -> None:
        request = load_session(FIXTURE_DIR / "valid-empty-session.jsonl")[1]
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

        for valid_length in (40, 64):
            candidate = load_json(FIXTURE_DIR / "valid-report.json")
            candidate["engine"]["source_revision"] = "a" * valid_length
            validator.validate(candidate)
        for invalid_length in (39, 41, 63, 65):
            candidate = load_json(FIXTURE_DIR / "valid-report.json")
            candidate["engine"]["source_revision"] = "a" * invalid_length
            with self.subTest(source_revision_length=invalid_length):
                self.assertTrue(list(validator.iter_errors(candidate)))

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

    def test_report_can_be_bound_to_an_external_source_pin(self) -> None:
        report = load_json(FIXTURE_DIR / "valid-report.json")
        expected = report["engine"]["source_revision"]
        validate_report(report, self.contracts, expected)

        forged = copy.deepcopy(report)
        forged_revision = "f" * 40
        forged["engine"]["source_revision"] = forged_revision
        forged["contract_sha256"] = hashlib.sha256(
            forged_revision.encode("ascii")
        ).hexdigest()
        validate_report(forged, self.contracts)
        with self.assertRaises(ContractError):
            validate_report(forged, self.contracts, expected)

    def test_decision_evaluation_time_is_required_and_report_wide(self) -> None:
        report = load_json(FIXTURE_DIR / "valid-report.json")
        validate_report(report, self.contracts)

        missing = copy.deepcopy(report)
        del missing["decisions"][0]["evaluated_at"]
        with self.assertRaises(ContractError):
            validate_report(missing, self.contracts)

        for invalid_timestamp in (
            "not-a-date",
            "2026-07-21T00:00:00+24:00",
            "2026-02-29T00:00:00Z",
            "2026-07-21T00:00:00.1234567890Z",
        ):
            invalid = copy.deepcopy(report)
            invalid["decisions"][0]["evaluated_at"] = invalid_timestamp
            with self.subTest(invalid_timestamp=invalid_timestamp), self.assertRaises(
                ContractError
            ):
                validate_report(invalid, self.contracts)

        mixed = copy.deepcopy(report)
        second_finding = copy.deepcopy(mixed["findings"][0])
        second_finding["finding_id"] = "019f7e95-0000-7000-8000-000000000107"
        second_finding["fingerprint"] = "dtfp1:" + "d" * 64
        second_finding["message"] = "A second finding evaluated in the same report"
        mixed["findings"].append(second_finding)
        second_decision = copy.deepcopy(mixed["decisions"][0])
        second_decision["decision_id"] = "019f7e95-0000-7000-8000-000000000108"
        second_decision["finding_id"] = second_finding["finding_id"]
        second_decision["evaluated_at"] = "2026-07-21T01:00:00+01:00"
        mixed["decisions"].append(second_decision)

        validate_report(mixed, self.contracts)

        mixed["decisions"][1]["evaluated_at"] = "2026-07-21T00:00:01Z"
        with self.assertRaises(ContractError):
            validate_report(mixed, self.contracts)

    def test_waive_expiry_uses_strict_parsed_instant_ordering(self) -> None:
        report = load_json(FIXTURE_DIR / "valid-report.json")
        report["verdict"] = "PASS"
        decision = report["decisions"][0]
        decision["action"] = "WAIVE"
        decision["evaluated_at"] = "2026-07-21T00:00:00Z"
        decision["waiver"] = {
            "fingerprint": report["findings"][0]["fingerprint"],
            "waived_action": "BLOCK",
            "reason": "accepted until the upstream fix lands",
            "owner": "maintainers",
            "expires_at": "2026-08-20T00:00:00Z",
        }

        accepted_expiries = (
            "2026-07-20T23:30:00-01:00",
            "2026-07-21T00:00:00.000000001Z",
        )
        for expiry in accepted_expiries:
            candidate = copy.deepcopy(report)
            candidate["decisions"][0]["waiver"]["expires_at"] = expiry
            with self.subTest(accepted_expiry=expiry):
                validate_report(candidate, self.contracts)

        rejected_expiries = (
            "2026-07-21T00:00:00Z",
            "2026-07-20T23:59:59.999999999Z",
            "2026-07-21T01:00:00+01:00",
            "2026-07-21T00:30:00+01:00",
        )
        for expiry in rejected_expiries:
            candidate = copy.deepcopy(report)
            candidate["decisions"][0]["waiver"]["expires_at"] = expiry
            with self.subTest(rejected_expiry=expiry), self.assertRaises(ContractError):
                validate_report(candidate, self.contracts)

        for evaluated_at, expires_at in (
            (
                "0000-01-01T00:00:00.000000000Z",
                "0000-01-01T00:00:00.000000001Z",
            ),
            (
                "9998-12-31T23:59:58.999999999Z",
                "9998-12-31T23:59:59.000000000Z",
            ),
        ):
            candidate = copy.deepcopy(report)
            candidate["decisions"][0]["evaluated_at"] = evaluated_at
            candidate["decisions"][0]["waiver"]["expires_at"] = expires_at
            with self.subTest(evaluated_at=evaluated_at, expires_at=expires_at):
                validate_report(candidate, self.contracts)

    def test_waiver_is_bound_to_a_fingerprint(self) -> None:
        report = load_json(FIXTURE_DIR / "valid-report.json")
        report["verdict"] = "PASS"
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

    def test_waiver_rfc3339_offset_boundaries(self) -> None:
        report = load_json(FIXTURE_DIR / "valid-report.json")
        report["verdict"] = "PASS"
        decision = report["decisions"][0]
        decision["action"] = "WAIVE"
        decision["waiver"] = {
            "fingerprint": report["findings"][0]["fingerprint"],
            "waived_action": "BLOCK",
            "reason": "temporary waiver",
            "owner": "maintainers",
            "expires_at": "2026-08-20T00:00:00+23:59",
        }
        for valid_expiry in (
            "2026-08-20T00:00:00Z",
            "2026-08-20t00:00:00z",
            "0000-01-01T00:00:00+23:59",
            "9998-12-31T23:59:59-23:59",
            "2000-02-29T00:00:00Z",
            "2400-02-29T00:00:00Z",
            "2026-08-20T00:00:00.123456789Z",
            "2026-08-20T00:00:00+23:59",
            "2026-08-20T00:00:00-23:59",
        ):
            candidate = copy.deepcopy(report)
            candidate["decisions"][0]["waiver"]["expires_at"] = valid_expiry
            with self.subTest(valid_expiry=valid_expiry):
                self.contracts.validator("model.schema.json").validate(candidate)

        for valid_expiry in (
            "2026-08-20T00:00:00Z",
            "2026-08-20T00:00:00+23:59",
            "2026-08-20T00:00:00-23:59",
            "2026-08-20T00:00:00.123456789Z",
        ):
            candidate = copy.deepcopy(report)
            candidate["decisions"][0]["waiver"]["expires_at"] = valid_expiry
            with self.subTest(semantic_valid_expiry=valid_expiry):
                validate_report(candidate, self.contracts)

        validator = self.contracts.validator("model.schema.json")
        for invalid_offset in ("+24:00", "-24:00", "+23:60", "-23:60"):
            candidate = copy.deepcopy(report)
            candidate["decisions"][0]["waiver"]["expires_at"] = (
                f"2026-08-20T00:00:00{invalid_offset}"
            )
            with self.subTest(offset=invalid_offset):
                self.assertTrue(list(validator.iter_errors(candidate)))
        for impossible_date in (
            "2023-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2024-04-31T00:00:00Z",
        ):
            candidate = copy.deepcopy(report)
            candidate["decisions"][0]["waiver"]["expires_at"] = impossible_date
            with self.subTest(impossible_date=impossible_date):
                self.assertTrue(list(validator.iter_errors(candidate)))

        annotation_only_validator = cast(
            Validator,
            Draft202012Validator(
                self.contracts.schemas["model.schema.json"],
                registry=self.contracts.registry,
            ),
        )
        for malformed_expiry in (
            "not-a-date+23:59",
            "9999-01-01T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2024-04-31T00:00:00Z",
            "2026-08-20T00:00:60Z",
            "2026-08-20T00:00:00.1234567890Z",
            "2026-08-20T00:00:00Z\n",
            "2026-08-20T00:00:00Z\u2028",
        ):
            candidate = copy.deepcopy(report)
            candidate["decisions"][0]["waiver"]["expires_at"] = malformed_expiry
            with self.subTest(malformed_expiry=malformed_expiry):
                self.assertTrue(list(annotation_only_validator.iter_errors(candidate)))

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
