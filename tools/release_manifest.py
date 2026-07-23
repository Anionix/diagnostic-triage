from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from pathlib import Path
from typing import cast

MATRIX_SCHEMA = "diagnostic-triage.release-matrix/v1"
MANIFEST_SCHEMA = "diagnostic-triage.release-manifest/v1"
SOURCE_REPOSITORY = "https://github.com/Anionix/diagnostic-triage"
REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
VERSION_PATTERN = re.compile(r"0\.[0-9]+\.[0-9]+-alpha\.[0-9]+")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
EXPECTED_PLATFORMS = {
    "aarch64-darwin": ("macos-15", "aarch64-apple-darwin"),
    "aarch64-linux": ("ubuntu-24.04-arm", "aarch64-unknown-linux-musl"),
    "x86_64-darwin": ("macos-15-intel", "x86_64-apple-darwin"),
    "x86_64-linux": ("ubuntu-24.04", "x86_64-unknown-linux-musl"),
}


class ReleaseContractError(ValueError):
    """Release input or output violated the deterministic publication contract."""


@dataclass(frozen=True)
class ArtifactSpec:
    system: str
    runner: str
    rust_target: str
    archive: str


@dataclass(frozen=True)
class ReleaseMatrix:
    version: str
    artifacts: tuple[ArtifactSpec, ...]


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ReleaseContractError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _load_json(path: Path) -> object:
    try:
        return cast(
            object,
            json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_object,
            ),
        )
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseContractError(f"cannot load JSON {path}: {error}") from error


def _object_record(value: object, description: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReleaseContractError(f"{description} must be an object")
    return cast(dict[str, object], value)


def _object_list(value: object, description: str) -> list[object]:
    if not isinstance(value, list):
        raise ReleaseContractError(f"{description} must be an array")
    return cast(list[object], value)


def _required_string(record: dict[str, object], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value:
        raise ReleaseContractError(f"{field} must be a non-empty string")
    return value


def _require_fields(
    record: dict[str, object],
    expected: set[str],
    description: str,
) -> None:
    if set(record) != expected:
        raise ReleaseContractError(f"{description} fields are not canonical")


def load_matrix(path: Path) -> ReleaseMatrix:
    raw = _object_record(_load_json(path), "release matrix")
    _require_fields(
        raw,
        {"schema_version", "release_version", "artifacts"},
        "release matrix",
    )
    if raw.get("schema_version") != MATRIX_SCHEMA:
        raise ReleaseContractError(f"matrix schema must be {MATRIX_SCHEMA}")
    version = _required_string(raw, "release_version")
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ReleaseContractError("release_version must be a pre-alpha SemVer")
    records = _object_list(raw.get("artifacts"), "matrix artifacts")
    if len(records) != 4:
        raise ReleaseContractError("release matrix must contain exactly four artifacts")

    artifacts: list[ArtifactSpec] = []
    for value in records:
        record = _object_record(value, "matrix artifact")
        _require_fields(
            record,
            {"system", "runner", "rust_target", "archive"},
            "matrix artifact",
        )
        spec = ArtifactSpec(
            system=_required_string(record, "system"),
            runner=_required_string(record, "runner"),
            rust_target=_required_string(record, "rust_target"),
            archive=_required_string(record, "archive"),
        )
        expected_archive = f"diagnostic-triage-v{version}-{spec.rust_target}.tar.gz"
        if spec.archive != expected_archive:
            raise ReleaseContractError(
                f"archive {spec.archive!r} must be {expected_archive!r}"
            )
        artifacts.append(spec)

    for field in ("system", "runner", "rust_target", "archive"):
        values = [getattr(spec, field) for spec in artifacts]
        if len(values) != len(set(values)):
            raise ReleaseContractError(f"matrix {field} values must be unique")
    if artifacts != sorted(artifacts, key=lambda spec: spec.system):
        raise ReleaseContractError("matrix artifacts must be sorted by system")
    platforms = {spec.system: (spec.runner, spec.rust_target) for spec in artifacts}
    if platforms != EXPECTED_PLATFORMS:
        raise ReleaseContractError(
            "release matrix platform identities are not canonical"
        )
    return ReleaseMatrix(version=version, artifacts=tuple(artifacts))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise ReleaseContractError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def _artifact_record(
    artifact_dir: Path,
    name: str,
    *,
    kind: str,
    system: str | None = None,
    runner: str | None = None,
    rust_target: str | None = None,
) -> dict[str, object]:
    path = artifact_dir / name
    if path.is_symlink() or not path.is_file():
        raise ReleaseContractError(f"required release artifact is missing: {name}")
    record: dict[str, object] = {
        "name": name,
        "kind": kind,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }
    if system is not None:
        record["system"] = system
    if runner is not None:
        record["runner"] = runner
    if rust_target is not None:
        record["rust_target"] = rust_target
    return record


def _write_json(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)
    path.write_text(f"{encoded}\n", encoding="utf-8")


def _lock_digests(repository_root: Path) -> dict[str, str]:
    return {
        "cargo_lock_sha256": sha256_file(repository_root / "Cargo.lock"),
        "flake_lock_sha256": sha256_file(repository_root / "flake.lock"),
    }


def _require_release_directory(
    artifact_dir: Path,
    *,
    required: set[str],
    permitted_outputs: AbstractSet[str] = frozenset(),
) -> None:
    try:
        entries = list(artifact_dir.iterdir())
    except OSError as error:
        raise ReleaseContractError(
            f"cannot inspect release artifact directory: {error}"
        ) from error
    invalid = sorted(
        entry.name for entry in entries if entry.is_symlink() or not entry.is_file()
    )
    observed = {entry.name for entry in entries}
    missing = sorted(required - observed)
    unexpected = sorted(observed - required - permitted_outputs)
    if invalid or missing or unexpected:
        raise ReleaseContractError(
            "release artifact directory does not match the contract: "
            f"missing={missing}, invalid={invalid}, unexpected={unexpected}"
        )


def _artifact_output_names(artifact_dir: Path, *paths: Path) -> set[str]:
    try:
        artifact_root = artifact_dir.resolve()
        names: set[str] = set()
        for path in paths:
            resolved = path.resolve()
            try:
                relative = resolved.relative_to(artifact_root)
            except ValueError:
                continue
            if len(relative.parts) != 1:
                raise ReleaseContractError(
                    "release outputs inside the artifact directory "
                    "must be direct children"
                )
            names.add(relative.name)
        return names
    except (OSError, RuntimeError) as error:
        raise ReleaseContractError(
            f"cannot resolve release output paths: {error}"
        ) from error


def _require_distinct_output_names(
    archive_names: AbstractSet[str],
    manifest_path: Path,
    checksums_path: Path,
) -> None:
    output_names = [manifest_path.name, checksums_path.name]
    if len(set(output_names)) != 2 or set(archive_names).intersection(output_names):
        raise ReleaseContractError(
            "release manifest, checksums, and archive names must be distinct"
        )


def create_release_manifest(
    *,
    repository_root: Path,
    matrix_path: Path,
    artifact_dir: Path,
    tag: str,
    revision: str,
    manifest_path: Path,
    checksums_path: Path,
) -> dict[str, object]:
    # LLM contract: SOURCE_PINNED -> MATRIX_VALIDATED -> DIRECTORY_BOUND ->
    # ARTIFACTS_HASHED -> MANIFESTED -> CHECKSUMMED; missing, mutable,
    # unmanifested, or mismatched input -> FAILED.
    matrix = load_matrix(matrix_path)
    if tag != f"v{matrix.version}":
        raise ReleaseContractError(
            f"release tag {tag!r} must equal 'v{matrix.version}'"
        )
    if REVISION_PATTERN.fullmatch(revision) is None:
        raise ReleaseContractError("source revision must be 40 lowercase hex digits")

    source_name = f"diagnostic-triage-v{matrix.version}-source.tar.gz"
    required_names = {spec.archive for spec in matrix.artifacts} | {source_name}
    _require_distinct_output_names(
        required_names,
        manifest_path,
        checksums_path,
    )
    _require_release_directory(
        artifact_dir,
        required=required_names,
        permitted_outputs=_artifact_output_names(
            artifact_dir,
            manifest_path,
            checksums_path,
        ),
    )
    artifact_records = [
        _artifact_record(
            artifact_dir,
            spec.archive,
            kind="platform-archive",
            system=spec.system,
            runner=spec.runner,
            rust_target=spec.rust_target,
        )
        for spec in matrix.artifacts
    ]
    artifact_records.append(
        _artifact_record(artifact_dir, source_name, kind="source-archive")
    )
    artifact_records.sort(key=lambda record: str(record["name"]))

    document: dict[str, object] = {
        "schema_version": MANIFEST_SCHEMA,
        "release": {
            "tag": tag,
            "version": matrix.version,
            "compatibility": "pre-alpha",
            "source_repository": SOURCE_REPOSITORY,
            "source_revision": revision,
        },
        "environment": {
            **_lock_digests(repository_root),
            "matrix_sha256": sha256_file(matrix_path),
            "rust_toolchain": "1.85.1",
        },
        "artifacts": artifact_records,
    }
    _write_json(manifest_path, document)

    checksum_files = [
        *(artifact_dir / str(record["name"]) for record in artifact_records),
        manifest_path,
    ]
    checksum_files.sort(key=lambda path: path.name)
    checksums_path.write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in checksum_files),
        encoding="utf-8",
    )
    return document


def _parse_checksums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ReleaseContractError(f"cannot read checksums: {error}") from error
    if lines != sorted(lines, key=lambda line: line[66:] if len(line) > 66 else line):
        raise ReleaseContractError("SHA256SUMS entries must be sorted by file name")
    for line in lines:
        digest, separator, name = line.partition("  ")
        if (
            separator != "  "
            or SHA256_PATTERN.fullmatch(digest) is None
            or not name
            or Path(name).name != name
            or name in checksums
        ):
            raise ReleaseContractError(f"invalid SHA256SUMS entry: {line!r}")
        checksums[name] = digest
    return checksums


def verify_release(
    *,
    repository_root: Path,
    matrix_path: Path,
    artifact_dir: Path,
    expected_tag: str,
    expected_revision: str,
    manifest_path: Path,
    checksums_path: Path,
) -> None:
    matrix = load_matrix(matrix_path)
    if expected_tag != f"v{matrix.version}":
        raise ReleaseContractError("expected tag does not match release matrix")
    if REVISION_PATTERN.fullmatch(expected_revision) is None:
        raise ReleaseContractError(
            "expected source revision must be 40 lowercase hex digits"
        )
    source_name = f"diagnostic-triage-v{matrix.version}-source.tar.gz"
    archive_names = {*(spec.archive for spec in matrix.artifacts), source_name}
    _require_distinct_output_names(
        archive_names,
        manifest_path,
        checksums_path,
    )
    required_names = archive_names | _artifact_output_names(
        artifact_dir,
        manifest_path,
        checksums_path,
    )
    _require_release_directory(artifact_dir, required=required_names)
    raw = _object_record(_load_json(manifest_path), "release manifest")
    _require_fields(
        raw,
        {"schema_version", "release", "environment", "artifacts"},
        "release manifest",
    )
    if raw.get("schema_version") != MANIFEST_SCHEMA:
        raise ReleaseContractError(f"manifest schema must be {MANIFEST_SCHEMA}")
    release = _object_record(raw.get("release"), "manifest release")
    environment = _object_record(raw.get("environment"), "manifest environment")
    records = _object_list(raw.get("artifacts"), "manifest artifacts")
    expected_release = {
        "tag": expected_tag,
        "version": matrix.version,
        "compatibility": "pre-alpha",
        "source_repository": SOURCE_REPOSITORY,
        "source_revision": expected_revision,
    }
    if release != expected_release:
        raise ReleaseContractError(
            "manifest release identity does not match the expected source"
        )
    expected_environment = {
        **_lock_digests(repository_root),
        "matrix_sha256": sha256_file(matrix_path),
        "rust_toolchain": "1.85.1",
    }
    if environment != expected_environment:
        raise ReleaseContractError("manifest environment digests do not match")
    if len(records) != 5:
        raise ReleaseContractError("manifest must describe five release archives")

    expected_records: dict[str, dict[str, object]] = {
        spec.archive: {
            "name": spec.archive,
            "kind": "platform-archive",
            "system": spec.system,
            "runner": spec.runner,
            "rust_target": spec.rust_target,
        }
        for spec in matrix.artifacts
    }
    expected_records[source_name] = {
        "name": source_name,
        "kind": "source-archive",
    }
    checksums = _parse_checksums(checksums_path)
    seen_names: set[str] = set()
    for value in records:
        record = _object_record(value, "manifest artifact")
        name = _required_string(record, "name")
        digest = _required_string(record, "sha256")
        size = record.get("bytes")
        expected = expected_records.get(name)
        path = artifact_dir / name
        if (
            expected is None
            or name in seen_names
            or Path(name).name != name
            or path.is_symlink()
            or not path.is_file()
        ):
            raise ReleaseContractError(f"manifest artifact is unavailable: {name}")
        identity = {
            key: value
            for key, value in record.items()
            if key not in {"bytes", "sha256"}
        }
        if identity != expected:
            raise ReleaseContractError(f"manifest artifact metadata changed: {name}")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or SHA256_PATTERN.fullmatch(digest) is None
        ):
            raise ReleaseContractError(f"manifest artifact bounds are invalid: {name}")
        if digest != sha256_file(path) or size != path.stat().st_size:
            raise ReleaseContractError(f"manifest artifact changed: {name}")
        seen_names.add(name)
    if seen_names != set(expected_records):
        raise ReleaseContractError(
            "manifest artifact set does not match release matrix"
        )
    expected_checksum_names = {*seen_names, manifest_path.name}
    if set(checksums) != expected_checksum_names:
        raise ReleaseContractError(
            "SHA256SUMS file set does not match release manifest"
        )
    for name, digest in checksums.items():
        path = manifest_path if name == manifest_path.name else artifact_dir / name
        if digest != sha256_file(path):
            raise ReleaseContractError(f"checksum mismatch: {name}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Diagnostic Triage release contract")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("create", "verify"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--repository-root", type=Path, default=Path("."))
        subparser.add_argument(
            "--matrix", type=Path, default=Path("release/artifact-matrix.json")
        )
        subparser.add_argument("--artifact-dir", type=Path, required=True)
        subparser.add_argument("--manifest", type=Path, required=True)
        subparser.add_argument("--checksums", type=Path, required=True)
        subparser.add_argument("--tag", required=True)
        subparser.add_argument("--revision", required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    repository_root = cast(Path, arguments.repository_root)
    matrix_path = cast(Path, arguments.matrix)
    artifact_dir = cast(Path, arguments.artifact_dir)
    manifest_path = cast(Path, arguments.manifest)
    checksums_path = cast(Path, arguments.checksums)
    tag = cast(str, arguments.tag)
    revision = cast(str, arguments.revision)
    try:
        if arguments.command == "create":
            create_release_manifest(
                repository_root=repository_root,
                matrix_path=matrix_path,
                artifact_dir=artifact_dir,
                tag=tag,
                revision=revision,
                manifest_path=manifest_path,
                checksums_path=checksums_path,
            )
        else:
            verify_release(
                repository_root=repository_root,
                matrix_path=matrix_path,
                artifact_dir=artifact_dir,
                expected_tag=tag,
                expected_revision=revision,
                manifest_path=manifest_path,
                checksums_path=checksums_path,
            )
    except ReleaseContractError as error:
        print(f"release contract failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
