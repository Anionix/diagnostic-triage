from __future__ import annotations

import json
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import Any, cast

from tools.release_manifest import (
    ReleaseContractError,
    create_release_manifest,
    load_matrix,
    verify_release,
)

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "release" / "artifact-matrix.json"
REVISION = "0123456789abcdef0123456789abcdef01234567"


class ReleaseContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifact_dir = self.root / "dist"
        self.artifact_dir.mkdir()
        self.matrix = load_matrix(MATRIX_PATH)
        for index, spec in enumerate(self.matrix.artifacts):
            (self.artifact_dir / spec.archive).write_bytes(
                f"platform-{index}\n".encode()
            )
        self.source_name = f"diagnostic-triage-v{self.matrix.version}-source.tar.gz"
        (self.artifact_dir / self.source_name).write_bytes(b"source\n")
        self.manifest = self.artifact_dir / "release-manifest.json"
        self.checksums = self.artifact_dir / "SHA256SUMS"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create(self) -> dict[str, object]:
        return create_release_manifest(
            repository_root=ROOT,
            matrix_path=MATRIX_PATH,
            artifact_dir=self.artifact_dir,
            tag=f"v{self.matrix.version}",
            revision=REVISION,
            manifest_path=self.manifest,
            checksums_path=self.checksums,
        )

    def verify(self, revision: str = REVISION) -> None:
        verify_release(
            repository_root=ROOT,
            matrix_path=MATRIX_PATH,
            artifact_dir=self.artifact_dir,
            expected_tag=f"v{self.matrix.version}",
            expected_revision=revision,
            manifest_path=self.manifest,
            checksums_path=self.checksums,
        )

    def manifest_document(self) -> dict[str, object]:
        raw: object = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertIsInstance(raw, dict)
        return cast(dict[str, object], raw)

    def write_manifest(self, document: dict[str, object]) -> None:
        self.manifest.write_text(
            f"{json.dumps(document, indent=2, sort_keys=True)}\n",
            encoding="utf-8",
        )

    def test_manifest_and_checksums_verify_the_exact_release_set(self) -> None:
        document = self.create()

        self.verify()

        release = document["release"]
        self.assertIsInstance(release, dict)
        self.assertEqual(
            cast(dict[str, object], release)["source_revision"],
            REVISION,
        )
        artifacts = document["artifacts"]
        self.assertIsInstance(artifacts, list)
        self.assertEqual(len(cast(list[object], artifacts)), 5)
        checksum_names = {
            line.split("  ", 1)[1]
            for line in self.checksums.read_text(encoding="utf-8").splitlines()
        }
        self.assertEqual(
            checksum_names,
            {
                *(spec.archive for spec in self.matrix.artifacts),
                self.source_name,
                self.manifest.name,
            },
        )

    def test_tampered_archive_is_rejected(self) -> None:
        self.create()
        target = self.artifact_dir / self.matrix.artifacts[0].archive
        target.write_bytes(b"tampered\n")

        with self.assertRaisesRegex(ReleaseContractError, "artifact changed"):
            self.verify()

    def test_symlink_artifact_and_duplicate_manifest_key_are_rejected(self) -> None:
        target = self.artifact_dir / self.matrix.artifacts[0].archive
        target.unlink()
        target.symlink_to(self.source_name)
        with self.assertRaisesRegex(ReleaseContractError, "artifact is missing"):
            self.create()

        target.unlink()
        target.write_bytes(b"restored\n")
        self.create()
        self.manifest.write_text(
            '{"schema_version":"first","schema_version":"second"}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ReleaseContractError, "duplicate JSON key"):
            self.verify()

    def test_forged_release_and_platform_identity_are_rejected(self) -> None:
        self.create()
        release_document = self.manifest_document()
        release = release_document["release"]
        self.assertIsInstance(release, dict)
        cast(dict[str, object], release)["source_repository"] = (
            "https://example.invalid"
        )
        self.write_manifest(release_document)
        with self.assertRaisesRegex(ReleaseContractError, "release identity"):
            self.verify()

        self.create()
        with self.assertRaisesRegex(ReleaseContractError, "release identity"):
            self.verify("f" * 40)

        artifact_document = self.manifest_document()
        records = artifact_document["artifacts"]
        self.assertIsInstance(records, list)
        first = cast(list[object], records)[0]
        self.assertIsInstance(first, dict)
        cast(dict[str, object], first)["system"] = "forged-system"
        self.write_manifest(artifact_document)
        with self.assertRaisesRegex(ReleaseContractError, "metadata changed"):
            self.verify()

    def test_matrix_version_matches_workspace_and_release_notes(self) -> None:
        cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        workspace = cargo["workspace"]
        self.assertIsInstance(workspace, dict)
        package = workspace["package"]
        self.assertIsInstance(package, dict)
        self.assertEqual(package["version"], self.matrix.version)
        notes = (ROOT / "release" / "RELEASE_NOTES.md").read_text(encoding="utf-8")
        self.assertIn(f"v{self.matrix.version}", notes)

    def test_matrix_has_four_unique_native_runners(self) -> None:
        self.assertEqual(
            {spec.runner for spec in self.matrix.artifacts},
            {
                "macos-15",
                "macos-15-intel",
                "ubuntu-24.04",
                "ubuntu-24.04-arm",
            },
        )
        raw: Any = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
        self.assertEqual(raw["schema_version"], "diagnostic-triage.release-matrix/v1")


if __name__ == "__main__":
    unittest.main()
