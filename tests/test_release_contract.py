from __future__ import annotations

import json
import re
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
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "release.yml"
REVISION = "0123456789abcdef0123456789abcdef01234567"
ACTION_PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "cachix/install-nix-action": "630ae543ea3a38a9a4166f03376c02c50f408342",
}


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

    def test_unmanifested_directory_files_are_rejected_in_both_phases(self) -> None:
        unexpected = self.artifact_dir / "stale-release.tar.gz"
        unexpected.write_bytes(b"unattested\n")
        with self.assertRaisesRegex(ReleaseContractError, "does not match"):
            self.create()

        unexpected.unlink()
        self.create()
        unexpected.write_bytes(b"unattested\n")
        with self.assertRaisesRegex(ReleaseContractError, "does not match"):
            self.verify()

    def test_symlink_artifact_and_duplicate_manifest_key_are_rejected(self) -> None:
        target = self.artifact_dir / self.matrix.artifacts[0].archive
        target.unlink()
        target.symlink_to(self.source_name)
        with self.assertRaisesRegex(ReleaseContractError, "does not match"):
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

    def test_release_workflow_pins_every_action(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        references = re.findall(
            r"^\s*uses:\s+([^@\s]+)@([^\s#]+)", workflow, re.MULTILINE
        )
        self.assertTrue(references)
        self.assertTrue(
            all(re.fullmatch(r"[0-9a-f]{40}", ref) for _, ref in references)
        )
        self.assertEqual(set(references), set(ACTION_PINS.items()))
        self.assertNotIn("sigstore/cosign-installer", workflow)
        self.assertNotIn("cosign-release:", workflow)
        self.assertIn(
            "nix develop --accept-flake-config .#release --command bash",
            workflow,
        )
        self.assertIn("github.event_name == 'push'", workflow)
        self.assertEqual(workflow.count("ref: ${{ github.sha }}"), 4)
        self.assertEqual(
            workflow.count('test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"'),
            4,
        )
        self.assertIn(
            'test "$(git rev-parse "${GITHUB_REF}^{commit}")" = "${GITHUB_SHA}"',
            workflow,
        )
        self.assertIn('git archive \\\n', workflow)
        self.assertIn('"${GITHUB_SHA}" \\\n            | gzip -n', workflow)
        self.assertIn('install_root="$(mktemp -d)"', workflow)
        self.assertIn("gzip -t", workflow)
        self.assertIn('source_root="${source_unpack}/diagnostic-triage-', workflow)
        publish_job, release_job = workflow.split("\n  release:\n", 1)
        publish_job = publish_job.split("\n  publish:\n", 1)[1]
        self.assertIn("contents: read", publish_job)
        self.assertNotIn("contents: write", publish_job)
        self.assertIn("contents: write", release_job)

    def test_cosign_is_sourced_from_the_locked_release_shell(self) -> None:
        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        self.assertIn("release = pkgs.mkShell", flake)
        self.assertIn("packages = [ pkgs.cosign ];", flake)

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
