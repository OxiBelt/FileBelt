#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for fail-closed image evidence validation."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROLE = "filebelt-api"
PLATFORM = "linux/amd64"
REPOSITORY = "ghcr.io/oxibelt/filebelt-api"
VERSION = "0.1.0"
TAG = "0.1.0-build.0123456789ab"
LOCAL_REF = f"{REPOSITORY}:{TAG}-amd64"
REVISION = "0123456789abcdef0123456789abcdef01234567"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tar_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class ImageEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="filebelt-evidence-")
        self.directory = Path(self.temporary.name)
        self.script = Path(__file__).with_name("validate-image-evidence.py")
        self.plan = self.directory / "image-plan.json"
        self.archive = self.directory / f"{ROLE}-amd64.docker.tar"
        self.metadata = self.directory / f"{ROLE}-amd64.build.json"
        self.checksum = self.directory / f"{self.archive.name}.sha256"
        self.output = self.directory / "evidence.json"
        self.plan_value = {
            "schemaVersion": 1,
            "version": VERSION,
            "tag": TAG,
            "source": {
                "revision": REVISION,
                "ref": "refs/heads/main",
                "created": "2026-08-06T12:34:56Z",
                "dirty": False,
                "kind": "ci",
            },
            "images": [
                {
                    "role": ROLE,
                    "repository": REPOSITORY,
                    "platforms": [PLATFORM],
                    "build": {
                        "dockerfile": "source/ops/Dockerfile.roles",
                        "target": ROLE,
                    },
                }
            ],
        }
        self.plan.write_text(
            json.dumps(self.plan_value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        self.write_fixture()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_archive(self, *, local_ref: str = LOCAL_REF, architecture: str = "amd64") -> None:
        manifest = [{"Config": "config.json", "RepoTags": [local_ref], "Layers": []}]
        config = {"os": "linux", "architecture": architecture, "config": {}}
        with tarfile.open(self.archive, "w") as archive:
            for name, data in (("manifest.json", tar_bytes(manifest)), ("config.json", tar_bytes(config))):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(data))

    def expected_metadata(self) -> dict[str, Any]:
        return {
            "schemaVersion": 1,
            "planSha256": sha256(self.plan),
            "role": ROLE,
            "platform": PLATFORM,
            "repository": REPOSITORY,
            "version": VERSION,
            "tag": TAG,
            "localRef": LOCAL_REF,
            "sourceRevision": REVISION,
            "sourceRef": "refs/heads/main",
            "sourceCreated": "2026-08-06T12:34:56Z",
            "sourceDirty": False,
            "sourceKind": "ci",
            "dockerfile": "source/ops/Dockerfile.roles",
            "buildTarget": ROLE,
            "archive": self.archive.name,
            "archiveSha256": sha256(self.archive),
        }

    def write_fixture(
        self,
        *,
        local_ref: str = LOCAL_REF,
        architecture: str = "amd64",
        metadata_overrides: dict[str, Any] | None = None,
        checksum_digest: str | None = None,
    ) -> None:
        self.write_archive(local_ref=local_ref, architecture=architecture)
        metadata = self.expected_metadata()
        metadata.update(metadata_overrides or {})
        self.metadata.write_text(json.dumps(metadata) + "\n", encoding="utf-8")
        digest = checksum_digest if checksum_digest is not None else sha256(self.archive)
        self.checksum.write_text(f"{digest}  {self.archive.name}\n", encoding="ascii")

    def run_validator(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(self.script),
                "--plan",
                str(self.plan),
                "--metadata",
                str(self.metadata),
                "--checksum",
                str(self.checksum),
                "--archive",
                str(self.archive),
                "--role",
                ROLE,
                "--platform",
                PLATFORM,
                "--output",
                str(self.output),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_rejected(self, message: str) -> None:
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)

    def test_accepts_complete_cross_linked_evidence(self) -> None:
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(evidence["planSha256"], sha256(self.plan))
        self.assertEqual(evidence["archiveSha256"], sha256(self.archive))
        self.assertEqual(evidence["localRef"], LOCAL_REF)

    def test_rejects_archive_checksum_tampering(self) -> None:
        self.write_fixture(checksum_digest="f" * 64)
        self.assert_rejected("archive SHA-256 does not match")

    def test_rejects_archive_digest_metadata_tampering(self) -> None:
        self.write_fixture(metadata_overrides={"archiveSha256": "f" * 64})
        self.assert_rejected("build metadata archiveSha256")

    def test_rejects_local_reference_inside_archive(self) -> None:
        self.write_fixture(local_ref=f"{REPOSITORY}:untrusted-amd64")
        self.assert_rejected("local reference does not match")

    def test_rejects_archive_platform_mismatch(self) -> None:
        self.write_fixture(architecture="arm64")
        self.assert_rejected("config platform does not match")

    def test_rejects_plan_and_build_metadata_drift(self) -> None:
        mutations = {
            "planSha256": "f" * 64,
            "repository": "ghcr.io/example/filebelt-api",
            "version": "9.9.9",
            "tag": "9.9.9",
            "localRef": f"{REPOSITORY}:untrusted-amd64",
            "platform": "linux/arm64",
            "sourceRevision": "f" * 40,
            "sourceRef": "refs/heads/untrusted",
            "sourceCreated": "2026-08-07T00:00:00Z",
            "sourceDirty": True,
            "sourceKind": "local",
            "dockerfile": "Dockerfile.untrusted",
            "buildTarget": "untrusted",
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                self.write_fixture(metadata_overrides={key: value})
                self.assert_rejected(f"build metadata {key}")

    def test_rejects_unknown_build_metadata(self) -> None:
        self.write_fixture(metadata_overrides={"untrusted": True})
        self.assert_rejected("missing or unknown properties")

    def test_rebuild_gate_validates_both_archives_before_comparison(self) -> None:
        rebuild = Path(__file__).with_name("verify-image-rebuild.sh").read_text(encoding="utf-8")
        first_validation = rebuild.index('--archive "${first}" --metadata "${first_metadata}"')
        second_validation = rebuild.index('--archive "${second}" --metadata "${second_metadata}"')
        first_sbom = rebuild.index('first_sbom="${output_dir}/first/')
        comparison = rebuild.index('compare-image-artifacts.py')
        self.assertLess(first_validation, first_sbom)
        self.assertLess(second_validation, first_sbom)
        self.assertLess(first_sbom, comparison)
        self.assertEqual(rebuild.count("validate-image-evidence.py"), 2)


if __name__ == "__main__":
    unittest.main()
