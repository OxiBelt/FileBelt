#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROLES = (
    "filebelt-api",
    "filebelt-worker-io",
    "filebelt-worker-maintenance",
    "filebelt-media-controller",
    "filebelt-mcp-broker",
    "filebelt-tools",
    "filebelt-web",
)


class KubernetesReleaseGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / "artifacts"
        self.bin = self.root / "bin"
        self.artifacts.mkdir()
        self.bin.mkdir()
        self.docker_log = self.root / "docker.log"
        self.docker_log.write_text("", encoding="utf-8")
        docker = self.bin / "docker"
        docker.write_text(
            """#!/usr/bin/env bash
printf '%s\n' "$*" >>"$DOCKER_LOG"
exit 99
""",
            encoding="utf-8",
        )
        docker.chmod(0o755)
        self.script = Path(__file__).with_name("run-kubernetes-release-gate.sh")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_plan(self, *, repository_owner: str = "oxibelt") -> None:
        plan = {
            "schemaVersion": 1,
            "channel": "release",
            "version": "1.2.3",
            "tag": "1.2.3",
            "source": {
                "kind": "release",
                "dirty": False,
                "url": "https://github.com/OxiBelt/FileBelt",
                "ref": "refs/tags/1.2.3",
                "revision": "a" * 40,
            },
            "runtime": {"uid": 10001, "gid": 10001},
            "images": [
                {
                    "role": role,
                    "repository": f"ghcr.io/{repository_owner}/{role}",
                    "platforms": ["linux/amd64", "linux/arm64", "linux/riscv64"],
                }
                for role in ROLES
            ],
        }
        (self.artifacts / "image-plan.json").write_text(
            json.dumps(plan), encoding="utf-8"
        )

    def run_script(self) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.bin}:{environment['PATH']}",
                "DOCKER_LOG": str(self.docker_log),
            }
        )
        return subprocess.run(
            [self.script, "--image-dir", self.artifacts],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_requires_each_validated_active_archive_before_docker_runs(self) -> None:
        self.write_plan()
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected exactly one filebelt-api-amd64.docker.tar", result.stderr)
        self.assertEqual(self.docker_log.read_text(encoding="utf-8"), "")

    def test_rejects_a_release_plan_outside_the_ghcr_allowlist(self) -> None:
        self.write_plan(repository_owner="attacker")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.docker_log.read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
