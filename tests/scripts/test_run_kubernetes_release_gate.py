#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class KubernetesReleaseGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / "artifacts"
        self.diagnostics = self.root / "diagnostics"
        self.bin = self.root / "bin"
        self.artifacts.mkdir()
        self.bin.mkdir()
        self.python_log = self.root / "python.log"
        python = self.bin / "python3"
        python.write_text(
            """#!/usr/bin/env bash
printf '%s\n' "$*" >"$PYTHON_LOG"
""",
            encoding="utf-8",
        )
        python.chmod(0o755)
        self.script = Path(__file__).with_name("run-kubernetes-release-gate.sh")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_script(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.bin}:{environment['PATH']}",
                "PYTHON_LOG": str(self.python_log),
            }
        )
        return subprocess.run(
            [self.script, *arguments],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_delegates_one_release_unit_to_the_shared_exact_artifact_runner(self) -> None:
        result = self.run_script(
            "--image-dir",
            str(self.artifacts),
            "--unit",
            "collaboration",
            "--diagnostics-dir",
            str(self.diagnostics),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        invocation = self.python_log.read_text(encoding="utf-8")
        self.assertIn("tests/docker/units/run-unit.py", invocation)
        self.assertIn("--unit collaboration", invocation)
        self.assertIn(f"--image-dir {self.artifacts}", invocation)
        self.assertIn("--image-channel release", invocation)
        self.assertIn("--docker-topology auto", invocation)
        self.assertIn(f"--diagnostics-dir {self.diagnostics}", invocation)

    def test_forwards_explicit_docker_topology(self) -> None:
        result = self.run_script(
            "--image-dir",
            str(self.artifacts),
            "--unit",
            "core",
            "--docker-topology",
            "outside",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "--docker-topology outside",
            self.python_log.read_text(encoding="utf-8"),
        )

    def test_rejects_unknown_unit_before_invoking_python(self) -> None:
        result = self.run_script(
            "--image-dir", str(self.artifacts), "--unit", "media"
        )
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.python_log.exists())

    def test_requires_an_existing_image_directory(self) -> None:
        result = self.run_script(
            "--image-dir", str(self.root / "missing"), "--unit", "core"
        )
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.python_log.exists())

    def test_rejects_unknown_docker_topology_before_invoking_python(self) -> None:
        result = self.run_script(
            "--image-dir",
            str(self.artifacts),
            "--unit",
            "core",
            "--docker-topology",
            "public",
        )
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.python_log.exists())


if __name__ == "__main__":
    unittest.main()
