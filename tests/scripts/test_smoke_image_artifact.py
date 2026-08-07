#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for image smoke metadata handling."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any


IMAGE_REF = "ghcr.io/oxibelt/filebelt-api:test"
REVISION = "0123456789abcdef0123456789abcdef01234567"


class ImageSmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="filebelt-smoke-")
        self.directory = Path(self.temporary.name)
        self.fake_bin = self.directory / "bin"
        self.fake_bin.mkdir()
        self.script = Path(__file__).with_name("smoke-image-artifact.sh")
        self.plan = self.directory / "plan.json"
        self.archive = self.directory / "image.tar"
        self.output = self.directory / "smoke.json"
        self.archive.touch()

        self.write_executable("python3", "#!/bin/sh\nexit 0\n")
        self.write_executable(
            "tar",
            "#!/bin/sh\n"
            "printf '[{\"RepoTags\":[\"%s\"]}]\\n' \"${MOCK_IMAGE_REF}\"\n",
        )
        self.write_executable(
            "docker",
            r"""#!/bin/sh
case "${1-}" in
  image)
    if [ "${2-}" = inspect ]; then
      exit 1
    fi
    exit 0
    ;;
  load)
    printf 'Loaded image: %s\n' "${MOCK_IMAGE_REF}"
    ;;
  run)
    case " $* " in
      *" --version "*)
        printf '%s %s (%s)\n' "${MOCK_ROLE}" "${MOCK_VERSION}" "${MOCK_REVISION}"
        ;;
      *" --build-info=json "*)
        printf '{"role":"%s","version":"%s","revision":"%s","source_ref":"%s","dirty":%s,"kind":"%s"}\n' \
          "${MOCK_ROLE}" "${MOCK_VERSION}" "${MOCK_REVISION}" "${MOCK_SOURCE_REF}" \
          "${MOCK_DIRTY}" "${MOCK_KIND}"
        ;;
      *) exit 1 ;;
    esac
    ;;
  *) exit 1 ;;
esac
""",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_executable(self, name: str, contents: str) -> None:
        path = self.fake_bin / name
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o755)

    def write_plan(self, dirty: Any) -> None:
        self.plan.write_text(
            json.dumps(
                {
                    "version": "0.1.0",
                    "source": {
                        "revision": REVISION,
                        "ref": "refs/heads/main",
                        "dirty": dirty,
                        "kind": "ci",
                    },
                }
            ),
            encoding="utf-8",
        )

    def run_smoke(self, dirty: str) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "PATH": f"{self.fake_bin}:{os.environ['PATH']}",
            "MOCK_IMAGE_REF": IMAGE_REF,
            "MOCK_ROLE": "filebelt-api",
            "MOCK_VERSION": "0.1.0",
            "MOCK_REVISION": REVISION,
            "MOCK_SOURCE_REF": "refs/heads/main",
            "MOCK_DIRTY": dirty,
            "MOCK_KIND": "ci",
        }
        return subprocess.run(
            [
                "sh",
                str(self.script),
                "--plan",
                str(self.plan),
                "--role",
                "filebelt-api",
                "--platform",
                "linux/amd64",
                "--archive",
                str(self.archive),
                "--output",
                str(self.output),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_boolean_dirty_values_complete_smoke_validation(self) -> None:
        for dirty in (False, True):
            with self.subTest(dirty=dirty):
                self.output.unlink(missing_ok=True)
                self.write_plan(dirty)
                result = self.run_smoke(str(dirty).lower())
                self.assertEqual(result.returncode, 0, result.stderr)
                evidence = json.loads(self.output.read_text(encoding="utf-8"))
                self.assertTrue(evidence["passed"])
                self.assertEqual(evidence["sourceRevision"], REVISION)

    def test_non_boolean_dirty_value_fails_closed(self) -> None:
        self.write_plan("false")
        result = self.run_smoke("false")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("image plan source.dirty must be a boolean", result.stderr)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
