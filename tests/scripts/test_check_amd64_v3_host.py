#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Direct contracts for the bounded x86-64-v3 host preflight."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "tests/scripts/check-amd64-v3-host.sh"
V3_FLAGS = (
    "cx16 lahf_lm popcnt sse3 ssse3 sse4_1 sse4_2 avx avx2 bmi1 bmi2 "
    "f16c fma lzcnt movbe xsave"
)


def cpuinfo(*flag_sets: str) -> str:
    return "\n\n".join(
        f"processor\t: {index}\nflags\t\t: {flags}" for index, flags in enumerate(flag_sets)
    ) + "\n"


class Amd64V3HostPreflightTests(unittest.TestCase):
    def run_checker(self, contents: str, *, machine: str = "x86_64") -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            fixture = temporary_path / "cpuinfo"
            fixture.write_text(contents, encoding="utf-8")
            binary = temporary_path / "uname"
            binary.write_text(f"#!/bin/sh\n[ \"$1\" = -m ] && printf '%s\\n' '{machine}'\n", encoding="utf-8")
            binary.chmod(0o755)
            environment = os.environ | {"PATH": f"{temporary}:{os.environ['PATH']}"}
            return subprocess.run(
                [str(CHECKER), "--format", "json", "--cpuinfo", str(fixture)],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )

    def test_accepts_every_v3_processor(self) -> None:
        result = self.run_checker(cpuinfo(V3_FLAGS, V3_FLAGS.replace("sse3", "pni", 1).replace("lzcnt", "abm")))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout),
            {
                "schemaVersion": 1,
                "architecture": "x86_64",
                "cpuCount": 2,
                "baseline": "x86-64-v3",
                "supported": True,
                "missingFeatures": [],
            },
        )

    def test_rejects_a_feature_missing_on_one_processor(self) -> None:
        result = self.run_checker(cpuinfo(V3_FLAGS, V3_FLAGS.replace("avx2 ", "")))
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report["supported"])
        self.assertEqual(report["cpuCount"], 2)
        self.assertEqual(report["missingFeatures"], ["avx2"])

    def test_reports_unique_missing_features_in_byte_order(self) -> None:
        result = self.run_checker(cpuinfo(V3_FLAGS.replace("avx2 ", "").replace("cx16 ", "")))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["missingFeatures"], ["avx2", "cx16"])

    def test_rejects_non_x86_host_without_cpu_inventory(self) -> None:
        result = self.run_checker(cpuinfo(V3_FLAGS), machine="aarch64")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["missingFeatures"], ["architecture:x86_64"])

    def test_rejects_malformed_cpuinfo(self) -> None:
        result = self.run_checker("processor\t: 0\n")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")

    def test_rejects_malformed_invocation(self) -> None:
        result = subprocess.run(
            [str(CHECKER), "--format"], check=False, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
