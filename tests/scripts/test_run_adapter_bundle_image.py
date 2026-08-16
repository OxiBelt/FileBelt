#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Unit contracts for closed adapter bundle-image build arguments."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tests/scripts/run-adapter-bundle-image.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("run_adapter_bundle_image", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class AdapterBundleImageArgumentsTests(unittest.TestCase):
    def test_platform_cpu_arguments_are_closed_and_plan_derived(self) -> None:
        plan = {"amd64IsaBaseline": "x86-64-v3"}
        self.assertEqual(
            RUNNER.platform_cpu_build_arguments(plan, "linux/amd64"),
            {
                "FILEBELT_AMD64_ISA": "x86-64-v3",
                "FILEBELT_TARGET_CPU": "x86-64-v3",
            },
        )
        self.assertEqual(
            RUNNER.platform_cpu_build_arguments(plan, "linux/arm64"),
            {"FILEBELT_TARGET_CPU": "architecture-default"},
        )
        self.assertEqual(
            RUNNER.platform_cpu_build_arguments(plan, "linux/riscv64"),
            {"FILEBELT_TARGET_CPU": "architecture-default"},
        )

    def test_rejects_an_altered_plan_baseline(self) -> None:
        with self.assertRaisesRegex(ValueError, "AMD64 ISA baseline"):
            RUNNER.platform_cpu_build_arguments(
                {"amd64IsaBaseline": "x86-64-v2"}, "linux/amd64"
            )


if __name__ == "__main__":
    unittest.main()
