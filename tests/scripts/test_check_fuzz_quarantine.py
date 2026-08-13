#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the sustained-fuzz quarantine sentinel."""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = Path(__file__).with_name("check-fuzz-quarantine.py")
SPEC = importlib.util.spec_from_file_location("check_fuzz_quarantine", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class FuzzQuarantineTests(unittest.TestCase):
    def test_accepts_the_exact_reviewed_quarantine(self) -> None:
        CHECKER.validate_quarantine(REPO_ROOT, "collaboration_wire")

    def test_rejects_an_unreviewed_target(self) -> None:
        with self.assertRaisesRegex(CHECKER.QuarantineError, "not the reviewed"):
            CHECKER.validate_quarantine(REPO_ROOT, "runtime_config")

    def test_rejects_dependency_and_quarantine_drift(self) -> None:
        for path, old, new, message in (
            (
                "Cargo.lock",
                'version = "0.27.3"',
                'version = "0.27.4"',
                "missing or duplicated",
            ),
            (
                "fuzz/targets.toml",
                'status = "risk_accepted"',
                'status = "ignored"',
                "exact sentinel",
            ),
            (
                "fuzz/targets.toml",
                '[[quarantine]]',
                '[[quarantine]]\n'
                + "\n".join(
                    f"{key} = {self.toml(value)}"
                    for key, value in CHECKER.EXPECTED_QUARANTINE.items()
                )
                + "\n\n[[quarantine]]",
                "exact sentinel",
            ),
        ):
            with self.subTest(path=path, old=old, new=new):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "fuzz/fuzz_targets").mkdir(parents=True)
                    shutil.copy(REPO_ROOT / "Cargo.lock", root / "Cargo.lock")
                    shutil.copy(REPO_ROOT / "fuzz/targets.toml", root / "fuzz/targets.toml")
                    shutil.copy(
                        REPO_ROOT / "fuzz/fuzz_targets/collaboration_wire.rs",
                        root / "fuzz/fuzz_targets/collaboration_wire.rs",
                    )
                    fixture = root / path
                    source = fixture.read_text(encoding="utf-8")
                    self.assertIn(old, source)
                    fixture.write_text(source.replace(old, new, 1), encoding="utf-8")
                    with self.assertRaisesRegex(CHECKER.QuarantineError, message):
                        CHECKER.validate_quarantine(root, "collaboration_wire")

    def test_rejects_target_source_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fuzz/fuzz_targets").mkdir(parents=True)
            shutil.copy(REPO_ROOT / "Cargo.lock", root / "Cargo.lock")
            shutil.copy(REPO_ROOT / "fuzz/targets.toml", root / "fuzz/targets.toml")
            target = root / "fuzz/fuzz_targets/collaboration_wire.rs"
            target.write_bytes(
                (REPO_ROOT / "fuzz/fuzz_targets/collaboration_wire.rs").read_bytes()
                + b"\n"
            )
            with self.assertRaisesRegex(CHECKER.QuarantineError, "target source changed"):
                CHECKER.validate_quarantine(root, "collaboration_wire")

    @staticmethod
    def toml(value: object) -> str:
        if value is True:
            return "true"
        if isinstance(value, str):
            return f'"{value}"'
        if isinstance(value, list):
            return "[" + ", ".join(f'"{item}"' for item in value) + "]"
        raise AssertionError(f"unsupported TOML test value: {value!r}")


if __name__ == "__main__":
    unittest.main()
