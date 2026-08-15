#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for the dependency-free ONLYOFFICE launcher lockfile."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = Path(__file__).with_name("check-onlyoffice-pnpm-lock.py")
SPEC = importlib.util.spec_from_file_location("onlyoffice_pnpm_lock", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class OnlyofficePnpmLockTests(unittest.TestCase):
    def test_onlyoffice_workflow_checks_the_lockfile_before_installing(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/onlyoffice-release.yml").read_text(
            encoding="utf-8"
        )
        check = workflow.find(
            "python3 tests/scripts/check-onlyoffice-pnpm-lock.py --repo-root ."
        )
        install = workflow.find("pnpm install --frozen-lockfile --ignore-scripts")
        self.assertNotEqual(check, -1)
        self.assertNotEqual(install, -1)
        self.assertLess(check, install)

    def test_current_lockfile_is_dependency_free(self) -> None:
        self.assertEqual(CHECKER.check(REPO_ROOT), [])

    def test_package_addition_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lockfile = root / CHECKER.LOCKFILE_PATH
            lockfile.parent.mkdir(parents=True)
            lockfile.write_text(
                f"{CHECKER.EXPECTED_LOCKFILE}\npackages:\n  example@1.0.0: {{}}\n",
                encoding="utf-8",
            )
            failures = CHECKER.check(root)
            self.assertEqual(len(failures), 1)
            self.assertIn("separate adapter-local dependency admission", failures[0])

    def test_missing_lockfile_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            failures = CHECKER.check(Path(temporary))
            self.assertEqual(len(failures), 1)
            self.assertIn("lockfile is missing", failures[0])


if __name__ == "__main__":
    unittest.main()
