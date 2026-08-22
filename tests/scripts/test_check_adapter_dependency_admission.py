#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for adapter dependency-admission command generation."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = Path(__file__).with_name("check-adapter-dependency-admission.py")
SPEC = importlib.util.spec_from_file_location("adapter_dependency_admission", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class AdapterDependencyAdmissionTests(unittest.TestCase):
    def test_each_registered_adapter_has_audit_and_license_commands(self) -> None:
        manifests = CHECKER.registered_adapters(REPO_ROOT)
        CHECKER.validate_admission_artifacts(manifests)
        commands = CHECKER.commands(REPO_ROOT, manifests)
        self.assertEqual(len(commands), len(manifests) * 2)
        self.assertFalse(any("vet" in command for command in commands))
        for manifest in manifests:
            with self.subTest(manifest=manifest):
                self.assertIn(
                    ("cargo", "audit", "--file", str(manifest.parent / "Cargo.lock")),
                    commands,
                )
                self.assertIn(
                    (
                        "cargo",
                        "deny",
                        "--config",
                        str(manifest.parent / "deny.toml"),
                        "--manifest-path",
                        str(manifest),
                        "--locked",
                        "check",
                    ),
                    commands,
                )

    def test_registered_adapter_names_are_complete_and_deterministic(self) -> None:
        manifests = CHECKER.registered_adapters(REPO_ROOT)
        CHECKER.validate_admission_artifacts(manifests)
        self.assertEqual(
            CHECKER.adapter_names(REPO_ROOT, manifests),
            (
                "directory-repository",
                "ftp-ftps",
                "git",
                "nfs",
                "onlyoffice",
                "smb",
                "transcode",
                "wireguard",
            ),
        )


if __name__ == "__main__":
    unittest.main()
