#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for independent media-protocol dependency admission."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = Path(__file__).with_name("check-media-dependency-admission.py")
SPEC = importlib.util.spec_from_file_location("media_dependency_admission", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class MediaDependencyAdmissionTests(unittest.TestCase):
    def test_workflow_runs_media_admission(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/check-filebelt.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "python3 tests/scripts/check-media-dependency-admission.py --repo-root .",
            workflow,
        )

    def test_media_commands_use_root_apache_vet_store(self) -> None:
        CHECKER.validate_admission_artifacts(REPO_ROOT)
        commands = CHECKER.commands(REPO_ROOT)
        manifest = REPO_ROOT / "protocol/media/Cargo.toml"
        self.assertEqual(
            commands,
            (
                ("cargo", "audit", "--file", str(REPO_ROOT / "protocol/media/Cargo.lock")),
                (
                    "cargo",
                    "deny",
                    "--config",
                    str(REPO_ROOT / "protocol/media/deny.toml"),
                    "--manifest-path",
                    str(manifest),
                    "--locked",
                    "check",
                ),
                (
                    "cargo",
                    "vet",
                    "--manifest-path",
                    str(manifest),
                    "--store-path",
                    str(REPO_ROOT / "supply-chain"),
                    "--locked",
                    "--no-minimize-exemptions",
                ),
            ),
        )
        self.assertEqual(
            CHECKER.working_directory(REPO_ROOT, commands[0]),
            REPO_ROOT / "protocol/media",
        )
        self.assertEqual(CHECKER.working_directory(REPO_ROOT, commands[1]), REPO_ROOT)
        audit_config = (
            REPO_ROOT / "protocol/media/.cargo/audit.toml"
        ).read_text(encoding="utf-8")
        self.assertIn("ignore = []", audit_config)
        deny_config = (REPO_ROOT / "protocol/media/deny.toml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("ignore =", deny_config)
        self.assertNotIn("exceptions =", deny_config)

    def test_missing_media_lockfile_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "protocol/media").mkdir(parents=True)
            (root / "protocol/media/.cargo").mkdir()
            (root / "supply-chain").mkdir()
            (root / "protocol/media/Cargo.toml").write_text("[package]\n", encoding="utf-8")
            (root / "protocol/media/.cargo/audit.toml").write_text(
                "[advisories]\nignore = []\n", encoding="utf-8"
            )
            (root / "protocol/media/deny.toml").write_text(
                "[graph]\n", encoding="utf-8"
            )
            (root / "supply-chain/config.toml").write_text("[cargo-vet]\n", encoding="utf-8")
            (root / "supply-chain/audits.toml").write_text("[audits]\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Cargo.lock"):
                CHECKER.validate_admission_artifacts(root)


if __name__ == "__main__":
    unittest.main()
