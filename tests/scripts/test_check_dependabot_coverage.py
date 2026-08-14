#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for Dependabot composition discovery."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = Path(__file__).with_name("check-dependabot-coverage.py")
SPEC = importlib.util.spec_from_file_location("dependabot_coverage", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class DependabotCoverageTests(unittest.TestCase):
    def test_repository_coverage_is_complete(self) -> None:
        self.assertEqual(CHECKER.check(REPO_ROOT), [])

    def test_uncovered_adapter_lockfile_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".github").mkdir()
            (root / "adapters/example").mkdir(parents=True)
            (root / "supply-chain").mkdir()
            (root / ".github/dependabot.yml").write_text(
                'version: 2\nupdates:\n  - package-ecosystem: cargo\n    directory: "/"\n',
                encoding="utf-8",
            )
            (root / "adapters/example/Cargo.toml").write_text("[package]\n", encoding="utf-8")
            (root / "adapters/example/Cargo.lock").write_text("version = 4\n", encoding="utf-8")
            (root / "supply-chain/cargo-boundaries-v1.toml").write_text(
                '[repository]\nregistered_adapter_manifests = ["adapters/example/Cargo.toml"]\n',
                encoding="utf-8",
            )
            failures = CHECKER.check(root)
            self.assertTrue(any("adapter lacks independent Cargo" in failure for failure in failures))
            self.assertTrue(any("adapter admission artifact" in failure for failure in failures))

    def test_uncovered_docker_composition_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".github").mkdir()
            (root / "supply-chain").mkdir()
            (root / "images/example").mkdir(parents=True)
            (root / ".github/dependabot.yml").write_text(
                'version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: "/"\n',
                encoding="utf-8",
            )
            (root / "images/example/Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            (root / "supply-chain/cargo-boundaries-v1.toml").write_text(
                '[repository]\nregistered_adapter_manifests = []\n', encoding="utf-8"
            )
            failures = CHECKER.check(root)
            self.assertTrue(any("docker Dependabot coverage differs" in failure for failure in failures))

    def test_uncovered_compose_file_outside_deploy_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".github").mkdir()
            (root / "examples/standalone").mkdir(parents=True)
            (root / "supply-chain").mkdir()
            (root / ".github/dependabot.yml").write_text(
                'version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: "/"\n',
                encoding="utf-8",
            )
            (root / "examples/standalone/docker-compose.yml").write_text(
                "services: {}\n", encoding="utf-8"
            )
            (root / "supply-chain/cargo-boundaries-v1.toml").write_text(
                '[repository]\nregistered_adapter_manifests = []\n', encoding="utf-8"
            )
            failures = CHECKER.check(root)
            self.assertTrue(any("docker Dependabot coverage differs" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
