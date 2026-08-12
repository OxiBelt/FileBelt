#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for FileBelt's exact Cargo Vet acceptance baseline."""

from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
EXACT_VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


def load_toml(relative_path: str) -> dict:
    with (REPO_ROOT / relative_path).open("rb") as handle:
        return tomllib.load(handle)


class CargoVetPolicyTests(unittest.TestCase):
    def test_opentelemetry_graph_is_coordinated_and_patched(self) -> None:
        cargo_lock = load_toml("Cargo.lock")
        expected_versions = {
            "opentelemetry": {"0.32.0"},
            "opentelemetry-http": {"0.32.0"},
            "opentelemetry-otlp": {"0.32.0"},
            "opentelemetry-proto": {"0.32.0"},
            "opentelemetry_sdk": {"0.32.1"},
            "tracing-opentelemetry": {"0.33.0"},
        }
        actual_versions = {
            crate_name: {
                package["version"]
                for package in cargo_lock.get("package", [])
                if package["name"] == crate_name
            }
            for crate_name in expected_versions
        }

        self.assertEqual(actual_versions, expected_versions)

    def test_exemptions_are_exact_locked_safe_to_deploy_records(self) -> None:
        config = load_toml("supply-chain/config.toml")
        cargo_lock = load_toml("Cargo.lock")
        exemptions = config.get("exemptions")

        self.assertIsInstance(exemptions, dict)
        self.assertTrue(exemptions, "Cargo Vet exemptions must not be empty")

        locked_packages = {
            (package["name"], package["version"])
            for package in cargo_lock.get("package", [])
        }
        seen: set[tuple[str, str]] = set()

        for crate_name, records in exemptions.items():
            self.assertIsInstance(crate_name, str)
            self.assertTrue(crate_name)
            self.assertIsInstance(records, list)
            self.assertTrue(records)

            for record in records:
                self.assertEqual(set(record), {"version", "criteria"})
                version = record["version"]
                self.assertIsInstance(version, str)
                self.assertRegex(version, EXACT_VERSION)
                self.assertEqual(record["criteria"], "safe-to-deploy")
                self.assertIn((crate_name, version), locked_packages)
                self.assertNotIn((crate_name, version), seen)
                seen.add((crate_name, version))

    def test_trusted_publishers_are_not_an_acceptance_substitute(self) -> None:
        config = load_toml("supply-chain/config.toml")
        self.assertNotIn("trusted", config)


if __name__ == "__main__":
    unittest.main()
