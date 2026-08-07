#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for FileBelt's Cargo boundary checker."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = Path(__file__).with_name("check-cargo-boundaries.py")
FIXTURE_ROOT = REPO_ROOT / "tests/fixtures/cargo-boundaries"
SPEC = importlib.util.spec_from_file_location("check_cargo_boundaries", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)
POLICY = CHECKER.load_policy(REPO_ROOT / CHECKER.POLICY_FILENAME)
PROFILE_BY_PACKAGE = {profile.package: profile for profile in POLICY.profiles}


def fixture(name: str) -> str:
    return (FIXTURE_ROOT / name).read_text(encoding="utf-8")


class CargoBoundaryTests(unittest.TestCase):
    def test_policy_registers_every_current_production_manifest(self) -> None:
        self.assertEqual(POLICY.schema_version, 1)
        self.assertEqual(len(POLICY.profiles), 21)
        CHECKER.validate_repository_layout(REPO_ROOT, POLICY)

    def test_accepts_exact_authorization_graph(self) -> None:
        summary = CHECKER.validate_profile_graph(
            PROFILE_BY_PACKAGE["filebelt-authz"],
            fixture("allowed-authz.txt"),
            POLICY.first_party_packages,
        )
        self.assertEqual(summary.packages, 3)
        self.assertEqual(summary.first_party_packages, 2)

    def test_rejects_first_party_closure_drift(self) -> None:
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            "first-party package closure differs",
        ):
            CHECKER.validate_profile_graph(
                PROFILE_BY_PACKAGE["filebelt-authz"],
                fixture("forbidden-first-party.txt"),
                POLICY.first_party_packages,
            )

    def test_rejects_first_party_feature_drift(self) -> None:
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            r"filebelt-authz features are \[default\] but must be \[\]",
        ):
            CHECKER.validate_profile_graph(
                PROFILE_BY_PACKAGE["filebelt-authz"],
                fixture("forbidden-feature.txt"),
                POLICY.first_party_packages,
            )

    def test_rejects_forbidden_external_family(self) -> None:
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            "forbidden transitive packages: sqlx",
        ):
            CHECKER.validate_profile_graph(
                PROFILE_BY_PACKAGE["filebelt-authz"],
                fixture("forbidden-sql.txt"),
                POLICY.first_party_packages,
            )

    def test_rejects_unregistered_local_package(self) -> None:
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            "unknown local/path packages: unregistered-local-helper",
        ):
            CHECKER.validate_profile_graph(
                PROFILE_BY_PACKAGE["filebelt-authz"],
                fixture("forbidden-unregistered-local.txt"),
                POLICY.first_party_packages,
            )

    def test_rejects_empty_and_malformed_graphs(self) -> None:
        for name, message in [
            ("empty.txt", "did not contain any package nodes"),
            ("malformed.txt", "separator"),
        ]:
            with self.subTest(name=name):
                with self.assertRaisesRegex(CHECKER.BoundaryError, message):
                    CHECKER.validate_profile_graph(
                        PROFILE_BY_PACKAGE["filebelt-authz"],
                        fixture(name),
                        POLICY.first_party_packages,
                    )

    def test_commands_are_locked_target_complete_and_exclude_dev_edges(self) -> None:
        for profile in POLICY.profiles:
            with self.subTest(package=profile.package):
                command = CHECKER.cargo_tree_command(profile)
                self.assertIn("--locked", command)
                self.assertEqual(command[command.index("--target") + 1], "all")
                self.assertEqual(command[command.index("-e") + 1], "normal,build")
                self.assertEqual(
                    command[command.index("--manifest-path") + 1],
                    profile.manifest,
                )
                self.assertNotIn("dev", command)
                self.assertEqual(command[command.index("--color") + 1], "never")

    def test_workspace_metadata_is_structured_and_manifest_bound(self) -> None:
        packages = []
        members = []
        for profile in POLICY.profiles:
            package_id = f"path+file:///workspace/{profile.package}#0.1.0"
            packages.append(
                {
                    "id": package_id,
                    "name": profile.package,
                    "manifest_path": f"/workspace/{profile.manifest}",
                }
            )
            members.append(package_id)
        metadata = CHECKER.parse_workspace_metadata(
            json.dumps({"packages": packages, "workspace_members": members}),
            Path("/workspace"),
        )
        self.assertEqual(metadata.workspace_packages, POLICY.first_party_packages)

    def test_adapter_fixture_is_independent_and_requires_registration(self) -> None:
        fixture_root = FIXTURE_ROOT / "adapter-repository"
        discovered = CHECKER.discover_adapter_manifests(fixture_root, "adapters")
        expected = frozenset({"adapters/example/Cargo.toml"})
        self.assertEqual(discovered, expected)
        CHECKER.validate_adapter_registration(discovered, expected)
        with self.assertRaisesRegex(CHECKER.BoundaryError, "unregistered"):
            CHECKER.validate_adapter_registration(discovered, frozenset())


if __name__ == "__main__":
    unittest.main()
