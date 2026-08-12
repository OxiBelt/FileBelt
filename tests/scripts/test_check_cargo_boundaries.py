#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for FileBelt's Cargo boundary checker."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
REPO_ROOT = Path(__file__).resolve().parents[2]
METADATA_REPO_ROOT = Path("/workspace")
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


def metadata_for_profiles(
    profiles: list[CHECKER.GraphProfile],
    extra_members: tuple[tuple[str, str], ...] = (),
) -> CHECKER.WorkspaceMetadata:
    packages = []
    members = []
    for profile in profiles:
        package_id = f"path+file:///workspace/{profile.package}#0.1.0"
        packages.append(
            {
                "id": package_id,
                "name": profile.package,
                "version": "0.1.0",
                "source": None,
                "manifest_path": f"/workspace/{profile.manifest}",
            }
        )
        members.append(package_id)
    for manifest, name in extra_members:
        package_id = f"path+file:///workspace/{name}#0.1.0"
        packages.append(
            {
                "id": package_id,
                "name": name,
                "version": "0.1.0",
                "source": None,
                "manifest_path": f"/workspace/{manifest}",
            }
        )
        members.append(package_id)
    return CHECKER.parse_workspace_metadata(
        json.dumps({"packages": packages, "workspace_members": members}),
        METADATA_REPO_ROOT,
    )


def reviewed_catalog() -> CHECKER.IdentityCatalog:
    adapter_manifests = POLICY.repository.registered_adapter_manifests
    root_profiles = [
        profile
        for profile in POLICY.profiles
        if profile.manifest not in adapter_manifests
    ]
    adapter_metadata = {
        profile.manifest: metadata_for_profiles([profile])
        for profile in POLICY.profiles
        if profile.manifest in adapter_manifests
    }
    return CHECKER.validate_metadata(
        metadata_for_profiles(root_profiles), adapter_metadata, POLICY
    )


CATALOG = reviewed_catalog()


class CargoBoundaryTests(unittest.TestCase):
    def validate_authz(self, graph_name: str) -> CHECKER.GraphSummary:
        return CHECKER.validate_profile_graph(
            PROFILE_BY_PACKAGE["filebelt-authz"],
            fixture(graph_name),
            CATALOG,
            METADATA_REPO_ROOT,
        )

    def test_policy_registers_every_current_production_manifest(self) -> None:
        self.assertEqual(POLICY.schema_version, 1)
        self.assertEqual(len(POLICY.profiles), 37)
        CHECKER.validate_repository_layout(REPO_ROOT, POLICY)

    def test_accepts_exact_authorization_graph(self) -> None:
        summary = self.validate_authz("allowed-authz.txt")
        self.assertEqual(summary.packages, 3)
        self.assertEqual(summary.first_party_packages, 2)

    def test_rejects_first_party_closure_drift(self) -> None:
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            "first-party package closure differs",
        ):
            self.validate_authz("forbidden-first-party.txt")

    def test_rejects_first_party_feature_drift(self) -> None:
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            r"filebelt-authz features are \[default\] but must be \[\]",
        ):
            self.validate_authz("forbidden-feature.txt")

    def test_rejects_forbidden_external_family(self) -> None:
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            "forbidden transitive packages: sqlx",
        ):
            self.validate_authz("forbidden-sql.txt")

    def test_rejects_unregistered_local_package(self) -> None:
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            "unknown local/path packages: unregistered-local-helper",
        ):
            self.validate_authz("forbidden-unregistered-local.txt")

    def test_rejects_same_name_local_spoof_even_with_legitimate_package(self) -> None:
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            "reserved first-party package identities differ: filebelt-domain v9.9.9",
        ):
            self.validate_authz("spoofed-local-domain.txt")

    def test_does_not_collapse_distinct_same_name_identities(self) -> None:
        parsed = CHECKER.parse_cargo_tree(
            fixture("spoofed-local-domain.txt"), METADATA_REPO_ROOT
        )
        domain_identities = [
            identity
            for identity in parsed.features_by_identity
            if identity.name == "filebelt-domain"
        ]
        self.assertEqual(len(domain_identities), 2)
        with self.assertRaises(CHECKER.BoundaryError):
            self.validate_authz("spoofed-local-domain.txt")

    def test_rejects_reserved_registry_and_git_name_collisions(self) -> None:
        for graph_name in ("spoofed-registry-domain.txt", "spoofed-git-domain.txt"):
            with self.subTest(graph_name=graph_name):
                with self.assertRaisesRegex(
                    CHECKER.BoundaryError,
                    (
                        "reserved first-party package identities differ: "
                        "filebelt-domain v0.1.0"
                    ),
                ):
                    self.validate_authz(graph_name)

    def test_canonicalizes_file_url_local_sources(self) -> None:
        for source in (
            "file:///workspace/source/crates/filebelt-domain",
            "path+file:///workspace/source/crates/filebelt-domain",
        ):
            with self.subTest(source=source):
                parsed = CHECKER.parse_cargo_tree(
                    f"filebelt-domain v0.1.0 ({source})|\n",
                    METADATA_REPO_ROOT,
                )
                identity = next(iter(parsed.features_by_identity))
                self.assertEqual(identity.source_path, "source/crates/filebelt-domain")

    def test_canonicalizes_symlinked_local_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "source/crates/filebelt-domain"
            target.mkdir(parents=True)
            link = root / "links/domain"
            link.parent.mkdir()
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"test environment cannot create symlinks: {error}")
            parsed = CHECKER.parse_cargo_tree(
                f"filebelt-domain v0.1.0 ({link})|\n", root
            )
            identity = next(iter(parsed.features_by_identity))
            self.assertEqual(identity.source_path, "source/crates/filebelt-domain")

    def test_handles_windows_local_sources_by_host_platform(self) -> None:
        if sys.platform != "win32":
            with self.assertRaisesRegex(CHECKER.BoundaryError, "non-native Windows"):
                CHECKER.parse_cargo_tree(
                    "filebelt-domain v0.1.0 (C:\\workspace\\domain)|\n",
                    METADATA_REPO_ROOT,
                )
            return

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "source/crates/filebelt-domain"
            target.mkdir(parents=True)
            for source in (target, target.as_uri(), f"path+{target.as_uri()}"):
                with self.subTest(source=source):
                    parsed = CHECKER.parse_cargo_tree(
                        f"filebelt-domain v0.1.0 ({source})|\n", root
                    )
                    identity = next(iter(parsed.features_by_identity))
                    self.assertEqual(
                        identity.source_path, "source/crates/filebelt-domain"
                    )

    def test_rejects_empty_malformed_and_escaping_graphs(self) -> None:
        for name, message in [
            ("empty.txt", "did not contain any package nodes"),
            ("malformed.txt", "separator"),
            ("path-escape.txt", "path escapes repository root"),
        ]:
            with self.subTest(name=name):
                with self.assertRaisesRegex(CHECKER.BoundaryError, message):
                    self.validate_authz(name)

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
        self.assertEqual(
            CHECKER.cargo_metadata_command(),
            ("cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"),
        )

    def test_metadata_is_manifest_bound_and_adapter_scoped(self) -> None:
        root_profiles = [
            profile
            for profile in POLICY.profiles
            if profile.manifest not in POLICY.repository.registered_adapter_manifests
        ]
        root_metadata = metadata_for_profiles(root_profiles)
        self.assertEqual(len(root_metadata.workspace_members), len(root_profiles))
        catalog = reviewed_catalog()
        self.assertEqual(
            catalog.for_profile(PROFILE_BY_PACKAGE["filebelt-authz"]).manifest,
            "source/crates/filebelt-authz/Cargo.toml",
        )

    def test_metadata_allows_excluded_root_members_without_trusting_them(self) -> None:
        root_profiles = [
            profile
            for profile in POLICY.profiles
            if profile.manifest not in POLICY.repository.registered_adapter_manifests
        ]
        adapter_metadata = {
            profile.manifest: metadata_for_profiles([profile])
            for profile in POLICY.profiles
            if profile.manifest in POLICY.repository.registered_adapter_manifests
        }
        catalog = CHECKER.validate_metadata(
            metadata_for_profiles(
                root_profiles,
                (
                    ("fuzz/Cargo.toml", "filebelt-fuzz"),
                    ("tests/rust/Cargo.toml", "filebelt-rust-tests"),
                    ("tests/unsafe-harness/Cargo.toml", "filebelt-unsafe-harness"),
                ),
            ),
            adapter_metadata,
            POLICY,
        )
        self.assertNotIn("filebelt-fuzz", catalog.by_name)
        self.assertNotIn("fuzz/Cargo.toml", catalog.by_manifest)

    def test_metadata_rejects_non_excluded_root_member(self) -> None:
        root_profiles = [
            profile
            for profile in POLICY.profiles
            if profile.manifest not in POLICY.repository.registered_adapter_manifests
        ]
        adapter_metadata = {
            profile.manifest: metadata_for_profiles([profile])
            for profile in POLICY.profiles
            if profile.manifest in POLICY.repository.registered_adapter_manifests
        }
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            (
                "root Cargo workspace has unregistered workspace manifest: "
                "tools/Cargo.toml"
            ),
        ):
            CHECKER.validate_metadata(
                metadata_for_profiles(
                    root_profiles, (("tools/Cargo.toml", "unregistered-helper"),)
                ),
                adapter_metadata,
                POLICY,
            )

    def test_rejects_malformed_or_escaping_metadata(self) -> None:
        missing_source = {
            "packages": [
                {
                    "id": "path+file:///workspace/authz#0.1.0",
                    "name": "filebelt-authz",
                    "version": "0.1.0",
                    "manifest_path": (
                        "/workspace/source/crates/filebelt-authz/Cargo.toml"
                    ),
                }
            ],
            "workspace_members": ["path+file:///workspace/authz#0.1.0"],
        }
        escaping_manifest = {
            "packages": [
                {
                    "id": "path+file:///outside/authz#0.1.0",
                    "name": "filebelt-authz",
                    "version": "0.1.0",
                    "source": None,
                    "manifest_path": "/outside/Cargo.toml",
                }
            ],
            "workspace_members": ["path+file:///outside/authz#0.1.0"],
        }
        for document, message in [
            (missing_source, "missing source"),
            (escaping_manifest, "path escapes repository root"),
        ]:
            with self.subTest(document=document):
                with self.assertRaisesRegex(CHECKER.BoundaryError, message):
                    CHECKER.parse_workspace_metadata(
                        json.dumps(document), METADATA_REPO_ROOT
                    )

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
