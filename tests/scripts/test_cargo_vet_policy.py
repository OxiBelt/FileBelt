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
BLAKE3_VERSION = "1.8.7"
BLAKE3_CHECKSUM = (
    "6d9e454fc11f76977dc803893aff6304ed33d6a26efae8696573bea74baa27ae"
)
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"


def load_toml(relative_path: str) -> dict:
    with (REPO_ROOT / relative_path).open("rb") as handle:
        return tomllib.load(handle)


def cargo_workspaces() -> tuple[Path, ...]:
    boundaries = load_toml("supply-chain/cargo-boundaries-v1.toml")
    adapters = (
        Path(manifest).parent
        for manifest in boundaries["repository"]["registered_adapter_manifests"]
    )
    return tuple(sorted({Path("."), Path("protocol/media"), *adapters}))


class CargoVetPolicyTests(unittest.TestCase):
    def test_arrayref_recovery_is_exact_and_fail_closed(self) -> None:
        config = load_toml("supply-chain/config.toml")
        audits = load_toml("supply-chain/audits.toml")

        affected_workspaces = {
            Path("."),
            Path("adapters/ftp-ftps"),
            Path("adapters/nfs"),
            Path("adapters/smb"),
        }
        for workspace in cargo_workspaces():
            with self.subTest(workspace=str(workspace)):
                cargo_lock = load_toml(str(workspace / "Cargo.lock"))
                packages = cargo_lock.get("package", [])
                package_names = {package["name"] for package in packages}
                cargo_manifest = load_toml(str(workspace / "Cargo.toml"))
                deny = load_toml(str(workspace / "deny.toml"))
                ignored_arrayref = [
                    item
                    for item in deny["advisories"].get("ignore", [])
                    if isinstance(item, dict)
                    and item.get("crate", "").startswith("arrayref@")
                ]

                self.assertEqual(deny["advisories"]["yanked"], "deny")
                self.assertEqual(deny["sources"]["unknown-git"], "deny")
                self.assertNotIn(
                    "arrayref",
                    cargo_manifest.get("patch", {}).get("crates-io", {}),
                )
                self.assertNotIn("allow-git", deny["sources"])
                self.assertFalse(
                    {"arrayref", "proc-macro1", "proc-macro-en"} & package_names
                )
                self.assertEqual(ignored_arrayref, [])

                blake3_packages = [
                    package for package in packages if package["name"] == "blake3"
                ]
                if workspace in affected_workspaces:
                    self.assertEqual(len(blake3_packages), 1)
                    self.assertEqual(blake3_packages[0]["version"], BLAKE3_VERSION)
                    self.assertEqual(blake3_packages[0]["source"], CRATES_IO_SOURCE)
                    self.assertEqual(blake3_packages[0]["checksum"], BLAKE3_CHECKSUM)
                    self.assertNotIn(
                        "arrayref", blake3_packages[0].get("dependencies", [])
                    )
                else:
                    self.assertEqual(blake3_packages, [])

        self.assertNotIn("arrayref:0.3.9", config["policy"])
        self.assertNotIn("blake3:1.8.6", config["policy"])
        self.assertNotIn("arrayref", audits["audits"])
        self.assertNotIn("arrayref", config.get("exemptions", {}))
        self.assertEqual(
            config.get("exemptions", {}).get("blake3"),
            [{"version": "1.8.6", "criteria": "safe-to-deploy"}],
        )

        blake3_audits = audits["audits"]["blake3"]
        self.assertTrue(
            any(
                audit.get("criteria") == "safe-to-deploy"
                and audit.get("delta") == "1.8.6 -> 1.8.7"
                and BLAKE3_CHECKSUM in audit.get("notes", "")
                for audit in blake3_audits
            )
        )

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

    def test_exemptions_are_exact_locked_or_reviewed_delta_baselines(self) -> None:
        config = load_toml("supply-chain/config.toml")
        audits = load_toml("supply-chain/audits.toml").get("audits", {})
        imported_audits = load_toml("supply-chain/imports.lock").get("audits", {})
        cargo_lock = load_toml("Cargo.lock")
        exemptions = config.get("exemptions")

        self.assertIsInstance(exemptions, dict)
        self.assertTrue(exemptions, "Cargo Vet exemptions must not be empty")

        locked_packages = {
            (package["name"], package["version"])
            for package in cargo_lock.get("package", [])
        }
        reviewed_delta_baselines: set[tuple[str, str]] = set()
        audit_stores = [audits]
        audit_stores.extend(
            store.get("audits", {})
            for store in imported_audits.values()
            if isinstance(store, dict)
        )
        for audit_store in audit_stores:
            for crate_name, records in audit_store.items():
                for record in records:
                    delta = record.get("delta")
                    criteria = record.get("criteria")
                    if not isinstance(delta, str) or criteria != "safe-to-deploy":
                        continue
                    baseline, separator, target = delta.partition(" -> ")
                    if separator and (crate_name, target) in locked_packages:
                        reviewed_delta_baselines.add((crate_name, baseline))
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
                self.assertTrue(
                    (crate_name, version) in locked_packages
                    or (crate_name, version) in reviewed_delta_baselines,
                    f"{crate_name}@{version} is neither locked nor a reviewed "
                    "safe-to-deploy delta baseline for a locked version",
                )
                self.assertNotIn((crate_name, version), seen)
                seen.add((crate_name, version))

    def test_trusted_publishers_are_not_an_acceptance_substitute(self) -> None:
        config = load_toml("supply-chain/config.toml")
        self.assertNotIn("trusted", config)


if __name__ == "__main__":
    unittest.main()
