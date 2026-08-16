#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the versioned license compatibility checker."""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = Path(__file__).with_name("check-license-compatibility.py")
SPEC = importlib.util.spec_from_file_location("check_license_compatibility", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)
POLICY = CHECKER.load_policy(REPO_ROOT / CHECKER.POLICY_FILENAME)
WORKSPACES = {workspace.id: workspace for workspace in POLICY.workspaces}
CHECK_COMMAND = "python3 tests/scripts/check-license-compatibility.py"
FETCH_LOOP = (
    "for manifest in Cargo.toml "
    "adapters/{smb,ftp-ftps,onlyoffice,git,nfs,transcode}/Cargo.toml; do"
)
FETCH_COMMAND = 'cargo fetch --locked --manifest-path "$manifest"'


def workflow_job_run_lines(source: str) -> dict[str, tuple[str, ...]]:
    jobs: dict[str, tuple[str, ...]] = {}
    current: str | None = None
    body: list[str] = []
    in_jobs = False

    def finish_job() -> None:
        if current is None:
            return
        scripts: list[str] = []
        index = 0
        while index < len(body):
            line = body[index]
            stripped = line.lstrip().removeprefix("- ")
            if not stripped.startswith("run:"):
                index += 1
                continue
            indent = len(line) - len(line.lstrip())
            value = stripped.removeprefix("run:").strip()
            if value not in {"|", ">", ">-", "|-"}:
                if value and not value.startswith("#"):
                    scripts.append(value)
                index += 1
                continue
            index += 1
            while index < len(body):
                candidate = body[index]
                if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indent:
                    break
                command = candidate.strip()
                if command and not command.startswith("#"):
                    scripts.append(command)
                index += 1
        jobs[current] = tuple(scripts)

    for line in source.splitlines():
        if line == "jobs:":
            in_jobs = True
            continue
        if in_jobs and line and not line.startswith(" "):
            break
        if in_jobs and line.startswith("  ") and not line.startswith("    "):
            job, separator, value = line.strip().partition(":")
            if not separator or (value.strip() and not value.lstrip().startswith("#")):
                continue
            finish_job()
            current = job
            body = []
            continue
        if current is not None:
            body.append(line)
    finish_job()
    return jobs


def package(
    package_id: str,
    name: str,
    license_name: str,
    manifest_path: Path,
    *,
    version: str = "0.1.0",
    local: bool = True,
) -> dict[str, object]:
    return {
        "id": package_id,
        "name": name,
        "version": version,
        "license": license_name,
        "source": None if local else "registry+https://github.com/rust-lang/crates.io-index",
        "manifest_path": str(manifest_path),
    }


def dependency(package_id: str, kind: str | None = None) -> dict[str, object]:
    return {
        "name": package_id,
        "pkg": package_id,
        "dep_kinds": [{"kind": kind, "target": None}],
    }


def metadata(
    workspace: CHECKER.WorkspacePolicy,
    packages: list[dict[str, object]],
    edges: dict[str, list[dict[str, object]]],
) -> dict[str, object]:
    return {
        "packages": packages,
        "workspace_members": [packages[0]["id"]],
        "workspace_default_members": [packages[0]["id"]],
        "resolve": {
            "nodes": [
                {
                    "id": item["id"],
                    "dependencies": [edge["pkg"] for edge in edges.get(str(item["id"]), [])],
                    "deps": edges.get(str(item["id"]), []),
                    "features": [],
                }
                for item in packages
            ],
            "root": packages[0]["id"],
        },
        "target_directory": str(REPO_ROOT / "target"),
        "version": 1,
        "workspace_root": str((REPO_ROOT / workspace.manifest).parent),
        "metadata": None,
    }


def root_with_dependency(
    name: str,
    license_name: str,
    *,
    version: str = "1.0.0",
    kind: str | None = None,
) -> dict[str, object]:
    workspace = dataclasses.replace(
        WORKSPACES["root"], package_licenses={"filebelt": "Apache-2.0"}
    )
    root_id = "path+file:///repo/source#filebelt@0.1.0"
    dependency_id = f"registry+https://github.com/rust-lang/crates.io-index#{name}@{version}"
    return metadata(
        workspace,
        [
            package(root_id, "filebelt", "Apache-2.0", REPO_ROOT / "source/Cargo.toml"),
            package(
                dependency_id,
                name,
                license_name,
                Path(f"/cargo/registry/{name}-{version}/Cargo.toml"),
                version=version,
                local=False,
            ),
        ],
        {root_id: [dependency(dependency_id, kind)]},
    )


class LicenseCompatibilityTests(unittest.TestCase):
    def load_mutated_policy(self, source: str) -> CHECKER.CompatibilityPolicy:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.toml"
            path.write_text(source, encoding="utf-8")
            return CHECKER.load_policy(path)

    def test_policy_registers_closed_workspace_and_relationship_sets(self) -> None:
        self.assertEqual(POLICY.schema_version, 1)
        self.assertEqual(
            {workspace.id for workspace in POLICY.workspaces},
            {"root", "smb", "ftp-ftps", "onlyoffice", "git", "nfs", "transcode"},
        )
        self.assertEqual(
            POLICY.relationship_types,
            {"linked", "copied", "separate-executable", "external", "build-only"},
        )
        self.assertEqual(len(POLICY.artifacts), 6)
        CHECKER.validate_repository_layout(REPO_ROOT, POLICY)

    def test_rejects_unknown_workspace_relationship_and_missing_component(self) -> None:
        source = (REPO_ROOT / CHECKER.POLICY_FILENAME).read_text(encoding="utf-8")
        unknown_workspace = source.replace(
            'id = "transcode"\nmanifest = ', 'id = "unknown"\nmanifest = ', 1
        )
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "all six adapter workspaces"):
            self.load_mutated_policy(unknown_workspace)

        unknown_relationship = source.replace(
            'relationship = "copied"', 'relationship = "embedded"', 1
        )
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "unknown relationship"):
            self.load_mutated_policy(unknown_relationship)

        component = '''[[artifacts.components]]
id = "filebelt-vfs-protocol"
version = "0.1.0"
relationship = "linked"
license = "Apache-2.0"
path = "/usr/local/bin/filebelt-smb-bridge"
source_required = true

'''
        self.assertIn(component, source)
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "omits Cargo/local components"):
            self.load_mutated_policy(source.replace(component, "", 1))

    def test_accepts_exact_mpl_exception(self) -> None:
        workspace = dataclasses.replace(
            WORKSPACES["root"], package_licenses={"filebelt": "Apache-2.0"}
        )
        CHECKER.validate_metadata_document(
            root_with_dependency("option-ext", "MPL-2.0", version="0.2.0"),
            workspace,
            POLICY,
            REPO_ROOT,
        )

    def test_rejects_wrong_mpl_version_and_stale_exception(self) -> None:
        workspace = dataclasses.replace(
            WORKSPACES["root"], package_licenses={"filebelt": "Apache-2.0"}
        )
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "undeclared restricted license"):
            CHECKER.validate_metadata_document(
                root_with_dependency("option-ext", "MPL-2.0", version="0.2.1"),
                workspace,
                POLICY,
                REPO_ROOT,
            )
        root_id = "path+file:///repo/source#filebelt@0.1.0"
        without_option_ext = metadata(
            workspace,
            [package(root_id, "filebelt", "Apache-2.0", REPO_ROOT / "source/Cargo.toml")],
            {},
        )
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "stale restricted license"):
            CHECKER.validate_metadata_document(
                without_option_ext, workspace, POLICY, REPO_ROOT
            )

    def test_does_not_admit_mpl_when_a_permissive_or_branch_is_selected(self) -> None:
        workspace = dataclasses.replace(
            WORKSPACES["root"],
            package_licenses={"filebelt": "Apache-2.0"},
            restricted_license_exceptions=(),
        )
        CHECKER.validate_metadata_document(
            root_with_dependency("dual-license", "MPL-2.0 OR MIT"),
            workspace,
            POLICY,
            REPO_ROOT,
        )

    def test_rejects_apache_link_to_copyleft(self) -> None:
        workspace = dataclasses.replace(
            WORKSPACES["root"],
            package_licenses={"filebelt": "Apache-2.0"},
            restricted_license_exceptions=(),
        )
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "undeclared restricted license"):
            CHECKER.validate_metadata_document(
                root_with_dependency("copyleft", "GPL-3.0-or-later"),
                workspace,
                POLICY,
                REPO_ROOT,
            )

    def test_accepts_reviewed_inward_apache_protocol_edge(self) -> None:
        workspace = WORKSPACES["smb"]
        bridge_id = "path+file:///repo/adapters/smb#filebelt-smb-bridge@0.1.0"
        protocol_id = "path+file:///repo/source/vfs#filebelt-vfs-protocol@0.1.0"
        document = metadata(
            workspace,
            [
                package(
                    bridge_id,
                    "filebelt-smb-bridge",
                    "GPL-3.0-or-later",
                    REPO_ROOT / "adapters/smb/Cargo.toml",
                ),
                package(
                    protocol_id,
                    "filebelt-vfs-protocol",
                    "Apache-2.0",
                    REPO_ROOT / "source/crates/filebelt-vfs-protocol/Cargo.toml",
                ),
            ],
            {bridge_id: [dependency(protocol_id)]},
        )
        CHECKER.validate_metadata_document(document, workspace, POLICY, REPO_ROOT)

    def test_rejects_unknown_local_edge_and_stale_reviewed_edge(self) -> None:
        workspace = WORKSPACES["smb"]
        bridge_id = "path+file:///repo/adapters/smb#filebelt-smb-bridge@0.1.0"
        helper_id = "path+file:///repo/source/helper#filebelt-helper@0.1.0"
        unknown = metadata(
            workspace,
            [
                package(
                    bridge_id,
                    "filebelt-smb-bridge",
                    "GPL-3.0-or-later",
                    REPO_ROOT / "adapters/smb/Cargo.toml",
                ),
                package(
                    helper_id,
                    "filebelt-helper",
                    "Apache-2.0",
                    REPO_ROOT / "source/Cargo.toml",
                ),
            ],
            {bridge_id: [dependency(helper_id)]},
        )
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "undeclared local dependency"):
            CHECKER.validate_metadata_document(unknown, workspace, POLICY, REPO_ROOT)
        no_protocol = metadata(
            workspace,
            [
                package(
                    bridge_id,
                    "filebelt-smb-bridge",
                    "GPL-3.0-or-later",
                    REPO_ROOT / "adapters/smb/Cargo.toml",
                )
            ],
            {},
        )
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "stale allowed local"):
            CHECKER.validate_metadata_document(no_protocol, workspace, POLICY, REPO_ROOT)

    def test_build_only_is_distinct_from_linked(self) -> None:
        base = WORKSPACES["smb"]
        workspace = dataclasses.replace(
            base,
            allowed_local_dependencies=(
                CHECKER.LocalDependency("filebelt-vfs-protocol", "Apache-2.0", "build-only"),
            ),
        )
        bridge_id = "path+file:///repo/adapters/smb#filebelt-smb-bridge@0.1.0"
        protocol_id = "path+file:///repo/source/vfs#filebelt-vfs-protocol@0.1.0"
        document = metadata(
            workspace,
            [
                package(
                    bridge_id,
                    "filebelt-smb-bridge",
                    "GPL-3.0-or-later",
                    REPO_ROOT / "adapters/smb/Cargo.toml",
                ),
                package(
                    protocol_id,
                    "filebelt-vfs-protocol",
                    "Apache-2.0",
                    REPO_ROOT / "source/crates/filebelt-vfs-protocol/Cargo.toml",
                ),
            ],
            {bridge_id: [dependency(protocol_id, "build")]},
        )
        CHECKER.validate_metadata_document(document, workspace, POLICY, REPO_ROOT)

    def test_rejects_known_git_implementation_package(self) -> None:
        workspace = dataclasses.replace(
            WORKSPACES["root"],
            package_licenses={"filebelt": "Apache-2.0"},
            restricted_license_exceptions=(),
        )
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "forbidden Git implementation"):
            CHECKER.validate_metadata_document(
                root_with_dependency("libgit2-sys", "MIT"),
                workspace,
                POLICY,
                REPO_ROOT,
            )
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "forbidden Git implementation"):
            CHECKER.validate_metadata_document(
                root_with_dependency("gix", "MIT OR Apache-2.0"),
                workspace,
                POLICY,
                REPO_ROOT,
            )

    def test_rejects_unreviewed_copyleft_variants(self) -> None:
        workspace = dataclasses.replace(
            WORKSPACES["root"],
            package_licenses={"filebelt": "Apache-2.0"},
            restricted_license_exceptions=(),
        )
        for license_name in ["LGPL-2.1-only", "GPL-3.0-only", "AGPL-3.0-or-later"]:
            with self.subTest(license_name=license_name):
                with self.assertRaisesRegex(CHECKER.CompatibilityError, "undeclared restricted license"):
                    CHECKER.validate_metadata_document(
                        root_with_dependency("copyleft-variant", license_name),
                        workspace,
                        POLICY,
                        REPO_ROOT,
                    )

    def test_rejects_workspace_package_identity_or_license_drift(self) -> None:
        workspace = dataclasses.replace(
            WORKSPACES["root"],
            package_licenses={"filebelt": "Apache-2.0"},
            restricted_license_exceptions=(),
        )
        root_id = "path+file:///repo/source#filebelt@0.1.0"
        document = metadata(
            workspace,
            [package(root_id, "filebelt", "GPL-3.0-or-later", REPO_ROOT / "source/Cargo.toml")],
            {},
        )
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "workspace package licenses differ"):
            CHECKER.validate_metadata_document(document, workspace, POLICY, REPO_ROOT)

    def test_pre_image_gate_blocks_images_until_every_condition_qualifies(self) -> None:
        blocked_entries = []
        for artifact in POLICY.artifacts:
            preconditions = {name: "qualified" for name in POLICY.image_build_preconditions}
            preconditions["source-bundle"] = "blocked"
            blocked_entries.append(
                {
                    "id": artifact.id,
                    "image_build_state": "blocked",
                    "preconditions": preconditions,
                    "produced": ["source-bundle"],
                }
            )
        CHECKER.validate_pre_image_evidence(
            {"schema_version": 1, "artifacts": blocked_entries}, POLICY
        )
        blocked_entries[0]["produced"].append("image")
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "produced image evidence while blocked"):
            CHECKER.validate_pre_image_evidence(
                {"schema_version": 1, "artifacts": blocked_entries}, POLICY
            )

    def test_pre_image_gate_requires_build_after_eligibility(self) -> None:
        entries = []
        for artifact in POLICY.artifacts:
            entries.append(
                {
                    "id": artifact.id,
                    "image_build_state": "eligible",
                    "preconditions": {
                        name: "qualified" for name in POLICY.image_build_preconditions
                    },
                    "produced": [
                        "source-bundle",
                        "image",
                        "image-sbom",
                    "image-provenance",
                    "image-validation",
                    "vulnerability-decision",
                    "rebuild",
                    "notices",
                    ],
                }
            )
        CHECKER.validate_pre_image_evidence(
            {"schema_version": 1, "artifacts": entries}, POLICY
        )
        entries[0]["produced"].remove("image-sbom")
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "did not produce required evidence"):
            CHECKER.validate_pre_image_evidence(
                {"schema_version": 1, "artifacts": entries}, POLICY
            )

    def test_supplied_metadata_requires_locked_offline_provenance(self) -> None:
        workspace = WORKSPACES["transcode"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transcode.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "workspace": "transcode",
                        "command": ["cargo", "metadata", "--format-version", "1"],
                        "metadata": {},
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CHECKER.CompatibilityError, "lacks locked/offline provenance"):
                CHECKER._load_supplied_metadata(path, workspace)

    def test_workflow_jobs_prime_every_graph_before_checking_licenses(self) -> None:
        checked_jobs: set[str] = set()
        workflow_root = REPO_ROOT / ".github/workflows"
        paths = sorted([*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml")])
        for path in paths:
            for job, lines in workflow_job_run_lines(path.read_text(encoding="utf-8")).items():
                checks = [index for index, line in enumerate(lines) if line.startswith(CHECK_COMMAND)]
                if not checks:
                    continue
                identity = f"{path.name}:{job}"
                checked_jobs.add(identity)
                with self.subTest(job=identity):
                    loops = [index for index, line in enumerate(lines) if line == FETCH_LOOP]
                    fetches = [index for index, line in enumerate(lines) if line == FETCH_COMMAND]
                    self.assertTrue(loops, f"{identity} does not enumerate every Cargo graph")
                    self.assertTrue(fetches, f"{identity} does not fetch locked Cargo sources")
                    self.assertLess(loops[0], fetches[0], f"{identity} fetches outside the loop")
                    self.assertLess(fetches[0], checks[0], f"{identity} primes Cargo sources too late")
        self.assertTrue(
            {
                "adapter-license-qualification.yml:source-and-policy",
                "adapter-license-qualification.yml:immutable-plan",
                "adapter-release.yml:qualification",
            }
            <= checked_jobs
        )

    def test_workflow_run_parser_ignores_names_and_comments(self) -> None:
        jobs = workflow_job_run_lines(
            f"""jobs:
  qualification: # a valid job header comment
    name: {FETCH_LOOP}
    steps:
      - run: |
          # {FETCH_LOOP}
          {CHECK_COMMAND} --repo-root .
"""
        )
        self.assertEqual(jobs["qualification"], (f"{CHECK_COMMAND} --repo-root .",))

    def test_workflow_run_parser_preserves_command_order(self) -> None:
        jobs = workflow_job_run_lines(
            f"""jobs:
  qualification:
    steps:
      - run: |
          {CHECK_COMMAND} --repo-root .
          {FETCH_LOOP}
"""
        )
        self.assertEqual(
            jobs["qualification"],
            (f"{CHECK_COMMAND} --repo-root .", FETCH_LOOP),
        )


if __name__ == "__main__":
    unittest.main()
