#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Fail closed on FileBelt repository, workspace, and license boundaries."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


IGNORED_PARTS = {".agents", ".git", "dist", "node_modules", "target"}
ADAPTER_ROOTS = {
    "adapters/smb": "GPL-3.0-or-later",
    "adapters/ftp-ftps": "GPL-3.0-or-later",
    "adapters/onlyoffice": "AGPL-3.0-only",
    "adapters/git": "GPL-2.0-only",
    "adapters/nfs": "LGPL-3.0-or-later",
    "adapters/transcode": "GPL-3.0-or-later",
}
EXPECTED_RUST_MEMBERS = {
    "source",
    "source/apps/filebelt-api",
    "source/apps/filebelt-worker-io",
    "source/apps/filebelt-worker-maintenance",
    "source/apps/filebelt-media-controller",
    "source/apps/filebelt-collaboration",
    "source/apps/filebelt-mcp-broker",
    "source/apps/filebelt-mcp-runner",
    "source/apps/filebelt-controller",
    "source/apps/filebelt-document",
    "source/apps/filebelt-revision",
    "source/apps/filebeltctl",
    "source/apps/filebelt-vfs",
    "source/apps/filebelt-headscale-sync",
    "source/apps/filebelt-nfs-relay",
    "source/crates/filebelt-build-identity",
    "source/crates/filebelt-domain",
    "source/crates/filebelt-authz",
    "source/crates/filebelt-database",
    "source/crates/filebelt-events-protocol",
    "source/crates/filebelt-storage",
    "source/crates/filebelt-capability-keyset",
    "source/crates/filebelt-storage-protocol",
    "source/crates/filebelt-vfs-protocol",
    "source/crates/filebelt-document-protocol",
    "source/crates/filebelt-revision-protocol",
    "source/crates/filebelt-collaboration-protocol",
    "source/crates/filebelt-mcp-policy",
    "source/crates/filebelt-mcp-protocol",
    "source/crates/filebelt-mcp-vault",
    "source/crates/filebelt-secret-vault",
    "source/crates/filebelt-control-protocol",
    "source/crates/filebelt-runtime",
    "source/crates/filebelt-deployment-diagnostics",
    "fuzz",
    "tests/rust",
    "tests/unsafe-harness",
}
EXPECTED_NODE_PACKAGES = {
    "devops": "@filebelt/devops",
    "ui/admin": "@filebelt/admin",
    "ui/design-system": "@filebelt/design-system",
    "ui/markdown": "@filebelt/markdown",
    "ui/mcp-settings": "@filebelt/mcp-settings",
    "ui/web": "@filebelt/web",
}
REQUIRED_LIVING_SPECS = (
    "docs/README.md",
    "docs/NamespaceAndAuthorization.md",
    "docs/InterfacesAndCapabilities.md",
    "docs/StorageAndDurability.md",
    "docs/RuntimeAndDeployment.md",
)
SPDX_EXTENSIONS = {".cmake", ".js", ".md", ".py", ".rs", ".toml", ".ts", ".yaml", ".yml"}
TOOL_OWNED_SPDX_FILES = {
    ".serena/project.local.yml",
    "supply-chain/audits.toml",
    "supply-chain/config.toml",
    "supply-chain/imports.lock",
}


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def iter_files(root: Path):
    for path in root.rglob("*"):
        if path.is_file() and not any(part in IGNORED_PARTS for part in path.parts):
            yield path


def dependency_tables(manifest: dict[str, Any]):
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = manifest.get(key, {})
        if isinstance(table, dict):
            yield table
    for target in manifest.get("target", {}).values():
        if isinstance(target, dict):
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                table = target.get(key, {})
                if isinstance(table, dict):
                    yield table


def check(root: Path) -> list[str]:
    failures: list[str] = []

    required_files = [
        "AGENTS.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        *REQUIRED_LIVING_SPECS,
        "docs/LicenseMap.md",
        "docs/ThreatModel.md",
        "supply-chain/license-regions.toml",
        "supply-chain/node-policy.toml",
        "supply-chain/cargo-boundaries-v1.toml",
        "supply-chain/imports.lock",
        "tests/scripts/check-cargo-boundaries.py",
        "tests/scripts/check-cargo-boundaries.sh",
        "tests/scripts/check-rust-module-size.sh",
        "tests/scripts/check-node-licenses.py",
        "tests/scripts/test_cargo_vet_policy.py",
        ".github/CODEOWNERS",
        ".github/workflows/check-filebelt.yml",
        ".github/workflows/release-dry-run.yml",
        ".github/workflows/release.yml",
        "source/ops/Dockerfile.roles",
        "source/ops/riscv64-musl-toolchain.cmake",
        "ui/web/Dockerfile",
        "deploy/helm/filebelt/Chart.yaml",
        "deploy/helm/filebelt/values.schema.json",
        "supply-chain/image-vulnerability-exceptions.json",
        "supply-chain/tooling.toml",
        "supply-chain/release-tag-signers.txt",
        "supply-chain/release-tag-signers/F4CED383110CA1847CE9E9174D41B82B06DFFDBC.asc",
        "tests/scripts/build-docker-image-artifact.sh",
        "tests/scripts/check-helm-chart.sh",
        "tests/scripts/validate-image-evidence.py",
        "tests/scripts/validate-image.py",
        "tests/scripts/run-image-matrix.sh",
        "tests/scripts/package-release-assets.sh",
        "tests/scripts/promote-release-artifacts.sh",
        "tests/scripts/run-kubernetes-kind-compatibility.sh",
        "tests/scripts/run-kubernetes-release-gate.sh",
        "tests/scripts/normalize-cyclonedx.py",
        "tests/scripts/verify-release-tag.sh",
        "tests/docker/qemu-riscv64/Dockerfile",
    ]
    for relative in required_files:
        if not (root / relative).is_file():
            failures.append(f"missing required file: {relative}")

    if (root / "docs/adr").exists():
        failures.append("legacy docs/adr directory must not exist")

    region_data = load_toml(root / "supply-chain/license-regions.toml")
    regions = {
        item["path"]: item["license"]
        for item in region_data.get("regions", [])
        if isinstance(item, dict) and "path" in item and "license" in item
    }
    expected_top = {
        "source",
        "protocol",
        "ui",
        "devops",
        "deploy",
        "tests",
        "docs",
        "supply-chain",
        "fuzz",
        "tools",
    }
    missing_regions = expected_top - regions.keys()
    if missing_regions:
        failures.append(f"top-level paths missing license regions: {sorted(missing_regions)}")
    for adapter, license_id in ADAPTER_ROOTS.items():
        if regions.get(adapter) != license_id:
            failures.append(f"{adapter} must be mapped as {license_id}")
        for filename in ("AGENTS.md", "LICENSE", "THIRD_PARTY_NOTICES.md"):
            if not (root / adapter / filename).is_file():
                failures.append(f"{adapter} is missing {filename}")

    cargo = load_toml(root / "Cargo.toml")
    workspace = cargo.get("workspace", {})
    members = set(workspace.get("members", []))
    if members != EXPECTED_RUST_MEMBERS:
        failures.append(
            f"root Cargo members differ: missing={sorted(EXPECTED_RUST_MEMBERS - members)}, "
            f"unexpected={sorted(members - EXPECTED_RUST_MEMBERS)}"
        )
    for member in members:
        if member.startswith("adapters/"):
            failures.append(f"adapter is a root Cargo member: {member}")
        manifest_path = root / member / "Cargo.toml"
        if not manifest_path.is_file():
            failures.append(f"workspace member has no manifest: {member}")
            continue
        manifest = load_toml(manifest_path)
        package = manifest.get("package", {})
        name = package.get("name", "")
        if not isinstance(name, str) or not name.startswith("filebelt"):
            failures.append(f"invalid Cargo package name in {member}: {name!r}")
        if package.get("publish") != {"workspace": True}:
            failures.append(f"Cargo package must inherit publish=false: {member}")

    for manifest_path in root.rglob("Cargo.toml"):
        relative = manifest_path.relative_to(root).as_posix()
        if any(part in IGNORED_PARTS for part in manifest_path.parts):
            continue
        manifest = load_toml(manifest_path)
        for table in dependency_tables(manifest):
            for name, dependency in table.items():
                if isinstance(dependency, dict) and "path" in dependency:
                    resolved = (manifest_path.parent / dependency["path"]).resolve()
                    adapter_root = (root / "adapters").resolve()
                    if not relative.startswith("adapters/") and resolved.is_relative_to(adapter_root):
                        failures.append(
                            f"Apache manifest {relative} path-depends on adapter {name}"
                        )

    workspace_text = (root / "pnpm-workspace.yaml").read_text(encoding="utf-8")
    if "adapters/" in workspace_text:
        failures.append("root pnpm workspace may not include adapters")
    for relative, expected_name in EXPECTED_NODE_PACKAGES.items():
        package_path = root / relative / "package.json"
        if not package_path.is_file():
            failures.append(f"missing pnpm package: {relative}")
            continue
        package = json.loads(package_path.read_text(encoding="utf-8"))
        if package.get("name") != expected_name:
            failures.append(f"unexpected pnpm package name in {relative}")
        if package.get("version") != "0.1.0" or package.get("private") is not True:
            failures.append(f"pnpm package must be private version 0.1.0: {relative}")

    root_package = json.loads((root / "package.json").read_text(encoding="utf-8"))
    exact_version = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
    for name, version in root_package.get("devDependencies", {}).items():
        if not isinstance(version, str) or not exact_version.fullmatch(version):
            failures.append(f"Node dependency must use an exact version: {name}={version}")

    node_policy = load_toml(root / "supply-chain/node-policy.toml")
    allowed_node_licenses = node_policy.get("allowed_licenses", [])
    if not allowed_node_licenses or len(allowed_node_licenses) != len(
        set(allowed_node_licenses)
    ):
        failures.append("Node license allowlist must be non-empty and contain no duplicates")
    node_license_admissions = node_policy.get("package_license_admissions", {})
    if not isinstance(node_license_admissions, dict) or any(
        not isinstance(selector, str)
        or not re.fullmatch(
            r"(?:@[^/@]+/[^@]+|[^@]+)@[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?",
            selector,
        )
        or not isinstance(license_name, str)
        or not license_name
        or license_name in allowed_node_licenses
        for selector, license_name in node_license_admissions.items()
    ):
        failures.append(
            "Node package license admissions must be exact and outside the global allowlist"
        )

    for path in iter_files(root):
        if path.suffix not in SPDX_EXTENSIONS:
            continue
        relative = path.relative_to(root).as_posix()
        if path.name == "pnpm-lock.yaml" or relative in TOOL_OWNED_SPDX_FILES:
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        if "SPDX-License-Identifier:" not in content[:500]:
            failures.append(f"missing SPDX identifier: {relative}")

    workflow_dir = root / ".github/workflows"
    if workflow_dir.is_dir():
        for workflow in workflow_dir.glob("*.yml"):
            content = workflow.read_text(encoding="utf-8")
            if "pull_request_target:" in content:
                failures.append(f"forbidden pull_request_target in {workflow.name}")
            write_permissions = re.findall(
                r"(?:packages|contents|id-token|attestations):\s*write", content
            )
            if workflow.name != "release.yml" and write_permissions:
                failures.append(f"write permission outside release workflow {workflow.name}")
            if workflow.name == "release.yml":
                if "workflow_dispatch:" in content or "pull_request:" in content:
                    failures.append("release workflow must be tag-only")
                expected = {
                    "packages: write",
                    "contents: write",
                    "id-token: write",
                    "attestations: write",
                }
                if len(write_permissions) != len(expected) or set(write_permissions) != expected:
                    failures.append("release promotion permissions differ from the allowlist")
                promote = content.find("\n  promote:\n")
                if promote < 0 or any(
                    content.find(permission) < promote for permission in expected
                ):
                    failures.append("release write permissions must be scoped to promotion")
                if not re.search(
                    r'on:\s*\n  push:\s*\n    tags:\s*\n      - "\[0-9\]\*\.\[0-9\]\*\.\[0-9\]\*"',
                    content,
                ) or re.search(r"\n  (?:schedule|workflow_call):", content):
                    failures.append("release workflow trigger differs from signed tags only")
                if promote >= 0:
                    promotion = content[promote:]
                    for inactive in ["filebelt-media-controller"]:
                        if inactive in promotion:
                            failures.append(
                                f"inactive role is present in release promotion: {inactive}"
                            )
            for uses in re.findall(r"uses:\s*([^\s#]+)", content):
                if uses.startswith("./"):
                    continue
                if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", uses):
                    failures.append(f"GitHub Action is not SHA-pinned: {uses}")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    failures = check(root)
    if failures:
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
        return 1
    print("FileBelt source-structure contracts passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
