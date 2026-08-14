#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Fail closed when an independently locked composition lacks Dependabot coverage."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path


ENTRY = re.compile(r"^  - package-ecosystem: ([a-z-]+)$")
DIRECTORY = re.compile(r'^    directory: "(/[^"]*)"$')
IGNORED_PARTS = {".git", "node_modules", "target"}


def relative_directory(root: Path, path: Path) -> str:
    relative = path.relative_to(root).as_posix()
    return "/" if relative == "." else f"/{relative}"


def configured_directories(path: Path) -> dict[str, set[str]]:
    configured: dict[str, set[str]] = {}
    current: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = ENTRY.fullmatch(line)
        if entry:
            current = entry.group(1)
            configured.setdefault(current, set())
            continue
        directory = DIRECTORY.fullmatch(line)
        if directory and current:
            configured[current].add(directory.group(1))
    return configured


def discover_directories(root: Path, filename: str) -> set[str]:
    return {
        relative_directory(root, path.parent)
        for path in root.rglob(filename)
        if not any(part in IGNORED_PARTS for part in path.parts)
    }


def independent_cargo_directories(root: Path) -> set[str]:
    return {
        relative_directory(root, lock.parent)
        for lock in root.rglob("Cargo.lock")
        if not any(part in IGNORED_PARTS for part in lock.parts)
        and (lock.parent / "Cargo.toml").is_file()
    }


def adapter_directories(root: Path) -> set[str]:
    with (root / "supply-chain/cargo-boundaries-v1.toml").open("rb") as handle:
        policy = tomllib.load(handle)
    manifests = policy["repository"]["registered_adapter_manifests"]
    return {f"/{Path(manifest).parent.as_posix()}" for manifest in manifests}


def expected_docker_directories(root: Path) -> set[str]:
    dockerfiles = {
        relative_directory(root, path.parent)
        for path in root.rglob("Dockerfile*")
        if not any(part in IGNORED_PARTS for part in path.parts)
        and path.is_file()
        and path.name != "Dockerfile.dockerignore"
    }
    compose = {
        relative_directory(root, path.parent)
        for filename in ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
        for path in root.rglob(filename)
        if not any(part in IGNORED_PARTS for part in path.parts) and path.is_file()
    }
    return dockerfiles | compose


def check(root: Path) -> list[str]:
    configured = configured_directories(root / ".github/dependabot.yml")
    expected = {
        "cargo": independent_cargo_directories(root),
        "npm": discover_directories(root, "pnpm-lock.yaml"),
        "docker": expected_docker_directories(root),
        "github-actions": {"/"},
    }
    failures: list[str] = []
    for ecosystem, directories in expected.items():
        actual = configured.get(ecosystem, set())
        if actual != directories:
            failures.append(
                f"{ecosystem} Dependabot coverage differs: "
                f"missing={sorted(directories - actual)}, unexpected={sorted(actual - directories)}"
            )

    adapters = adapter_directories(root)
    cargo = configured.get("cargo", set())
    for adapter in sorted(adapters):
        directory = root / adapter.lstrip("/")
        for filename in ("Cargo.toml", "Cargo.lock", "deny.toml", "LICENSE", "THIRD_PARTY_NOTICES.md"):
            if not (directory / filename).is_file():
                failures.append(f"adapter admission artifact is missing: {adapter}/{filename}")
        if adapter not in cargo:
            failures.append(f"adapter lacks independent Cargo Dependabot coverage: {adapter}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args()
    failures = check(args.repo_root.resolve())
    if failures:
        print("\n".join(f"error: {failure}" for failure in failures), file=sys.stderr)
        return 1
    print("Dependabot covers every independently locked Cargo/npm and Docker composition.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
