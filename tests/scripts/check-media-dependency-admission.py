#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Admit the independently locked Apache media-protocol Cargo graph."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def validate_admission_artifacts(root: Path) -> None:
    for relative_path in (
        "protocol/media/Cargo.toml",
        "protocol/media/Cargo.lock",
        "protocol/media/.cargo/audit.toml",
        "protocol/media/deny.toml",
        "supply-chain/config.toml",
        "supply-chain/audits.toml",
    ):
        path = root / relative_path
        if not path.is_file():
            raise RuntimeError(f"media dependency-admission artifact is missing: {path}")


def commands(root: Path) -> tuple[tuple[str, ...], ...]:
    manifest = root / "protocol/media/Cargo.toml"
    lockfile = root / "protocol/media/Cargo.lock"
    return (
        ("cargo", "audit", "--file", str(lockfile)),
        (
            "cargo",
            "deny",
            "--config",
            str(root / "protocol/media/deny.toml"),
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
            str(root / "supply-chain"),
            "--locked",
            "--no-minimize-exemptions",
        ),
    )


def working_directory(root: Path, command: tuple[str, ...]) -> Path:
    if command[:2] == ("cargo", "audit"):
        return root / "protocol/media"
    return root


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument(
        "--print-commands",
        action="store_true",
        help="print deterministic media-admission commands without executing them",
    )
    args = parser.parse_args()
    root = args.repo_root.resolve()
    validate_admission_artifacts(root)
    admission_commands = commands(root)
    if args.print_commands:
        print("\n".join(" ".join(command) for command in admission_commands))
        return 0
    for command in admission_commands:
        subprocess.run(command, cwd=working_directory(root, command), check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
