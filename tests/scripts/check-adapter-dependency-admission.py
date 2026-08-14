#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Audit and license-check every registered adapter without expanding Cargo Vet."""

from __future__ import annotations

import argparse
import subprocess
import tomllib
from pathlib import Path


def registered_adapters(root: Path) -> tuple[Path, ...]:
    with (root / "supply-chain/cargo-boundaries-v1.toml").open("rb") as handle:
        policy = tomllib.load(handle)
    manifests = policy["repository"]["registered_adapter_manifests"]
    return tuple(root / manifest for manifest in sorted(manifests))


def validate_admission_artifacts(manifests: tuple[Path, ...]) -> None:
    for manifest in manifests:
        for filename in ("Cargo.lock", "deny.toml", "LICENSE", "THIRD_PARTY_NOTICES.md"):
            path = manifest.parent / filename
            if not path.is_file():
                raise RuntimeError(f"adapter admission artifact is missing: {path}")


def commands(root: Path, manifests: tuple[Path, ...]) -> tuple[tuple[str, ...], ...]:
    commands: list[tuple[str, ...]] = []
    for manifest in manifests:
        commands.extend(
            (
                ("cargo", "audit", "--file", str(manifest.parent / "Cargo.lock")),
                (
                    "cargo",
                    "deny",
                    "--config",
                    str(manifest.parent / "deny.toml"),
                    "--manifest-path",
                    str(manifest),
                    "--locked",
                    "check",
                ),
            )
        )
    return tuple(commands)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument(
        "--print-commands",
        action="store_true",
        help="print the deterministic audit and license admission commands without executing them",
    )
    args = parser.parse_args()
    root = args.repo_root.resolve()
    manifests = registered_adapters(root)
    validate_admission_artifacts(manifests)
    admission_commands = commands(root, manifests)
    if args.print_commands:
        print("\n".join(" ".join(command) for command in admission_commands))
        return 0
    for command in admission_commands:
        subprocess.run(command, cwd=root, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
