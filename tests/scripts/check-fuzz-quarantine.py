#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Fail closed unless the reviewed sustained-fuzz quarantine is unchanged."""

from __future__ import annotations

import argparse
import hashlib
import tomllib
from pathlib import Path
from typing import Any


EXPECTED_QUARANTINE: dict[str, Any] = {
    "target": "collaboration_wire",
    "target_source": "fuzz/fuzz_targets/collaboration_wire.rs",
    "target_sha256": "ade6705cb0a691a9c9e6d7779932ede34a7b127e50d95fc2eac0a081d2c26d8b",
    "status": "risk_accepted",
    "dependency_name": "yrs",
    "dependency_version": "0.27.3",
    "dependency_source": "registry+https://github.com/rust-lang/crates.io-index",
    "dependency_checksum": "9d3a728b1abffeca5b9e5319c5b81e04b73790cbdc1e342da8d91b440b3026cb",
    "tracker": "https://github.com/OxiBelt/FileBelt/issues/10",
    "review_required_on_change": True,
    "clearance_requires": [
        "tracked_resolution",
        "dependency_identity_change",
        "private_validation",
    ],
}


class QuarantineError(ValueError):
    """The reviewed quarantine or dependency identity has drifted."""


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def validate_quarantine(repo_root: Path, target: str) -> None:
    catalog = load_toml(repo_root / "fuzz/targets.toml")
    if catalog.get("schema_version") != 2:
        raise QuarantineError("fuzz catalog schema must remain 2")
    quarantines = catalog.get("quarantine")
    if quarantines != [EXPECTED_QUARANTINE]:
        raise QuarantineError("reviewed fuzz quarantine differs from the exact sentinel")
    if target != EXPECTED_QUARANTINE["target"]:
        raise QuarantineError(f"target {target!r} is not the reviewed quarantine target")

    targets = [entry.get("name") for entry in catalog.get("target", [])]
    if targets.count(target) != 1:
        raise QuarantineError("reviewed quarantine target is missing or duplicated")

    target_source = repo_root / EXPECTED_QUARANTINE["target_source"]
    try:
        target_digest = hashlib.sha256(target_source.read_bytes()).hexdigest()
    except OSError as error:
        raise QuarantineError("reviewed quarantine target source is unavailable") from error
    if target_digest != EXPECTED_QUARANTINE["target_sha256"]:
        raise QuarantineError("reviewed quarantine target source changed")

    lockfile = load_toml(repo_root / "Cargo.lock")
    matching = [
        package
        for package in lockfile.get("package", [])
        if package.get("name") == EXPECTED_QUARANTINE["dependency_name"]
        and package.get("version") == EXPECTED_QUARANTINE["dependency_version"]
    ]
    if len(matching) != 1:
        raise QuarantineError("reviewed dependency identity is missing or duplicated")
    package = matching[0]
    for field in ("source", "checksum"):
        expected = EXPECTED_QUARANTINE[f"dependency_{field}"]
        if package.get(field) != expected:
            raise QuarantineError(f"reviewed dependency {field} changed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--target", required=True)
    arguments = parser.parse_args()
    validate_quarantine(arguments.repo_root.resolve(), arguments.target)
    print(f"reviewed fuzz quarantine is unchanged: {arguments.target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
