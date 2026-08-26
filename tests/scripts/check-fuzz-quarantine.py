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
    "target_sha256": "de7845d41dce16f42c6afaa0128426484c119e1d05af29f909e1e2bd4fdc7421",
    "target_manifest": "fuzz/Cargo.toml",
    "target_manifest_bin_path": "fuzz_targets/collaboration_wire.rs",
    "implementation_sources": [
        {
            "path": "fuzz/src/lib.rs",
            "sha256": "ff50f91441c6d445d0cd0d9abc6570165730255eaf1091388a8892c303a2ec69",
        },
        {
            "path": "source/apps/filebelt-collaboration/src/lib.rs",
            "sha256": "552ada6729d16225429bf9a94e595b796b7507bc3c8685120bde564d2ed5dbd4",
        },
        {
            "path": "source/apps/filebelt-collaboration/src/update_decoder.rs",
            "sha256": "96d9e159c99794465f469809bc157a11d3ae9aeb228b53c7f45085083cca83ab",
        },
    ],
    "status": "risk_accepted",
    "dependency_name": "yrs",
    "dependency_version": "0.27.4",
    "dependency_source": "registry+https://github.com/rust-lang/crates.io-index",
    "dependency_checksum": "3987db9bdbe6f0f49c58ec3d0daf4750a70b40019c190f6c6708abfcdfe6bea0",
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
    if catalog.get("schema_version") != 3:
        raise QuarantineError("fuzz catalog schema must remain 3")
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

    manifest = load_toml(repo_root / EXPECTED_QUARANTINE["target_manifest"])
    matching_bins = [
        binary
        for binary in manifest.get("bin", [])
        if binary.get("name") == EXPECTED_QUARANTINE["target"]
    ]
    if len(matching_bins) != 1:
        raise QuarantineError("reviewed quarantine manifest bin is missing or duplicated")
    if matching_bins[0].get("path") != EXPECTED_QUARANTINE["target_manifest_bin_path"]:
        raise QuarantineError("reviewed quarantine manifest bin path changed")

    for implementation in EXPECTED_QUARANTINE["implementation_sources"]:
        implementation_source = repo_root / implementation["path"]
        try:
            implementation_digest = hashlib.sha256(
                implementation_source.read_bytes()
            ).hexdigest()
        except OSError as error:
            raise QuarantineError(
                "reviewed quarantine implementation source is unavailable"
            ) from error
        if implementation_digest != implementation["sha256"]:
            raise QuarantineError("reviewed quarantine implementation source changed")

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
