#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate pnpm's resolved license report against FileBelt policy."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path
from typing import Any


def load_policy(path: Path) -> tuple[set[str], dict[str, str]]:
    with path.open("rb") as handle:
        policy = tomllib.load(handle)
    configured = policy.get("allowed_licenses")
    if not isinstance(configured, list) or not configured:
        raise ValueError("allowed_licenses must be a non-empty array")
    if not all(isinstance(item, str) and item for item in configured):
        raise ValueError("allowed_licenses entries must be non-empty strings")
    overrides = policy.get("package_license_overrides", {})
    if not isinstance(overrides, dict) or not all(
        isinstance(selector, str)
        and selector
        and isinstance(license_name, str)
        and license_name in configured
        for selector, license_name in overrides.items()
    ):
        raise ValueError("package_license_overrides must map exact package selectors to allowlisted licenses")
    return set(configured), overrides


def report_licenses(report: Any, overrides: dict[str, str]) -> set[str]:
    if not isinstance(report, dict):
        raise ValueError("pnpm license report must be a JSON object")
    if not report:
        raise ValueError("pnpm license report is empty")
    if not all(isinstance(key, str) and key for key in report):
        raise ValueError("pnpm license report contains an invalid license key")
    observed: set[str] = set()
    for license_name, packages in report.items():
        if license_name != "Unknown":
            observed.add(license_name)
            continue
        if not isinstance(packages, list) or not packages:
            raise ValueError("unknown license report entry must name at least one package")
        for package in packages:
            if not isinstance(package, dict):
                raise ValueError("unknown license report package must be an object")
            name = package.get("name")
            versions = package.get("versions")
            if not isinstance(name, str) or not isinstance(versions, list) or len(versions) != 1 or not isinstance(versions[0], str):
                raise ValueError("unknown license report package must have one exact name and version")
            resolved = overrides.get(f"{name}@{versions[0]}")
            if resolved is None:
                raise ValueError(f"unknown dependency license has no exact override: {name}@{versions[0]}")
            observed.add(resolved)
    return observed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()

    try:
        allowed, overrides = load_policy(args.policy)
        observed = report_licenses(json.load(sys.stdin), overrides)
    except (OSError, ValueError, tomllib.TOMLDecodeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    rejected = observed - allowed
    if rejected:
        print(
            f"error: dependency licenses are not allowlisted: {sorted(rejected)}",
            file=sys.stderr,
        )
        return 1

    print(f"Node dependency licenses passed: {sorted(observed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
