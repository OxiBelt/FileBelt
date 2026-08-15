#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate pnpm's resolved license report against FileBelt policy."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


EXACT_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")


def exact_selector(selector: str) -> bool:
    name, separator, version = selector.rpartition("@")
    return bool(separator and name and EXACT_VERSION.fullmatch(version))


def load_policy(path: Path) -> tuple[set[str], dict[str, str], dict[str, str]]:
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
    admissions = policy.get("package_license_admissions", {})
    if not isinstance(admissions, dict) or not all(
        isinstance(selector, str)
        and exact_selector(selector)
        and isinstance(license_name, str)
        and license_name
        and license_name not in configured
        for selector, license_name in admissions.items()
    ):
        raise ValueError(
            "package_license_admissions must map exact package selectors to non-allowlisted licenses"
        )
    return set(configured), overrides, admissions


def report_licenses(
    report: Any,
    allowed: set[str],
    overrides: dict[str, str],
    admissions: dict[str, str],
) -> tuple[set[str], set[str]]:
    if not isinstance(report, dict):
        raise ValueError("pnpm license report must be a JSON object")
    if not report:
        raise ValueError("pnpm license report is empty")
    if not all(isinstance(key, str) and key for key in report):
        raise ValueError("pnpm license report contains an invalid license key")
    observed: set[str] = set()
    admitted: set[str] = set()
    for license_name, packages in report.items():
        if not isinstance(packages, list) or not packages:
            raise ValueError("license report entry must name at least one package")
        for package in packages:
            if not isinstance(package, dict):
                raise ValueError("license report package must be an object")
            name = package.get("name")
            versions = package.get("versions")
            if (
                not isinstance(name, str)
                or not name
                or not isinstance(versions, list)
                or not versions
                or not all(isinstance(version, str) and EXACT_VERSION.fullmatch(version) for version in versions)
            ):
                raise ValueError("license report package must have an exact name and version list")
            for version in versions:
                selector = f"{name}@{version}"
                if license_name == "Unknown":
                    resolved = overrides.get(selector)
                    if resolved is None:
                        raise ValueError(f"unknown dependency license has no exact override: {selector}")
                    observed.add(resolved)
                elif license_name in allowed:
                    observed.add(license_name)
                elif admissions.get(selector) == license_name:
                    admitted.add(selector)
                else:
                    raise ValueError(
                        f"dependency license is not allowlisted or exactly admitted: {selector} ({license_name})"
                    )
    return observed, admitted


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()

    try:
        allowed, overrides, admissions = load_policy(args.policy)
        observed, admitted = report_licenses(json.load(sys.stdin), allowed, overrides, admissions)
    except (OSError, ValueError, tomllib.TOMLDecodeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"Node dependency licenses passed: {sorted(observed)}")
    if admitted:
        print(f"Exact package license admissions passed: {sorted(admitted)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
