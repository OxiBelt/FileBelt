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


def load_policy(path: Path) -> set[str]:
    with path.open("rb") as handle:
        policy = tomllib.load(handle)
    configured = policy.get("allowed_licenses")
    if not isinstance(configured, list) or not configured:
        raise ValueError("allowed_licenses must be a non-empty array")
    if not all(isinstance(item, str) and item for item in configured):
        raise ValueError("allowed_licenses entries must be non-empty strings")
    return set(configured)


def report_licenses(report: Any) -> set[str]:
    if not isinstance(report, dict):
        raise ValueError("pnpm license report must be a JSON object")
    if not report:
        raise ValueError("pnpm license report is empty")
    if not all(isinstance(key, str) and key for key in report):
        raise ValueError("pnpm license report contains an invalid license key")
    return set(report)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()

    try:
        allowed = load_policy(args.policy)
        observed = report_licenses(json.load(sys.stdin))
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
