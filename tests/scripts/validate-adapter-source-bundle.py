#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate deterministic FileBelt adapter corresponding-source evidence."""

import argparse
import pathlib

from adapter_source_bundle import (
    BundleError,
    validate_bundle,
    validate_bundle_against_plan,
    validate_canonical_adapter_plan,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=pathlib.Path, required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--commit-timestamp", type=int, required=True)
    parser.add_argument("--plan", type=pathlib.Path)
    arguments = parser.parse_args()
    try:
        digest = validate_bundle(
            arguments.bundle,
            arguments.role,
            arguments.version,
            arguments.revision,
            arguments.commit_timestamp,
        )
        if arguments.plan is not None:
            validate_canonical_adapter_plan(arguments.plan)
            validate_bundle_against_plan(arguments.bundle, arguments.plan, arguments.role)
    except (BundleError, OSError, ValueError) as error:
        parser.error(str(error))
    print(f"{digest}  {arguments.bundle.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
