#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create one deterministic FileBelt adapter corresponding-source archive."""

import argparse
import pathlib

from adapter_source_bundle import BundleError, package_bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-tree", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--commit-timestamp", type=int, required=True)
    arguments = parser.parse_args()
    try:
        digest = package_bundle(
            arguments.source_tree,
            arguments.output,
            arguments.role,
            arguments.version,
            arguments.revision,
            arguments.commit_timestamp,
        )
    except BundleError as error:
        parser.error(str(error))
    print(f"{digest}  {arguments.output.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
