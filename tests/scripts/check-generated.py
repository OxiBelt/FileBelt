#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regenerate Protobuf clients when schemas exist and require a clean tree."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument(
        "--breaking-against",
        action="append",
        default=[],
        help="run Buf breaking policy against this local input; may be repeated",
    )
    args = parser.parse_args()
    root = args.repo_root.resolve()
    protocol = root / "protocol"
    if not any(protocol.rglob("*.proto")):
        print("No accepted Protobuf schemas; generation check is not applicable")
        return 0
    if shutil.which("buf") is None:
        print("error: pinned buf is required when schemas exist", file=sys.stderr)
        return 1
    subprocess.run(["buf", "lint"], cwd=protocol, check=True)
    for baseline in args.breaking_against:
        subprocess.run(
            ["buf", "breaking", ".", "--against", baseline],
            cwd=protocol,
            check=True,
        )
    subprocess.run(
        [
            sys.executable,
            str(protocol / "generate.py"),
            "--repo-root",
            str(root),
        ],
        cwd=root,
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            str(protocol / "generate-openapi-client.py"),
            "--repo-root",
            str(root),
        ],
        cwd=root,
        check=True,
    )
    subprocess.run(["git", "diff", "--exit-code", "--", "protocol", "source", "ui"], cwd=root, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
