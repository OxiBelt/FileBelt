#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Keep the isolated ONLYOFFICE launcher lockfile dependency-free."""

from __future__ import annotations

import argparse
from pathlib import Path


LOCKFILE_PATH = Path("adapters/onlyoffice/pnpm-lock.yaml")
EXPECTED_LOCKFILE = """lockfileVersion: '9.0'

settings:
  autoInstallPeers: false
  excludeLinksFromLockfile: false

importers:
  .: {}
"""


def check(root: Path) -> list[str]:
    lockfile = root / LOCKFILE_PATH
    if not lockfile.is_file():
        return [f"ONLYOFFICE launcher lockfile is missing: {lockfile}"]
    if lockfile.read_text(encoding="utf-8") != EXPECTED_LOCKFILE:
        return [
            "ONLYOFFICE launcher lockfile must remain dependency-free; "
            "adding packages requires separate adapter-local dependency admission"
        ]
    return []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args()
    failures = check(args.repo_root.resolve())
    if failures:
        print("\n".join(f"error: {failure}" for failure in failures))
        return 1
    print("ONLYOFFICE launcher lockfile remains dependency-free.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
