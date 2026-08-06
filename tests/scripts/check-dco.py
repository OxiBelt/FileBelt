#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate DCO sign-offs for every non-merge commit in a Git range."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys


SIGNOFF = re.compile(r"^Signed-off-by:\s+.+\s+<[^<>\s]+@[^<>\s]+>$", re.MULTILINE)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("base")
    parser.add_argument("head")
    args = parser.parse_args()
    output = subprocess.run(
        ["git", "log", "--no-merges", "--format=%H%x00%B%x00", f"{args.base}..{args.head}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    fields = output.split("\x00")
    failures: list[str] = []
    for index in range(0, len(fields) - 1, 2):
        commit = fields[index].strip()
        message = fields[index + 1]
        if commit and not SIGNOFF.search(message):
            failures.append(commit)
    if failures:
        print(f"error: commits missing DCO sign-off: {', '.join(failures)}", file=sys.stderr)
        return 1
    print("DCO sign-offs passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
