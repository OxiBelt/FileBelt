#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate local Markdown paths and headings without network access."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote


IGNORED_PARTS = {".agents", ".git", "dist", "node_modules", "target"}
LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$", re.MULTILINE)


def slug(text: str) -> str:
    value = re.sub(r"<[^>]+>", "", text.strip().lower())
    value = re.sub(r"[^\w\- ]", "", value, flags=re.UNICODE)
    return re.sub(r"[ -]+", "-", value).strip("-")


def anchors(path: Path) -> set[str]:
    found: set[str] = set()
    counts: dict[str, int] = {}
    for heading in HEADING.findall(path.read_text(encoding="utf-8")):
        base = slug(heading)
        count = counts.get(base, 0)
        found.add(base if count == 0 else f"{base}-{count}")
        counts[base] = count + 1
    return found


def validate(root: Path) -> list[str]:
    failures: list[str] = []
    for document in root.rglob("*.md"):
        if any(part in IGNORED_PARTS for part in document.parts):
            continue
        content = document.read_text(encoding="utf-8")
        for raw_target in LINK.findall(content):
            target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            path_text, _, fragment = target.partition("#")
            resolved = document if not path_text else document.parent / unquote(path_text)
            if resolved.is_dir():
                resolved = resolved / "README.md"
            if not resolved.is_file():
                failures.append(
                    f"{document.relative_to(root)}: missing local target {target}"
                )
                continue
            if fragment and unquote(fragment).lower() not in anchors(resolved):
                failures.append(
                    f"{document.relative_to(root)}: missing anchor #{fragment} in "
                    f"{resolved.relative_to(root)}"
                )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args()
    failures = validate(args.repo_root.resolve())
    if failures:
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
        return 1
    print("Markdown local links passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
