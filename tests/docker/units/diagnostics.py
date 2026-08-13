#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Bound and scrub Docker integration diagnostics before retention."""

from __future__ import annotations

import re
from pathlib import Path


MAXIMUM_DIAGNOSTIC_BYTES = 1_048_576
TOKEN_PATTERNS = (
    re.compile(rb"fbcap[12][ .][A-Za-z0-9._~-]+"),
    re.compile(rb"fbmcp1[ .][A-Za-z0-9._~-]+"),
    re.compile(rb"(?i)(authorization|x-api-key|cookie|set-cookie)(\s*[:=]\s*)[^\r\n]+"),
    re.compile(rb"postgresql://[^\s@]+@"),
)


def secret_values(state_dir: Path) -> tuple[bytes, ...]:
    values: set[bytes] = set()
    for directory in (state_dir / "secrets", state_dir / "tls"):
        if not directory.is_dir():
            continue
        for path in directory.iterdir():
            if not path.is_file() or path.suffix in {".crt", ".pem"}:
                continue
            value = path.read_bytes().strip()
            if len(value) >= 8:
                values.add(value)
    return tuple(sorted(values, key=len, reverse=True))


def scrub(data: bytes, secrets: tuple[bytes, ...]) -> bytes:
    bounded = data[-MAXIMUM_DIAGNOSTIC_BYTES:]
    for value in secrets:
        bounded = bounded.replace(value, b"[REDACTED]")
    for pattern in TOKEN_PATTERNS:
        bounded = pattern.sub(
            lambda match: (match.group(1) + match.group(2) if match.lastindex == 2 else b"") + b"[REDACTED]",
            bounded,
        )
    return bounded


def write_scrubbed(path: Path, data: bytes, secrets: tuple[bytes, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(scrub(data, secrets))
