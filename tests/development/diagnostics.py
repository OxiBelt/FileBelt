#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Failure-only, bounded diagnostic retention for local deployment sessions."""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from pathlib import Path


MAXIMUM_DIAGNOSTIC_BYTES = 1_048_576
TOKEN_PATTERNS = (
    re.compile(rb"fbcap[12][ .][A-Za-z0-9._~-]+"),
    re.compile(rb"fbmcp1[ .][A-Za-z0-9._~-]+"),
    re.compile(rb"(?i)(authorization|proxy-authorization|x-api-key|cookie|set-cookie)(\s*[:=]\s*)[^\r\n]+"),
    re.compile(rb"(?i)(postgres(?:ql)?://)[^\s/@:]+:[^\s/@]+@"),
    re.compile(rb"(?i)(client-secret|private-key|password|token)(\s*[:=]\s*)[^\r\n]+"),
)


def secret_values(work_dir: Path) -> tuple[bytes, ...]:
    values: set[bytes] = set()
    for directory in (work_dir / "state" / "secrets", work_dir / "state" / "tls", work_dir / "secrets"):
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAXIMUM_DIAGNOSTIC_BYTES:
                continue
            value = path.read_bytes().strip()
            if len(value) >= 8:
                values.add(value)
    return tuple(sorted(values, key=len, reverse=True))


def remember_secret(work_dir: Path, name: str, value: bytes) -> None:
    """Keep a private cleanup-bound copy solely for later output scrubbing."""
    if not name.replace("-", "").isalnum() or not 8 <= len(value) <= MAXIMUM_DIAGNOSTIC_BYTES:
        raise ValueError("known diagnostic secret is invalid or exceeds the bounded size")
    directory = work_dir / "secrets"
    if directory.is_symlink():
        raise ValueError("known diagnostic secret directory must not be a symlink")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    destination = directory / name
    descriptor = os.open(
        destination,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())


def scrub(data: bytes, secrets: tuple[bytes, ...]) -> bytes:
    bounded = data[-MAXIMUM_DIAGNOSTIC_BYTES:]
    for value in secrets:
        bounded = bounded.replace(value, b"[REDACTED]")
    for pattern in TOKEN_PATTERNS:
        bounded = pattern.sub(
            lambda match: (match.group(1) + match.group(2) if match.lastindex == 2 else b"[REDACTED]"),
            bounded,
        )
    return bounded


def diagnostic_directory(root: Path, name: str) -> Path:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    parent = root / "diagnostics"
    if parent.is_symlink():
        raise ValueError("diagnostic directory must not be a symlink")
    parent.mkdir(mode=0o700, parents=False, exist_ok=True)
    parent.chmod(0o700)
    session_parent = parent / name
    if session_parent.is_symlink():
        raise ValueError("diagnostic session directory must not be a symlink")
    session_parent.mkdir(mode=0o700, exist_ok=True)
    session_parent.chmod(0o700)
    path = session_parent / timestamp
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    path.chmod(0o700)
    return path


def write_failure(path: Path, name: str, data: bytes, secrets: tuple[bytes, ...]) -> Path:
    destination = path / f"{name}.txt"
    destination.write_bytes(scrub(data, secrets))
    destination.chmod(0o600)
    return destination
