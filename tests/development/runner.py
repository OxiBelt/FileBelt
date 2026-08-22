#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Subprocess boundary shared by local deployment backends."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import BinaryIO, Sequence


class CommandFailure(RuntimeError):
    def __init__(self, command: Sequence[str], returncode: int, stdout: bytes, stderr: bytes):
        super().__init__(f"command failed with exit code {returncode}: {command[0]}")
        self.command = tuple(command)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class Runner:
    def __init__(self, root: Path):
        self.root = root

    def run(
        self,
        command: Sequence[str],
        *,
        environment: dict[str, str] | None = None,
        cwd: Path | None = None,
        input_data: bytes | None = None,
        capture: bool = True,
        stdout: BinaryIO | int | None = None,
        stderr: BinaryIO | int | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            list(command),
            cwd=cwd or self.root,
            env=environment or os.environ.copy(),
            input=input_data,
            stdout=subprocess.PIPE if capture else stdout,
            stderr=subprocess.PIPE if capture else stderr,
            check=False,
        )
        if result.returncode != 0:
            raise CommandFailure(
                command, result.returncode, result.stdout or b"", result.stderr or b""
            )
        return result

    def stream(
        self,
        command: Sequence[str],
        *,
        environment: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> int:
        return subprocess.run(
            list(command),
            cwd=cwd or self.root,
            env=environment or os.environ.copy(),
            check=False,
        ).returncode
