#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Backend interface for bounded development deployment topologies."""

from __future__ import annotations

from typing import Protocol

from .model import DevelopmentConfiguration, Session


class Backend(Protocol):
    def up(self, session: Session, configuration: DevelopmentConfiguration) -> None: ...

    def status(self, session: Session) -> dict[str, object]: ...

    def logs(self, session: Session, component: str, tail: int) -> bytes: ...

    def restart(self, session: Session, component: str) -> None: ...

    def diagnose(self, session: Session) -> dict[str, bytes]: ...

    def port_forward(self, session: Session, port: int) -> int: ...

    def down(self, session: Session) -> None: ...
