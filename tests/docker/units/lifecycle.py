#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Ownership checks for Docker integration resources."""

from __future__ import annotations

import re


PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


def validate_project(value: str) -> str:
    if PROJECT.fullmatch(value) is None or not value.startswith("filebelt-"):
        raise ValueError("project name must be a bounded FileBelt-owned Docker identifier")
    return value


def fixture_tag(kind: str, project: str) -> str:
    validate_project(project)
    if kind not in {"mcp-egress", "oidc"}:
        raise ValueError("fixture kind is not runner-owned")
    return f"filebelt-{kind}-fixture:{project}"
