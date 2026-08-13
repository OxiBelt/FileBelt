#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Load and validate the versioned Docker integration-unit catalog."""

from __future__ import annotations

import dataclasses
import re
import tomllib
from pathlib import Path


NAME = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
ROLE = re.compile(r"^filebelt-[a-z0-9-]+$")
KNOWN_TIERS = {"pull_request", "push", "scheduled", "manual", "release"}
KNOWN_BROWSERS = {"chromium", "firefox"}
KNOWN_STATUS = {"ready", "blocked"}


@dataclasses.dataclass(frozen=True)
class Unit:
    name: str
    description: str
    compose_files: tuple[Path, ...]
    profiles: tuple[str, ...]
    driver: tuple[str, ...]
    roles: tuple[str, ...]
    event_tiers: tuple[str, ...]
    browser_projects: tuple[str, ...]
    exact_artifacts: bool
    status: str
    blocker: str | None


def _string_list(value: object, field: str, *, pattern: re.Pattern[str] | None = None) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{field} must be a non-empty string array")
    result = tuple(value)
    if len(set(result)) != len(result):
        raise ValueError(f"{field} must not contain duplicates")
    if pattern is not None and any(pattern.fullmatch(item) is None for item in result):
        raise ValueError(f"{field} contains an invalid value")
    return result


def load_catalog(root: Path, catalog_path: Path) -> dict[str, Unit]:
    with catalog_path.open("rb") as source:
        document = tomllib.load(source)
    if set(document) != {"schema_version", "units"} or document["schema_version"] != 1:
        raise ValueError("Docker unit catalog must use schema version 1")
    raw_units = document["units"]
    if not isinstance(raw_units, dict) or set(raw_units) != {"core", "collaboration", "mcp"}:
        raise ValueError("Docker unit catalog must define exactly core, collaboration, and mcp")
    units: dict[str, Unit] = {}
    allowed = {
        "description", "compose_files", "profiles", "driver", "roles",
        "event_tiers", "browser_projects", "exact_artifacts", "status", "blocker",
    }
    for name, raw in raw_units.items():
        if NAME.fullmatch(name) is None or not isinstance(raw, dict) or set(raw) - allowed:
            raise ValueError(f"Docker unit {name!r} is malformed")
        description = raw.get("description")
        if not isinstance(description, str) or not description or len(description) > 240:
            raise ValueError(f"Docker unit {name} has an invalid description")
        compose_names = _string_list(raw.get("compose_files"), f"{name}.compose_files")
        compose_files: list[Path] = []
        for compose_name in compose_names:
            relative = Path(compose_name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError(f"Docker unit {name} compose path escapes the repository")
            resolved = (root / relative).resolve()
            if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
                raise ValueError(f"Docker unit {name} compose file does not exist: {compose_name}")
            compose_files.append(resolved)
        profiles = _string_list(raw.get("profiles"), f"{name}.profiles", pattern=NAME)
        driver = _string_list(raw.get("driver"), f"{name}.driver")
        driver_path = Path(driver[1] if driver[0] in {"python3", "node"} and len(driver) > 1 else driver[0])
        if driver_path.is_absolute() or ".." in driver_path.parts or not (root / driver_path).is_file():
            raise ValueError(f"Docker unit {name} driver is not a tracked repository file")
        roles = _string_list(raw.get("roles"), f"{name}.roles", pattern=ROLE)
        tiers = _string_list(raw.get("event_tiers"), f"{name}.event_tiers")
        if not set(tiers) <= KNOWN_TIERS:
            raise ValueError(f"Docker unit {name} has an unknown event tier")
        browsers_value = raw.get("browser_projects")
        if not isinstance(browsers_value, list) or not all(isinstance(item, str) for item in browsers_value):
            raise ValueError(f"Docker unit {name} browser_projects must be an array")
        browsers = tuple(browsers_value)
        if len(set(browsers)) != len(browsers) or not set(browsers) <= KNOWN_BROWSERS:
            raise ValueError(f"Docker unit {name} has invalid browser projects")
        status = raw.get("status")
        blocker = raw.get("blocker")
        if status not in KNOWN_STATUS or (status == "blocked") != isinstance(blocker, str):
            raise ValueError(f"Docker unit {name} has an invalid status/blocker contract")
        if raw.get("exact_artifacts") is not True:
            raise ValueError(f"Docker unit {name} must require exact artifacts")
        units[name] = Unit(
            name=name,
            description=description,
            compose_files=tuple(compose_files),
            profiles=profiles,
            driver=driver,
            roles=roles,
            event_tiers=tiers,
            browser_projects=browsers,
            exact_artifacts=True,
            status=status,
            blocker=blocker if isinstance(blocker, str) else None,
        )
    if units["core"].browser_projects:
        raise ValueError("core must not require a browser")
    if units["collaboration"].browser_projects != ("chromium", "firefox"):
        raise ValueError("collaboration must run Chromium and Firefox")
    return units
