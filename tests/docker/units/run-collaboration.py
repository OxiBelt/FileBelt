#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Seed and exercise collaboration through Chromium and Firefox at the TLS edge."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
ACCEPTANCE = ROOT / "tests/docker/phase2/acceptance.py"
SPEC = importlib.util.spec_from_file_location("filebelt_phase2_acceptance", ACCEPTANCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the core acceptance helpers")
CORE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CORE
SPEC.loader.exec_module(CORE)


def exercise() -> None:
    admin = CORE.Browser()
    member = CORE.Browser()
    CORE.wait_api(admin)
    admin_session = admin.login("admin")
    member_session = member.login("member")
    CORE.activate_descendant_share_security(str(admin_session["principal_id"]))
    drive = CORE.private_drive(admin)
    nodes: dict[str, str] = {}
    for browser_name in ("chromium", "firefox"):
        for scenario in ("convergence", "conflict"):
            committed = CORE.upload(
                admin,
                drive,
                f"collaboration-{browser_name}-{scenario}.md",
                b"# Collaboration\n\nbase\n",
                declared_media_type="text/markdown",
            )
            share = admin.api(
                "POST",
                f"/drives/{drive['id']}/nodes/{committed['node_id']}/shares",
                {
                    "inheritance": "self",
                    "kind": "direct",
                    "preset": "contributor",
                    "verified_email": "member@example.test",
                },
                expected=201,
                idempotent=True,
            )
            assert share["principal_id"] == member_session["principal_id"]
            nodes[f"{browser_name}:{scenario}"] = committed["node_id"]
    environment = {
        **os.environ,
        "FILEBELT_COLLABORATION_DRIVE_ID": drive["id"],
        "FILEBELT_COLLABORATION_NODE_IDS": json.dumps(nodes, separators=(",", ":")),
        "FILEBELT_COLLABORATION_MEMBER_ID": member_session["principal_id"],
    }
    subprocess.run(
        [
            "corepack", "pnpm", "--filter", "@filebelt/web", "exec", "playwright", "test",
            "--config", str(ROOT / "ui/web/playwright.docker.config.mjs"),
            "--tsconfig", str(ROOT / "ui/web/playwright.tsconfig.json"),
        ],
        cwd=ROOT,
        env=environment,
        check=True,
    )
    print("Collaboration Docker acceptance passed in Chromium and Firefox")


if __name__ == "__main__":
    exercise()
