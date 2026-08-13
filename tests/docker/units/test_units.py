#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for catalog, diagnostic, evidence, and lifecycle refusal."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from catalog import load_catalog  # noqa: E402
from diagnostics import MAXIMUM_DIAGNOSTIC_BYTES, scrub  # noqa: E402
from images import validate_role  # noqa: E402
from lifecycle import fixture_tag, validate_project  # noqa: E402


class CatalogTest(unittest.TestCase):
    def test_catalog_defines_three_isolated_exact_artifact_units(self) -> None:
        units = load_catalog(ROOT, ROOT / "tests/docker/units.toml")
        self.assertEqual(set(units), {"core", "collaboration", "mcp"})
        self.assertTrue(all(unit.exact_artifacts for unit in units.values()))
        expected_tiers = ("pull_request", "push", "scheduled", "manual", "release")
        self.assertTrue(all(unit.event_tiers == expected_tiers for unit in units.values()))
        self.assertEqual(units["collaboration"].browser_projects, ("chromium", "firefox"))
        self.assertIn("filebelt-mcp-broker", units["mcp"].roles)
        collaboration = (ROOT / "ui/web/browser/docker-integration.spec.mjs").read_text(
            encoding="utf-8"
        )
        for required in (
            "CommitExternalHead",
            "Live collaboration disconnected.",
            "Save local edits as a copy",
            "timeout: 60_000",
        ):
            self.assertIn(required, collaboration)
        mcp_fixture = (ROOT / "tests/docker/mcp-egress/Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "install -d -o 10001 -g 10001 -m 0555 /opt/filebelt-mcp-egress",
            mcp_fixture,
        )

    def test_catalog_rejects_path_escape(self) -> None:
        document = (ROOT / "tests/docker/units.toml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "units.toml"
            path.write_text(document.replace('"deploy/compose/compose.yaml"', '"../compose.yaml"', 1), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "escapes"):
                load_catalog(ROOT, path)


class LifecycleTest(unittest.TestCase):
    def test_cleanup_names_are_runner_owned_and_bounded(self) -> None:
        project = validate_project("filebelt-core-a1b2c3")
        self.assertEqual(fixture_tag("oidc", project), "filebelt-oidc-fixture:filebelt-core-a1b2c3")
        for unsafe in ("core", "FileBelt-core", "filebelt-core/escape", "filebelt-" + "a" * 64):
            with self.assertRaises(ValueError):
                validate_project(unsafe)
        with self.assertRaises(ValueError):
            fixture_tag("production", project)

    def test_diagnostics_are_bounded_and_redacted(self) -> None:
        secret = b"fixture-secret-value"
        source = b"prefix\nAuthorization: Bearer exposed\n" + secret + b"\n" + b"x" * (MAXIMUM_DIAGNOSTIC_BYTES + 100)
        result = scrub(source, (secret,))
        self.assertLessEqual(len(result), MAXIMUM_DIAGNOSTIC_BYTES)
        self.assertNotIn(secret, result)
        self.assertNotIn(b"Bearer exposed", result)


class ImageEvidenceTest(unittest.TestCase):
    def test_wrong_channel_fails_before_archive_loading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "image-plan.json"
            plan.write_text(json.dumps({
                "schemaVersion": 1,
                "channel": "release",
                "source": {"kind": "release", "dirty": False, "revision": "a" * 40},
                "images": [],
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source contract"):
                validate_role(ROOT, root, plan, "filebelt-api", "build", "a" * 40)


if __name__ == "__main__":
    unittest.main()
