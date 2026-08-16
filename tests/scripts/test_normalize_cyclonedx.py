#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for fail-closed Rust CycloneDX augmentation."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


PLATFORM = "linux/amd64"


def component(
    name: str,
    relationship: str,
    *,
    component_type: str | None = None,
    purl_type: str | None = None,
) -> dict[str, str]:
    if component_type is None:
        component_type = "application" if name in {"filebelt-api", "rustc"} else "library"
    if purl_type is None:
        purl_type = "cargo" if name in {"filebelt-api", "webpki-roots"} else "generic"
    return {
        "type": component_type,
        "name": name,
        "version": "1.0.0",
        "purl": f"pkg:{purl_type}/{name}@1.0.0?target=amd64",
        "license": "MIT",
        "relationship": relationship,
        "evidence": "https://example.invalid/immutable@sha256:" + "a" * 64,
    }


class CycloneDxNormalizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="filebelt-cdx-")
        self.directory = Path(self.temporary.name)
        self.script = Path(__file__).with_name("normalize-cyclonedx.py")
        self.plan = self.directory / "plan.json"
        self.raw = self.directory / "raw.json"
        self.output = self.directory / "normalized.json"
        self.runtime_output = self.directory / "runtime.json"
        inventory = {
            platform: [
                component("filebelt-api", "runtime"),
                component("webpki-roots", "runtime"),
                component("rust-std", "runtime"),
                component("rustc", "build-tool"),
            ]
            for platform in ("linux/amd64", "linux/arm64", "linux/riscv64")
        }
        self.plan_value: dict[str, Any] = {
            "schemaVersion": 2,
            "amd64IsaBaseline": "x86-64-v3",
            "version": "0.1.0",
            "tag": "0.1.0-build.0123456789ab",
            "source": {
                "revision": "0123456789abcdef0123456789abcdef01234567",
                "ref": "refs/heads/main",
                "created": "2026-08-06T12:34:56Z",
            },
            "images": [
                {
                    "role": "filebelt-api",
                    "repository": "ghcr.io/oxibelt/filebelt-api",
                    "license": "Apache-2.0 AND MIT",
                    "platforms": [PLATFORM],
                    "artifact": {
                        "kind": "rust-binary",
                        "binary": "filebelt-api",
                        "targetCpu": {
                            "linux/amd64": "x86-64-v3",
                            "linux/arm64": None,
                            "linux/riscv64": None,
                        },
                        "components": inventory,
                    },
                }
            ],
        }
        self.raw.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.7",
                    "metadata": {
                        "tools": {"components": []},
                        "component": {"bom-ref": "trivy-subject"},
                    },
                    "components": [],
                    "dependencies": [],
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_normalizer(self) -> subprocess.CompletedProcess[str]:
        self.plan.write_text(json.dumps(self.plan_value), encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                str(self.script),
                "--plan",
                str(self.plan),
                "--role",
                "filebelt-api",
                "--platform",
                PLATFORM,
                "--input",
                str(self.raw),
                "--output",
                str(self.output),
                "--runtime-output",
                str(self.runtime_output),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_empty_trivy_scratch_inventory_is_augmented_from_plan(self) -> None:
        result = self.run_normalizer()
        self.assertEqual(result.returncode, 0, result.stderr)
        normalized = json.loads(self.output.read_text(encoding="utf-8"))
        subject_properties = {
            item["name"]: item["value"]
            for item in normalized["metadata"]["component"]["properties"]
        }
        self.assertEqual(subject_properties["io.filebelt.build.target-cpu"], "x86-64-v3")
        self.assertEqual(len(subject_properties["io.filebelt.build.plan-sha256"]), 64)
        self.assertEqual(len(normalized["components"]), 4)
        subject_dependency = normalized["dependencies"][-1]
        self.assertEqual(
            subject_dependency["dependsOn"],
            sorted(
                [
                    component("filebelt-api", "runtime")["purl"],
                    component("webpki-roots", "runtime")["purl"],
                    component("rust-std", "runtime")["purl"],
                ]
            ),
        )
        runtime = json.loads(self.runtime_output.read_text(encoding="utf-8"))
        scanner = next(
            item
            for item in runtime["components"]
            if item["bom-ref"].endswith(":trivy-cargo")
        )
        self.assertEqual(scanner["name"], "/usr/local/bin/filebelt-api")
        scanner_dependency = next(
            item for item in runtime["dependencies"] if item["ref"] == scanner["bom-ref"]
        )
        self.assertEqual(
            scanner_dependency["dependsOn"],
            sorted(
                [
                    component("filebelt-api", "runtime")["purl"],
                    component("webpki-roots", "runtime")["purl"],
                ]
            ),
        )
        runtime_subject = next(
            item
            for item in runtime["dependencies"]
            if item["ref"].startswith("urn:filebelt:")
            and not item["ref"].endswith(":trivy-cargo")
        )
        self.assertEqual(
            runtime_subject["dependsOn"],
            sorted([component("rust-std", "runtime")["purl"], scanner["bom-ref"]]),
        )
        self.assertNotIn(
            component("rustc", "build-tool")["purl"],
            {item["bom-ref"] for item in runtime["components"]},
        )

    def test_missing_rust_inventory_fails_closed(self) -> None:
        self.plan_value["images"][0]["artifact"]["components"][PLATFORM] = []
        result = self.run_normalizer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be nonempty", result.stderr)

    def test_missing_build_tool_relationship_fails_closed(self) -> None:
        self.plan_value["images"][0]["artifact"]["components"][PLATFORM] = [
            component("filebelt-api", "runtime")
        ]
        result = self.run_normalizer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runtime and build-tool", result.stderr)

    def test_missing_cargo_application_fails_closed(self) -> None:
        self.plan_value["images"][0]["artifact"]["components"][PLATFORM] = [
            component("filebelt-api", "runtime", component_type="library"),
            component("rustc", "build-tool"),
        ]
        result = self.run_normalizer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one Cargo application", result.stderr)

    def test_duplicate_cargo_application_fails_closed(self) -> None:
        self.plan_value["images"][0]["artifact"]["components"][PLATFORM].append(
            component(
                "filebelt-helper",
                "runtime",
                component_type="application",
                purl_type="cargo",
            )
        )
        result = self.run_normalizer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one Cargo application", result.stderr)


if __name__ == "__main__":
    unittest.main()
