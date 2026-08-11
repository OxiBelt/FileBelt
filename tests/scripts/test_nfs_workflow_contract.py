#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/nfs-qualification.yml"
NATIVE = ROOT / "tests/scripts/run-nfs-native-build.sh"


def run_blocks(text: str) -> list[str]:
    lines = text.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.lstrip()
        if not stripped.startswith("run:"):
            index += 1
            continue
        indent = len(line) - len(stripped)
        value = stripped.removeprefix("run:").strip()
        if value not in {"|", ">", ">-", "|-"}:
            blocks.append(value)
            index += 1
            continue
        body: list[str] = []
        index += 1
        while index < len(lines):
            candidate = lines[index]
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indent:
                break
            body.append(candidate)
            index += 1
        blocks.append("\n".join(body))
    return blocks


class NfsWorkflowSecurityContractTests(unittest.TestCase):
    def test_untrusted_dispatch_values_never_enter_run_expressions(self) -> None:
        blocks = run_blocks(WORKFLOW.read_text(encoding="utf-8"))
        self.assertGreater(len(blocks), 0)
        for block in blocks:
            self.assertNotIn("${{ inputs.", block)
            self.assertNotIn("${{ matrix.", block)

    def test_workflow_has_no_publication_authority_and_ends_blocked(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("ref: ${{ inputs.", text)
        self.assertNotIn("release_tag:", text)
        self.assertIn("github.ref_type == 'tag'", text)
        for permission in (
            "contents: write",
            "packages: write",
            "id-token: write",
            "attestations: write",
        ):
            self.assertNotIn(permission, text)
        self.assertIn("Refuse publication without an assembled immutable evidence package", text)
        self.assertIn("exit 1", text)

    def test_malicious_release_tag_fails_before_external_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "executed"
            malicious = f"1.2.3'; touch {marker}; printf '"
            result = subprocess.run(
                [
                    NATIVE,
                    "--tag",
                    malicious,
                    "--platform",
                    "linux/amd64",
                    "--output",
                    str(Path(temporary) / "evidence.json"),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("signed release tag must be an exact SemVer", result.stderr)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
