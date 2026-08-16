#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Unit contracts for adapter publication-plan schema admission."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tests/scripts/validate-adapter-publication.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("validate_adapter_publication", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


class AdapterPublicationPlanHeaderTests(unittest.TestCase):
    def test_accepts_the_schema_v3_amd64_baseline(self) -> None:
        VALIDATOR.validate_plan_header(
            {"schemaVersion": 3, "amd64IsaBaseline": "x86-64-v3", "roles": []}
        )

    def test_rejects_a_legacy_or_altered_baseline(self) -> None:
        for plan in (
            {"schemaVersion": 2, "amd64IsaBaseline": "x86-64-v3", "roles": []},
            {"schemaVersion": 3, "amd64IsaBaseline": "x86-64-v2", "roles": []},
        ):
            with self.assertRaisesRegex(ValueError, "schemaVersion must be 3"):
                VALIDATOR.validate_plan_header(plan)


if __name__ == "__main__":
    unittest.main()
