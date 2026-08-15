#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Static contract for the exact PostgreSQL integration helper image."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "deploy/compose/compose.yaml"
POSTGRES_18_6 = (
    "docker.io/library/postgres@"
    "sha256:ae6c78831cbc35fa3a4aaf4d763ddacf6183d6004774cc2dc28b3920410d1d1a"
)
POSTGRES_SERVICES = ("postgres", "postgres-migrator-role", "postgres-runtime-roles")


class ComposePostgresImageTest(unittest.TestCase):
    def test_all_postgres_services_use_the_admitted_18_6_digest(self) -> None:
        compose = COMPOSE.read_text(encoding="utf-8")
        for service in POSTGRES_SERVICES:
            match = re.search(
                rf"^  {re.escape(service)}:\n(?:(?:    [^\n]*\n)|\n)*?"
                r"^    image: ([^\n]+)$",
                compose,
                flags=re.MULTILINE,
            )
            self.assertIsNotNone(match, service)
            assert match is not None
            self.assertEqual(match.group(1), POSTGRES_18_6, service)


if __name__ == "__main__":
    unittest.main()
