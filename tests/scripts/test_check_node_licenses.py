#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for exact Node dependency-license admissions."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).with_name("check-node-licenses.py")
SPEC = importlib.util.spec_from_file_location("node_licenses", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class NodeLicenseTests(unittest.TestCase):
    def test_exact_non_allowlisted_license_is_admitted(self) -> None:
        observed, admitted = CHECKER.report_licenses(
            {
                "MIT": [{"name": "allowed-package", "versions": ["1.0.0"]}],
                "MPL-2.0": [{"name": "reviewed-package", "versions": ["2.3.4"]}],
            },
            {"MIT"},
            {},
            {"reviewed-package@2.3.4": "MPL-2.0"},
        )
        self.assertEqual(observed, {"MIT"})
        self.assertEqual(admitted, {"reviewed-package@2.3.4"})

    def test_unreviewed_version_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "not allowlisted or exactly admitted"):
            CHECKER.report_licenses(
                {
                    "MPL-2.0": [
                        {"name": "reviewed-package", "versions": ["2.3.4", "2.3.5"]}
                    ]
                },
                {"MIT"},
                {},
                {"reviewed-package@2.3.4": "MPL-2.0"},
            )

    def test_unknown_license_requires_an_exact_override(self) -> None:
        with self.assertRaisesRegex(ValueError, "has no exact override"):
            CHECKER.report_licenses(
                {"Unknown": [{"name": "unknown-package", "versions": ["1.0.0"]}]},
                {"MIT"},
                {},
                {},
            )

    def test_policy_rejects_ranges_and_globally_allowed_admissions(self) -> None:
        for selector, license_name in [
            ("reviewed-package@^2.3.4", "MPL-2.0"),
            ("reviewed-package@2.3.4", "MIT"),
        ]:
            with self.subTest(selector=selector, license_name=license_name):
                with tempfile.TemporaryDirectory() as temporary:
                    policy = Path(temporary) / "node-policy.toml"
                    policy.write_text(
                        "\n".join(
                            [
                                'allowed_licenses = ["MIT"]',
                                "[package_license_overrides]",
                                "[package_license_admissions]",
                                f'"{selector}" = "{license_name}"',
                            ]
                        ),
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(ValueError, "must map exact package selectors"):
                        CHECKER.load_policy(policy)


if __name__ == "__main__":
    unittest.main()
