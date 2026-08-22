# SPDX-License-Identifier: Apache-2.0

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tests/performance/phase8/run_local_qualification.py"
SPEC = importlib.util.spec_from_file_location("run_local_phase8_qualification", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LocalPhase8QualificationTests(unittest.TestCase):
    def test_role_and_feature_catalogs_cover_the_fail_closed_contract(self) -> None:
        runnable = set(MODULE.HEALTH_ENDPOINTS) | {"filebelt-collaboration", "filebelt-tools"}
        skipped = set(MODULE.ROLE_PREREQUISITES)
        self.assertEqual(runnable | skipped, set(MODULE.VALIDATOR.REQUIRED_ROLES))
        self.assertFalse(runnable & skipped)
        self.assertEqual(
            set(MODULE.FEATURE_PREREQUISITES), set(MODULE.VALIDATOR.REQUIRED_FEATURES)
        )

    def test_skipped_results_are_nonmetric_and_prerequisite_bearing(self) -> None:
        result = MODULE.skipped_result(
            "role",
            "filebelt-vfs",
            "a" * 40,
            "provider-neutral VFS fixture",
            "filebelt-phase8-test",
        )
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["prerequisite"], "provider-neutral VFS fixture")
        self.assertEqual(result["cleanup"]["status"], "not_required")
        for forbidden in (
            "samplesMilliseconds",
            "successAssertion",
            "failureAssertion",
            "p99Milliseconds",
        ):
            self.assertNotIn(forbidden, result)

    def test_configuration_digest_binds_paths_and_bytes(self) -> None:
        first = ROOT / "deploy/compose/filebelt.toml"
        second = ROOT / "deploy/compose/filebelt-collaboration.toml"
        self.assertEqual(
            MODULE.digest_files((first, second)), MODULE.digest_files((first, second))
        )
        self.assertNotEqual(
            MODULE.digest_files((first, second)), MODULE.digest_files((second, first))
        )

    def test_node_drivers_are_real_endpoint_clients(self) -> None:
        health = MODULE.HEALTH_DRIVER.read_text(encoding="utf-8")
        collaboration = MODULE.COLLABORATION_DRIVER.read_text(encoding="utf-8")
        self.assertIn('Request(Endpoint.url)', health)
        self.assertIn('Failure.Status !== 404', health)
        self.assertIn("connectTls({", collaboration)
        self.assertIn("`Origin: ${Configuration.origin}`", collaboration)
        self.assertIn("rejectUnauthorized: true", collaboration)
        self.assertIn('Success.FirstByte !== 0x1a', collaboration)
        self.assertIn('Reused.FirstByte !== 0x4a', collaboration)

        harness = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"NODE_EXTRA_CA_CERTS": certificate', harness)
        self.assertNotIn('"NODE_TLS_REJECT_UNAUTHORIZED": "0"', harness)


if __name__ == "__main__":
    unittest.main()
