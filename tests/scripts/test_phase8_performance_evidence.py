# SPDX-License-Identifier: Apache-2.0

import copy
import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tests/performance/phase8/phase8_evidence.py"
SPEC = importlib.util.spec_from_file_location("phase8_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


REVISION = "a" * 40
DIGEST = "sha256:" + "b" * 64


def assertion(expected: str, observed: str) -> dict:
    return {"expected": expected, "observed": observed, "passed": True}


def passed_result(identifier: str, name: str) -> dict:
    return {
        identifier: name,
        "status": "passed",
        "sourceRevision": REVISION,
        "endpoint": f"local://{name}",
        "samplesMilliseconds": [1.0, 2.0, 3.0],
        "successAssertion": assertion("success", "success"),
        "failureAssertion": assertion("rejected", "rejected"),
        "cleanup": {"status": "passed", "detail": "owned resources removed"},
    }


def evidence() -> dict:
    roles = [passed_result("role", role) for role in MODULE.REQUIRED_ROLES]
    features = [
        passed_result("feature", feature) for feature in MODULE.REQUIRED_FEATURES
    ]
    for feature in features:
        feature["p99Milliseconds"] = (
            85.0 if feature["feature"] == "webtransport" else 100.0
        )
    return {
        "schema": MODULE.SCHEMA,
        "configurationVersion": MODULE.CONFIGURATION_VERSION,
        "sourceRevision": REVISION,
        "hostFingerprint": DIGEST,
        "configurationDigest": DIGEST,
        "mode": "qualification",
        "cadence": "change-smoke",
        "durationSeconds": 300,
        "observedDurationSeconds": 300,
        "roles": roles,
        "features": features,
        "baseline": {
            "hostFingerprint": DIGEST,
            "configurationDigest": DIGEST,
            "nfsP99Milliseconds": 100,
            "mediaP99Milliseconds": 100,
            "webSocketP99Milliseconds": 100,
        },
        "candidate": {
            "acknowledgedLosses": 0,
            "orphanedUpdates": 0,
            "memoryGrowthPercentPerHour": 1,
            "settledDescriptorGrowthPercent": 5,
            "settledTaskGrowthPercent": 5,
        },
        "accepted": True,
    }


class Phase8EvidenceTests(unittest.TestCase):
    def test_accepts_executable_complete_threshold_evidence(self) -> None:
        candidate = evidence()
        for cadence, seconds in MODULE.CADENCE_SECONDS.items():
            with self.subTest(cadence=cadence):
                current = copy.deepcopy(candidate)
                current["cadence"] = cadence
                current["durationSeconds"] = seconds
                current["observedDurationSeconds"] = seconds
                self.assertTrue(MODULE.validate(current)["accepted"])

    def test_skips_are_prerequisite_bearing_and_never_accepted(self) -> None:
        candidate = evidence()
        candidate["roles"][4] = {
            "role": "filebelt-media-controller",
            "status": "skipped",
            "sourceRevision": REVISION,
            "endpoint": "media-controller://dispatch",
            "prerequisite": "scoped I/O transfer and reconciled Job callbacks",
            "cleanup": {"status": "not_required", "detail": "no workload started"},
        }
        candidate["accepted"] = False
        result = MODULE.validate(candidate)
        self.assertFalse(result["accepted"])
        self.assertIn(
            "roles[4] is skipped and cannot qualify the release", result["failures"]
        )

        missing = copy.deepcopy(candidate)
        del missing["roles"][4]["prerequisite"]
        self.assertIn(
            "roles[4].prerequisite must be a non-empty string",
            MODULE.validate(missing)["failures"],
        )

    def test_rejects_legacy_fabricated_metrics(self) -> None:
        legacy = {
            "schemaVersion": 1,
            "cadence": "change-smoke",
            "durationSeconds": 300,
            "accepted": True,
            "baseline": {},
            "candidate": {},
        }
        result = MODULE.validate(legacy)
        self.assertFalse(result["accepted"])
        self.assertIn(f"schema must be {MODULE.SCHEMA}", result["failures"])
        self.assertIn("roles must be an array", result["failures"])

    def test_rejects_missing_assertions_cleanup_and_samples(self) -> None:
        candidate = evidence()
        role = candidate["roles"][0]
        del role["successAssertion"]
        del role["samplesMilliseconds"]
        role["cleanup"]["status"] = "pending"
        candidate["accepted"] = False
        failures = MODULE.validate(candidate)["failures"]
        self.assertIn("roles[0].successAssertion must be an object", failures)
        self.assertIn(
            "roles[0].samplesMilliseconds must be a nonempty positive-number array",
            failures,
        )
        self.assertIn(
            "roles[0].cleanup.status must be passed or not_required", failures
        )

    def test_contract_mode_and_performance_regressions_fail_closed(self) -> None:
        candidate = evidence()
        candidate["mode"] = "contract"
        candidate["accepted"] = False
        self.assertIn(
            "contract-mode evidence is never release qualification",
            MODULE.validate(candidate)["failures"],
        )

        candidate = evidence()
        candidate["observedDurationSeconds"] = 299.999
        candidate["accepted"] = False
        self.assertIn(
            "observedDurationSeconds must cover the full 300-second cadence",
            MODULE.validate(candidate)["failures"],
        )

        candidate = evidence()
        candidate["features"][0]["p99Milliseconds"] = 111
        candidate["features"][1]["p99Milliseconds"] = 111
        candidate["features"][2]["p99Milliseconds"] = 86
        candidate["candidate"].update(
            {
                "acknowledgedLosses": 1,
                "orphanedUpdates": 1,
                "memoryGrowthPercentPerHour": 1.1,
                "settledDescriptorGrowthPercent": 5.1,
                "settledTaskGrowthPercent": 5.1,
            }
        )
        candidate["accepted"] = False
        result = MODULE.validate(candidate)
        self.assertFalse(result["accepted"])
        for expected in (
            "nfsP99Milliseconds regression must not exceed 10 percent",
            "mediaP99Milliseconds regression must not exceed 10 percent",
            "WebTransport p99 improvement must be at least 15 percent",
            "acknowledgedLosses must be zero",
            "orphanedUpdates must be zero",
        ):
            self.assertIn(expected, result["failures"])


if __name__ == "__main__":
    unittest.main()
