# SPDX-License-Identifier: Apache-2.0

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tests/performance/phase8/phase8_evidence.py"
SPEC = importlib.util.spec_from_file_location("phase8_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def evidence() -> dict:
    return {
        "schemaVersion": 1,
        "cadence": "change-smoke",
        "durationSeconds": 300,
        "hostFingerprint": "host-a",
        "configurationDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "baseline": {
            "hostFingerprint": "host-a",
            "configurationDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "nfsP99Milliseconds": 100,
            "mediaP99Milliseconds": 100,
            "webSocketP99Milliseconds": 100,
        },
        "candidate": {
            "nfsP99Milliseconds": 110,
            "mediaP99Milliseconds": 110,
            "webTransportP99Milliseconds": 85,
            "acknowledgedLosses": 0,
            "orphanedUpdates": 0,
            "memoryGrowthPercentPerHour": 1,
            "settledDescriptorGrowthPercent": 5,
            "settledTaskGrowthPercent": 5,
        },
    }


class Phase8EvidenceTests(unittest.TestCase):
    def test_accepts_thresholds_and_all_cadences(self) -> None:
        for cadence, seconds in MODULE.CADENCE_SECONDS.items():
            candidate = evidence()
            candidate["cadence"] = cadence
            candidate["durationSeconds"] = seconds
            self.assertTrue(MODULE.validate(candidate)["accepted"])

    def test_rejects_regressions_transport_and_stability_failures(self) -> None:
        candidate = evidence()
        candidate["candidate"].update({
            "nfsP99Milliseconds": 111,
            "mediaP99Milliseconds": 111,
            "webTransportP99Milliseconds": 86,
            "acknowledgedLosses": 1,
            "orphanedUpdates": 1,
            "memoryGrowthPercentPerHour": 1.1,
            "settledDescriptorGrowthPercent": 5.1,
            "settledTaskGrowthPercent": 5.1,
        })
        result = MODULE.validate(candidate)
        self.assertFalse(result["accepted"])
        self.assertEqual(len(result["failures"]), 8)

    def test_rejects_nonidentical_baseline(self) -> None:
        candidate = evidence()
        candidate["baseline"]["hostFingerprint"] = "host-b"
        candidate["baseline"]["configurationDigest"] = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        result = MODULE.validate(candidate)
        self.assertFalse(result["accepted"])
        self.assertIn("baseline hostFingerprint must match candidate hostFingerprint", result["failures"])
        self.assertIn("baseline configurationDigest must match candidate configurationDigest", result["failures"])


if __name__ == "__main__":
    unittest.main()
