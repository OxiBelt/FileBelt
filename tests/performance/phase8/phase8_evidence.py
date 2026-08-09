#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed Phase 8 performance evidence gate."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


CADENCE_SECONDS = {
    "change-smoke": 5 * 60,
    "nightly": 60 * 60,
    "weekly": 2 * 60 * 60,
    "pre-release": int(2.5 * 60 * 60),
}
MAX_REGRESSION_PERCENT = 10.0
MIN_WEBTRANSPORT_IMPROVEMENT_PERCENT = 15.0
MAX_MEMORY_GROWTH_PERCENT_PER_HOUR = 1.0
MAX_SETTLED_GROWTH_PERCENT = 5.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    result = validate(read_json(arguments.input))
    arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not result["accepted"]:
        for failure in result["failures"]:
            print(f"Phase 8 evidence: {failure}")
        return 1
    print("Phase 8 evidence accepted")
    return 0


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot read valid JSON evidence from {path}: {error}") from error


def validate(evidence: Any) -> dict[str, Any]:
    failures: list[str] = []
    if not isinstance(evidence, dict):
        return {"accepted": False, "failures": ["evidence must be an object"]}
    if evidence.get("schemaVersion") != 1:
        failures.append("schemaVersion must be 1")
    cadence = evidence.get("cadence")
    expected_duration = CADENCE_SECONDS.get(cadence)
    if expected_duration is None:
        failures.append("cadence must be change-smoke, nightly, weekly, or pre-release")
    elif evidence.get("durationSeconds") != expected_duration:
        failures.append(f"{cadence} duration must be exactly {expected_duration} seconds")

    baseline = require_object(evidence, "baseline", failures)
    candidate = require_object(evidence, "candidate", failures)
    host = require_string(evidence, "hostFingerprint", failures)
    configuration = require_digest(evidence, "configurationDigest", failures)
    if baseline is not None:
        if baseline.get("hostFingerprint") != host:
            failures.append("baseline hostFingerprint must match candidate hostFingerprint")
        if baseline.get("configurationDigest") != configuration:
            failures.append("baseline configurationDigest must match candidate configurationDigest")

    if baseline is not None and candidate is not None:
        check_regression(baseline, candidate, "nfsP99Milliseconds", failures)
        check_regression(baseline, candidate, "mediaP99Milliseconds", failures)
        websocket = require_positive(baseline, "webSocketP99Milliseconds", failures)
        webtransport = require_positive(candidate, "webTransportP99Milliseconds", failures)
        if websocket is not None and webtransport is not None:
            improvement = (websocket - webtransport) * 100.0 / websocket
            if improvement < MIN_WEBTRANSPORT_IMPROVEMENT_PERCENT:
                failures.append("WebTransport p99 improvement must be at least 15 percent")
        for key in ("acknowledgedLosses", "orphanedUpdates"):
            value = require_nonnegative(candidate, key, failures)
            if value is not None and value != 0:
                failures.append(f"{key} must be zero")
        check_ceiling(candidate, "memoryGrowthPercentPerHour", MAX_MEMORY_GROWTH_PERCENT_PER_HOUR, failures)
        check_ceiling(candidate, "settledDescriptorGrowthPercent", MAX_SETTLED_GROWTH_PERCENT, failures)
        check_ceiling(candidate, "settledTaskGrowthPercent", MAX_SETTLED_GROWTH_PERCENT, failures)

    return {
        "accepted": not failures,
        "cadence": cadence,
        "failures": failures,
        "schemaVersion": 1,
    }


def require_object(value: dict[str, Any], key: str, failures: list[str]) -> dict[str, Any] | None:
    result = value.get(key)
    if not isinstance(result, dict):
        failures.append(f"{key} must be an object")
        return None
    return result


def require_string(value: dict[str, Any], key: str, failures: list[str]) -> str | None:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        failures.append(f"{key} must be a non-empty string")
        return None
    return result


def require_digest(value: dict[str, Any], key: str, failures: list[str]) -> str | None:
    result = require_string(value, key, failures)
    if result is not None and re.fullmatch(r"sha256:[0-9a-f]{64}", result) is None:
        failures.append(f"{key} must be a lowercase sha256 digest")
    return result


def require_positive(value: dict[str, Any], key: str, failures: list[str]) -> float | None:
    result = value.get(key)
    if not isinstance(result, (int, float)) or isinstance(result, bool) or result <= 0:
        failures.append(f"{key} must be a positive number")
        return None
    return float(result)


def require_nonnegative(value: dict[str, Any], key: str, failures: list[str]) -> float | None:
    result = value.get(key)
    if not isinstance(result, (int, float)) or isinstance(result, bool) or result < 0:
        failures.append(f"{key} must be a non-negative number")
        return None
    return float(result)


def check_regression(baseline: dict[str, Any], candidate: dict[str, Any], key: str, failures: list[str]) -> None:
    baseline_value = require_positive(baseline, key, failures)
    candidate_value = require_positive(candidate, key, failures)
    if baseline_value is not None and candidate_value is not None:
        regression = (candidate_value - baseline_value) * 100.0 / baseline_value
        if regression > MAX_REGRESSION_PERCENT:
            failures.append(f"{key} regression must not exceed 10 percent")


def check_ceiling(candidate: dict[str, Any], key: str, maximum: float, failures: list[str]) -> None:
    value = require_nonnegative(candidate, key, failures)
    if value is not None and value > maximum:
        failures.append(f"{key} must not exceed {maximum:g} percent")


if __name__ == "__main__":
    raise SystemExit(main())
