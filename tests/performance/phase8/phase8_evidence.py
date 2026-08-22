#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate executable, fail-closed Phase 8 qualification evidence."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCHEMA = "filebelt.phase8.qualification.v2"
CONFIGURATION_VERSION = 9
REQUIRED_ROLES = (
    "filebelt-api",
    "filebelt-worker-io",
    "filebelt-worker-maintenance",
    "filebelt-collaboration",
    "filebelt-media-controller",
    "filebelt-vfs",
    "filebelt-tools",
)
REQUIRED_FEATURES = ("nfs", "media", "webtransport")
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
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{7,64}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    result = validate(read_json(arguments.input))
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
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
        return {
            "accepted": False,
            "failures": ["evidence must be an object"],
            "schema": SCHEMA,
        }
    if evidence.get("schema") != SCHEMA:
        failures.append(f"schema must be {SCHEMA}")
    if evidence.get("configurationVersion") != CONFIGURATION_VERSION:
        failures.append(f"configurationVersion must be {CONFIGURATION_VERSION}")
    revision = require_string(evidence, "sourceRevision", failures)
    if revision is not None and REVISION.fullmatch(revision) is None:
        failures.append(
            "sourceRevision must be 7 through 64 lowercase hexadecimal characters"
        )
    require_digest(evidence, "hostFingerprint", failures)
    configuration = require_digest(evidence, "configurationDigest", failures)

    mode = evidence.get("mode")
    if mode not in {"qualification", "contract"}:
        failures.append("mode must be qualification or contract")
    elif mode == "contract":
        failures.append("contract-mode evidence is never release qualification")
    cadence = evidence.get("cadence")
    expected_duration = CADENCE_SECONDS.get(cadence)
    if expected_duration is None:
        failures.append("cadence must be change-smoke, nightly, weekly, or pre-release")
    elif evidence.get("durationSeconds") != expected_duration:
        failures.append(f"{cadence} duration must be exactly {expected_duration} seconds")
    observed_duration = require_positive(evidence, "observedDurationSeconds", failures)
    if (
        mode == "qualification"
        and expected_duration is not None
        and observed_duration is not None
        and observed_duration < expected_duration
    ):
        failures.append(
            f"observedDurationSeconds must cover the full {expected_duration}-second cadence"
        )

    roles = validate_result_set(
        evidence.get("roles"), "role", REQUIRED_ROLES, revision, failures
    )
    features = validate_result_set(
        evidence.get("features"), "feature", REQUIRED_FEATURES, revision, failures
    )

    if roles is not None and features is not None:
        passed_roles = all(item.get("status") == "passed" for item in roles.values())
        passed_features = all(
            item.get("status") == "passed" for item in features.values()
        )
        if passed_roles and passed_features:
            validate_performance(evidence, roles, features, configuration, failures)

    supplied_accepted = evidence.get("accepted")
    if not isinstance(supplied_accepted, bool):
        failures.append("accepted must be a boolean computed by the harness")
    computed_accepted = not failures
    if supplied_accepted is True and not computed_accepted:
        failures.append("accepted cannot be true when qualification checks failed")
    if supplied_accepted is False and computed_accepted:
        failures.append("accepted must be true when every qualification check passed")

    return {
        "accepted": not failures,
        "cadence": cadence,
        "failures": failures,
        "schema": SCHEMA,
    }


def validate_result_set(
    value: Any,
    identifier: str,
    required: tuple[str, ...],
    revision: str | None,
    failures: list[str],
) -> dict[str, dict[str, Any]] | None:
    if not isinstance(value, list):
        failures.append(f"{identifier}s must be an array")
        return None
    indexed: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(value):
        context = f"{identifier}s[{index}]"
        if not isinstance(item, dict):
            failures.append(f"{context} must be an object")
            continue
        name = item.get(identifier)
        if not isinstance(name, str) or name not in required:
            failures.append(f"{context}.{identifier} is not in the required catalog")
            continue
        if name in indexed:
            failures.append(f"duplicate {identifier} result: {name}")
            continue
        indexed[name] = item
        validate_result(item, context, revision, failures)
    missing = set(required) - set(indexed)
    extra = set(indexed) - set(required)
    if missing:
        failures.append(f"missing {identifier} results: {', '.join(sorted(missing))}")
    if extra:
        failures.append(f"unexpected {identifier} results: {', '.join(sorted(extra))}")
    return indexed


def validate_result(
    result: dict[str, Any], context: str, revision: str | None, failures: list[str]
) -> None:
    status = result.get("status")
    if status not in {"passed", "failed", "skipped"}:
        failures.append(f"{context}.status must be passed, failed, or skipped")
        return
    result_revision = require_string(result, "sourceRevision", failures, context)
    if revision is not None and result_revision != revision:
        failures.append(f"{context}.sourceRevision must match the top-level revision")
    require_string(result, "endpoint", failures, context)
    cleanup = result.get("cleanup")
    if not isinstance(cleanup, dict):
        failures.append(f"{context}.cleanup must be an object")
    else:
        cleanup_status = cleanup.get("status")
        if cleanup_status not in {"passed", "not_required"}:
            failures.append(f"{context}.cleanup.status must be passed or not_required")
        require_string(cleanup, "detail", failures, f"{context}.cleanup")

    if status == "skipped":
        require_string(result, "prerequisite", failures, context)
        failures.append(f"{context} is skipped and cannot qualify the release")
        for forbidden in (
            "successAssertion",
            "failureAssertion",
            "samplesMilliseconds",
        ):
            if forbidden in result:
                failures.append(f"{context}.{forbidden} is forbidden for a skipped result")
        return
    if status == "failed":
        require_string(result, "failure", failures, context)
        failures.append(f"{context} failed its executable qualification")
        return

    require_assertion(result, "successAssertion", context, failures)
    require_assertion(result, "failureAssertion", context, failures)
    samples = result.get("samplesMilliseconds")
    if (
        not isinstance(samples, list)
        or not samples
        or any(not is_positive_number(sample) for sample in samples)
    ):
        failures.append(
            f"{context}.samplesMilliseconds must be a nonempty positive-number array"
        )


def require_assertion(
    result: dict[str, Any], key: str, context: str, failures: list[str]
) -> None:
    assertion = result.get(key)
    if not isinstance(assertion, dict):
        failures.append(f"{context}.{key} must be an object")
        return
    require_string(assertion, "expected", failures, f"{context}.{key}")
    require_string(assertion, "observed", failures, f"{context}.{key}")
    if assertion.get("passed") is not True:
        failures.append(f"{context}.{key}.passed must be true")


def validate_performance(
    evidence: dict[str, Any],
    roles: dict[str, dict[str, Any]],
    features: dict[str, dict[str, Any]],
    configuration: str | None,
    failures: list[str],
) -> None:
    baseline = evidence.get("baseline")
    if not isinstance(baseline, dict):
        failures.append("baseline must be an object when every endpoint passed")
        return
    if baseline.get("hostFingerprint") != evidence.get("hostFingerprint"):
        failures.append("baseline hostFingerprint must match candidate hostFingerprint")
    if baseline.get("configurationDigest") != configuration:
        failures.append(
            "baseline configurationDigest must match candidate configurationDigest"
        )
    check_regression(baseline, features["nfs"], "nfsP99Milliseconds", failures)
    check_regression(baseline, features["media"], "mediaP99Milliseconds", failures)
    websocket = require_positive(baseline, "webSocketP99Milliseconds", failures)
    webtransport = require_positive(
        features["webtransport"], "p99Milliseconds", failures
    )
    if websocket is not None and webtransport is not None:
        improvement = (websocket - webtransport) * 100.0 / websocket
        if improvement < MIN_WEBTRANSPORT_IMPROVEMENT_PERCENT:
            failures.append("WebTransport p99 improvement must be at least 15 percent")
    if percentile(
        roles["filebelt-collaboration"].get("samplesMilliseconds"), 99
    ) is None:
        failures.append("collaboration samples cannot produce a p99")
    candidate = evidence.get("candidate")
    if not isinstance(candidate, dict):
        failures.append("candidate stability metrics must be an object")
        return
    for key in ("acknowledgedLosses", "orphanedUpdates"):
        value = require_nonnegative(candidate, key, failures)
        if value is not None and value != 0:
            failures.append(f"{key} must be zero")
    check_ceiling(
        candidate,
        "memoryGrowthPercentPerHour",
        MAX_MEMORY_GROWTH_PERCENT_PER_HOUR,
        failures,
    )
    check_ceiling(
        candidate,
        "settledDescriptorGrowthPercent",
        MAX_SETTLED_GROWTH_PERCENT,
        failures,
    )
    check_ceiling(
        candidate,
        "settledTaskGrowthPercent",
        MAX_SETTLED_GROWTH_PERCENT,
        failures,
    )


def percentile(value: Any, percent: int) -> float | None:
    if (
        not isinstance(value, list)
        or not value
        or any(not is_positive_number(item) for item in value)
    ):
        return None
    ordered = sorted(float(item) for item in value)
    index = max(0, (len(ordered) * percent + 99) // 100 - 1)
    return ordered[index]


def require_string(
    value: dict[str, Any],
    key: str,
    failures: list[str],
    context: str | None = None,
) -> str | None:
    result = value.get(key)
    label = f"{context}.{key}" if context else key
    if not isinstance(result, str) or not result:
        failures.append(f"{label} must be a non-empty string")
        return None
    return result


def require_digest(
    value: dict[str, Any], key: str, failures: list[str]
) -> str | None:
    result = require_string(value, key, failures)
    if result is not None and SHA256.fullmatch(result) is None:
        failures.append(f"{key} must be a lowercase sha256 digest")
    return result


def is_positive_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and value > 0
    )


def require_positive(
    value: dict[str, Any], key: str, failures: list[str]
) -> float | None:
    result = value.get(key)
    if not is_positive_number(result):
        failures.append(f"{key} must be a positive number")
        return None
    return float(result)


def require_nonnegative(
    value: dict[str, Any], key: str, failures: list[str]
) -> float | None:
    result = value.get(key)
    if (
        not isinstance(result, (int, float))
        or isinstance(result, bool)
        or result < 0
    ):
        failures.append(f"{key} must be a non-negative number")
        return None
    return float(result)


def check_regression(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    key: str,
    failures: list[str],
) -> None:
    baseline_value = require_positive(baseline, key, failures)
    candidate_value = require_positive(candidate, "p99Milliseconds", failures)
    if baseline_value is not None and candidate_value is not None:
        regression = (candidate_value - baseline_value) * 100.0 / baseline_value
        if regression > MAX_REGRESSION_PERCENT:
            failures.append(f"{key} regression must not exceed 10 percent")


def check_ceiling(
    candidate: dict[str, Any], key: str, maximum: float, failures: list[str]
) -> None:
    value = require_nonnegative(candidate, key, failures)
    if value is not None and value > maximum:
        failures.append(f"{key} must not exceed {maximum:g} percent")


if __name__ == "__main__":
    raise SystemExit(main())
