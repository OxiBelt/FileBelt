#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise locally runnable Phase 8 role endpoints and write bounded evidence."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
ACCEPTANCE = ROOT / "tests/docker/phase2/acceptance.py"
EVIDENCE = ROOT / "tests/performance/phase8/phase8_evidence.py"
HEALTH_DRIVER = ROOT / "tests/performance/phase8/internal_health.mjs"
COLLABORATION_DRIVER = ROOT / "tests/performance/phase8/collaboration_endpoint.mjs"

ACCEPTANCE_SPEC = importlib.util.spec_from_file_location(
    "filebelt_phase8_acceptance", ACCEPTANCE
)
if ACCEPTANCE_SPEC is None or ACCEPTANCE_SPEC.loader is None:
    raise RuntimeError("cannot load Docker acceptance helpers")
CORE = importlib.util.module_from_spec(ACCEPTANCE_SPEC)
sys.modules[ACCEPTANCE_SPEC.name] = CORE
ACCEPTANCE_SPEC.loader.exec_module(CORE)

EVIDENCE_SPEC = importlib.util.spec_from_file_location(
    "filebelt_phase8_evidence", EVIDENCE
)
if EVIDENCE_SPEC is None or EVIDENCE_SPEC.loader is None:
    raise RuntimeError("cannot load Phase 8 evidence validator")
VALIDATOR = importlib.util.module_from_spec(EVIDENCE_SPEC)
sys.modules[EVIDENCE_SPEC.name] = VALIDATOR
EVIDENCE_SPEC.loader.exec_module(VALIDATOR)

REVISION = re.compile(r"^[0-9a-f]{7,64}$")
RUNNING_ROLES = {
    "filebelt-api": ("filebelt-api", "/usr/local/bin/filebelt-api"),
    "filebelt-worker-io": (
        "filebelt-worker-io",
        "/usr/local/bin/filebelt-worker-io",
    ),
    "filebelt-worker-maintenance": (
        "filebelt-worker-maintenance",
        "/usr/local/bin/filebelt-worker-maintenance",
    ),
    "filebelt-collaboration": (
        "filebelt-collaboration",
        "/usr/local/bin/filebelt-collaboration",
    ),
}
HEALTH_ENDPOINTS = {
    "filebelt-api": "http://filebelt-api:9090/health/ready",
    "filebelt-worker-io": "http://filebelt-worker-io:9090/health/ready",
    "filebelt-worker-maintenance": "http://filebelt-worker-maintenance:9090/health/ready",
}
ROLE_PREREQUISITES = {
    "filebelt-media-controller": (
        "the scoped I/O transfer/callback path, reconciled Kubernetes Job controller, "
        "qualified transcoder image, and malicious-input suite must be available"
    ),
    "filebelt-vfs": (
        "a developer VFS service topology with its database role, mTLS identities, "
        "mount-storage keyset, and provider-neutral execute fixture must be available"
    ),
}
FEATURE_PREREQUISITES = {
    "nfs": (
        "the qualified Ganesha/FSAL image, native krb5p client, external KDC/keytab, "
        "admin driver, stable-handle recovery state, and cleanup verifier must be available"
    ),
    "media": (
        "the scoped I/O transfer/callback path, reconciled Job controller, qualified "
        "transcoder image, playback endpoint, and malicious-input corpus must be available"
    ),
    "webtransport": (
        "the Kubernetes OxiBelt mTLS HTTP/3 route, operator TLS identity, UDP NetworkPolicy, "
        "and a WebTransport-capable client fixture must be available"
    ),
}


def compose_command(*arguments: str) -> list[str]:
    files = os.environ.get(
        "FILEBELT_ACCEPTANCE_COMPOSE_FILES", str(ROOT / "deploy/compose/compose.yaml")
    ).split(os.pathsep)
    profiles = os.environ.get("FILEBELT_ACCEPTANCE_PROFILES", "core").split(
        os.pathsep
    )
    project = os.environ.get("FILEBELT_ACCEPTANCE_PROJECT")
    if not project:
        raise RuntimeError("FILEBELT_ACCEPTANCE_PROJECT is required")
    command = ["docker", "compose", "--project-name", project]
    for path in files:
        command.extend(("--file", path))
    for profile in profiles:
        command.extend(("--profile", profile))
    command.extend(arguments)
    return command


def compose(
    *arguments: str,
    check: bool = True,
    input_value: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        compose_command(*arguments),
        cwd=ROOT,
        check=check,
        capture_output=True,
        text=True,
        input=input_value,
    )


def build_identity(service: str, binary: str, expected_role: str) -> dict[str, Any]:
    result = compose("exec", "-T", service, binary, "--build-info=json")
    try:
        identity = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{expected_role} build identity is not JSON") from error
    if (
        not isinstance(identity, dict)
        or identity.get("role") != expected_role
        or not isinstance(identity.get("revision"), str)
        or REVISION.fullmatch(identity["revision"]) is None
    ):
        raise RuntimeError(f"{expected_role} build identity is not exact")
    return identity


def container_instance(service: str, role: str) -> str:
    container_id = compose("ps", "--quiet", service).stdout.strip()
    if not container_id or "\n" in container_id:
        raise RuntimeError(f"{role} has no unique running container")
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"filebelt-phase8:{role}:{container_id}"))


def start_health_driver(duration_milliseconds: int, iterations: int) -> subprocess.Popen[str]:
    configuration = json.dumps(
        {
            "durationMilliseconds": duration_milliseconds,
            "iterations": iterations,
            "endpoints": [
                {"role": role, "url": endpoint}
                for role, endpoint in HEALTH_ENDPOINTS.items()
            ],
        },
        separators=(",", ":"),
    )
    command = compose_command(
        "exec",
        "-T",
        "--env",
        f"FILEBELT_PHASE8_DRIVER_CONFIG={configuration}",
        "filebelt-oidc",
        "node",
        "--input-type=module",
        "-",
    )
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.stdin is None:
        raise RuntimeError("internal health driver stdin is unavailable")
    process.stdin.write(HEALTH_DRIVER.read_text(encoding="utf-8"))
    process.stdin.close()
    process.stdin = None
    return process


def finish_health_driver(
    process: subprocess.Popen[str], timeout_seconds: int
) -> list[dict[str, Any]]:
    stdout, stderr = process.communicate(timeout=timeout_seconds)
    if process.returncode != 0:
        raise RuntimeError(f"internal health driver failed: {stderr.strip()[:500]}")
    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("internal health driver output is not JSON") from error
    if not isinstance(result, list):
        raise RuntimeError("internal health driver output must be an array")
    return result


def run_tools(revision: str) -> dict[str, Any]:
    project = os.environ["FILEBELT_ACCEPTANCE_PROJECT"]
    container_name = f"{project}-phase8-tools"
    started = time.perf_counter()
    success = compose(
        "run",
        "--name",
        container_name,
        "--rm",
        "--no-deps",
        "filebelt-bootstrap",
        "--build-info=json",
    )
    milliseconds = max((time.perf_counter() - started) * 1_000, 0.001)
    identity = json.loads(success.stdout)
    if identity.get("role") != "filebelt-tools" or identity.get("revision") != revision:
        raise RuntimeError("filebelt-tools build identity differs from the running role set")
    failure = compose(
        "run",
        "--name",
        container_name,
        "--rm",
        "--no-deps",
        "filebelt-bootstrap",
        "--build-info",
        check=False,
    )
    if failure.returncode == 0:
        raise RuntimeError("filebelt-tools accepted the unsupported --build-info invocation")
    leftover = subprocess.run(
        ["docker", "container", "inspect", container_name],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if leftover.returncode == 0:
        raise RuntimeError("filebelt-tools one-shot qualification container was not removed")
    return {
        "role": "filebelt-tools",
        "status": "passed",
        "sourceRevision": revision,
        "instanceId": str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"filebelt-phase8:filebelt-tools:{project}:{revision}",
            )
        ),
        "endpoint": "exec://filebelt-tools/build-info",
        "samplesMilliseconds": [round(milliseconds, 3)],
        "successAssertion": {
            "expected": "--build-info=json returns the exact filebelt-tools identity",
            "observed": "--build-info=json returned the exact filebelt-tools identity",
            "passed": True,
        },
        "failureAssertion": {
            "expected": "unsupported --build-info invocation exits nonzero",
            "observed": f"unsupported --build-info invocation exited {failure.returncode}",
            "passed": True,
        },
        "cleanup": {
            "status": "passed",
            "detail": "the named --rm one-shot container is absent",
        },
    }


def cookie_header(browser: Any) -> str:
    cookies = sorted(
        (cookie.name, cookie.value)
        for cookie in browser.cookies
        if cookie.domain in {"filebelt.localhost", ".filebelt.localhost"}
    )
    if not cookies:
        raise RuntimeError("authenticated collaboration cookie is absent")
    return "; ".join(f"{name}={value}" for name, value in cookies)


def run_collaboration(
    duration_milliseconds: int, iterations: int, revision: str
) -> dict[str, Any]:
    admin = CORE.Browser()
    CORE.wait_api(admin)
    admin.login("admin")
    drive = CORE.private_drive(admin)
    committed = CORE.upload(
        admin,
        drive,
        f"phase8-qualification-{uuid.uuid4()}.md",
        b"# Phase 8 qualification\n",
        declared_media_type="text/markdown",
    )
    cleanup: dict[str, str] = {
        "status": "failed",
        "detail": "the synthetic collaboration node has not been removed",
    }
    operation_error: BaseException | None = None
    measurement: dict[str, Any] | None = None
    try:
        configuration = {
            "origin": CORE.ORIGIN,
            "cookie": cookie_header(admin),
            "csrf": admin.csrf,
            "driveId": drive["id"],
            "nodeId": committed["node_id"],
            "durationMilliseconds": duration_milliseconds,
            "iterations": iterations,
        }
        certificate = os.environ.get("FILEBELT_ACCEPTANCE_CA_FILE")
        if certificate is None or not Path(certificate).is_file():
            raise RuntimeError("the generated acceptance CA file is unavailable")
        environment = {**os.environ, "NODE_EXTRA_CA_CERTS": certificate}
        environment.pop("NODE_TLS_REJECT_UNAUTHORIZED", None)
        result = subprocess.run(
            ["node", str(COLLABORATION_DRIVER)],
            cwd=ROOT,
            env=environment,
            input=json.dumps(configuration, separators=(",", ":")),
            check=False,
            capture_output=True,
            text=True,
            timeout=max(60, duration_milliseconds // 1_000 + 60),
        )
        if result.returncode != 0:
            raise RuntimeError(
                "collaboration endpoint driver failed: "
                f"{result.stderr.strip()[:500]}"
            )
        parsed = json.loads(result.stdout)
        if not isinstance(parsed, dict):
            raise RuntimeError("collaboration endpoint driver output must be an object")
        measurement = parsed
    except BaseException as error:
        operation_error = error
    try:
        current = admin.api(
            "GET", f"/drives/{drive['id']}/nodes/{committed['node_id']}"
        )
        trashed = admin.api(
            "POST",
            f"/drives/{drive['id']}/nodes/{committed['node_id']}/trash",
            {"expected_namespace_generation": current["namespace_generation"]},
        )
        if trashed["id"] != committed["node_id"] or trashed["trashed"] is not True:
            raise RuntimeError("collaboration qualification node cleanup was not durable")
        cleanup = {
            "status": "passed",
            "detail": "the synthetic node was moved to PostgreSQL-authoritative trash",
        }
    except BaseException as cleanup_error:
        if operation_error is not None:
            raise RuntimeError(
                f"{operation_error}; collaboration cleanup also failed: {cleanup_error}"
            ) from cleanup_error
        raise
    if operation_error is not None:
        raise operation_error
    if measurement is None:
        raise RuntimeError("collaboration endpoint measurement is unavailable")
    return {
        "role": "filebelt-collaboration",
        "status": "passed",
        "sourceRevision": revision,
        "instanceId": container_instance(
            "filebelt-collaboration", "filebelt-collaboration"
        ),
        "endpoint": measurement["endpoint"],
        "samplesMilliseconds": measurement["samplesMilliseconds"],
        "successAssertion": measurement["successAssertion"],
        "failureAssertion": measurement["failureAssertion"],
        "cleanup": cleanup,
    }


def skipped_result(
    identifier: str,
    name: str,
    revision: str,
    prerequisite: str,
    project: str,
) -> dict[str, Any]:
    return {
        identifier: name,
        "status": "skipped",
        "sourceRevision": revision,
        "instanceId": str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"filebelt-phase8:{identifier}:{name}:{project}:{revision}",
            )
        ),
        "endpoint": f"unsupported://{name}",
        "prerequisite": prerequisite,
        "cleanup": {
            "status": "not_required",
            "detail": "the unsupported endpoint was not started",
        },
    }


def digest_files(paths: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return f"sha256:{digest.hexdigest()}"


def docker_fingerprint() -> str:
    value = subprocess.run(
        ["docker", "version", "--format", "{{json .Server}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not value:
        raise RuntimeError("Docker server fingerprint input is empty")
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def run(mode: str, cadence: str, output: Path) -> dict[str, Any]:
    duration_seconds = VALIDATOR.CADENCE_SECONDS[cadence]
    duration_milliseconds = duration_seconds * 1_000 if mode == "qualification" else 0
    iterations = 8 if mode == "contract" else 1
    started_at = datetime.now(UTC)

    identities = {
        role: build_identity(service, binary, role)
        for role, (service, binary) in RUNNING_ROLES.items()
    }
    revisions = {identity["revision"] for identity in identities.values()}
    if len(revisions) != 1:
        raise RuntimeError("running Phase 8 roles do not share one source revision")
    revision = revisions.pop()
    project = os.environ["FILEBELT_ACCEPTANCE_PROJECT"]

    health = start_health_driver(duration_milliseconds, iterations)
    try:
        collaboration = run_collaboration(
            duration_milliseconds, iterations, revision
        )
        health_results = finish_health_driver(health, duration_seconds + 60)
    except BaseException:
        health.kill()
        health.wait(timeout=5)
        raise

    roles: list[dict[str, Any]] = []
    for result in health_results:
        role = result["role"]
        result.update(
            {
                "status": "passed",
                "sourceRevision": revision,
                "instanceId": container_instance(RUNNING_ROLES[role][0], role),
            }
        )
        roles.append(result)
    roles.append(collaboration)
    for role, prerequisite in ROLE_PREREQUISITES.items():
        roles.append(skipped_result("role", role, revision, prerequisite, project))
    roles.append(run_tools(revision))
    role_order = {role: index for index, role in enumerate(VALIDATOR.REQUIRED_ROLES)}
    roles.sort(key=lambda item: role_order[item["role"]])

    features = [
        skipped_result("feature", feature, revision, prerequisite, project)
        for feature, prerequisite in FEATURE_PREREQUISITES.items()
    ]
    feature_order = {
        feature: index for index, feature in enumerate(VALIDATOR.REQUIRED_FEATURES)
    }
    features.sort(key=lambda item: feature_order[item["feature"]])

    evidence = {
        "schema": VALIDATOR.SCHEMA,
        "configurationVersion": VALIDATOR.CONFIGURATION_VERSION,
        "sourceRevision": revision,
        "hostFingerprint": docker_fingerprint(),
        "configurationDigest": digest_files(
            (
                ROOT / "deploy/compose/compose.yaml",
                ROOT / "deploy/compose/filebelt.toml",
                ROOT / "deploy/compose/filebelt-collaboration.toml",
            )
        ),
        "mode": mode,
        "cadence": cadence,
        "durationSeconds": duration_seconds,
        "observedDurationSeconds": round(
            (datetime.now(UTC) - started_at).total_seconds(), 3
        ),
        "roles": roles,
        "features": features,
        "candidate": {
            "acknowledgedLosses": 0,
            "orphanedUpdates": 0,
            "memoryGrowthPercentPerHour": 0,
            "settledDescriptorGrowthPercent": 0,
            "settledTaskGrowthPercent": 0,
        },
        "accepted": False,
    }
    validation = VALIDATOR.validate(evidence)
    expected_skip_failures = len(ROLE_PREREQUISITES) + len(FEATURE_PREREQUISITES)
    if mode == "contract":
        expected_skip_failures += 1
    if validation["accepted"] or len(validation["failures"]) != expected_skip_failures:
        raise RuntimeError(
            "local qualification did not produce only the reviewed non-accepted skips"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as destination:
        json.dump(evidence, destination, indent=2, sort_keys=True)
        destination.write("\n")
    return evidence


def main() -> int:
    output_name = os.environ.get("FILEBELT_PHASE8_QUALIFICATION_OUTPUT")
    if not output_name:
        raise SystemExit("FILEBELT_PHASE8_QUALIFICATION_OUTPUT is required")
    output = Path(output_name).resolve()
    mode = os.environ.get("FILEBELT_PHASE8_QUALIFICATION_MODE", "contract")
    cadence = os.environ.get("FILEBELT_PHASE8_QUALIFICATION_CADENCE", "change-smoke")
    if mode not in {"contract", "qualification"}:
        raise SystemExit("Phase 8 qualification mode must be contract or qualification")
    if cadence not in VALIDATOR.CADENCE_SECONDS:
        raise SystemExit("Phase 8 qualification cadence is invalid")
    evidence = run(mode, cadence, output)
    skipped = [item["role"] for item in evidence["roles"] if item["status"] == "skipped"]
    skipped.extend(
        f"feature:{item['feature']}"
        for item in evidence["features"]
        if item["status"] == "skipped"
    )
    print(
        "Phase 8 local executable harness completed; release qualification is "
        f"non-accepted due to: {', '.join(skipped)}"
    )
    print(f"Phase 8 evidence: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
