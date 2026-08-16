#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Run the FileBelt x86-64-v3 compatibility probe on every AMD64 cluster node."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "tests/scripts/check-amd64-v3-host.sh"
NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
RUN_ID = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,23}[a-z0-9])?$")
IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$")
MAX_LOG_BYTES = 4096
KNOWN_MISSING_FEATURES = {
    "cx16", "lahf_lm", "popcnt", "sse3", "ssse3", "sse4_1", "sse4_2", "avx", "avx2",
    "bmi1", "bmi2", "f16c", "fma", "lzcnt", "movbe", "xsave",
}


class PreflightError(RuntimeError):
    """The bounded cluster preflight cannot provide qualifying evidence."""


def command(kubectl: str, *arguments: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [kubectl, *arguments],
        input=input_text,
        check=False,
        capture_output=True,
        text=True,
    )


def checked(kubectl: str, *arguments: str, input_text: str | None = None) -> str:
    result = command(kubectl, *arguments, input_text=input_text)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().replace("\n", " ")[:240]
        raise PreflightError(f"kubectl {' '.join(arguments[:2])} failed: {detail or 'no detail'}")
    return result.stdout


def safe_name(value: str, description: str) -> str:
    if NAME.fullmatch(value) is None:
        raise PreflightError(f"{description} must be a DNS label")
    return value


def selected_nodes(kubectl: str) -> list[str]:
    document = json.loads(
        checked(kubectl, "get", "nodes", "-l", "kubernetes.io/arch=amd64", "-o", "json")
    )
    items = document.get("items") if isinstance(document, dict) else None
    if not isinstance(items, list):
        raise PreflightError("node list is malformed")
    names: list[str] = []
    for item in items:
        metadata = item.get("metadata") if isinstance(item, dict) else None
        name = metadata.get("name") if isinstance(metadata, dict) else None
        if not isinstance(name, str) or NAME.fullmatch(name) is None:
            raise PreflightError("selected node has an invalid name")
        spec = item.get("spec") if isinstance(item, dict) else None
        if isinstance(spec, dict) and spec.get("unschedulable") is True:
            raise PreflightError(f"selected AMD64 node is unschedulable: {name}")
        names.append(name)
    if not names:
        raise PreflightError("cluster has no schedulable AMD64 nodes")
    if len(set(names)) != len(names):
        raise PreflightError("node list contains duplicate names")
    return sorted(names)


def resources(namespace: str, run_id: str, image: str) -> tuple[str, str, str, str]:
    prefix = f"filebelt-amd64-v3-preflight-{run_id}"
    daemon_set = safe_name(prefix, "DaemonSet name")
    config_map = safe_name(f"{prefix}-script", "ConfigMap name")
    script = CHECKER.read_text(encoding="utf-8")
    common_labels = {
        "app.kubernetes.io/name": "filebelt-amd64-v3-preflight",
        "app.kubernetes.io/managed-by": "filebelt-preflight",
        "filebelt.dev/run-id": run_id,
    }
    config = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": config_map, "namespace": namespace, "labels": common_labels},
        "immutable": True,
        "data": {"check-amd64-v3-host.sh": script},
    }
    pod = {
        "automountServiceAccountToken": False,
        "nodeSelector": {"kubernetes.io/arch": "amd64"},
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "runAsGroup": 65534,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [
            {
                "name": "preflight",
                "image": image,
                "imagePullPolicy": "IfNotPresent",
                "command": ["/bin/bash", "-c"],
                "args": [
                    "set +e; /opt/filebelt/check-amd64-v3-host.sh --format json; "
                    "ProbeStatus=$?; printf '{\\\"probeExit\\\":%s}\\n' \"${ProbeStatus}\"; "
                    "exec sleep 3600"
                ],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                    "readOnlyRootFilesystem": True,
                },
                "resources": {
                    "requests": {"cpu": "10m", "memory": "16Mi"},
                    "limits": {"cpu": "100m", "memory": "64Mi"},
                },
                "volumeMounts": [
                    {"name": "preflight-script", "mountPath": "/opt/filebelt", "readOnly": True}
                ],
            }
        ],
        "volumes": [
            {
                "name": "preflight-script",
                "configMap": {"name": config_map, "defaultMode": 365},
            }
        ],
    }
    daemon = {
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {"name": daemon_set, "namespace": namespace, "labels": common_labels},
        "spec": {
            "selector": {"matchLabels": {"filebelt.dev/preflight": daemon_set}},
            "template": {
                "metadata": {"labels": {**common_labels, "filebelt.dev/preflight": daemon_set}},
                "spec": pod,
            },
        },
    }
    return daemon_set, config_map, json.dumps(config, sort_keys=True), json.dumps(daemon, sort_keys=True)


def pod_nodes(kubectl: str, namespace: str, daemon_set: str) -> dict[str, str]:
    document = json.loads(
        checked(
            kubectl,
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            f"filebelt.dev/preflight={daemon_set}",
            "-o",
            "json",
        )
    )
    items = document.get("items") if isinstance(document, dict) else None
    if not isinstance(items, list):
        raise PreflightError("preflight Pod list is malformed")
    result: dict[str, str] = {}
    for item in items:
        metadata = item.get("metadata") if isinstance(item, dict) else None
        spec = item.get("spec") if isinstance(item, dict) else None
        name = metadata.get("name") if isinstance(metadata, dict) else None
        node = spec.get("nodeName") if isinstance(spec, dict) else None
        if isinstance(name, str) and isinstance(node, str):
            if node in result:
                raise PreflightError(f"multiple preflight Pods are assigned to {node}")
            result[node] = name
    return result


def read_report(kubectl: str, namespace: str, pod: str) -> dict[str, Any]:
    output = checked(kubectl, "logs", "-n", namespace, pod, "-c", "preflight")
    if len(output.encode()) > MAX_LOG_BYTES:
        raise PreflightError(f"preflight log exceeds {MAX_LOG_BYTES} bytes for {pod}")
    records: list[dict[str, Any]] = []
    exit_records: list[int] = []
    for line in output.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("schemaVersion") == 1:
            records.append(value)
        if isinstance(value, dict) and set(value) == {"probeExit"} and isinstance(value["probeExit"], int):
            exit_records.append(value["probeExit"])
    if len(records) != 1:
        raise PreflightError(f"preflight log has no unique bounded report for {pod}")
    if len(exit_records) != 1:
        raise PreflightError(f"preflight log has no unique exit status for {pod}")
    report = records[0]
    expected = {"schemaVersion", "architecture", "cpuCount", "baseline", "supported", "missingFeatures"}
    if set(report) != expected or report.get("architecture") != "x86_64" or report.get("baseline") != "x86-64-v3":
        raise PreflightError(f"preflight report is malformed for {pod}")
    if not isinstance(report["cpuCount"], int) or report["cpuCount"] < 1:
        raise PreflightError(f"preflight CPU count is invalid for {pod}")
    if not isinstance(report["supported"], bool) or not isinstance(report["missingFeatures"], list):
        raise PreflightError(f"preflight support result is invalid for {pod}")
    if not all(isinstance(item, str) for item in report["missingFeatures"]):
        raise PreflightError(f"preflight missing features are invalid for {pod}")
    if report["missingFeatures"] != sorted(set(report["missingFeatures"])):
        raise PreflightError(f"preflight missing features are not sorted for {pod}")
    if not set(report["missingFeatures"]).issubset(KNOWN_MISSING_FEATURES):
        raise PreflightError(f"preflight missing features are unknown for {pod}")
    if report["supported"] != (not report["missingFeatures"]):
        raise PreflightError(f"preflight support result disagrees with missing features for {pod}")
    expected_exit = 0 if report["supported"] else 1
    if exit_records[0] != expected_exit:
        raise PreflightError(f"preflight exit status disagrees with the report for {pod}")
    return report


def cleanup(
    kubectl: str,
    namespace: str,
    daemon_set: str,
    config_map: str,
    *,
    daemon_set_created: bool,
    config_map_created: bool,
) -> list[str]:
    failures: list[str] = []
    resources_to_delete = []
    if daemon_set_created:
        resources_to_delete.append(("daemonset", daemon_set))
    if config_map_created:
        resources_to_delete.append(("configmap", config_map))
    for kind, name in resources_to_delete:
        result = command(
            kubectl,
            "delete",
            kind,
            name,
            "-n",
            namespace,
            "--ignore-not-found=true",
            "--wait=true",
        )
        if result.returncode != 0:
            failures.append(kind)
    return failures


def run(arguments: argparse.Namespace) -> dict[str, Any]:
    namespace = safe_name(arguments.namespace, "namespace")
    if RUN_ID.fullmatch(arguments.run_id) is None:
        raise PreflightError("run ID must be a lowercase DNS-label suffix of at most 25 characters")
    if IMAGE.fullmatch(arguments.probe_image) is None:
        raise PreflightError("probe image must be a lowercase immutable image reference with @sha256 digest")
    if not CHECKER.is_file():
        raise PreflightError("owned AMD64 v3 checker is missing")
    nodes = selected_nodes(arguments.kubectl)
    daemon_set, config_map, config_manifest, daemon_manifest = resources(
        namespace, arguments.run_id, arguments.probe_image
    )
    config_map_created = False
    daemon_set_created = False
    cleanup_failures: list[str] = []
    try:
        checked(arguments.kubectl, "create", "-f", "-", input_text=config_manifest)
        config_map_created = True
        checked(arguments.kubectl, "create", "-f", "-", input_text=daemon_manifest)
        daemon_set_created = True
        deadline = time.monotonic() + arguments.timeout_seconds
        assignments: dict[str, str] = {}
        while time.monotonic() < deadline:
            assignments = pod_nodes(arguments.kubectl, namespace, daemon_set)
            if set(assignments) == set(nodes):
                break
            time.sleep(0.2)
        if set(assignments) != set(nodes):
            missing = sorted(set(nodes) - set(assignments))
            raise PreflightError(f"preflight Pods did not start on every AMD64 node: {','.join(missing)}")
        remaining = max(1, int(deadline - time.monotonic()))
        checked(
            arguments.kubectl,
            "rollout",
            "status",
            f"daemonset/{daemon_set}",
            "-n",
            namespace,
            f"--timeout={remaining}s",
        )
        reports = []
        for node in nodes:
            report = read_report(arguments.kubectl, namespace, assignments[node])
            reports.append({"node": node, **report})
        unsupported = [item["node"] for item in reports if item["supported"] is not True]
        return {
            "schemaVersion": 1,
            "baseline": "x86-64-v3",
            "namespace": namespace,
            "runId": arguments.run_id,
            "probeImage": arguments.probe_image,
            "selectedNodes": nodes,
            "results": reports,
            "passed": not unsupported,
            "unsupportedNodes": unsupported,
        }
    finally:
        if config_map_created or daemon_set_created:
            cleanup_failures = cleanup(
                arguments.kubectl,
                namespace,
                daemon_set,
                config_map,
                daemon_set_created=daemon_set_created,
                config_map_created=config_map_created,
            )
        if cleanup_failures:
            raise PreflightError(f"preflight cleanup failed for: {','.join(cleanup_failures)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--probe-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--kubectl", default="kubectl")
    arguments = parser.parse_args()
    if not 1 <= arguments.timeout_seconds <= 600:
        parser.error("--timeout-seconds must be in 1..600")
    if arguments.output.exists():
        print("error: refusing to replace preflight output", file=sys.stderr)
        return 2
    try:
        result = run(arguments)
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    except (PreflightError, OSError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    if result["passed"] is not True:
        print("error: one or more AMD64 nodes do not support x86-64-v3", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
