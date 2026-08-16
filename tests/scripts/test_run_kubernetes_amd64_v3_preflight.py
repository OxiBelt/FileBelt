#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Direct contracts for the bounded Kubernetes AMD64 v3 preflight."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "tests/scripts/run-kubernetes-amd64-v3-preflight.py"
IMAGE = "registry.example/filebelt-probe@sha256:" + "a" * 64
PASS_REPORT = {
    "schemaVersion": 1,
    "architecture": "x86_64",
    "cpuCount": 4,
    "baseline": "x86-64-v3",
    "supported": True,
    "missingFeatures": [],
}
PASS_LOG = [PASS_REPORT, {"probeExit": 0}]

FAKE_KUBECTL = """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

state_path = Path(os.environ["FAKE_KUBECTL_STATE"])
state = json.loads(state_path.read_text())
arguments = sys.argv[1:]
if arguments[:2] == ["get", "nodes"]:
    print(json.dumps({"items": state["nodes"]}))
elif arguments[:2] == ["create", "-f"]:
    state.setdefault("manifests", []).append(sys.stdin.read())
    if state.get("fail_create_at") == len(state["manifests"]):
        state_path.write_text(json.dumps(state))
        print("configured create failure", file=sys.stderr)
        sys.exit(7)
elif arguments[:2] == ["get", "pods"]:
    print(json.dumps({"items": state["pods"]}))
elif arguments[:2] == ["rollout", "status"]:
    if state.get("fail_rollout"):
        print("configured rollout failure", file=sys.stderr)
        sys.exit(8)
elif arguments[:1] == ["logs"]:
    for record in state["logs"][arguments[3]]:
        print(json.dumps(record))
elif arguments[:1] == ["delete"]:
    state.setdefault("deletes", []).append(arguments[1:3])
else:
    print("unexpected kubectl arguments: " + repr(arguments), file=sys.stderr)
    sys.exit(9)
state_path.write_text(json.dumps(state))
"""


def node(name: str) -> dict[str, object]:
    return {"metadata": {"name": name}, "spec": {}}


def pod(name: str, node_name: str) -> dict[str, object]:
    return {"metadata": {"name": name}, "spec": {"nodeName": node_name}}


class KubernetesAmd64V3PreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        directory = Path(self.temporary.name)
        self.state_path = directory / "state.json"
        self.output = directory / "evidence.json"
        self.kubectl = directory / "kubectl"
        self.kubectl.write_text(FAKE_KUBECTL, encoding="utf-8")
        self.kubectl.chmod(0o755)

    def invoke(self, state: dict[str, object], *, timeout: int = 1) -> subprocess.CompletedProcess[str]:
        self.state_path.write_text(json.dumps(state), encoding="utf-8")
        environment = os.environ | {"FAKE_KUBECTL_STATE": str(self.state_path)}
        return subprocess.run(
            [
                str(HELPER),
                "--namespace", "filebelt-system",
                "--run-id", "case-1",
                "--probe-image", IMAGE,
                "--output", str(self.output),
                "--timeout-seconds", str(timeout),
                "--kubectl", str(self.kubectl),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_reports_every_selected_node_and_cleans_up(self) -> None:
        state = {
            "nodes": [node("node-b"), node("node-a")],
            "pods": [pod("probe-b", "node-b"), pod("probe-a", "node-a")],
            "logs": {"probe-a": PASS_LOG, "probe-b": PASS_LOG},
        }
        result = self.invoke(state)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertTrue(evidence["passed"])
        self.assertEqual(evidence["selectedNodes"], ["node-a", "node-b"])
        self.assertEqual([item["node"] for item in evidence["results"]], ["node-a", "node-b"])
        observed = json.loads(self.state_path.read_text(encoding="utf-8"))
        config, daemon = [json.loads(manifest) for manifest in observed["manifests"]]
        self.assertEqual(config["kind"], "ConfigMap")
        self.assertEqual(daemon["kind"], "DaemonSet")
        pod_spec = daemon["spec"]["template"]["spec"]
        self.assertEqual(pod_spec["nodeSelector"], {"kubernetes.io/arch": "amd64"})
        self.assertNotIn("affinity", pod_spec)
        self.assertEqual(pod_spec["containers"][0]["image"], IMAGE)
        self.assertEqual(observed["deletes"], [
            ["daemonset", "filebelt-amd64-v3-preflight-case-1"],
            ["configmap", "filebelt-amd64-v3-preflight-case-1-script"],
        ])

    def test_fails_closed_when_a_selected_node_has_no_pod(self) -> None:
        state = {
            "nodes": [node("node-a"), node("node-b")],
            "pods": [pod("probe-a", "node-a")],
            "logs": {"probe-a": PASS_LOG},
        }
        result = self.invoke(state)
        self.assertEqual(result.returncode, 1)
        self.assertIn("did not start on every AMD64 node", result.stderr)
        self.assertFalse(self.output.exists())
        observed = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual(len(observed["deletes"]), 2)

    def test_writes_evidence_but_returns_unsupported_for_a_v2_node(self) -> None:
        unsupported = PASS_REPORT | {"supported": False, "missingFeatures": ["avx2"]}
        state = {
            "nodes": [node("node-a")],
            "pods": [pod("probe-a", "node-a")],
            "logs": {"probe-a": [unsupported, {"probeExit": 1}]},
        }
        result = self.invoke(state)
        self.assertEqual(result.returncode, 1)
        evidence = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertFalse(evidence["passed"])
        self.assertEqual(evidence["unsupportedNodes"], ["node-a"])

    def test_rejects_a_report_whose_process_exit_disagrees(self) -> None:
        state = {
            "nodes": [node("node-a")],
            "pods": [pod("probe-a", "node-a")],
            "logs": {"probe-a": [PASS_REPORT, {"probeExit": 1}]},
        }
        result = self.invoke(state)
        self.assertEqual(result.returncode, 1)
        self.assertIn("exit status disagrees", result.stderr)
        self.assertFalse(self.output.exists())

    def test_cleans_only_the_configmap_when_daemonset_creation_fails(self) -> None:
        state = {
            "nodes": [node("node-a")],
            "pods": [],
            "logs": {},
            "fail_create_at": 2,
        }
        result = self.invoke(state)
        self.assertEqual(result.returncode, 1)
        observed = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual(len(observed["manifests"]), 2)
        self.assertEqual(observed["deletes"], [
            ["configmap", "filebelt-amd64-v3-preflight-case-1-script"],
        ])


if __name__ == "__main__":
    unittest.main()
