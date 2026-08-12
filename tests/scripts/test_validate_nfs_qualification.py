#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tests/scripts/validate-nfs-qualification.py"
SPEC = importlib.util.spec_from_file_location("validate_nfs_qualification", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NfsQualificationEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.artifacts = Path(self.temporary.name)
        self.artifact_counter = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def artifact(self, label: str) -> dict[str, str]:
        self.artifact_counter += 1
        path = Path(f"evidence/{self.artifact_counter:02d}-{label}.json")
        target = self.artifacts / path
        target.parent.mkdir(parents=True, exist_ok=True)
        content = f"{label}\n".encode()
        target.write_bytes(content)
        return {"path": path.as_posix(), "sha256": hashlib.sha256(content).hexdigest()}

    def evidence(self) -> dict:
        revision = "a" * 40
        image_index = self.artifact("image-index")
        image_digest = f"sha256:{image_index['sha256']}"
        builds = []
        for platform, runner in MODULE.PLATFORMS.items():
            architecture = platform.split("/", 1)[1]
            builds.append({
                "platform": platform,
                "runnerArchitecture": runner,
                "native": True,
                "emulation": "none",
                "revision": revision,
                "imageDigest": "sha256:" + {
                    "amd64": "c",
                    "arm64": "d",
                    "riscv64": "e",
                }[architecture] * 64,
                "ganeshaPackage": "6.5-8",
                "fsalApi": "13.0",
                "configuredBuild": True,
                "abiProbePassed": True,
                "linkProbePassed": True,
                "callbacksQualified": True,
                "normalizedRebuildMatched": True,
                "qualificationLabel": "qualified",
                "undefinedFilebeltSymbols": [],
                "artifacts": {
                    key: self.artifact(f"{architecture}-{key}")
                    for key in (
                        "imageArchive",
                        "artifactContract",
                        "abiLog",
                        "linkLog",
                        "sbom",
                        "vulnerabilityReport",
                        "rebuildComparison",
                    )
                },
            })
        clients = []
        cases = MODULE.required_cases(ROOT, [])
        for distribution, architecture in sorted(MODULE.CLIENTS):
            clients.append({
                "distribution": distribution,
                "version": "10.1" if distribution == "rhel" else "current-pinned",
                "architecture": architecture,
                "runnerArchitecture": MODULE.PLATFORMS[f"linux/{architecture}"],
                "native": True,
                "emulation": "none",
                "rootfsDigest": "sha256:" + "f" * 64,
                "imageIndexDigest": image_digest,
                "securityFlavor": "krb5p",
                "runtimeAttestation": {
                    "bridgeHasKeytab": False,
                    "bridgeImageDigest": image_digest,
                    "bridgeRevision": revision,
                    "clientRootfsDigest": "sha256:" + "f" * 64,
                    "ganeshaHasKeytab": True,
                    "ganeshaImageDigest": image_digest,
                    "ganeshaRevision": revision,
                    "ipcCarriesSecrets": False,
                    "relayHasAuthoritySecrets": False,
                    "relayHasTailstate": False,
                    "relayHasTun": False,
                    "relayImageDigest": "sha256:" + "7" * 64,
                    "relayRevision": revision,
                    "tailscaledHasTailstate": True,
                    "tailscaledImageDigest": "sha256:" + "8" * 64,
                    "topologyGeneration": "1234567890abcdef",
                    "vfsClusterIP": "10.96.20.10",
                    "backendClusterIP": "10.96.20.11",
                    "tailstateClaim": "filebelt-nfs-tailstate",
                    "recoveryClaim": "filebelt-nfs-recovery",
                    "backendHasDnsEgress": False,
                    "backendHasHeadscaleEgress": False,
                    "samePinnedImage": True,
                },
                "cases": dict.fromkeys(cases, True),
                "cleanup": {
                    "complete": True,
                    "leftovers": [],
                    "resourcePrefix": (
                        f"filebelt-nfs-qualification-{distribution}-{architecture}"
                    ),
                    "log": self.artifact(f"{distribution}-{architecture}-cleanup"),
                },
                "secretIsolation": {
                    "keytabsExcluded": True,
                    "ticketsExcluded": True,
                    "privateKeysExcluded": True,
                },
                "log": self.artifact(f"{distribution}-{architecture}-client"),
            })
        return {
            "schemaVersion": 1,
            "qualified": True,
            "release": {
                "version": "1.2.3",
                "tag": "1.2.3",
                "revision": revision,
                "imageIndexDigest": image_digest,
                "imageIndex": image_index,
                "platformDigests": {
                    item["platform"]: item["imageDigest"] for item in builds
                },
                "signerFingerprint": "F4CED383110CA1847CE9E9174D41B82B06DFFDBC",
                "tagSignatureVerified": True,
                "tagVerification": self.artifact("tag-verification"),
                "provenance": self.artifact("provenance"),
            },
            "builds": builds,
            "runtimeImage": {
                "ganeshaImageDigest": image_digest,
                "bridgeImageDigest": image_digest,
                "ganeshaRevision": revision,
                "bridgeRevision": revision,
                "samePinnedImage": True,
                "ganeshaHasKeytab": True,
                "bridgeHasKeytab": False,
                "ipcCarriesSecrets": False,
                "relayImageDigest": "sha256:" + "7" * 64,
                "relayRevision": revision,
                "tailscaledImageDigest": "sha256:" + "8" * 64,
                "topologyGeneration": "1234567890abcdef",
                "vfsClusterIP": "10.96.20.10",
                "backendClusterIP": "10.96.20.11",
                "relayHasTailstate": False,
                "relayHasTun": False,
                "relayHasAuthoritySecrets": False,
                "tailscaledHasTailstate": True,
                "backendHasDnsEgress": False,
                "backendHasHeadscaleEgress": False,
                "tailstateClaim": "filebelt-nfs-tailstate",
                "recoveryClaim": "filebelt-nfs-recovery",
                "networkPolicyEvidence": [
                    {"cni": cni, "passed": True, "log": self.artifact(f"{cni}-network-policy")}
                    for cni in ("calico", "cilium")
                ],
            },
            "licensing": {
                "expression": "LGPL-3.0-or-later",
                "completeSourceArchive": self.artifact("complete-source"),
                "notices": self.artifact("notices"),
                "sourceOffer": self.artifact("source-offer"),
                "relinkingInstructions": self.artifact("relinking"),
                "sourceManifest": self.artifact("source-manifest"),
                "replacementInstructionsVerified": True,
            },
            "clients": clients,
        }

    def validate(self, evidence: dict) -> dict:
        return MODULE.validate(evidence, self.artifacts, ROOT)

    def test_accepts_only_complete_bound_evidence(self) -> None:
        result = self.validate(self.evidence())
        self.assertTrue(result["accepted"], result["failures"])

    def test_rejects_emulated_riscv_and_mixed_container_identity(self) -> None:
        evidence = self.evidence()
        riscv = next(item for item in evidence["builds"] if item["platform"] == "linux/riscv64")
        riscv["native"] = False
        riscv["emulation"] = "qemu-user"
        evidence["runtimeImage"]["bridgeImageDigest"] = "sha256:" + "9" * 64
        result = self.validate(evidence)
        self.assertFalse(result["accepted"])
        self.assertIn("builds[2] must be a native build without emulation", result["failures"])
        self.assertIn(
            "runtimeImage.bridgeImageDigest must equal release.imageIndexDigest",
            result["failures"],
        )

    def test_rejects_missing_negative_case_and_secret_named_artifact(self) -> None:
        evidence = self.evidence()
        del evidence["clients"][0]["cases"]["reject_auth_sys"]
        evidence["licensing"]["notices"]["path"] = "evidence/keytab/notices.json"
        result = self.validate(evidence)
        self.assertFalse(result["accepted"])
        self.assertTrue(
            any("reject_auth_sys" in failure for failure in result["failures"]),
            result["failures"],
        )
        self.assertIn("notices.path resembles secret material", result["failures"])

    def test_rejects_relay_secret_or_backend_dns_regression(self) -> None:
        evidence = self.evidence()
        evidence["runtimeImage"]["relayHasAuthoritySecrets"] = True
        evidence["runtimeImage"]["backendHasDnsEgress"] = True
        result = self.validate(evidence)
        self.assertFalse(result["accepted"])
        self.assertIn("runtimeImage.relayHasAuthoritySecrets must be false", result["failures"])
        self.assertIn("runtimeImage.backendHasDnsEgress must be false", result["failures"])

    def test_rejects_missing_live_cni_evidence(self) -> None:
        evidence = self.evidence()
        evidence["runtimeImage"]["networkPolicyEvidence"].pop()
        result = self.validate(evidence)
        self.assertFalse(result["accepted"])
        self.assertIn(
            "runtimeImage.networkPolicyEvidence must cover Calico and Cilium",
            result["failures"],
        )

    def test_rejects_checksum_mismatch_and_incomplete_cleanup(self) -> None:
        evidence = self.evidence()
        evidence["release"]["provenance"]["sha256"] = "0" * 64
        evidence["clients"][0]["cleanup"]["leftovers"] = ["namespace"]
        result = self.validate(evidence)
        self.assertFalse(result["accepted"])
        self.assertIn("provenance checksum mismatch", result["failures"])
        self.assertTrue(
            any("cleanup must be complete" in failure for failure in result["failures"])
        )

    def test_rejects_unbound_platform_and_secret_log_content(self) -> None:
        evidence = self.evidence()
        evidence["release"]["platformDigests"]["linux/amd64"] = "sha256:" + "9" * 64
        log = self.artifacts / evidence["clients"][0]["log"]["path"]
        content = b"-----BEGIN PRIVATE KEY-----\nforbidden\n"
        log.write_bytes(content)
        evidence["clients"][0]["log"]["sha256"] = hashlib.sha256(content).hexdigest()
        result = self.validate(evidence)
        self.assertFalse(result["accepted"])
        self.assertTrue(
            any("release.platformDigests" in failure for failure in result["failures"])
        )
        self.assertTrue(
            any("secret-shaped content" in failure for failure in result["failures"])
        )

    def test_rejects_symlinked_artifact(self) -> None:
        evidence = self.evidence()
        artifact = evidence["release"]["provenance"]
        path = self.artifacts / artifact["path"]
        target = self.artifacts / "evidence/provenance-target.json"
        content = b"provenance\n"
        target.write_bytes(content)
        path.unlink()
        path.symlink_to(target)
        artifact["sha256"] = hashlib.sha256(content).hexdigest()
        result = self.validate(evidence)
        self.assertFalse(result["accepted"])
        self.assertIn(
            "provenance.path must resolve to a regular file below artifact-root",
            result["failures"],
        )


if __name__ == "__main__":
    unittest.main()
