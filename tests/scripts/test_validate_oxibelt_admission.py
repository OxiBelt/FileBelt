#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for retained OxiBelt v3 admission evidence."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).with_name("validate-oxibelt-admission.py")
SPEC = importlib.util.spec_from_file_location("validate_oxibelt_admission", SCRIPT)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class OxiBeltAdmissionTests(unittest.TestCase):
    def copy_static_admission_inputs(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        supply_chain = REPO_ROOT / "supply-chain"
        shutil.copytree(supply_chain / "attestations", root / "supply-chain/attestations")
        for relative in (
            "ui/web/Dockerfile",
            "ui/web/OXIBELT_NOTICE.md",
            "devops/source/image-plan.ts",
        ):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / relative, destination)
        return directory, root

    def test_repository_admission_is_valid(self) -> None:
        trusted_root = CHECKER.validate(REPO_ROOT, REPO_ROOT / CHECKER.ADMISSION_PATH)
        self.assertEqual(trusted_root, REPO_ROOT / CHECKER.TRUSTED_ROOT_PATH)

    def copy_admission(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        directory, root = self.copy_static_admission_inputs()
        admission = root / CHECKER.ADMISSION_PATH
        admission.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / CHECKER.ADMISSION_PATH, admission)
        return directory, root, admission

    @staticmethod
    def read_record(path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def write_record(path: Path, record: dict[str, Any]) -> None:
        path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")

    @staticmethod
    def artifact_path(root: Path, artifact: dict[str, Any]) -> Path:
        return root / artifact["path"]

    def rewrite_artifact(
        self,
        root: Path,
        artifact: dict[str, Any],
        members: dict[str, bytes],
    ) -> None:
        path = self.artifact_path(root, artifact)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload in members.items():
                archive.writestr(name, payload)
        artifact["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        artifact["memberSha256s"] = {
            name: hashlib.sha256(payload).hexdigest() for name, payload in members.items()
        }

    def artifact_members(self, root: Path, artifact: dict[str, Any]) -> dict[str, bytes]:
        with zipfile.ZipFile(self.artifact_path(root, artifact)) as archive:
            return {name: archive.read(name) for name in archive.namelist()}

    @staticmethod
    def update_artifact_sha(artifact: dict[str, Any], path: Path) -> None:
        artifact["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    def rewrite_bundle(
        self,
        root: Path,
        entry: dict[str, Any],
        mutate_statement: Any,
    ) -> None:
        path = root / entry["path"]
        bundle = json.loads(path.read_text(encoding="utf-8"))
        statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
        mutate_statement(statement)
        bundle["dsseEnvelope"]["payload"] = base64.b64encode(
            json.dumps(statement, separators=(",", ":")).encode()
        ).decode()
        path.write_text(json.dumps(bundle, separators=(",", ":")), encoding="utf-8")
        entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def mark_first_zip_member_encrypted(path: Path) -> None:
        encoded = bytearray(path.read_bytes())
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            position = encoded.find(signature)
            if position < 0:
                raise AssertionError(f"ZIP header {signature!r} is missing")
            flags = int.from_bytes(encoded[position + offset : position + offset + 2], "little")
            encoded[position + offset : position + offset + 2] = (flags | 1).to_bytes(2, "little")
        path.write_bytes(encoded)

    def test_synthetic_v3_record_is_valid(self) -> None:
        directory, root = self.copy_static_admission_inputs()
        self.addCleanup(directory.cleanup)
        evidence_directory = root / CHECKER.EVIDENCE_DIRECTORY
        admission = root / CHECKER.ADMISSION_PATH
        admission.parent.mkdir(parents=True, exist_ok=True)
        digest_number = 1

        def next_digest() -> str:
            nonlocal digest_number
            value = f"sha256:{digest_number:064x}"
            digest_number += 1
            return value

        source = {
            "repository": "https://github.com/OxiBelt/OxiBelt",
            "ref": CHECKER.ADMITTED_REF,
            "revision": CHECKER.ADMITTED_REVISION,
            "tagObjectSha": CHECKER.ADMITTED_TAG_OBJECT_SHA,
            "releaseId": CHECKER.ADMITTED_RELEASE_ID,
        }
        image = {
            "name": CHECKER.ROLE_IMAGES["standalone"],
            "role": "standalone",
            "version": CHECKER.ADMITTED_VERSION,
            "indexDigest": CHECKER.ADMITTED_INDEX_DIGEST,
            "platforms": [
                {"artifactArch": "amd64", "os": "linux", "architecture": "amd64", "targetCpu": "x86-64-v3", "digest": CHECKER.ADMITTED_PLATFORM_DIGESTS["amd64"]},
                {"artifactArch": "arm64", "os": "linux", "architecture": "arm64", "targetCpu": None, "digest": CHECKER.ADMITTED_PLATFORM_DIGESTS["arm64"]},
                {"artifactArch": "riscv64", "os": "linux", "architecture": "riscv64", "targetCpu": None, "digest": CHECKER.ADMITTED_PLATFORM_DIGESTS["riscv64"]},
            ],
        }
        producer = {
            "workflowPath": ".github/workflows/release.yml",
            "runId": 34124900919,
            "runAttempt": 1,
            "event": "release",
            "headSha": source["revision"],
            "conclusion": "success",
        }
        verifier = {
            "workflowPath": ".github/workflows/verify-release-rebuild.yml",
            "workflowSha": "1" * 40,
            "runId": 1,
            "runAttempt": 1,
            "jobId": 1,
            "event": "workflow_run",
            "conclusion": "success",
        }
        image_receipts = []
        for role, role_image in CHECKER.ROLE_IMAGES.items():
            for artifact_arch, (os_name, architecture) in CHECKER.ARTIFACT_ARCHITECTURES.items():
                digest = next_digest()
                if role == "standalone" and artifact_arch in {platform["artifactArch"] for platform in image["platforms"]}:
                    digest = next(platform["digest"] for platform in image["platforms"] if platform["artifactArch"] == artifact_arch)
                image_receipts.append({"role": role, "artifactArch": artifact_arch, "image": role_image, "canonicalTag": f"{role_image}:{image['version']}-alpine-musl-{artifact_arch}", "digest": digest, "receiptSha256": next_digest().removeprefix("sha256:"), "os": os_name, "architecture": architecture})
        receipt_digests = {(receipt["role"], receipt["artifactArch"]): receipt["digest"] for receipt in image_receipts}
        manifests = []
        for role, role_image in CHECKER.ROLE_IMAGES.items():
            children = [{"artifactArch": platform["artifactArch"], "digest": receipt_digests[(role, platform["artifactArch"])], "os": "linux", "architecture": platform["artifactArch"], "variant": None, "mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 1} for platform in image["platforms"]]
            manifest_digest = image["indexDigest"] if role == "standalone" else next_digest()
            for tag in (f"{role_image}:{image['version']}", f"{role_image}:{image['version']}-alpine-musl"):
                manifests.append({"role": role, "image": role_image, "canonicalTag": tag, "digest": manifest_digest, "children": children})
        charts = []
        for chart in ("oxibelt", "oxibelt-gateway-controller"):
            charts.append({"schemaVersion": 1, "outcome": "exact", "chart": chart, "archiveSha256": next_digest().removeprefix("sha256:"), "predicate": {"schemaVersion": 3, "type": "https://oxibelt.dev/attestations/helm-chart-rebuild/v3", "sha256": next_digest().removeprefix("sha256:")}, "receiptSha256": next_digest().removeprefix("sha256:"), "source": {"repository": "OxiBelt/OxiBelt", "ref": source["ref"], "revision": source["revision"]}, "subject": {"repository": f"ghcr.io/oxibelt/charts/{chart}", "digest": next_digest()}, "workflow": {"repository": "OxiBelt/OxiBelt", "path": verifier["workflowPath"], "sha": verifier["workflowSha"], "runId": verifier["runId"], "runAttempt": verifier["runAttempt"]}})
        aggregate = {"schemaVersion": 3, "repository": "OxiBelt/OxiBelt", "releaseKind": "beta", "version": image["version"], "ref": source["ref"], "tagObjectSha": source["tagObjectSha"], "commit": source["revision"], "releaseId": source["releaseId"], "publishedAt": "2026-01-01T00:00:00Z", "producer": producer, "kind": "release-qualification", "verifier": {key: verifier[key] for key in ("workflowPath", "workflowSha", "runId", "runAttempt", "event", "conclusion")}, "receipts": {"images": image_receipts, "charts": charts}, "manifests": manifests, "aliases": []}
        qualification_artifact = {"id": 1, "name": f"release-qualification-{source['revision']}", "path": f"{CHECKER.EVIDENCE_DIRECTORY}/release-qualification.zip", "sha256": "", "memberSha256s": {}}
        qualification_members = {CHECKER.QUALIFICATION_MEMBER: json.dumps(aggregate).encode()}
        self.rewrite_artifact(root, qualification_artifact, qualification_members)
        subjects = [{"role": receipt["role"], "architecture": receipt["artifactArch"], "evidenceAttempt": 1, "imageId": receipt["digest"], "manifestDigest": receipt["digest"], "reportSha256": next_digest(), "allowed": True, "blockingFindings": 0, "exceptedFindings": 0, "reportedFindings": 0, "errors": []} for receipt in image_receipts]
        vulnerability_artifact = {"id": 2, "name": "release-vulnerability-decision-34124900919-1", "path": f"{CHECKER.EVIDENCE_DIRECTORY}/release-vulnerability-decision.zip", "sha256": "", "memberSha256s": {}, "producerRunId": 34124900919, "producerRunAttempt": 1}
        vulnerability_members = {CHECKER.VULNERABILITY_DECISION_MEMBER: json.dumps({"schemaVersion": 2, "channel": "beta", "decision": "allow", "errors": [], "evaluatedOn": "2026-01-01T00:00:00Z", "findings": [], "policySha256": next_digest(), "revision": source["revision"], "run": {"id": "34124900919", "attempt": 1}, "subjects": subjects}).encode(), CHECKER.VULNERABILITY_DECISION_MARKDOWN_MEMBER: b"# Synthetic\n"}
        self.rewrite_artifact(root, vulnerability_artifact, vulnerability_members)
        bundles = []
        for kind, artifact_arch in (("index", "index"), ("platform", "amd64"), ("platform", "arm64"), ("platform", "riscv64")):
            path = f"{CHECKER.EVIDENCE_DIRECTORY}/{artifact_arch}-rebuild.json"
            bundles.append({"kind": kind, "artifactArch": artifact_arch, "certificateIdentity": f"https://github.com/OxiBelt/OxiBelt/.github/workflows/{'release.yml' if kind == 'index' else 'release-image-arch.yml'}@{source['ref']}", "path": path, "subjectPath": f"{CHECKER.EVIDENCE_DIRECTORY}/{artifact_arch}-manifest.json", "sha256": hashlib.sha256((root / path).read_bytes()).hexdigest()})
        record = {"schemaVersion": 3, "baseline": "x86-64-v3", "source": source, "image": image, "verification": {"repository": "OxiBelt/OxiBelt", "predicateType": "https://oxibelt.dev/attestations/rebuild/v1", "oidcIssuer": "https://token.actions.githubusercontent.com", "denySelfHostedRunners": True}, "qualification": {"producer": producer, "verifier": verifier, "artifact": qualification_artifact}, "vulnerabilityDecision": {"artifact": vulnerability_artifact}, "bundles": bundles}
        self.write_record(admission, record)
        with mock.patch.multiple(CHECKER, RELEASE_VERIFIER_WORKFLOW_SHA=verifier["workflowSha"], RELEASE_VERIFIER_RUN_ID=verifier["runId"], RELEASE_VERIFIER_RUN_ATTEMPT=verifier["runAttempt"], RELEASE_VERIFIER_JOB_ID=verifier["jobId"], RELEASE_QUALIFICATION_ARTIFACT_ID=qualification_artifact["id"], RELEASE_VULNERABILITY_ARTIFACT_ID=vulnerability_artifact["id"]):
            self.assertEqual(CHECKER.validate(root, admission), root / CHECKER.TRUSTED_ROOT_PATH)
            plan = CHECKER.validate(root, admission, emit_verification_plan=True)
        self.assertEqual(plan["trustedRoot"], str(root / CHECKER.TRUSTED_ROOT_PATH))
        self.assertEqual(len(plan["invocations"]), 4)
        self.assertEqual({invocation["subject"] for invocation in plan["invocations"]}, {str(root / bundle["subjectPath"]) for bundle in bundles})

    def test_rejects_unsafe_zip_modes_and_member_sizes(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        path = root / "evidence.zip"

        def artifact() -> dict[str, Any]:
            return {
                "id": 1,
                "name": "evidence",
                "path": "evidence.zip",
                "sha256": "",
                "memberSha256s": {CHECKER.QUALIFICATION_MEMBER: ""},
            }

        def write_member(payload: bytes, *, mode: int | None = None, compression: int = zipfile.ZIP_DEFLATED) -> dict[str, Any]:
            with zipfile.ZipFile(path, "w", compression=compression) as archive:
                info = zipfile.ZipInfo(CHECKER.QUALIFICATION_MEMBER)
                info.compress_type = compression
                if mode is not None:
                    info.external_attr = mode << 16
                archive.writestr(info, payload)
            value = artifact()
            value["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            value["memberSha256s"][CHECKER.QUALIFICATION_MEMBER] = hashlib.sha256(payload).hexdigest()
            return value

        for label, mode in (("symlink", stat.S_IFLNK | 0o777), ("character device", stat.S_IFCHR | 0o600)):
            with self.subTest(label=label):
                value = write_member(b"payload", mode=mode)
                with self.assertRaisesRegex(CHECKER.AdmissionError, "ZIP contains an unsafe member"):
                    CHECKER.artifact_zip(root, value, set(value), {CHECKER.QUALIFICATION_MEMBER}, "test artifact")
        for label, payload, compression in (
            ("uncompressed", b"x" * (CHECKER.MAX_ZIP_MEMBER_BYTES + 1), zipfile.ZIP_DEFLATED),
            ("compressed", os.urandom(CHECKER.MAX_ZIP_MEMBER_BYTES + 1), zipfile.ZIP_STORED),
        ):
            with self.subTest(label=label):
                value = write_member(payload, compression=compression)
                with self.assertRaisesRegex(CHECKER.AdmissionError, "ZIP contains an unsafe member"):
                    CHECKER.artifact_zip(root, value, set(value), {CHECKER.QUALIFICATION_MEMBER}, "test artifact")

    def test_rejects_duplicate_json_object_keys(self) -> None:
        with self.assertRaisesRegex(CHECKER.AdmissionError, "duplicate object keys"):
            CHECKER.load_json_bytes(b'{"key":1,"key":2}', "duplicate JSON")

    def test_rejects_changed_bundle(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        record = self.read_record(admission)
        bundle = root / record["bundles"][1]["path"]
        bundle.write_bytes(bundle.read_bytes() + b"\n")
        with self.assertRaisesRegex(CHECKER.AdmissionError, "bundle sha256 does not match"):
            CHECKER.validate(root, admission)

    def test_rejects_untrusted_signer_policy(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        record = self.read_record(admission)
        record["verification"]["denySelfHostedRunners"] = False
        self.write_record(admission, record)
        with self.assertRaisesRegex(CHECKER.AdmissionError, "signer policy"):
            CHECKER.validate(root, admission)

    def test_rejects_repository_replacement_of_pinned_trusted_root(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        trusted_root = root / CHECKER.TRUSTED_ROOT_PATH
        trusted_root.write_bytes(trusted_root.read_bytes() + b"\n")
        with self.assertRaisesRegex(CHECKER.AdmissionError, "verifier-pinned sha256"):
            CHECKER.validate(root, admission)

    def test_rejects_missing_pinned_trusted_root(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        (root / CHECKER.TRUSTED_ROOT_PATH).unlink()
        with self.assertRaisesRegex(CHECKER.AdmissionError, "trusted root path is missing or unsafe"):
            CHECKER.validate(root, admission)

    def test_rejects_symlinked_repository_evidence(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        record = self.read_record(admission)
        bundle = root / record["bundles"][0]["path"]
        duplicate = bundle.with_name("bundle-copy.json")
        shutil.copy2(bundle, duplicate)
        bundle.unlink()
        bundle.symlink_to(duplicate)
        with self.assertRaisesRegex(CHECKER.AdmissionError, "bundle path is missing or unsafe"):
            CHECKER.validate(root, admission)

    def test_rejects_admission_selected_trusted_root(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        record = self.read_record(admission)
        record["trustedRoot"] = {"path": "supply-chain/attestations/sigstore/attacker-root.jsonl"}
        self.write_record(admission, record)
        with self.assertRaisesRegex(CHECKER.AdmissionError, "admission record must contain exactly"):
            CHECKER.validate(root, admission)

    def test_rejects_legacy_schema(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        record = self.read_record(admission)
        record["schemaVersion"] = 2
        self.write_record(admission, record)
        with self.assertRaisesRegex(CHECKER.AdmissionError, "schema or baseline"):
            CHECKER.validate(root, admission)

    def test_rejects_fixed_source_and_workflow_metadata_drift(self) -> None:
        cases = (
            ("source ref", lambda record: record["source"].__setitem__("ref", "refs/tags/0.9.2"), "repository or ref"),
            ("source revision", lambda record: record["source"].__setitem__("revision", "0" * 40), "source revision"),
            ("tag object", lambda record: record["source"].__setitem__("tagObjectSha", "0" * 40), "tag object"),
            ("release id", lambda record: record["source"].__setitem__("releaseId", 1), "release id"),
            ("producer run", lambda record: record["qualification"]["producer"].__setitem__("runId", 1), "qualification producer runId"),
            ("producer attempt", lambda record: record["qualification"]["producer"].__setitem__("runAttempt", record["qualification"]["producer"]["runAttempt"] + 1), "qualification producer runAttempt"),
            ("verifier run", lambda record: record["qualification"]["verifier"].__setitem__("runId", record["qualification"]["verifier"]["runId"] + 1), "qualification verifier runId"),
            ("verifier attempt", lambda record: record["qualification"]["verifier"].__setitem__("runAttempt", record["qualification"]["verifier"]["runAttempt"] + 1), "qualification verifier runAttempt"),
            ("verifier job", lambda record: record["qualification"]["verifier"].__setitem__("jobId", record["qualification"]["verifier"]["jobId"] + 1), "qualification verifier jobId"),
            ("qualification artifact", lambda record: record["qualification"]["artifact"].__setitem__("id", record["qualification"]["artifact"]["id"] + 1), "release qualification artifact"),
            ("vulnerability artifact", lambda record: record["vulnerabilityDecision"]["artifact"].__setitem__("id", record["vulnerabilityDecision"]["artifact"]["id"] + 1), "vulnerability decision producer attempt"),
        )
        for label, mutate, error in cases:
            with self.subTest(label=label):
                directory, root, admission = self.copy_admission()
                self.addCleanup(directory.cleanup)
                record = self.read_record(admission)
                mutate(record)
                self.write_record(admission, record)
                with self.assertRaisesRegex(CHECKER.AdmissionError, error):
                    CHECKER.validate(root, admission)

    def test_rejects_web_base_digest_drift(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        record = self.read_record(admission)
        dockerfile = root / "ui/web/Dockerfile"
        dockerfile.write_text(
            dockerfile.read_text(encoding="utf-8").replace(
                record["image"]["indexDigest"], "sha256:" + "0" * 64
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(CHECKER.AdmissionError, "base does not match"):
            CHECKER.validate(root, admission)

    def test_rejects_image_plan_or_notice_drift(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        record = self.read_record(admission)
        for relative in ("devops/source/image-plan.ts", "ui/web/OXIBELT_NOTICE.md"):
            path = root / relative
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    record["source"]["revision"], "0" * 40
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CHECKER.AdmissionError, "not bound"):
                CHECKER.validate(root, admission)
            shutil.copy2(REPO_ROOT / relative, path)

    def test_rejects_qualification_archive_or_member_drift(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        record = self.read_record(admission)
        artifact = record["qualification"]["artifact"]
        path = self.artifact_path(root, artifact)
        path.write_bytes(path.read_bytes() + b"x")
        with self.assertRaisesRegex(CHECKER.AdmissionError, "artifact sha256 does not match"):
            CHECKER.validate(root, admission)

        shutil.copy2(REPO_ROOT / artifact["path"], path)
        members = self.artifact_members(root, artifact)
        aggregate = json.loads(members[CHECKER.QUALIFICATION_MEMBER])
        aggregate["aliases"] = [{"alias": "ghcr.io/oxibelt/oxibelt:latest"}]
        members[CHECKER.QUALIFICATION_MEMBER] = json.dumps(aggregate).encode()
        self.rewrite_artifact(root, artifact, members)
        self.write_record(admission, record)
        with self.assertRaisesRegex(CHECKER.AdmissionError, "must not contain stable aliases"):
            CHECKER.validate(root, admission)

    def test_rejects_unsafe_or_extra_qualification_zip_member(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        record = self.read_record(admission)
        artifact = record["qualification"]["artifact"]
        members = self.artifact_members(root, artifact)
        members["../unexpected.json"] = b"{}"
        self.rewrite_artifact(root, artifact, members)
        self.write_record(admission, record)
        with self.assertRaisesRegex(CHECKER.AdmissionError, "ZIP members are invalid"):
            CHECKER.validate(root, admission)

    def test_rejects_duplicate_or_encrypted_zip_members(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        record = self.read_record(admission)
        artifact = record["qualification"]["artifact"]
        path = self.artifact_path(root, artifact)
        members = self.artifact_members(root, artifact)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(CHECKER.QUALIFICATION_MEMBER, members[CHECKER.QUALIFICATION_MEMBER])
            archive.writestr(CHECKER.QUALIFICATION_MEMBER, members[CHECKER.QUALIFICATION_MEMBER])
        self.update_artifact_sha(artifact, path)
        self.write_record(admission, record)
        with self.assertRaisesRegex(CHECKER.AdmissionError, "ZIP members are invalid"):
            CHECKER.validate(root, admission)

        shutil.copy2(REPO_ROOT / artifact["path"], path)
        self.mark_first_zip_member_encrypted(path)
        self.update_artifact_sha(artifact, path)
        self.write_record(admission, record)
        with self.assertRaisesRegex(CHECKER.AdmissionError, "ZIP contains an unsafe member"):
            CHECKER.validate(root, admission)

    def test_rejects_vulnerability_decision_or_markdown_drift(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        record = self.read_record(admission)
        artifact = record["vulnerabilityDecision"]["artifact"]
        members = self.artifact_members(root, artifact)
        decision = json.loads(members[CHECKER.VULNERABILITY_DECISION_MEMBER])
        decision["findings"] = [{"id": "CVE-test"}]
        members[CHECKER.VULNERABILITY_DECISION_MEMBER] = json.dumps(decision).encode()
        self.rewrite_artifact(root, artifact, members)
        self.write_record(admission, record)
        with self.assertRaisesRegex(CHECKER.AdmissionError, "vulnerability decision identity"):
            CHECKER.validate(root, admission)

        members = self.artifact_members(root, artifact)
        members[CHECKER.VULNERABILITY_DECISION_MARKDOWN_MEMBER] += b"\nchanged"
        self.rewrite_artifact(root, artifact, members)
        artifact["memberSha256s"][CHECKER.VULNERABILITY_DECISION_MARKDOWN_MEMBER] = "0" * 64
        self.write_record(admission, record)
        with self.assertRaisesRegex(CHECKER.AdmissionError, "member sha256 does not match"):
            CHECKER.validate(root, admission)

    def test_rejects_missing_riscv_bundle_and_beta_waiver(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        record = self.read_record(admission)
        record["bundles"] = [
            entry for entry in record["bundles"] if entry["artifactArch"] != "riscv64"
        ]
        self.write_record(admission, record)
        with self.assertRaisesRegex(CHECKER.AdmissionError, "bundle inventory"):
            CHECKER.validate(root, admission)

        record = self.read_record(REPO_ROOT / CHECKER.ADMISSION_PATH)
        self.write_record(admission, record)
        artifact = record["qualification"]["artifact"]
        members = self.artifact_members(root, artifact)
        aggregate = json.loads(members[CHECKER.QUALIFICATION_MEMBER])
        aggregate["betaGateWaiver"] = {"policyId": "not-admitted"}
        members[CHECKER.QUALIFICATION_MEMBER] = json.dumps(aggregate).encode()
        self.rewrite_artifact(root, artifact, members)
        self.write_record(admission, record)
        with self.assertRaisesRegex(CHECKER.AdmissionError, "aggregate must contain exactly"):
            CHECKER.validate(root, admission)

    def test_rejects_aggregate_inventory_and_child_drift(self) -> None:
        cases = (
            ("image inventory", lambda aggregate: aggregate["receipts"]["images"].pop(), "image receipt inventory"),
            ("chart inventory", lambda aggregate: aggregate["receipts"]["charts"].pop(), "chart receipt inventory"),
            ("manifest inventory", lambda aggregate: aggregate["manifests"].pop(), "manifest inventory"),
            ("release kind", lambda aggregate: aggregate.__setitem__("releaseKind", "stable"), "aggregate identity"),
            ("child digest", lambda aggregate: aggregate["manifests"][0]["children"][0].__setitem__("digest", aggregate["manifests"][0]["children"][1]["digest"]), "manifest child does not match"),
        )
        for label, mutate, error in cases:
            with self.subTest(label=label):
                directory, root, admission = self.copy_admission()
                self.addCleanup(directory.cleanup)
                record = self.read_record(admission)
                artifact = record["qualification"]["artifact"]
                members = self.artifact_members(root, artifact)
                aggregate = json.loads(members[CHECKER.QUALIFICATION_MEMBER])
                mutate(aggregate)
                members[CHECKER.QUALIFICATION_MEMBER] = json.dumps(aggregate).encode()
                self.rewrite_artifact(root, artifact, members)
                self.write_record(admission, record)
                with self.assertRaisesRegex(CHECKER.AdmissionError, error):
                    CHECKER.validate(root, admission)

    def test_rejects_vulnerability_subject_drift(self) -> None:
        cases = (
            ("subject digest", lambda subject: subject.__setitem__("imageId", "sha256:" + "0" * 64)),
            ("subject exception", lambda subject: subject.__setitem__("exceptedFindings", 1)),
            ("subject attempt", lambda subject: subject.__setitem__("evidenceAttempt", subject["evidenceAttempt"] + 1)),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                directory, root, admission = self.copy_admission()
                self.addCleanup(directory.cleanup)
                record = self.read_record(admission)
                artifact = record["vulnerabilityDecision"]["artifact"]
                members = self.artifact_members(root, artifact)
                decision = json.loads(members[CHECKER.VULNERABILITY_DECISION_MEMBER])
                mutate(decision["subjects"][0])
                members[CHECKER.VULNERABILITY_DECISION_MEMBER] = json.dumps(decision).encode()
                self.rewrite_artifact(root, artifact, members)
                self.write_record(admission, record)
                with self.assertRaisesRegex(CHECKER.AdmissionError, "subject is not an unexcepted allow"):
                    CHECKER.validate(root, admission)

    def test_rejects_arm_subject_build_and_signer_drift(self) -> None:
        cases = (
            ("ARM64 subject", lambda root, record: (root / next(entry["subjectPath"] for entry in record["bundles"] if entry["artifactArch"] == "arm64")).write_bytes(b"changed"), "retained bundle subject digest"),
            ("AMD64 target CPU", lambda root, record: self.rewrite_bundle(root, next(entry for entry in record["bundles"] if entry["artifactArch"] == "amd64"), lambda statement: statement["predicate"]["build"].__setitem__("targetCpu", "x86-64-v2")), "AMD64 rebuild does not bind"),
            ("certificate identity", lambda root, record: record["bundles"][0].__setitem__("certificateIdentity", "https://example.invalid/forged"), "signer policy"),
        )
        for label, mutate, error in cases:
            with self.subTest(label=label):
                directory, root, admission = self.copy_admission()
                self.addCleanup(directory.cleanup)
                record = self.read_record(admission)
                mutate(root, record)
                self.write_record(admission, record)
                with self.assertRaisesRegex(CHECKER.AdmissionError, error):
                    CHECKER.validate(root, admission)

    def test_offline_verifier_rejects_a_forged_dsse_signature(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        record = self.read_record(admission)
        bundle = root / record["bundles"][0]["path"]
        parsed = json.loads(bundle.read_text(encoding="utf-8"))
        signature = parsed["dsseEnvelope"]["signatures"][0]["sig"]
        parsed["dsseEnvelope"]["signatures"][0]["sig"] = (
            "A" if signature[0] != "A" else "B"
        ) + signature[1:]
        bundle.write_text(json.dumps(parsed, separators=(",", ":")), encoding="utf-8")
        record["bundles"][0]["sha256"] = hashlib.sha256(bundle.read_bytes()).hexdigest()
        self.write_record(admission, record)
        result = subprocess.run(
            [str(REPO_ROOT / "tests/scripts/verify-oxibelt-admission.sh"), str(root)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_offline_verifier_passes_only_the_pinned_root_to_gh(self) -> None:
        directory, root, _admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        fake_bin = root / "fake-bin"
        fake_bin.mkdir()
        capture = root / "gh-arguments.txt"
        fake_gh = fake_bin / "gh"
        fake_gh.write_text(
            "#!/usr/bin/env sh\n"
            "set -eu\n"
            "printf 'CALL\\n' >> \"${GH_CAPTURE}\"\n"
            "printf '%s\\n' \"$@\" >> \"${GH_CAPTURE}\"\n",
            encoding="utf-8",
        )
        fake_gh.chmod(0o755)
        environment = os.environ.copy()
        environment["GH_CAPTURE"] = str(capture)
        environment["PATH"] = f"{fake_bin}:{environment.get('PATH', '')}"
        result = subprocess.run(
            [str(REPO_ROOT / "tests/scripts/verify-oxibelt-admission.sh"), str(root)],
            capture_output=True,
            text=True,
            check=False,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = capture.read_text(encoding="utf-8").splitlines()
        custom_roots = [
            arguments[index + 1]
            for index, argument in enumerate(arguments)
            if argument == "--custom-trusted-root"
        ]
        self.assertEqual(custom_roots, [str(root / CHECKER.TRUSTED_ROOT_PATH)] * 4)


if __name__ == "__main__":
    unittest.main()
