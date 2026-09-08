#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate retained OxiBelt 0.9.2-beta.2 admission evidence offline."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import stat
import zipfile
from pathlib import Path
from typing import Any


ADMISSION_PATH = "supply-chain/oxibelt-admission-v3.json"
TRUSTED_ROOT_PATH = "supply-chain/attestations/sigstore/trusted-root-2026-08-16.jsonl"
TRUSTED_ROOT_SHA256 = "65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c"
MAX_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_SUBJECT_BYTES = 1024 * 1024
MAX_ADMISSION_BYTES = 256 * 1024
MAX_LOCAL_BINDING_BYTES = 1024 * 1024
MAX_ZIP_BYTES = 1024 * 1024
MAX_ZIP_MEMBER_BYTES = 256 * 1024
QUALIFICATION_MEMBER = "release-qualification.json"
VULNERABILITY_DECISION_MEMBER = "image-vulnerability-decision.json"
VULNERABILITY_DECISION_MARKDOWN_MEMBER = "image-vulnerability-decision.md"
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")

ROLE_IMAGES = {
    "standalone": "ghcr.io/oxibelt/oxibelt",
    "dataplane": "ghcr.io/oxibelt/oxibelt-dataplane",
    "dataplane-strict": "ghcr.io/oxibelt/oxibelt-dataplane-strict",
    "controller": "ghcr.io/oxibelt/oxibelt-gateway-controller",
    "tools": "ghcr.io/oxibelt/oxibelt-tools",
    "keysigner": "ghcr.io/oxibelt/oxibelt-keysigner",
}
ARTIFACT_ARCHITECTURES = {
    "amd64v2": ("linux", "amd64"),
    "amd64": ("linux", "amd64"),
    "amd64v4": ("linux", "amd64"),
    "arm64": ("linux", "arm64"),
    "riscv64": ("linux", "riscv64"),
}
INDEX_ARCHITECTURES = ("amd64", "arm64", "riscv64")
RUST_TARGETS = {
    "amd64": "x86_64-unknown-linux-musl",
    "arm64": "aarch64-unknown-linux-musl",
    "riscv64": "riscv64gc-unknown-linux-musl",
}
ADMITTED_VERSION = "0.9.2-beta.2"
ADMITTED_REF = f"refs/tags/{ADMITTED_VERSION}"
ADMITTED_REVISION = "ed19e61fa7ce49ac0218987ec269d4e9aad611a1"
ADMITTED_TAG_OBJECT_SHA = "f7ba50c9ec139f803654a479d7b88cd4083132f2"
ADMITTED_RELEASE_ID = 384084844
ADMITTED_INDEX_DIGEST = "sha256:6ecf55a7b63576883080d10fb3d17c957b4f48d95ad9ee561c9231c8baa407e8"
ADMITTED_PLATFORM_DIGESTS = {
    "amd64": "sha256:d9df633854cbe8fcc5dde7fde08ced529ce1fb49646cc84451c5fb9f5f8d9e72",
    "arm64": "sha256:30b4bb267b86c7b1025a707aa3d5060c57c684e0309e9d760b5656fb79d5328a",
    "riscv64": "sha256:08db6a84b5e2403beb620fbd4f5aa3c1208c7e0089bacd81896ca08e2d9853b7",
}
EVIDENCE_DIRECTORY = f"supply-chain/attestations/oxibelt/{ADMITTED_VERSION}"
RELEASE_VERIFIER_WORKFLOW_SHA = ADMITTED_REVISION
RELEASE_VERIFIER_RUN_ID = 34129080492
RELEASE_VERIFIER_RUN_ATTEMPT = 1
RELEASE_VERIFIER_JOB_ID = 101775338502
RELEASE_QUALIFICATION_ARTIFACT_ID = 10022634842
RELEASE_VULNERABILITY_ARTIFACT_ID = 10021119339


class AdmissionError(RuntimeError):
    """The retained admission record or evidence is invalid."""


def exact_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise AdmissionError(f"{context} must contain exactly {sorted(expected)}")
    return value


def text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise AdmissionError(f"{context} must be a non-empty string")
    return value


def sha256(value: Any, context: str) -> str:
    value = text(value, context)
    if SHA256_PATTERN.fullmatch(value) is None:
        raise AdmissionError(f"{context} must be a SHA-256 hex digest")
    return value


def digest(value: Any, context: str) -> str:
    value = text(value, context)
    if DIGEST_PATTERN.fullmatch(value) is None:
        raise AdmissionError(f"{context} must be a sha256 digest")
    return value


def commit(value: Any, context: str) -> str:
    value = text(value, context)
    if COMMIT_PATTERN.fullmatch(value) is None:
        raise AdmissionError(f"{context} must be a Git commit SHA")
    return value


def positive_integer(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AdmissionError(f"{context} must be a positive integer")
    return value


def repository_file(root: Path, value: Any, context: str) -> Path:
    relative = Path(text(value, context))
    if relative.is_absolute() or ".." in relative.parts:
        raise AdmissionError(f"{context} must be repository-relative")
    candidate = root / relative
    ancestor = root
    for component in relative.parts:
        ancestor /= component
        if ancestor.is_symlink():
            raise AdmissionError(f"{context} is missing or unsafe: {relative}")
    if not candidate.is_file():
        raise AdmissionError(f"{context} is missing or unsafe: {relative}")
    path = candidate.resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise AdmissionError(f"{context} escapes the repository") from error
    return path


def read_bounded(path: Path, maximum: int, context: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AdmissionError(f"{context} is missing or unsafe") from error
    with os.fdopen(descriptor, "rb", closefd=True) as file:
        before = os.fstat(file.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size < 1 or before.st_size > maximum:
            raise AdmissionError(f"{context} has an invalid size")
        encoded = bytearray()
        while len(encoded) < before.st_size:
            chunk = file.read(min(64 * 1024, before.st_size - len(encoded)))
            if not chunk:
                break
            encoded.extend(chunk)
        after = os.fstat(file.fileno())
    if after.st_size != before.st_size or len(encoded) != before.st_size:
        raise AdmissionError(f"{context} changed while it was read")
    return bytes(encoded)


def duplicate_free_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdmissionError("JSON contains duplicate object keys")
        result[key] = value
    return result


def load_json_bytes(encoded: bytes, context: str) -> Any:
    try:
        return json.loads(encoded, object_pairs_hook=duplicate_free_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdmissionError(f"{context} is not valid JSON") from error


def load_pinned_root(root: Path) -> Path:
    path = repository_file(root, TRUSTED_ROOT_PATH, "trusted root path")
    encoded = read_bounded(path, MAX_SUBJECT_BYTES, "trusted root")
    if hashlib.sha256(encoded).hexdigest() != TRUSTED_ROOT_SHA256:
        raise AdmissionError("trusted root does not match the verifier-pinned sha256")
    try:
        roots = [json.loads(line, object_pairs_hook=duplicate_free_object) for line in encoded.splitlines() if line]
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdmissionError("trusted root is not JSON lines") from error
    if not roots or not all(isinstance(root_entry, dict) for root_entry in roots):
        raise AdmissionError("trusted root contains no root objects")
    return path


def artifact_zip(
    root: Path,
    value: Any,
    expected_keys: set[str],
    expected_members: set[str],
    context: str,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    artifact = exact_keys(value, expected_keys, context)
    positive_integer(artifact["id"], f"{context} id")
    text(artifact["name"], f"{context} name")
    path = repository_file(root, artifact["path"], f"{context} path")
    encoded = read_bounded(path, MAX_ZIP_BYTES, context)
    if hashlib.sha256(encoded).hexdigest() != sha256(artifact["sha256"], f"{context} sha256"):
        raise AdmissionError(f"{context} sha256 does not match")
    try:
        with zipfile.ZipFile(io.BytesIO(encoded)) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(infos) != len(expected_members) or set(names) != expected_members or len(set(names)) != len(names):
                raise AdmissionError(f"{context} ZIP members are invalid")
            members: dict[str, bytes] = {}
            for info in infos:
                mode = info.external_attr >> 16
                if (
                    info.flag_bits & 1
                    or info.is_dir()
                    or info.filename.startswith("/")
                    or ".." in Path(info.filename).parts
                    or stat.S_ISLNK(mode)
                    or stat.S_ISCHR(mode)
                    or stat.S_ISBLK(mode)
                    or stat.S_ISFIFO(mode)
                    or stat.S_ISSOCK(mode)
                    or info.file_size < 1
                    or info.file_size > MAX_ZIP_MEMBER_BYTES
                    or info.compress_size < 1
                    or info.compress_size > MAX_ZIP_MEMBER_BYTES
                ):
                    raise AdmissionError(f"{context} ZIP contains an unsafe member")
                members[info.filename] = archive.read(info)
    except zipfile.BadZipFile as error:
        raise AdmissionError(f"{context} is not a ZIP archive") from error
    member_hashes = artifact["memberSha256s"]
    if not isinstance(member_hashes, dict) or set(member_hashes) != expected_members:
        raise AdmissionError(f"{context} member hashes are invalid")
    for member, member_hash in member_hashes.items():
        if hashlib.sha256(members[member]).hexdigest() != sha256(
            member_hash, f"{context} {member} sha256"
        ):
            raise AdmissionError(f"{context} member sha256 does not match")
    return artifact, members


def load_bundle(root: Path, entry: dict[str, Any]) -> dict[str, Any]:
    path = repository_file(root, entry["path"], "bundle path")
    encoded = read_bounded(path, MAX_BUNDLE_BYTES, "retained bundle")
    if hashlib.sha256(encoded).hexdigest() != sha256(entry["sha256"], "bundle sha256"):
        raise AdmissionError(f"retained bundle sha256 does not match: {path.relative_to(root)}")
    bundle = load_json_bytes(encoded, "retained bundle")
    exact_keys(bundle, {"mediaType", "verificationMaterial", "dsseEnvelope"}, "Sigstore bundle")
    envelope = exact_keys(bundle["dsseEnvelope"], {"payload", "payloadType", "signatures"}, "DSSE envelope")
    if envelope["payloadType"] != "application/vnd.in-toto+json":
        raise AdmissionError("DSSE payload type is invalid")
    try:
        statement = load_json_bytes(
            base64.b64decode(text(envelope["payload"], "DSSE payload"), validate=True),
            "DSSE payload",
        )
    except (ValueError, UnicodeDecodeError) as error:
        raise AdmissionError("DSSE payload is not canonical base64 JSON") from error
    return exact_keys(statement, {"_type", "subject", "predicateType", "predicate"}, "statement")


def validate_source(source: Any) -> dict[str, Any]:
    source = exact_keys(source, {"repository", "ref", "revision", "tagObjectSha", "releaseId"}, "admission source")
    if source["repository"] != "https://github.com/OxiBelt/OxiBelt" or source["ref"] != ADMITTED_REF:
        raise AdmissionError("OxiBelt admission source repository or ref is invalid")
    if commit(source["revision"], "admission source revision") != ADMITTED_REVISION:
        raise AdmissionError("OxiBelt admission source revision is invalid")
    if commit(source["tagObjectSha"], "admission source tag object") != ADMITTED_TAG_OBJECT_SHA:
        raise AdmissionError("OxiBelt admission source tag object is invalid")
    if positive_integer(source["releaseId"], "admission source release id") != ADMITTED_RELEASE_ID:
        raise AdmissionError("OxiBelt admission source release id is invalid")
    return source


def validate_image(value: Any) -> dict[str, Any]:
    image = exact_keys(value, {"name", "role", "version", "indexDigest", "platforms"}, "admission image")
    if image["name"] != ROLE_IMAGES["standalone"] or image["role"] != "standalone" or image["version"] != ADMITTED_VERSION:
        raise AdmissionError("OxiBelt admission image identity is invalid")
    if digest(image["indexDigest"], "admission index digest") != ADMITTED_INDEX_DIGEST:
        raise AdmissionError("OxiBelt admission index digest is invalid")
    platforms = image["platforms"]
    if not isinstance(platforms, list) or len(platforms) != 3:
        raise AdmissionError("OxiBelt admission platforms are invalid")
    expected = {
        "amd64": ("linux", "amd64", "x86-64-v3", ADMITTED_PLATFORM_DIGESTS["amd64"]),
        "arm64": ("linux", "arm64", None, ADMITTED_PLATFORM_DIGESTS["arm64"]),
        "riscv64": ("linux", "riscv64", None, ADMITTED_PLATFORM_DIGESTS["riscv64"]),
    }
    actual: dict[str, dict[str, Any]] = {}
    for platform in platforms:
        platform = exact_keys(platform, {"artifactArch", "os", "architecture", "targetCpu", "digest"}, "admission platform")
        arch = text(platform["artifactArch"], "admission platform artifact arch")
        if arch in actual:
            raise AdmissionError("OxiBelt admission platforms are duplicated")
        actual[arch] = platform
    if set(actual) != set(expected):
        raise AdmissionError("OxiBelt admission platform inventory is invalid")
    for arch, (os_name, architecture, target_cpu, expected_digest) in expected.items():
        platform = actual[arch]
        if (
            platform["os"] != os_name
            or platform["architecture"] != architecture
            or platform["targetCpu"] != target_cpu
            or digest(platform["digest"], f"admission {arch} digest") != expected_digest
        ):
            raise AdmissionError(f"OxiBelt admission {arch} platform is invalid")
    return image


def validate_workflow(value: Any, expected: dict[str, Any], context: str) -> dict[str, Any]:
    workflow = exact_keys(value, set(expected), context)
    for key, expected_value in expected.items():
        actual = workflow[key]
        if key in {"runId", "runAttempt", "jobId"}:
            positive_integer(actual, f"{context} {key}")
        elif key in {"headSha", "workflowSha"}:
            commit(actual, f"{context} {key}")
        elif not isinstance(actual, str):
            raise AdmissionError(f"{context} {key} is invalid")
        if expected_value is not None and actual != expected_value:
            raise AdmissionError(f"{context} {key} is invalid")
    return workflow


def validate_image_receipts(value: Any, version: str) -> dict[tuple[str, str], dict[str, Any]]:
    if not isinstance(value, list) or len(value) != 30:
        raise AdmissionError("release qualification image receipt inventory is invalid")
    receipts: dict[tuple[str, str], dict[str, Any]] = {}
    for receipt in value:
        receipt = exact_keys(receipt, {"role", "artifactArch", "image", "canonicalTag", "digest", "receiptSha256", "os", "architecture"}, "image rebuild receipt")
        role = text(receipt["role"], "image rebuild receipt role")
        artifact_arch = text(receipt["artifactArch"], "image rebuild receipt architecture")
        identity = (role, artifact_arch)
        if role not in ROLE_IMAGES or artifact_arch not in ARTIFACT_ARCHITECTURES or identity in receipts:
            raise AdmissionError("release qualification image receipt identity is invalid")
        os_name, architecture = ARTIFACT_ARCHITECTURES[artifact_arch]
        if receipt["image"] != ROLE_IMAGES[role] or receipt["canonicalTag"] != f"{ROLE_IMAGES[role]}:{version}-alpine-musl-{artifact_arch}" or receipt["os"] != os_name or receipt["architecture"] != architecture:
            raise AdmissionError("release qualification image receipt fields are invalid")
        digest(receipt["digest"], "image rebuild receipt digest")
        sha256(receipt["receiptSha256"], "image rebuild receipt sha256")
        receipts[identity] = receipt
    expected = {(role, arch) for role in ROLE_IMAGES for arch in ARTIFACT_ARCHITECTURES}
    if set(receipts) != expected:
        raise AdmissionError("release qualification image receipt inventory is incomplete")
    return receipts


def validate_chart_receipts(value: Any, source: dict[str, Any], verifier: dict[str, Any]) -> None:
    if not isinstance(value, list) or len(value) != 2:
        raise AdmissionError("release qualification chart receipt inventory is invalid")
    charts: set[str] = set()
    for receipt in value:
        receipt = exact_keys(receipt, {"schemaVersion", "outcome", "chart", "archiveSha256", "predicate", "receiptSha256", "source", "subject", "workflow"}, "chart rebuild receipt")
        if receipt["schemaVersion"] != 1 or receipt["outcome"] != "exact" or receipt["chart"] not in {"oxibelt", "oxibelt-gateway-controller"}:
            raise AdmissionError("chart rebuild receipt identity is invalid")
        charts.add(receipt["chart"])
        sha256(receipt["archiveSha256"], "chart rebuild archive sha256")
        sha256(receipt["receiptSha256"], "chart rebuild receipt sha256")
        predicate = exact_keys(receipt["predicate"], {"schemaVersion", "type", "sha256"}, "chart rebuild predicate")
        if predicate["schemaVersion"] != 3 or predicate["type"] != "https://oxibelt.dev/attestations/helm-chart-rebuild/v3":
            raise AdmissionError("chart rebuild predicate is invalid")
        sha256(predicate["sha256"], "chart rebuild predicate sha256")
        if receipt["source"] != {"repository": "OxiBelt/OxiBelt", "ref": source["ref"], "revision": source["revision"]}:
            raise AdmissionError("chart rebuild receipt source is invalid")
        subject = exact_keys(receipt["subject"], {"repository", "digest"}, "chart rebuild subject")
        if subject["repository"] != f"ghcr.io/oxibelt/charts/{receipt['chart']}":
            raise AdmissionError("chart rebuild subject repository is invalid")
        digest(subject["digest"], "chart rebuild subject digest")
        workflow = exact_keys(receipt["workflow"], {"repository", "path", "sha", "runId", "runAttempt"}, "chart rebuild workflow")
        expected_workflow = {"repository": "OxiBelt/OxiBelt", "path": verifier["workflowPath"], "sha": verifier["workflowSha"], "runId": verifier["runId"], "runAttempt": verifier["runAttempt"]}
        if workflow != expected_workflow:
            raise AdmissionError("chart rebuild workflow is invalid")
    if charts != {"oxibelt", "oxibelt-gateway-controller"}:
        raise AdmissionError("chart rebuild receipt inventory is incomplete")


def validate_manifests(value: Any, image: dict[str, Any], receipts: dict[tuple[str, str], dict[str, Any]]) -> None:
    if not isinstance(value, list) or len(value) != 12:
        raise AdmissionError("release qualification manifest inventory is invalid")
    manifests: dict[tuple[str, str], dict[str, Any]] = {}
    platform_digests = {platform["artifactArch"]: platform["digest"] for platform in image["platforms"]}
    for manifest in value:
        manifest = exact_keys(manifest, {"role", "image", "canonicalTag", "digest", "children"}, "qualified image manifest")
        role = text(manifest["role"], "qualified image manifest role")
        canonical_tag = text(manifest["canonicalTag"], "qualified image manifest tag")
        if role not in ROLE_IMAGES or manifest["image"] != ROLE_IMAGES[role]:
            raise AdmissionError("qualified image manifest role is invalid")
        expected_tags = {f"{ROLE_IMAGES[role]}:{image['version']}", f"{ROLE_IMAGES[role]}:{image['version']}-alpine-musl"}
        if canonical_tag not in expected_tags:
            raise AdmissionError("qualified image manifest tag is invalid")
        name = "release" if canonical_tag.endswith(f":{image['version']}") else "alpine"
        identity = (role, name)
        if identity in manifests:
            raise AdmissionError("qualified image manifests are duplicated")
        digest(manifest["digest"], "qualified image manifest digest")
        children = manifest["children"]
        if not isinstance(children, list) or len(children) != 3:
            raise AdmissionError("qualified image manifest children are invalid")
        actual_children: dict[str, dict[str, Any]] = {}
        for child in children:
            child = exact_keys(child, {"artifactArch", "digest", "os", "architecture", "variant", "mediaType", "size"}, "qualified manifest child")
            arch = text(child["artifactArch"], "qualified manifest child architecture")
            if arch not in INDEX_ARCHITECTURES or arch in actual_children:
                raise AdmissionError("qualified manifest child identity is invalid")
            if child["os"] != "linux" or child["architecture"] != arch or child["variant"] is not None:
                raise AdmissionError("qualified manifest child platform is invalid")
            if child["digest"] != receipts[(role, arch)]["digest"]:
                raise AdmissionError("qualified manifest child does not match its receipt")
            if role == "standalone" and child["digest"] != platform_digests[arch]:
                raise AdmissionError("standalone manifest child does not match admission")
            if child["mediaType"] not in {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"} or isinstance(child["size"], bool) or not isinstance(child["size"], int) or child["size"] < 1:
                raise AdmissionError("qualified manifest child media type or size is invalid")
            actual_children[arch] = child
        if set(actual_children) != set(INDEX_ARCHITECTURES):
            raise AdmissionError("qualified manifest child inventory is incomplete")
        manifests[identity] = manifest
    expected = {(role, name) for role in ROLE_IMAGES for name in {"release", "alpine"}}
    if set(manifests) != expected:
        raise AdmissionError("qualified image manifest inventory is incomplete")
    for role in ROLE_IMAGES:
        release, alpine = manifests[(role, "release")], manifests[(role, "alpine")]
        if release["digest"] != alpine["digest"] or release["children"] != alpine["children"]:
            raise AdmissionError("release and Alpine manifest bindings differ")
    if manifests[("standalone", "release")]["digest"] != image["indexDigest"]:
        raise AdmissionError("standalone manifest does not match admitted index")


def validate_beta_aliases(value: Any) -> None:
    if value != []:
        raise AdmissionError("beta release qualification must not contain stable aliases")


def validate_aggregate(aggregate: Any, source: dict[str, Any], image: dict[str, Any], producer: dict[str, Any], verifier: dict[str, Any]) -> None:
    aggregate = exact_keys(aggregate, {"schemaVersion", "repository", "releaseKind", "version", "ref", "tagObjectSha", "commit", "releaseId", "publishedAt", "producer", "kind", "verifier", "receipts", "manifests", "aliases"}, "release qualification aggregate")
    if aggregate["schemaVersion"] != 3 or aggregate["repository"] != "OxiBelt/OxiBelt" or aggregate["releaseKind"] != "beta" or aggregate["version"] != image["version"] or aggregate["ref"] != source["ref"] or aggregate["tagObjectSha"] != source["tagObjectSha"] or aggregate["commit"] != source["revision"] or aggregate["releaseId"] != source["releaseId"] or aggregate["kind"] != "release-qualification":
        raise AdmissionError("release qualification aggregate identity is invalid")
    text(aggregate["publishedAt"], "release qualification published at")
    if aggregate["producer"] != producer:
        raise AdmissionError("release qualification producer is invalid")
    aggregate_verifier = exact_keys(aggregate["verifier"], {"workflowPath", "workflowSha", "runId", "runAttempt", "event", "conclusion"}, "release qualification verifier")
    if any(aggregate_verifier[key] != verifier[key] for key in aggregate_verifier):
        raise AdmissionError("release qualification verifier is invalid")
    receipts = exact_keys(aggregate["receipts"], {"images", "charts"}, "release qualification receipts")
    image_receipts = validate_image_receipts(receipts["images"], image["version"])
    validate_chart_receipts(receipts["charts"], source, verifier)
    validate_manifests(aggregate["manifests"], image, image_receipts)
    validate_beta_aliases(aggregate["aliases"])


def validate_qualification(root: Path, record: dict[str, Any], source: dict[str, Any], image: dict[str, Any]) -> dict[str, Any]:
    qualification = exact_keys(record["qualification"], {"producer", "verifier", "artifact"}, "admission qualification")
    producer = validate_workflow(qualification["producer"], {"workflowPath": ".github/workflows/release.yml", "runId": 34124900919, "runAttempt": 1, "event": "release", "headSha": source["revision"], "conclusion": "success"}, "qualification producer")
    expected_verifier = {
        "workflowPath": ".github/workflows/verify-release-rebuild.yml",
        "workflowSha": RELEASE_VERIFIER_WORKFLOW_SHA,
        "runId": RELEASE_VERIFIER_RUN_ID,
        "runAttempt": RELEASE_VERIFIER_RUN_ATTEMPT,
        "jobId": RELEASE_VERIFIER_JOB_ID,
        "event": "workflow_run",
        "conclusion": "success",
    }
    verifier = validate_workflow(qualification["verifier"], expected_verifier, "qualification verifier")
    artifact, members = artifact_zip(root, qualification["artifact"], {"id", "name", "path", "sha256", "memberSha256s"}, {QUALIFICATION_MEMBER}, "release qualification artifact")
    if artifact["id"] != RELEASE_QUALIFICATION_ARTIFACT_ID or artifact["name"] != f"release-qualification-{source['revision']}" or artifact["path"] != f"{EVIDENCE_DIRECTORY}/release-qualification.zip":
        raise AdmissionError("release qualification artifact name is invalid")
    validate_aggregate(load_json_bytes(members[QUALIFICATION_MEMBER], "release qualification member"), source, image, producer, verifier)
    return qualification


def validate_vulnerability_decision(root: Path, record: dict[str, Any], source: dict[str, Any], qualification: dict[str, Any]) -> None:
    decision_record = exact_keys(record["vulnerabilityDecision"], {"artifact"}, "vulnerability decision")
    artifact, members = artifact_zip(root, decision_record["artifact"], {"id", "name", "path", "sha256", "memberSha256s", "producerRunId", "producerRunAttempt"}, {VULNERABILITY_DECISION_MEMBER, VULNERABILITY_DECISION_MARKDOWN_MEMBER}, "vulnerability decision artifact")
    positive_integer(artifact["producerRunId"], "vulnerability decision artifact producer run id")
    positive_integer(artifact["producerRunAttempt"], "vulnerability decision artifact producer run attempt")
    if artifact["id"] != RELEASE_VULNERABILITY_ARTIFACT_ID or artifact["path"] != f"{EVIDENCE_DIRECTORY}/release-vulnerability-decision.zip" or artifact["producerRunId"] != qualification["producer"]["runId"] or artifact["producerRunAttempt"] != qualification["producer"]["runAttempt"] or artifact["name"] != f"release-vulnerability-decision-{artifact['producerRunId']}-{artifact['producerRunAttempt']}":
        raise AdmissionError("vulnerability decision producer attempt is invalid")
    decision = exact_keys(load_json_bytes(members[VULNERABILITY_DECISION_MEMBER], "vulnerability decision member"), {"schemaVersion", "channel", "decision", "errors", "evaluatedOn", "findings", "policySha256", "revision", "run", "subjects"}, "vulnerability decision member")
    if decision["schemaVersion"] != 2 or decision["channel"] != "beta" or decision["decision"] != "allow" or decision["revision"] != source["revision"] or decision["errors"] != [] or decision["findings"] != []:
        raise AdmissionError("vulnerability decision identity is invalid")
    text(decision["evaluatedOn"], "vulnerability decision evaluated on")
    digest(decision["policySha256"], "vulnerability policy sha256")
    if exact_keys(decision["run"], {"id", "attempt"}, "vulnerability decision run") != {"id": str(artifact["producerRunId"]), "attempt": artifact["producerRunAttempt"]}:
        raise AdmissionError("vulnerability decision run is invalid")
    _qualification_artifact, qualification_members = artifact_zip(root, qualification["artifact"], {"id", "name", "path", "sha256", "memberSha256s"}, {QUALIFICATION_MEMBER}, "release qualification artifact")
    receipts = load_json_bytes(qualification_members[QUALIFICATION_MEMBER], "release qualification member")["receipts"]["images"]
    expected_digests = {(receipt["role"], receipt["artifactArch"]): receipt["digest"] for receipt in receipts}
    subjects = decision["subjects"]
    if not isinstance(subjects, list) or len(subjects) != 30:
        raise AdmissionError("vulnerability decision subject inventory is invalid")
    actual: set[tuple[str, str]] = set()
    for subject in subjects:
        subject = exact_keys(subject, {"allowed", "architecture", "blockingFindings", "errors", "evidenceAttempt", "exceptedFindings", "imageId", "manifestDigest", "reportSha256", "reportedFindings", "role"}, "vulnerability decision subject")
        identity = (text(subject["role"], "vulnerability decision subject role"), text(subject["architecture"], "vulnerability decision subject architecture"))
        if identity in actual or identity not in expected_digests or subject["allowed"] is not True or subject["blockingFindings"] != 0 or subject["exceptedFindings"] != 0 or subject["reportedFindings"] != 0 or subject["errors"] != [] or subject["evidenceAttempt"] != artifact["producerRunAttempt"] or subject["imageId"] != expected_digests[identity] or subject["manifestDigest"] != expected_digests[identity]:
            raise AdmissionError("vulnerability decision subject is not an unexcepted allow")
        digest(subject["reportSha256"], "vulnerability decision report sha256")
        actual.add(identity)
    if actual != set(expected_digests):
        raise AdmissionError("vulnerability decision subject inventory is incomplete")


def validate_statement(statement: dict[str, Any], entry: dict[str, Any], source: dict[str, Any], image: dict[str, Any], platform_digests: dict[str, str]) -> None:
    if statement["_type"] != "https://in-toto.io/Statement/v1" or statement["predicateType"] != "https://oxibelt.dev/attestations/rebuild/v1":
        raise AdmissionError("rebuild statement type is invalid")
    expected_digest = image["indexDigest"] if entry["kind"] == "index" else platform_digests[entry["artifactArch"]]
    if statement["subject"] != [{"name": image["name"], "digest": {"sha256": expected_digest.removeprefix("sha256:")}}]:
        raise AdmissionError("rebuild statement subject is invalid")
    predicate = statement["predicate"]
    expected_source = {"repository": source["repository"], "ref": source["ref"], "revision": source["revision"]}
    if entry["kind"] == "platform":
        expected_source |= {
            "tree": "5cd4c9572beb31a2611e28f812651c5b02a40671",
            "releaseOverlaySha256": "sha256:ecadc6cf4ca09bb76ecca7e426e4da71e8691ac5a22510a5a70cd2f51b3d89f0",
        }
    if not isinstance(predicate, dict) or predicate.get("kind") != entry["kind"] or predicate.get("source") != expected_source:
        raise AdmissionError("rebuild predicate kind or source is invalid")
    if entry["kind"] == "index":
        metadata = predicate.get("output", {}).get("indexMetadata")
        expected_children = [{"artifactArch": arch, "digest": platform_digests[arch], "os": "linux", "architecture": arch, "variant": None} for arch in INDEX_ARCHITECTURES]
        if not isinstance(metadata, dict) or metadata.get("role") != image["role"] or metadata.get("digest") != image["indexDigest"] or metadata.get("children") != expected_children:
            raise AdmissionError("index rebuild does not bind all admitted children")
        return
    arch = entry["artifactArch"]
    build = predicate.get("build")
    expected = {"role": image["role"], "artifactArch": arch, "platform": f"linux/{arch}", "dockerArchitecture": arch, "rustTarget": RUST_TARGETS[arch], "dockerTarget": image["role"]}
    if not isinstance(build, dict) or any(build.get(key) != value for key, value in expected.items()) or not isinstance(build.get("parameters"), dict):
        raise AdmissionError("platform rebuild fields are invalid")
    if arch == "amd64":
        if build.get("targetCpu") != "x86-64-v3" or build["parameters"].get("rust_target_cpu") != "x86-64-v3":
            raise AdmissionError("AMD64 rebuild does not bind x86-64-v3")
    elif build.get("targetCpu") is not None or build["parameters"].get("rust_target_cpu") is not None:
        raise AdmissionError("non-AMD64 rebuild declares an unsupported target CPU")


def validate_bundles(root: Path, record: dict[str, Any], source: dict[str, Any], image: dict[str, Any]) -> None:
    bundles = record["bundles"]
    if not isinstance(bundles, list) or len(bundles) != 4:
        raise AdmissionError("OxiBelt admission bundle inventory is invalid")
    platform_digests = {platform["artifactArch"]: platform["digest"] for platform in image["platforms"]}
    expected_entries = {("index", "index"), ("platform", "amd64"), ("platform", "arm64"), ("platform", "riscv64")}
    actual: set[tuple[str, str]] = set()
    for entry in bundles:
        entry = exact_keys(entry, {"kind", "artifactArch", "certificateIdentity", "path", "subjectPath", "sha256"}, "bundle entry")
        identity = (text(entry["kind"], "bundle kind"), text(entry["artifactArch"], "bundle artifact arch"))
        if identity in actual or identity not in expected_entries:
            raise AdmissionError("OxiBelt admission bundle identity is invalid")
        actual.add(identity)
        artifact_name = identity[1]
        if entry["path"] != f"{EVIDENCE_DIRECTORY}/{artifact_name}-rebuild.json" or entry["subjectPath"] != f"{EVIDENCE_DIRECTORY}/{artifact_name}-manifest.json":
            raise AdmissionError("OxiBelt admission bundle layout is invalid")
        expected_identity = f"https://github.com/OxiBelt/OxiBelt/.github/workflows/{'release.yml' if identity[0] == 'index' else 'release-image-arch.yml'}@{source['ref']}"
        if entry["certificateIdentity"] != expected_identity:
            raise AdmissionError("OxiBelt admission bundle signer policy is invalid")
        subject = read_bounded(repository_file(root, entry["subjectPath"], "bundle subject path"), MAX_SUBJECT_BYTES, "retained bundle subject")
        expected_digest = image["indexDigest"] if identity[0] == "index" else platform_digests[identity[1]]
        if hashlib.sha256(subject).hexdigest() != expected_digest.removeprefix("sha256:"):
            raise AdmissionError("retained bundle subject digest is invalid")
        validate_statement(load_bundle(root, entry), entry, source, image, platform_digests)
    if actual != expected_entries:
        raise AdmissionError("OxiBelt admission bundle inventory is incomplete")


def validate_local_bindings(root: Path, source: dict[str, Any], image: dict[str, Any]) -> None:
    try:
        dockerfile = read_bounded(
            repository_file(root, "ui/web/Dockerfile", "web Dockerfile"),
            MAX_LOCAL_BINDING_BYTES,
            "web Dockerfile",
        ).decode("utf-8")
    except UnicodeDecodeError as error:
        raise AdmissionError("web Dockerfile is not UTF-8") from error
    admitted_base = f"{image['name']}@{image['indexDigest']}"
    if dockerfile.splitlines().count(f"ARG OXIBELT_IMAGE={admitted_base}") != 1 or dockerfile.splitlines().count("FROM ${OXIBELT_IMAGE} AS filebelt-web") != 1:
        raise AdmissionError("web Dockerfile OxiBelt base does not match admission")
    for relative, context in (("devops/source/image-plan.ts", "image plan"), ("ui/web/OXIBELT_NOTICE.md", "OxiBelt notice")):
        try:
            content = read_bounded(
                repository_file(root, relative, context),
                MAX_LOCAL_BINDING_BYTES,
                context,
            ).decode("utf-8")
        except UnicodeDecodeError as error:
            raise AdmissionError(f"{context} is not UTF-8") from error
        if any(required not in content for required in (admitted_base, image["version"], source["revision"])):
            raise AdmissionError(f"{context} is not bound to the admitted OxiBelt base")


def verification_plan(root: Path, record: dict[str, Any], trusted_root: Path) -> dict[str, Any]:
    verification = record["verification"]
    source = record["source"]
    invocations = []
    for entry in sorted(record["bundles"], key=lambda bundle: (bundle["kind"], bundle["artifactArch"])):
        invocations.append(
            {
                "repository": verification["repository"],
                "predicateType": verification["predicateType"],
                "oidcIssuer": verification["oidcIssuer"],
                "sourceDigest": source["revision"],
                "sourceRef": source["ref"],
                "certificateIdentity": entry["certificateIdentity"],
                "subject": str(root / entry["subjectPath"]),
                "bundle": str(root / entry["path"]),
            }
        )
    return {"trustedRoot": str(trusted_root), "invocations": invocations}


def validate(
    root: Path,
    admission_path: Path,
    *,
    emit_verification_plan: bool = False,
) -> Path | dict[str, Any]:
    try:
        relative_admission_path = admission_path.relative_to(root).as_posix()
        record = load_json_bytes(
            read_bounded(
                repository_file(root, relative_admission_path, "OxiBelt admission record"),
                MAX_ADMISSION_BYTES,
                "OxiBelt admission record",
            ),
            "OxiBelt admission record",
        )
    except (OSError, ValueError) as error:
        raise AdmissionError("OxiBelt admission record is not readable") from error
    exact_keys(record, {"schemaVersion", "baseline", "source", "image", "verification", "qualification", "vulnerabilityDecision", "bundles"}, "admission record")
    if record["schemaVersion"] != 3 or record["baseline"] != "x86-64-v3":
        raise AdmissionError("OxiBelt admission schema or baseline is invalid")
    source = validate_source(record["source"])
    image = validate_image(record["image"])
    verification = exact_keys(record["verification"], {"repository", "predicateType", "oidcIssuer", "denySelfHostedRunners"}, "admission verification")
    if verification != {"repository": "OxiBelt/OxiBelt", "predicateType": "https://oxibelt.dev/attestations/rebuild/v1", "oidcIssuer": "https://token.actions.githubusercontent.com", "denySelfHostedRunners": True}:
        raise AdmissionError("OxiBelt admission signer policy is invalid")
    trusted_root = load_pinned_root(root)
    qualification = validate_qualification(root, record, source, image)
    validate_vulnerability_decision(root, record, source, qualification)
    validate_bundles(root, record, source, image)
    validate_local_bindings(root, source, image)
    if emit_verification_plan:
        return verification_plan(root, record, trusted_root)
    return trusted_root


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--print-trusted-root-path", action="store_true")
    output.add_argument("--print-verification-invocations", action="store_true")
    args = parser.parse_args()
    root = args.repo_root.resolve()
    try:
        result = validate(
            root,
            root / ADMISSION_PATH,
            emit_verification_plan=args.print_verification_invocations,
        )
    except AdmissionError as error:
        parser.error(str(error))
    if args.print_trusted_root_path:
        print(result)
    if args.print_verification_invocations:
        print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
