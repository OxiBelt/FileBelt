#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate the retained OxiBelt x86-64-v3 admission evidence offline."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any


class AdmissionError(RuntimeError):
    """The retained admission record or bundle is invalid."""


def exact_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise AdmissionError(f"{context} must contain exactly {sorted(expected)}")
    return value


def text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise AdmissionError(f"{context} must be a non-empty string")
    return value


def repository_file(root: Path, value: Any, context: str) -> Path:
    relative = Path(text(value, context))
    if relative.is_absolute() or ".." in relative.parts:
        raise AdmissionError(f"{context} must be repository-relative")
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise AdmissionError(f"{context} escapes the repository") from error
    if not path.is_file():
        raise AdmissionError(f"{context} is missing: {relative}")
    return path


def load_bundle(root: Path, entry: dict[str, Any]) -> dict[str, Any]:
    exact_keys(
        entry,
        {"kind", "certificateIdentity", "path", "subjectPath", "sha256"},
        "bundle entry",
    )
    path = repository_file(root, entry["path"], "bundle path")
    relative = path.relative_to(root)
    encoded = path.read_bytes()
    if not encoded or len(encoded) > 2 * 1024 * 1024:
        raise AdmissionError(f"retained bundle has an invalid size: {relative}")
    if hashlib.sha256(encoded).hexdigest() != text(entry["sha256"], "bundle sha256"):
        raise AdmissionError(f"retained bundle sha256 does not match: {relative}")
    try:
        bundle = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdmissionError(f"retained bundle is not one JSON object: {relative}") from error
    exact_keys(bundle, {"mediaType", "verificationMaterial", "dsseEnvelope"}, "Sigstore bundle")
    envelope = exact_keys(bundle["dsseEnvelope"], {"payload", "payloadType", "signatures"}, "DSSE envelope")
    if envelope["payloadType"] != "application/vnd.in-toto+json":
        raise AdmissionError("DSSE payload type is invalid")
    try:
        statement = json.loads(base64.b64decode(text(envelope["payload"], "DSSE payload"), validate=True))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdmissionError("DSSE payload is not canonical base64 JSON") from error
    return exact_keys(statement, {"_type", "subject", "predicateType", "predicate"}, "statement")


def validate_subject(root: Path, entry: dict[str, Any], record: dict[str, Any]) -> None:
    path = repository_file(root, entry["subjectPath"], "bundle subject path")
    encoded = path.read_bytes()
    if not encoded or len(encoded) > 1024 * 1024:
        raise AdmissionError("retained bundle subject has an invalid size")
    digest_key = "indexDigest" if entry["kind"] == "index" else "amd64Digest"
    expected = record["image"][digest_key].removeprefix("sha256:")
    if hashlib.sha256(encoded).hexdigest() != expected:
        raise AdmissionError(f"{entry['kind']} retained subject digest is invalid")


def validate_statement(
    statement: dict[str, Any], entry: dict[str, Any], record: dict[str, Any]
) -> None:
    source = record["source"]
    image = record["image"]
    verification = record["verification"]
    if statement["_type"] != "https://in-toto.io/Statement/v1":
        raise AdmissionError("statement type is invalid")
    if statement["predicateType"] != verification["predicateType"]:
        raise AdmissionError("statement predicate type is invalid")
    digest_key = "indexDigest" if entry["kind"] == "index" else "amd64Digest"
    digest = image[digest_key].removeprefix("sha256:")
    if statement["subject"] != [{"name": image["name"], "digest": {"sha256": digest}}]:
        raise AdmissionError(f"{entry['kind']} statement subject is invalid")
    predicate = statement["predicate"]
    if not isinstance(predicate, dict) or predicate.get("kind") != entry["kind"]:
        raise AdmissionError(f"{entry['kind']} rebuild predicate kind is invalid")
    predicate_source = predicate.get("source")
    if not isinstance(predicate_source, dict):
        raise AdmissionError("rebuild predicate source is missing")
    for key in ("repository", "ref", "revision"):
        if predicate_source.get(key) != source[key]:
            raise AdmissionError(f"rebuild predicate source {key} is invalid")
    if entry["kind"] == "index":
        metadata = predicate.get("output", {}).get("indexMetadata")
        if not isinstance(metadata, dict):
            raise AdmissionError("index metadata is missing")
        if metadata.get("role") != image["role"] or metadata.get("digest") != image["indexDigest"]:
            raise AdmissionError("index role or digest is invalid")
        amd64 = [child for child in metadata.get("children", []) if child.get("artifactArch") == "amd64"]
        expected = {
            "artifactArch": "amd64",
            "digest": image["amd64Digest"],
            "os": "linux",
            "architecture": "amd64",
            "variant": None,
        }
        if amd64 != [expected]:
            raise AdmissionError("index does not bind the admitted AMD64 child")
        return
    build = predicate.get("build")
    if not isinstance(build, dict):
        raise AdmissionError("platform build predicate is missing")
    expected_build = {
        "role": image["role"],
        "artifactArch": "amd64",
        "platform": "linux/amd64",
        "dockerArchitecture": "amd64",
        "rustTarget": "x86_64-unknown-linux-musl",
        "targetCpu": record["baseline"],
        "dockerTarget": image["role"],
    }
    for key, value in expected_build.items():
        if build.get(key) != value:
            raise AdmissionError(f"platform build {key} is invalid")
    parameters = build.get("parameters")
    if not isinstance(parameters, dict) or parameters.get("rust_target_cpu") != record["baseline"]:
        raise AdmissionError("platform build parameters do not bind the AMD64 baseline")


def validate(root: Path, admission_path: Path) -> None:
    try:
        record = json.loads(admission_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AdmissionError("OxiBelt admission record is not valid JSON") from error
    exact_keys(
        record,
        {"schemaVersion", "baseline", "source", "image", "verification", "trustedRoot", "bundles"},
        "admission record",
    )
    if record["schemaVersion"] != 1 or record["baseline"] != "x86-64-v3":
        raise AdmissionError("OxiBelt admission schema or baseline is invalid")
    exact_keys(record["source"], {"repository", "ref", "revision"}, "admission source")
    exact_keys(record["image"], {"name", "role", "indexDigest", "amd64Digest"}, "admission image")
    image = record["image"]
    if image["name"] != "ghcr.io/oxibelt/oxibelt" or image["role"] != "standalone":
        raise AdmissionError("OxiBelt admission image identity is invalid")
    for key in ("indexDigest", "amd64Digest"):
        if not isinstance(image[key], str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image[key]) is None:
            raise AdmissionError(f"OxiBelt admission {key} is invalid")
    exact_keys(
        record["verification"],
        {
            "admittedAt", "repository", "predicateType", "oidcIssuer",
            "denySelfHostedRunners",
        },
        "admission verification",
    )
    verification = record["verification"]
    if (
        verification["repository"] != "OxiBelt/OxiBelt"
        or verification["oidcIssuer"] != "https://token.actions.githubusercontent.com"
        or verification["denySelfHostedRunners"] is not True
    ):
        raise AdmissionError("OxiBelt admission signer policy is invalid")
    trusted_root = exact_keys(record["trustedRoot"], {"path", "sha256"}, "trusted root")
    trusted_root_path = repository_file(root, trusted_root["path"], "trusted root path")
    trusted_root_bytes = trusted_root_path.read_bytes()
    if not trusted_root_bytes or len(trusted_root_bytes) > 1024 * 1024:
        raise AdmissionError("trusted root has an invalid size")
    if hashlib.sha256(trusted_root_bytes).hexdigest() != text(trusted_root["sha256"], "trusted root sha256"):
        raise AdmissionError("trusted root sha256 does not match")
    try:
        roots = [json.loads(line) for line in trusted_root_bytes.splitlines() if line]
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdmissionError("trusted root is not JSON lines") from error
    if len(roots) < 1 or not all(isinstance(root_entry, dict) for root_entry in roots):
        raise AdmissionError("trusted root contains no root objects")

    dockerfile = repository_file(root, "ui/web/Dockerfile", "web Dockerfile").read_text(encoding="utf-8")
    admitted_base = f"{image['name']}@{image['indexDigest']}"
    if dockerfile.splitlines().count(f"ARG OXIBELT_IMAGE={admitted_base}") != 1:
        raise AdmissionError("web Dockerfile OxiBelt base does not match admission")
    if dockerfile.splitlines().count("FROM ${OXIBELT_IMAGE} AS filebelt-web") != 1:
        raise AdmissionError("web Dockerfile does not consume the admitted OxiBelt base")
    bundles = record["bundles"]
    if not isinstance(bundles, list) or [entry.get("kind") for entry in bundles if isinstance(entry, dict)] != ["index", "platform"]:
        raise AdmissionError("OxiBelt admission must contain index then platform bundles")
    expected_identities = {
        "index": "https://github.com/OxiBelt/OxiBelt/.github/workflows/release.yml@refs/tags/0.7.1-beta.2",
        "platform": "https://github.com/OxiBelt/OxiBelt/.github/workflows/release-image-arch.yml@refs/tags/0.7.1-beta.2",
    }
    for entry in bundles:
        if entry.get("certificateIdentity") != expected_identities.get(entry.get("kind")):
            raise AdmissionError(f"{entry.get('kind')} bundle signer policy is invalid")
        validate_subject(root, entry, record)
        validate_statement(load_bundle(root, entry), entry, record)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    try:
        validate(root, root / "supply-chain/oxibelt-admission-v1.json")
    except AdmissionError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
