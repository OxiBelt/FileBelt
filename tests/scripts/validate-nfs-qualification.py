#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate complete, immutable NFS release qualification evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


PLATFORMS = {
    "linux/amd64": "x86_64",
    "linux/arm64": "aarch64",
    "linux/riscv64": "riscv64",
}
CLIENTS = {
    (distribution, architecture)
    for distribution in ("ubuntu", "debian", "rhel")
    for architecture in ("amd64", "arm64")
}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}")
SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
)
FINGERPRINT = re.compile(r"[0-9A-F]{40}")
RESOURCE_PREFIX = re.compile(r"filebelt-nfs-qualification-[a-z0-9][a-z0-9-]{5,62}")
SECRET_PATH_PARTS = {
    "keytab",
    "krb5cc",
    "private-key",
    "private_key",
    "tls.key",
    "cookie",
    "credential",
    "secret",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    arguments = parser.parse_args()
    result = validate(
        read_json(arguments.input),
        arguments.artifact_root,
        arguments.repository_root,
    )
    verify_current_release_tag(
        read_json(arguments.input),
        arguments.repository_root,
        result["failures"],
    )
    result["accepted"] = not result["failures"]
    for failure in result["failures"]:
        print(f"NFS qualification: {failure}")
    if not result["accepted"]:
        return 1
    print("NFS release qualification evidence accepted")
    return 0


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot read valid JSON evidence from {path}: {error}") from error


def validate(evidence: Any, artifact_root: Path, repository_root: Path) -> dict[str, Any]:
    failures: list[str] = []
    if not isinstance(evidence, dict):
        return {"accepted": False, "failures": ["evidence must be an object"]}
    if evidence.get("schemaVersion") != 1:
        failures.append("schemaVersion must be 1")
    if evidence.get("qualified") is not True:
        failures.append("qualified must be true")

    release = require_object(evidence, "release", failures)
    release_digest: str | None = None
    release_revision: str | None = None
    if release is not None:
        version = require_match(release, "version", SEMVER, failures)
        if version is not None and release.get("tag") != version:
            failures.append("release tag must equal the exact SemVer version")
        release_revision = require_match(release, "revision", REVISION, failures)
        release_digest = require_match(release, "imageIndexDigest", DIGEST, failures)
        signer = require_match(release, "signerFingerprint", FINGERPRINT, failures)
        if release.get("tagSignatureVerified") is not True:
            failures.append("release tag signature must be verified")
        if signer is not None and signer not in authorized_signers(repository_root, failures):
            failures.append("release signerFingerprint is not authorized")
        check_artifact(release, "tagVerification", artifact_root, failures)
        check_artifact(release, "provenance", artifact_root, failures)
        check_artifact(release, "imageIndex", artifact_root, failures)
        index = release.get("imageIndex")
        if (
            isinstance(index, dict)
            and isinstance(index.get("sha256"), str)
            and release_digest != f"sha256:{index['sha256']}"
        ):
            failures.append("release.imageIndex checksum must equal imageIndexDigest")
        platform_digests = require_object(release, "platformDigests", failures)
    else:
        platform_digests = None

    builds = require_list(evidence, "builds", failures)
    observed_platforms: set[str] = set()
    if builds is not None:
        for index, item in enumerate(builds):
            prefix = f"builds[{index}]"
            if not isinstance(item, dict):
                failures.append(f"{prefix} must be an object")
                continue
            platform = require_string(item, "platform", failures, prefix)
            if platform not in PLATFORMS:
                failures.append(f"{prefix}.platform must be a required native platform")
                continue
            if platform in observed_platforms:
                failures.append(f"duplicate build platform: {platform}")
            observed_platforms.add(platform)
            if item.get("runnerArchitecture") != PLATFORMS[platform]:
                failures.append(f"{prefix}.runnerArchitecture must match {platform}")
            if item.get("native") is not True or item.get("emulation") != "none":
                failures.append(f"{prefix} must be a native build without emulation")
            if item.get("revision") != release_revision:
                failures.append(f"{prefix}.revision must match the signed release revision")
            require_match(item, "imageDigest", DIGEST, failures, prefix)
            if platform_digests is not None and platform_digests.get(platform) != item.get(
                "imageDigest"
            ):
                failures.append(f"{prefix}.imageDigest must match release.platformDigests")
            if item.get("ganeshaPackage") != "6.5-8":
                failures.append(f"{prefix}.ganeshaPackage must be 6.5-8")
            if item.get("fsalApi") != "13.0":
                failures.append(f"{prefix}.fsalApi must be 13.0")
            for key in (
                "configuredBuild",
                "abiProbePassed",
                "linkProbePassed",
                "callbacksQualified",
                "normalizedRebuildMatched",
            ):
                if item.get(key) is not True:
                    failures.append(f"{prefix}.{key} must be true")
            if item.get("qualificationLabel") != "qualified":
                failures.append(f"{prefix}.qualificationLabel must be qualified")
            if item.get("undefinedFilebeltSymbols") != []:
                failures.append(f"{prefix}.undefinedFilebeltSymbols must be empty")
            artifacts = require_object(item, "artifacts", failures, prefix)
            if artifacts is not None:
                for key in (
                    "imageArchive",
                    "artifactContract",
                    "abiLog",
                    "linkLog",
                    "sbom",
                    "vulnerabilityReport",
                    "rebuildComparison",
                ):
                    check_artifact(artifacts, key, artifact_root, failures, f"{prefix}.artifacts")
    if observed_platforms != set(PLATFORMS):
        failures.append(
            "builds must contain exactly native linux/amd64, linux/arm64, "
            "and linux/riscv64 evidence"
        )
    if platform_digests is not None and set(platform_digests) != set(PLATFORMS):
        failures.append("release.platformDigests must contain exactly the three native platforms")

    image = require_object(evidence, "runtimeImage", failures)
    if image is not None:
        for key in ("ganeshaImageDigest", "bridgeImageDigest"):
            value = require_match(image, key, DIGEST, failures)
            if value != release_digest:
                failures.append(f"runtimeImage.{key} must equal release.imageIndexDigest")
        for key in ("ganeshaRevision", "bridgeRevision"):
            if image.get(key) != release_revision:
                failures.append(f"runtimeImage.{key} must match the signed release revision")
        if image.get("samePinnedImage") is not True:
            failures.append("runtimeImage.samePinnedImage must be true")
        if image.get("ganeshaHasKeytab") is not True:
            failures.append("runtimeImage.ganeshaHasKeytab must be true")
        if image.get("bridgeHasKeytab") is not False:
            failures.append("runtimeImage.bridgeHasKeytab must be false")
        if image.get("ipcCarriesSecrets") is not False:
            failures.append("runtimeImage.ipcCarriesSecrets must be false")

    licensing = require_object(evidence, "licensing", failures)
    if licensing is not None:
        if licensing.get("expression") != "LGPL-3.0-or-later":
            failures.append("licensing.expression must be LGPL-3.0-or-later")
        for key in (
            "completeSourceArchive",
            "notices",
            "sourceOffer",
            "relinkingInstructions",
            "sourceManifest",
        ):
            check_artifact(licensing, key, artifact_root, failures)
        if licensing.get("replacementInstructionsVerified") is not True:
            failures.append("licensing replacement instructions must be verified")

    cases = required_cases(repository_root, failures)
    clients = require_list(evidence, "clients", failures)
    observed_clients: set[tuple[str, str]] = set()
    if clients is not None:
        for index, item in enumerate(clients):
            prefix = f"clients[{index}]"
            if not isinstance(item, dict):
                failures.append(f"{prefix} must be an object")
                continue
            distribution = require_string(item, "distribution", failures, prefix)
            architecture = require_string(item, "architecture", failures, prefix)
            client = (distribution, architecture)
            if client not in CLIENTS:
                failures.append(f"{prefix} is not a required client/platform combination")
                continue
            if client in observed_clients:
                failures.append(
                    f"duplicate client/platform evidence: {distribution}/{architecture}"
                )
            observed_clients.add(client)
            if distribution == "rhel" and not str(item.get("version", "")).startswith("10"):
                failures.append(f"{prefix}.version must be RHEL 10")
            elif distribution != "rhel":
                require_string(item, "version", failures, prefix)
            if item.get("runnerArchitecture") != PLATFORMS[f"linux/{architecture}"]:
                failures.append(f"{prefix}.runnerArchitecture must match its client architecture")
            if item.get("native") is not True or item.get("emulation") != "none":
                failures.append(f"{prefix} must run natively without emulation")
            require_match(item, "rootfsDigest", DIGEST, failures, prefix)
            if item.get("imageIndexDigest") != release_digest:
                failures.append(f"{prefix}.imageIndexDigest must match the release image")
            if item.get("securityFlavor") != "krb5p":
                failures.append(f"{prefix}.securityFlavor must be krb5p")
            runtime_attestation = require_object(item, "runtimeAttestation", failures, prefix)
            if runtime_attestation is not None:
                expected_runtime = {
                    "bridgeHasKeytab": False,
                    "bridgeImageDigest": release_digest,
                    "bridgeRevision": release_revision,
                    "clientRootfsDigest": item.get("rootfsDigest"),
                    "ganeshaHasKeytab": True,
                    "ganeshaImageDigest": release_digest,
                    "ganeshaRevision": release_revision,
                    "ipcCarriesSecrets": False,
                    "samePinnedImage": True,
                }
                if runtime_attestation != expected_runtime:
                    failures.append(f"{prefix}.runtimeAttestation must match the release boundary")
            results = require_object(item, "cases", failures, prefix)
            if results is not None:
                unknown = set(results) - cases
                missing = cases - set(results)
                if unknown:
                    failures.append(f"{prefix}.cases contains unknown cases: {sorted(unknown)}")
                if missing:
                    failures.append(f"{prefix}.cases is missing cases: {sorted(missing)}")
                for name in sorted(cases & set(results)):
                    if results[name] is not True:
                        failures.append(f"{prefix}.cases.{name} must be true")
            cleanup = require_object(item, "cleanup", failures, prefix)
            if cleanup is not None:
                if cleanup.get("complete") is not True or cleanup.get("leftovers") != []:
                    failures.append(f"{prefix}.cleanup must be complete with no leftovers")
                resource_prefix = cleanup.get("resourcePrefix")
                if (
                    not isinstance(resource_prefix, str)
                    or RESOURCE_PREFIX.fullmatch(resource_prefix) is None
                ):
                    failures.append(f"{prefix}.cleanup.resourcePrefix is not deterministic")
                check_artifact(
                    cleanup,
                    "log",
                    artifact_root,
                    failures,
                    f"{prefix}.cleanup",
                    secret_free=True,
                )
            isolation = require_object(item, "secretIsolation", failures, prefix)
            if isolation is not None:
                for key in ("keytabsExcluded", "ticketsExcluded", "privateKeysExcluded"):
                    if isolation.get(key) is not True:
                        failures.append(f"{prefix}.secretIsolation.{key} must be true")
            check_artifact(item, "log", artifact_root, failures, prefix, secret_free=True)
    if observed_clients != CLIENTS:
        failures.append("clients must contain Ubuntu, Debian, and RHEL on amd64 and arm64")

    return {"accepted": not failures, "failures": failures}


def authorized_signers(repository_root: Path, failures: list[str]) -> set[str]:
    path = repository_root / "supply-chain/release-tag-signers.txt"
    try:
        return {
            line.strip()
            for line in path.read_text(encoding="ascii").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
    except OSError as error:
        failures.append(f"cannot read authorized release signers: {error}")
        return set()


def verify_current_release_tag(
    evidence: Any, repository_root: Path, failures: list[str]
) -> None:
    if not isinstance(evidence, dict) or not isinstance(evidence.get("release"), dict):
        return
    release = evidence["release"]
    tag = release.get("tag")
    revision = release.get("revision")
    if not isinstance(tag, str) or SEMVER.fullmatch(tag) is None:
        return
    try:
        head = subprocess.run(
            ["git", "-C", repository_root, "rev-parse", "--verify", "HEAD^{commit}"],
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout.strip()
        if head != revision:
            failures.append("checked-out revision must match release.revision")
            return
        subprocess.run(
            [repository_root / "tests/scripts/verify-release-tag.sh", tag],
            text=True,
            capture_output=True,
            check=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        failures.append(f"live signed release-tag verification failed: {error}")


def required_cases(repository_root: Path, failures: list[str]) -> set[str]:
    path = repository_root / "tests/nfs/qualification/required-cases.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        positive = value["positive"]
        negative = value["negative"]
        if value.get("schemaVersion") != 1 or not all(
            isinstance(item, str) and item for item in positive + negative
        ):
            raise ValueError("invalid case contract")
        return set(positive + negative)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        failures.append(f"cannot read required NFS cases: {error}")
        return set()


def check_artifact(
    container: dict[str, Any],
    key: str,
    artifact_root: Path,
    failures: list[str],
    prefix: str = "",
    *,
    secret_free: bool = False,
) -> None:
    label = f"{prefix}.{key}" if prefix else key
    value = container.get(key)
    if not isinstance(value, dict):
        failures.append(f"{label} must be an artifact object")
        return
    relative = value.get("path")
    expected = value.get("sha256")
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        failures.append(f"{label}.path must be a non-empty relative path")
        return
    parts = {part.lower() for part in Path(relative).parts}
    if any(secret in part for part in parts for secret in SECRET_PATH_PARTS):
        failures.append(f"{label}.path resembles secret material")
        return
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        failures.append(f"{label}.sha256 must be a lowercase SHA-256 value")
        return
    root = artifact_root.resolve()
    candidate = root / relative
    path = candidate.resolve()
    partial = root
    symlinked = False
    for part in Path(relative).parts:
        partial /= part
        if partial.is_symlink():
            symlinked = True
            break
    if not path.is_relative_to(root) or not path.is_file() or symlinked:
        failures.append(f"{label}.path must resolve to a regular file below artifact-root")
        return
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected:
        failures.append(f"{label} checksum mismatch")
    if secret_free:
        scan_secret_free_artifact(path, label, failures)


def scan_secret_free_artifact(path: Path, label: str, failures: list[str]) -> None:
    if path.stat().st_size > 16 * 1024 * 1024:
        failures.append(f"{label} exceeds the 16 MiB secret-free log limit")
        return
    content = path.read_bytes()
    forbidden = (
        b"-----BEGIN PRIVATE KEY-----",
        b"-----BEGIN RSA PRIVATE KEY-----",
        b"Authorization:",
        b"KRB5CCNAME=",
        b"client-secret=",
        b"private-key=",
        b"\x05\x02",
    )
    if any(marker in content for marker in forbidden):
        failures.append(f"{label} contains forbidden secret-shaped content")


def require_object(
    value: dict[str, Any], key: str, failures: list[str], prefix: str = ""
) -> dict[str, Any] | None:
    result = value.get(key)
    label = f"{prefix}.{key}" if prefix else key
    if not isinstance(result, dict):
        failures.append(f"{label} must be an object")
        return None
    return result


def require_list(
    value: dict[str, Any], key: str, failures: list[str], prefix: str = ""
) -> list[Any] | None:
    result = value.get(key)
    label = f"{prefix}.{key}" if prefix else key
    if not isinstance(result, list):
        failures.append(f"{label} must be an array")
        return None
    return result


def require_string(
    value: dict[str, Any], key: str, failures: list[str], prefix: str = ""
) -> str | None:
    result = value.get(key)
    label = f"{prefix}.{key}" if prefix else key
    if not isinstance(result, str) or not result:
        failures.append(f"{label} must be a non-empty string")
        return None
    return result


def require_match(
    value: dict[str, Any],
    key: str,
    pattern: re.Pattern[str],
    failures: list[str],
    prefix: str = "",
) -> str | None:
    result = require_string(value, key, failures, prefix)
    label = f"{prefix}.{key}" if prefix else key
    if result is not None and pattern.fullmatch(result) is None:
        failures.append(f"{label} has an invalid format")
        return None
    return result


if __name__ == "__main__":
    raise SystemExit(main())
