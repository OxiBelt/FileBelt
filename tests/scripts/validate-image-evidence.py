#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate that a Docker archive and its evidence belong to one immutable plan row."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


ARCHITECTURES = {
    "linux/amd64": "amd64",
    "linux/arm64": "arm64",
    "linux/riscv64": "riscv64",
}
METADATA_KEYS = {
    "schemaVersion",
    "planSha256",
    "role",
    "platform",
    "repository",
    "version",
    "tag",
    "localRef",
    "sourceRevision",
    "sourceRef",
    "sourceCreated",
    "sourceDirty",
    "sourceKind",
    "targetCpu",
    "dockerfile",
    "buildTarget",
    "archive",
    "archiveSha256",
}


class EvidenceError(RuntimeError):
    """The build evidence cannot be linked exactly to its claimed image plan."""


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_object(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read {description}: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{description} must be a JSON object")
    return value


def plan_row(plan: dict[str, Any], role: str, platform: str) -> dict[str, Any]:
    if plan.get("schemaVersion") != 2:
        raise EvidenceError("image plan schemaVersion must be 2")
    if plan.get("amd64IsaBaseline") != "x86-64-v3":
        raise EvidenceError("image plan AMD64 ISA baseline must be x86-64-v3")
    images = plan.get("images")
    if not isinstance(images, list):
        raise EvidenceError("image plan images must be an array")
    matches = [item for item in images if isinstance(item, dict) and item.get("role") == role]
    if len(matches) != 1:
        raise EvidenceError(f"image plan must contain exactly one {role} row")
    row = matches[0]
    platforms = row.get("platforms")
    if not isinstance(platforms, list) or platform not in platforms:
        raise EvidenceError(f"image plan row {role} does not contain platform {platform}")
    if platform not in ARCHITECTURES:
        raise EvidenceError(f"unsupported image platform: {platform}")
    return row


def expected_metadata(
    plan: dict[str, Any],
    plan_digest: str,
    row: dict[str, Any],
    role: str,
    platform: str,
    archive: Path,
) -> dict[str, Any]:
    source = plan.get("source")
    build = row.get("build")
    artifact = row.get("artifact")
    if not isinstance(source, dict) or not isinstance(build, dict) or not isinstance(artifact, dict):
        raise EvidenceError("image plan source or build identity is missing")
    repository = row.get("repository")
    version = plan.get("version")
    tag = plan.get("tag")
    required_strings = {
        "repository": repository,
        "version": version,
        "tag": tag,
        "source revision": source.get("revision"),
        "source ref": source.get("ref"),
        "source created": source.get("created"),
        "source kind": source.get("kind"),
        "Dockerfile": build.get("dockerfile"),
        "build target": build.get("target"),
    }
    for description, value in required_strings.items():
        if not isinstance(value, str) or not value:
            raise EvidenceError(f"image plan {description} must be a non-empty string")
    if not isinstance(source.get("dirty"), bool):
        raise EvidenceError("image plan source dirty must be a boolean")
    architecture = ARCHITECTURES[platform]
    if artifact.get("kind") not in {"rust-binary", "oxibelt-edge"}:
        raise EvidenceError("image plan artifact kind is invalid")
    target_cpus = artifact.get("targetCpu")
    if not isinstance(target_cpus, dict):
        raise EvidenceError("image plan artifact target CPU is missing")
    target_cpu = target_cpus.get(platform)
    if target_cpu != ("x86-64-v3" if platform == "linux/amd64" else None):
        raise EvidenceError("image plan artifact target CPU is invalid")
    expected_archive = f"{role}-{architecture}.docker.tar"
    if archive.name != expected_archive:
        raise EvidenceError(f"archive name is {archive.name!r}, expected {expected_archive!r}")
    local_ref = f"{repository}:{tag}-{architecture}"
    return {
        "schemaVersion": 2,
        "planSha256": plan_digest,
        "role": role,
        "platform": platform,
        "repository": repository,
        "version": version,
        "tag": tag,
        "localRef": local_ref,
        "sourceRevision": source["revision"],
        "sourceRef": source["ref"],
        "sourceCreated": source["created"],
        "sourceDirty": source["dirty"],
        "sourceKind": source["kind"],
        "targetCpu": target_cpu,
        "dockerfile": build["dockerfile"],
        "buildTarget": build["target"],
        "archive": expected_archive,
        "archiveSha256": file_sha256(archive),
    }


def validate_checksum(checksum: Path, archive: Path, archive_digest: str) -> None:
    expected_name = f"{archive.name}.sha256"
    if checksum.name != expected_name:
        raise EvidenceError(f"checksum name is {checksum.name!r}, expected {expected_name!r}")
    try:
        contents = checksum.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise EvidenceError(f"cannot read archive checksum: {error}") from error
    match = re.fullmatch(r"([0-9a-f]{64})  ([^/\n]+)\n", contents)
    if match is None:
        raise EvidenceError("archive checksum must use exact sha256sum text format")
    claimed_digest, claimed_name = match.groups()
    if claimed_name != archive.name:
        raise EvidenceError("archive checksum names a different file")
    if claimed_digest != archive_digest:
        raise EvidenceError("archive SHA-256 does not match the checksum evidence")


def archive_config(archive_path: Path, expected_local_ref: str) -> dict[str, Any]:
    try:
        with tarfile.open(archive_path, "r:*") as archive:
            manifest_members = [member for member in archive.getmembers() if member.name == "manifest.json"]
            if len(manifest_members) != 1 or not manifest_members[0].isfile():
                raise EvidenceError("Docker archive must contain one regular manifest.json")
            manifest_file = archive.extractfile(manifest_members[0])
            if manifest_file is None:
                raise EvidenceError("Docker archive manifest cannot be read")
            manifest = json.load(manifest_file)
            if not isinstance(manifest, list) or len(manifest) != 1:
                raise EvidenceError("Docker archive must contain exactly one image")
            record = manifest[0]
            if not isinstance(record, dict):
                raise EvidenceError("Docker archive manifest record is malformed")
            if record.get("RepoTags") != [expected_local_ref]:
                raise EvidenceError("Docker archive local reference does not match build metadata")
            config_name = record.get("Config")
            if not isinstance(config_name, str):
                raise EvidenceError("Docker archive config name is missing")
            config_path = PurePosixPath(config_name)
            if config_path.is_absolute() or ".." in config_path.parts:
                raise EvidenceError("Docker archive config name is unsafe")
            config_members = [member for member in archive.getmembers() if member.name == config_name]
            if len(config_members) != 1 or not config_members[0].isfile():
                raise EvidenceError("Docker archive must contain exactly one regular config")
            config_file = archive.extractfile(config_members[0])
            if config_file is None:
                raise EvidenceError("Docker archive config cannot be read")
            config = json.load(config_file)
    except (OSError, tarfile.TarError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read Docker archive identity: {error}") from error
    if not isinstance(config, dict):
        raise EvidenceError("Docker archive config must be a JSON object")
    return config


def validate_evidence(
    plan_path: Path,
    metadata_path: Path,
    checksum_path: Path,
    archive_path: Path,
    role: str,
    platform: str,
) -> dict[str, Any]:
    plan = load_object(plan_path, "image plan")
    row = plan_row(plan, role, platform)
    plan_digest = file_sha256(plan_path)
    expected = expected_metadata(plan, plan_digest, row, role, platform, archive_path)

    expected_metadata_name = f"{role}-{ARCHITECTURES[platform]}.build.json"
    if metadata_path.name != expected_metadata_name:
        raise EvidenceError(
            f"metadata name is {metadata_path.name!r}, expected {expected_metadata_name!r}"
        )
    metadata = load_object(metadata_path, "build metadata")
    if set(metadata) != METADATA_KEYS:
        raise EvidenceError("build metadata contains missing or unknown properties")
    for key, expected_value in expected.items():
        if metadata.get(key) != expected_value:
            raise EvidenceError(
                f"build metadata {key} is {metadata.get(key)!r}, expected {expected_value!r}"
            )

    archive_digest = expected["archiveSha256"]
    validate_checksum(checksum_path, archive_path, archive_digest)
    config = archive_config(archive_path, expected["localRef"])
    if config.get("os") != "linux" or config.get("architecture") != ARCHITECTURES[platform]:
        raise EvidenceError("Docker archive config platform does not match build metadata")

    return {
        "schemaVersion": 2,
        "planSha256": plan_digest,
        "role": role,
        "platform": platform,
        "repository": expected["repository"],
        "tag": expected["tag"],
        "localRef": expected["localRef"],
        "sourceRevision": expected["sourceRevision"],
        "targetCpu": expected["targetCpu"],
        "archive": archive_path.name,
        "archiveSha256": archive_digest,
        "metadataSha256": file_sha256(metadata_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--checksum", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    result = validate_evidence(
        args.plan, args.metadata, args.checksum, args.archive, args.role, args.platform
    )
    serialized = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    if args.output is None:
        print(serialized, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
