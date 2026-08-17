#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate and load exact AMD64 FileBelt image archives for Compose units."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path
from typing import Any


REVISION = re.compile(r"^[0-9a-f]{40}$")
CORE_IMAGE_PLAN_SCHEMA_VERSION = 2
AMD64_PLATFORM = "linux/amd64"
AMD64_ISA_BASELINE = "x86-64-v3"


def _one(root: Path, name: str) -> Path:
    matches = tuple(root.rglob(name))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {name}, found {len(matches)}")
    return matches[0]


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _archive_reference(archive: Path) -> str:
    with tarfile.open(archive, "r") as source:
        member = source.getmember("manifest.json")
        extracted = source.extractfile(member)
        if extracted is None:
            raise ValueError(f"{archive.name} has no readable manifest")
        manifest = json.load(extracted)
    if not isinstance(manifest, list) or len(manifest) != 1:
        raise ValueError(f"{archive.name} must contain exactly one image")
    tags = manifest[0].get("RepoTags")
    if not isinstance(tags, list) or len(tags) != 1 or not isinstance(tags[0], str):
        raise ValueError(f"{archive.name} must contain exactly one repository tag")
    return tags[0]


def validate_role(root: Path, image_dir: Path, plan_path: Path, role: str, expected_channel: str, expected_revision: str) -> tuple[Path, str]:
    plan = _json(plan_path)
    if not isinstance(plan, dict):
        raise ValueError("image plan must be a JSON object")
    source = plan.get("source")
    if not isinstance(source, dict):
        raise ValueError("image plan source contract is invalid")
    if (
        plan.get("schemaVersion") != CORE_IMAGE_PLAN_SCHEMA_VERSION
        or plan.get("amd64IsaBaseline") != AMD64_ISA_BASELINE
    ):
        raise ValueError("image plan schema or AMD64 ISA contract is invalid")
    revision = source.get("revision")
    channel = plan.get("channel")
    kind = source.get("kind")
    dirty = source.get("dirty")
    coherent_source = (channel == expected_channel) and ((channel == "build" and kind == "ci") or (channel == "release" and kind == "release"))
    if not coherent_source or dirty is not False or not isinstance(revision, str) or revision != expected_revision or REVISION.fullmatch(revision) is None:
        raise ValueError("image plan source contract is invalid")
    images = plan.get("images")
    if not isinstance(images, list):
        raise ValueError("image plan images contract is invalid")
    rows = [row for row in images if isinstance(row, dict) and row.get("role") == role]
    if len(rows) != 1 or AMD64_PLATFORM not in rows[0].get("platforms", []):
        raise ValueError(f"image plan does not contain one AMD64 row for {role}")
    row = rows[0]
    repository = f"ghcr.io/oxibelt/{role}"
    if row.get("repository") != repository:
        raise ValueError(f"image plan repository is invalid for {role}")
    build_contract = row.get("build")
    artifact = row.get("artifact")
    if not isinstance(build_contract, dict) or not isinstance(artifact, dict):
        raise ValueError(f"image plan build contract is invalid for {role}")
    target_cpus = artifact.get("targetCpu")
    if not isinstance(target_cpus, dict) or target_cpus.get(AMD64_PLATFORM) != AMD64_ISA_BASELINE:
        raise ValueError(f"image plan AMD64 target CPU is invalid for {role}")
    source_ref = source.get("ref")
    source_created = source.get("created")
    dockerfile = build_contract.get("dockerfile")
    build_target = build_contract.get("target")
    if not all(
        isinstance(value, str) and value
        for value in (source_ref, source_created, dockerfile, build_target)
    ):
        raise ValueError(f"image plan build identity is invalid for {role}")
    expected_reference = f"{repository}:{plan.get('tag')}-amd64"

    archive = _one(image_dir, f"{role}-amd64.docker.tar")
    checksum = _one(image_dir, f"{role}-amd64.docker.tar.sha256")
    metadata = _one(image_dir, f"{role}-amd64.build.json")
    evidence = _one(image_dir, f"{role}-amd64.evidence.json")
    validation = _one(image_dir, f"{role}-amd64.validation.json")
    smoke = _one(image_dir, f"{role}-amd64.smoke.json")
    decision = _one(image_dir, f"{role}-amd64.vulnerability-decision.json")
    sbom = _one(image_dir, f"{role}-amd64.cdx.json")
    runtime_sbom = _one(image_dir, f"{role}-amd64.runtime.cdx.json")
    if sbom.stat().st_size == 0 or runtime_sbom.stat().st_size == 0:
        raise ValueError(f"SBOM evidence is empty for {role}/amd64")
    actual_sha = _sha(archive)
    if checksum.read_text(encoding="utf-8").strip() != f"{actual_sha}  {archive.name}":
        raise ValueError(f"archive checksum evidence mismatch for {role}/amd64")
    plan_sha = _sha(plan_path)
    metadata_sha = _sha(metadata)
    build = _json(metadata)
    reference = _archive_reference(archive)
    if reference != expected_reference:
        raise ValueError(f"archive tag does not match the image plan for {role}/amd64")
    expected_build = {
        "schemaVersion": CORE_IMAGE_PLAN_SCHEMA_VERSION,
        "planSha256": plan_sha,
        "role": role,
        "platform": AMD64_PLATFORM,
        "repository": repository,
        "version": plan.get("version"),
        "tag": plan.get("tag"),
        "localRef": reference,
        "sourceRevision": revision,
        "sourceRef": source_ref,
        "sourceCreated": source_created,
        "sourceDirty": dirty,
        "sourceKind": kind,
        "targetCpu": AMD64_ISA_BASELINE,
        "dockerfile": dockerfile,
        "buildTarget": build_target,
        "archive": archive.name,
        "archiveSha256": actual_sha,
    }
    if build != expected_build:
        raise ValueError(f"build metadata does not bind the expected {role}/amd64 archive")
    expected_evidence = {
        "schemaVersion": CORE_IMAGE_PLAN_SCHEMA_VERSION,
        "planSha256": plan_sha,
        "role": role,
        "platform": AMD64_PLATFORM,
        "repository": repository,
        "tag": plan.get("tag"),
        "localRef": reference,
        "sourceRevision": revision,
        "targetCpu": AMD64_ISA_BASELINE,
        "archive": archive.name,
        "archiveSha256": actual_sha,
        "metadataSha256": metadata_sha,
    }
    if _json(evidence) != expected_evidence:
        raise ValueError(f"image evidence is invalid for {role}/amd64")
    validated = _json(validation)
    smoked = _json(smoke)
    decided = _json(decision)
    if any(validated.get(key) != value for key, value in {"schemaVersion": CORE_IMAGE_PLAN_SCHEMA_VERSION, "role": role, "platform": AMD64_PLATFORM, "sourceRevision": revision, "targetCpu": AMD64_ISA_BASELINE, "repositoryTag": reference}.items()):
        raise ValueError(f"validation evidence is invalid for {role}/amd64")
    if any(smoked.get(key) != value for key, value in {"schemaVersion": 1, "role": role, "platform": AMD64_PLATFORM, "sourceRevision": revision, "passed": True}.items()):
        raise ValueError(f"smoke evidence is invalid for {role}/amd64")
    if decided.get("schemaVersion") != 1 or decided.get("allowed") is not True or decided.get("blockedFindings") != []:
        raise ValueError(f"vulnerability decision does not allow {role}/amd64")
    subprocess.run(
        ["python3", str(root / "tests/scripts/validate-image.py"), "--plan", str(plan_path), "--role", role, "--platform", AMD64_PLATFORM, "--archive", str(archive)],
        cwd=root,
        check=True,
    )
    return archive, reference


def load_roles(root: Path, image_dir: Path, roles: tuple[str, ...], compose_suffix: dict[str, str], expected_channel: str, expected_revision: str) -> list[str]:
    plan = _one(image_dir, "image-plan.json")
    loaded: list[str] = []
    try:
        for role in roles:
            archive, reference = validate_role(root, image_dir, plan, role, expected_channel, expected_revision)
            compose_reference = f"{role}:{compose_suffix.get(role, 'phase2')}"
            for candidate in (reference, compose_reference):
                exists = subprocess.run(["docker", "image", "inspect", candidate], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
                if exists:
                    raise ValueError(f"refusing to replace existing local image tag: {candidate}")
            result = subprocess.run(["docker", "load", "--input", str(archive)], check=True, capture_output=True, text=True)
            if f"Loaded image: {reference}" not in result.stdout:
                raise ValueError(f"loaded archive did not report expected reference {reference}")
            loaded.append(reference)
            architecture = subprocess.run(["docker", "image", "inspect", reference, "--format", "{{.Architecture}}"], check=True, capture_output=True, text=True).stdout.strip()
            if architecture != "amd64":
                raise ValueError(f"loaded archive has architecture {architecture}, expected amd64")
            subprocess.run(["docker", "tag", reference, compose_reference], check=True)
            loaded.append(compose_reference)
    except (OSError, subprocess.CalledProcessError, ValueError):
        for loaded_reference in reversed(loaded):
            subprocess.run(
                ["docker", "image", "rm", "--force", loaded_reference],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        raise
    return loaded
