#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministic FileBelt adapter corresponding-source bundle support."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import tarfile
import tempfile
import tomllib
from collections.abc import Iterable

ROLES = {
    "filebelt-smb-gateway": "smb",
    "filebelt-ftp-ftps-gateway": "ftp-ftps",
    "filebelt-onlyoffice-adapter": "onlyoffice",
    "filebelt-git-adapter": "git",
    "filebelt-nfs-gateway": "nfs",
    "filebelt-transcoder": "transcode",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
FORBIDDEN_PARTS = {".git", "node_modules", "target", "artifacts", "evidence"}
REQUIRED_INPUT_DIRS = ("LICENSES", "NOTICES", "upstream", "patches", "vendor/cargo", "build-inputs")
REQUIRED_CANONICAL_LICENSES = {
    "filebelt-smb-gateway": ("GPL-3.0-or-later.txt",),
    "filebelt-ftp-ftps-gateway": ("GPL-3.0-or-later.txt",),
    "filebelt-onlyoffice-adapter": ("AGPL-3.0-only.txt", "Apache-2.0.txt"),
    "filebelt-git-adapter": ("GPL-2.0-only.txt",),
    "filebelt-nfs-gateway": ("LGPL-3.0-or-later.txt",),
    "filebelt-transcoder": ("GPL-3.0-or-later.txt",),
}
PUBLISHED_PLATFORMS = {"linux/amd64", "linux/arm64", "linux/riscv64"}
MAX_ARCHIVE_MEMBERS = 250_000
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024 * 1024


class BundleError(ValueError):
    """A source bundle violates the publication contract."""


def validate_canonical_adapter_plan(path: pathlib.Path) -> None:
    """Require the TypeScript catalog to accept the complete schema-v2 plan."""
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    cli = repo_root / "devops" / "dist" / "cli.js"
    if not cli.is_file():
        raise BundleError(
            "canonical adapter plan validator is absent; build @filebelt/devops first"
        )
    result = subprocess.run(
        ["node", str(cli), "validate-adapter-image-plan", "--input", str(path)],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "validation failed"
        raise BundleError(f"adapter image plan is not canonical: {detail}")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_staging_tree(root: pathlib.Path, role: str, version: str, revision: str) -> dict[str, object]:
    if role not in ROLES:
        raise BundleError(f"unknown adapter role: {role}")
    if not SEMVER.fullmatch(version):
        raise BundleError("version must be exact SemVer")
    if not REVISION.fullmatch(revision):
        raise BundleError("revision must be a 40-character lowercase Git object ID")
    if not root.is_dir():
        raise BundleError(f"source tree is not a directory: {root}")
    source = root / "source"
    inputs = root / "adapter-inputs" / ROLES[role]
    if not source.is_dir():
        raise BundleError("bundle staging tree must contain source/")
    for relative in ("SOURCE-MANIFEST.json", "BUILD.md"):
        if not (inputs / relative).is_file():
            raise BundleError(f"missing adapter-inputs/{ROLES[role]}/{relative}")
    for relative in REQUIRED_INPUT_DIRS:
        if not (inputs / relative).is_dir():
            raise BundleError(f"missing adapter-inputs/{ROLES[role]}/{relative}/")
    if not any((inputs / "LICENSES").iterdir()):
        raise BundleError("adapter license-text inventory is empty")
    if not any((inputs / "NOTICES").iterdir()):
        raise BundleError("adapter notice inventory is empty")
    if role != "filebelt-onlyoffice-adapter" and not any((inputs / "upstream").iterdir()):
        raise BundleError("required upstream source inventory is empty")
    for name in REQUIRED_CANONICAL_LICENSES[role]:
        canonical = source / "LICENSES" / name
        supplied = inputs / "LICENSES" / name
        if not canonical.is_file() or not supplied.is_file() or supplied.read_bytes() != canonical.read_bytes():
            raise BundleError(f"adapter license text does not match tracked canonical text: {name}")

    manifest_path = inputs / "SOURCE-MANIFEST.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BundleError(f"invalid SOURCE-MANIFEST.json: {error}") from error
    validate_manifest(manifest, root, role, version, revision)
    validate_vendor_closure(source, inputs, role)
    for path in walk_tree(root):
        relative = path.relative_to(root)
        validate_relative_path(relative)
    return manifest


def validate_manifest(
    manifest: object,
    root: pathlib.Path,
    role: str,
    version: str,
    revision: str,
) -> None:
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1:
        raise BundleError("SOURCE-MANIFEST.json schemaVersion must be 1")
    expected = {"role": role, "version": version, "sourceRevision": revision}
    for name, value in expected.items():
        if manifest.get(name) != value:
            raise BundleError(f"SOURCE-MANIFEST.json {name} does not match bundle identity")
    image_license = manifest.get("imageLicense")
    if not isinstance(image_license, str) or not image_license:
        raise BundleError("SOURCE-MANIFEST.json imageLicense is required")
    entries = manifest.get("inputs")
    if not isinstance(entries, list) or not entries:
        raise BundleError("SOURCE-MANIFEST.json inputs must be a non-empty array")
    seen: set[str] = set()
    required_fields = {
        "name", "version", "spdx", "relationship", "upstreamUrl", "archivePath",
        "sha256", "modified", "patchPaths", "buildInstructions", "platforms", "systemLibrary",
    }
    for index, item in enumerate(entries):
        if not isinstance(item, dict) or set(item) != required_fields:
            raise BundleError(f"manifest input {index} must contain exactly the required fields")
        archive_path = item["archivePath"]
        for field in ("name", "version", "spdx", "buildInstructions"):
            if not isinstance(item[field], str) or not item[field].strip():
                raise BundleError(f"manifest input {index} {field} must be a non-empty string")
        if not isinstance(archive_path, str):
            raise BundleError(f"manifest input {index} archivePath must be a string")
        relative = pathlib.PurePosixPath(archive_path)
        validate_relative_path(relative)
        if archive_path in seen:
            raise BundleError(f"manifest input archivePath is duplicated: {archive_path}")
        seen.add(archive_path)
        local = root.joinpath(*relative.parts)
        if not local.is_file():
            raise BundleError(f"manifest input is missing: {archive_path}")
        digest = item["sha256"]
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise BundleError(f"manifest input {archive_path} has an invalid SHA-256")
        if sha256_file(local) != digest:
            raise BundleError(f"manifest input {archive_path} checksum does not match")
        upstream_url = item["upstreamUrl"]
        if not isinstance(upstream_url, str) or not upstream_url.startswith("https://"):
            raise BundleError(f"manifest input {archive_path} must have an HTTPS upstream URL")
        if re.search(r"/(?:main|master|latest)(?:/|$)", upstream_url, re.IGNORECASE):
            raise BundleError(f"manifest input {archive_path} has a mutable upstream URL")
        if item["relationship"] not in {"build-only", "copied", "linked", "separate-executable"}:
            raise BundleError(f"manifest input {archive_path} has an invalid relationship")
        if not isinstance(item["modified"], bool) or not isinstance(item["systemLibrary"], bool):
            raise BundleError(f"manifest input {archive_path} boolean fields are invalid")
        for field in ("patchPaths", "platforms"):
            if not isinstance(item[field], list) or not all(isinstance(value, str) for value in item[field]):
                raise BundleError(f"manifest input {archive_path} {field} must be an array of strings")
        if not item["platforms"] or not set(item["platforms"]).issubset(PUBLISHED_PLATFORMS):
            raise BundleError(f"manifest input {archive_path} platforms are invalid")
        if len(set(item["patchPaths"])) != len(item["patchPaths"]):
            raise BundleError(f"manifest input {archive_path} repeats a patch path")
        for patch_path in item["patchPaths"]:
            patch = pathlib.PurePosixPath(patch_path)
            validate_relative_path(patch)
            if not root.joinpath(*patch.parts).is_file():
                raise BundleError(f"manifest patch is missing: {patch_path}")


def validate_vendor_closure(source: pathlib.Path, inputs: pathlib.Path, role: str) -> None:
    adapter = ROLES[role]
    lock_path = source / "adapters" / adapter / "Cargo.lock"
    if not lock_path.is_file():
        raise BundleError(f"tracked source is missing adapters/{adapter}/Cargo.lock")
    config = inputs / ".cargo" / "config.toml"
    if not config.is_file():
        raise BundleError("Cargo source-replacement configuration is missing")
    config_text = config.read_text(encoding="utf-8")
    if "replace-with" not in config_text or "vendored-sources" not in config_text or "offline = true" not in config_text:
        raise BundleError("Cargo source-replacement configuration must select vendored-sources and offline mode")
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    expected = {
        (package["name"], package["version"]): package.get("checksum")
        for package in lock.get("package", [])
        if isinstance(package, dict) and isinstance(package.get("source"), str)
    }
    found: dict[tuple[str, str], str | None] = {}
    vendor = inputs / "vendor" / "cargo"
    for manifest_path in vendor.glob("*/Cargo.toml"):
        package = tomllib.loads(manifest_path.read_text(encoding="utf-8")).get("package", {})
        name, version = package.get("name"), package.get("version")
        checksum_path = manifest_path.parent / ".cargo-checksum.json"
        if not checksum_path.is_file():
            raise BundleError(f"vendored package lacks .cargo-checksum.json: {manifest_path.parent.name}")
        try:
            checksum_document = json.loads(checksum_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise BundleError(
                f"vendored package checksum metadata is invalid: {manifest_path.parent.name}"
            ) from error
        package_checksum = checksum_document.get("package") if isinstance(checksum_document, dict) else None
        if not isinstance(name, str) or not isinstance(version, str):
            raise BundleError(f"vendored package identity is malformed: {manifest_path.parent.name}")
        identity = (name, version)
        if identity in found:
            raise BundleError(f"Cargo vendor closure duplicates {name}@{version}")
        found[identity] = package_checksum
    missing = sorted(set(expected) - set(found))
    if missing:
        rendered = ", ".join(f"{name}@{version}" for name, version in missing[:8])
        raise BundleError(f"Cargo vendor closure is incomplete: {rendered}")
    extra = sorted(set(found) - set(expected))
    if extra:
        rendered = ", ".join(f"{name}@{version}" for name, version in extra[:8])
        raise BundleError(f"Cargo vendor closure contains undeclared packages: {rendered}")
    for identity, expected_checksum in expected.items():
        if expected_checksum is not None and found[identity] != expected_checksum:
            raise BundleError(
                f"vendored package checksum differs from Cargo.lock: {identity[0]}@{identity[1]}"
            )


def package_bundle(
    source_tree: pathlib.Path,
    output: pathlib.Path,
    role: str,
    version: str,
    revision: str,
    commit_timestamp: int,
) -> str:
    validate_staging_tree(source_tree, role, version, revision)
    if commit_timestamp < 0:
        raise BundleError("commit timestamp must be non-negative")
    expected_name = f"{role}-source-{version}.tar.gz"
    if output.name != expected_name:
        raise BundleError(f"output must be named {expected_name}")
    output.parent.mkdir(parents=True, exist_ok=True)
    prefix = f"{role}-source-{version}"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in walk_tree(source_tree, include_directories=True):
            relative = path.relative_to(source_tree).as_posix()
            info = tarfile.TarInfo(f"{prefix}/{relative}")
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = commit_timestamp
            if path.is_dir():
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.size = 0
                archive.addfile(info)
            else:
                contents = path.read_bytes()
                info.mode = 0o755 if os.access(path, os.X_OK) else 0o644
                info.size = len(contents)
                archive.addfile(info, io.BytesIO(contents))
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as compressed:
            compressed.write(buffer.getvalue())
    return sha256_file(output)


def validate_bundle(path: pathlib.Path, role: str, version: str, revision: str, commit_timestamp: int) -> str:
    if not path.is_file():
        raise BundleError(f"bundle does not exist: {path}")
    with path.open("rb") as stream:
        header = stream.read(10)
    if len(header) != 10 or header[:2] != b"\x1f\x8b" or header[3] & 0x08 or header[4:8] != b"\0\0\0\0":
        raise BundleError("gzip header must omit a filename and use timestamp zero")
    prefix = f"{role}-source-{version}"
    seen: set[str] = set()
    previous = ""
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if not members:
            raise BundleError("bundle is empty")
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise BundleError("bundle contains too many archive entries")
        if sum(member.size for member in members) > MAX_ARCHIVE_BYTES:
            raise BundleError("bundle expands beyond the source-archive size limit")
        for member in members:
            if member.name in seen:
                raise BundleError(f"duplicate archive entry: {member.name}")
            seen.add(member.name)
            if member.name < previous:
                raise BundleError("archive entries are not lexicographically sorted")
            previous = member.name
            relative = pathlib.PurePosixPath(member.name)
            if not relative.parts or relative.parts[0] != prefix:
                raise BundleError("archive entry is outside the single bundle root")
            validate_relative_path(pathlib.PurePosixPath(*relative.parts[1:]))
            if member.uid != 0 or member.gid != 0 or member.uname or member.gname:
                raise BundleError(f"archive ownership is not normalized: {member.name}")
            if member.mtime != commit_timestamp:
                raise BundleError(f"archive timestamp does not match release commit: {member.name}")
            if not (member.isdir() or member.isfile()):
                raise BundleError(f"archive contains a non-regular entry: {member.name}")
            expected_mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
            if member.mode != expected_mode:
                raise BundleError(f"archive mode is not normalized: {member.name}")
        manifest_name = f"{prefix}/adapter-inputs/{ROLES[role]}/SOURCE-MANIFEST.json"
        if manifest_name not in seen:
            raise BundleError("archive lacks SOURCE-MANIFEST.json")
        extracted = archive.extractfile(manifest_name)
        if extracted is None:
            raise BundleError("archive SOURCE-MANIFEST.json is not a regular file")
        manifest = json.loads(extracted.read())
        if not isinstance(manifest, dict) or manifest.get("sourceRevision") != revision:
            raise BundleError("archive source revision does not match release evidence")
        with tempfile.TemporaryDirectory(prefix="filebelt-source-validation-") as temporary:
            extraction_root = pathlib.Path(temporary)
            archive.extractall(extraction_root, filter="data")
            roots = list(extraction_root.iterdir())
            if len(roots) != 1 or roots[0].name != prefix or not roots[0].is_dir():
                raise BundleError("bundle does not contain its exact single source root")
            validate_staging_tree(roots[0], role, version, revision)
    return sha256_file(path)


def read_bundle_manifest(path: pathlib.Path, role: str, version: str) -> dict[str, object]:
    name = f"{role}-source-{version}/adapter-inputs/{ROLES[role]}/SOURCE-MANIFEST.json"
    with tarfile.open(path, mode="r:gz") as archive:
        extracted = archive.extractfile(name)
        if extracted is None:
            raise BundleError("archive lacks a regular SOURCE-MANIFEST.json")
        value = json.loads(extracted.read())
    if not isinstance(value, dict):
        raise BundleError("archive SOURCE-MANIFEST.json must be an object")
    return value


def validate_bundle_against_plan(path: pathlib.Path, plan_path: pathlib.Path, role: str) -> None:
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BundleError(f"invalid adapter image plan: {error}") from error
    if not isinstance(plan, dict) or plan.get("schemaVersion") != 2 or not isinstance(plan.get("roles"), list):
        raise BundleError("adapter image plan schemaVersion must be 2")
    matches = [item for item in plan["roles"] if isinstance(item, dict) and item.get("role") == role]
    if len(matches) != 1:
        raise BundleError("adapter image plan must contain exactly one matching role")
    row = matches[0]
    bundle = row.get("sourceBundle")
    source = row.get("source")
    if not isinstance(bundle, dict) or not isinstance(source, dict):
        raise BundleError("adapter image plan source evidence is malformed")
    digest = sha256_file(path)
    if bundle.get("assetName") != path.name or bundle.get("sha256") != digest:
        raise BundleError("source bundle name or checksum does not match adapter image plan")
    manifest = read_bundle_manifest(path, role, str(plan.get("version")))
    if manifest.get("sourceRevision") != source.get("revision"):
        raise BundleError("source bundle and image plan revisions differ")
    if manifest.get("imageLicense") != row.get("imageLicense"):
        raise BundleError("source bundle and image plan license expressions differ")


def walk_tree(root: pathlib.Path, include_directories: bool = False) -> Iterable[pathlib.Path]:
    paths: list[pathlib.Path] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if any(part in FORBIDDEN_PARTS for part in relative.parts) or relative.parts[:2] == (".agents", "temp"):
            raise BundleError(f"forbidden source-bundle path: {relative.as_posix()}")
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise BundleError(f"source bundle contains an unsafe file type: {relative.as_posix()}")
        if include_directories or path.is_file():
            paths.append(path)
    return sorted(paths, key=lambda item: item.relative_to(root).as_posix())


def validate_relative_path(path: pathlib.PurePath) -> None:
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise BundleError(f"unsafe bundle path: {path.as_posix()}")
    if any(part in FORBIDDEN_PARTS for part in path.parts) or path.parts[:2] == (".agents", "temp"):
        raise BundleError(f"forbidden bundle path: {path.as_posix()}")
