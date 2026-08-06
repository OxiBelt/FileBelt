#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Compare normalized image root filesystems, runtime config, and SBOMs."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


class ComparisonError(RuntimeError):
    """Two independently built artifacts differ materially."""


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def archive_contract(path: Path) -> dict[str, Any]:
    filesystem: dict[str, dict[str, Any]] = {}
    with tarfile.open(path, "r:*") as archive:
        manifest_file = archive.extractfile("manifest.json")
        if manifest_file is None:
            raise ComparisonError(f"{path} has no Docker manifest")
        manifest = json.load(manifest_file)
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise ComparisonError(f"{path} must contain exactly one image")
        record = manifest[0]
        config_file = archive.extractfile(record["Config"])
        if config_file is None:
            raise ComparisonError(f"{path} has no image config")
        config = json.load(config_file)
        for layer_name in record["Layers"]:
            layer_file = archive.extractfile(layer_name)
            if layer_file is None:
                raise ComparisonError(f"{path} is missing layer {layer_name}")
            with tarfile.open(fileobj=io.BytesIO(layer_file.read()), mode="r:*") as layer:
                members = layer.getmembers()
                lower_paths = set(filesystem)
                for member in members:
                    name = "/" + member.name.removeprefix("./").lstrip("/")
                    pure = PurePosixPath(name)
                    if ".." in pure.parts:
                        raise ComparisonError(f"{path} contains a traversal path")
                    base = pure.name
                    if base == ".wh..wh..opq":
                        parent = pure.parent.as_posix().rstrip("/") + "/"
                        for lower_path in lower_paths:
                            if lower_path.startswith(parent):
                                filesystem.pop(lower_path, None)
                    elif base.startswith(".wh."):
                        target_name = base.removeprefix(".wh.")
                        if not target_name:
                            raise ComparisonError(f"{path} contains an invalid whiteout entry")
                        target = (pure.parent / target_name).as_posix()
                        prefix = f"{target}/"
                        for lower_path in lower_paths:
                            if lower_path == target or lower_path.startswith(prefix):
                                filesystem.pop(lower_path, None)

                pending_hardlinks: list[tuple[str, tarfile.TarInfo]] = []
                for member in members:
                    name = "/" + member.name.removeprefix("./").lstrip("/")
                    pure = PurePosixPath(name)
                    base = pure.name
                    if base.startswith(".wh."):
                        continue
                    if member.isfile():
                        stream = layer.extractfile(member)
                        if stream is None:
                            raise ComparisonError(f"cannot read {name} from {path}")
                        prefix = f"{name}/"
                        for existing in list(filesystem):
                            if existing == name or existing.startswith(prefix):
                                filesystem.pop(existing, None)
                        filesystem[name] = {
                            "type": "file",
                            "mode": member.mode,
                            "uid": member.uid,
                            "gid": member.gid,
                            "sha256": hashlib.sha256(stream.read()).hexdigest(),
                        }
                    elif member.isdir():
                        filesystem.pop(name, None)
                        filesystem[name] = {
                            "type": "directory",
                            "mode": member.mode,
                            "uid": member.uid,
                            "gid": member.gid,
                        }
                    elif member.issym():
                        prefix = f"{name}/"
                        for existing in list(filesystem):
                            if existing == name or existing.startswith(prefix):
                                filesystem.pop(existing, None)
                        filesystem[name] = {
                            "type": "symlink",
                            "mode": member.mode,
                            "uid": member.uid,
                            "gid": member.gid,
                            "target": member.linkname,
                        }
                    elif member.islnk():
                        pending_hardlinks.append((name, member))
                    else:
                        raise ComparisonError(
                            f"{path} contains unsupported layer entry type for {name}"
                        )
                while pending_hardlinks:
                    unresolved: list[tuple[str, tarfile.TarInfo]] = []
                    for name, member in pending_hardlinks:
                        target = "/" + member.linkname.removeprefix("./").lstrip("/")
                        target_path = PurePosixPath(target)
                        if ".." in target_path.parts:
                            raise ComparisonError(f"{path} contains a traversal hardlink")
                        target_entry = filesystem.get(target_path.as_posix())
                        if target_entry is None or target_entry.get("type") not in {
                            "file",
                            "hardlink",
                        }:
                            unresolved.append((name, member))
                            continue
                        prefix = f"{name}/"
                        for existing in list(filesystem):
                            if existing == name or existing.startswith(prefix):
                                filesystem.pop(existing, None)
                        filesystem[name] = {
                            "type": "hardlink",
                            "mode": member.mode,
                            "uid": member.uid,
                            "gid": member.gid,
                            "target": member.linkname,
                            "sha256": target_entry["sha256"],
                        }
                    if len(unresolved) == len(pending_hardlinks):
                        name, member = unresolved[0]
                        raise ComparisonError(
                            f"{path} contains unresolved hardlink {name} -> {member.linkname}"
                        )
                    pending_hardlinks = unresolved
        runtime = config.get("config", {})
        return {
            "platform": {"os": config.get("os"), "architecture": config.get("architecture")},
            "runtime": {
                "User": runtime.get("User"),
                "Entrypoint": runtime.get("Entrypoint"),
                "Cmd": runtime.get("Cmd"),
                "Env": runtime.get("Env"),
                "WorkingDir": runtime.get("WorkingDir"),
                "Labels": runtime.get("Labels"),
            },
            "filesystem": dict(sorted(filesystem.items())),
        }


def normalized_sbom(path: Path) -> dict[str, Any]:
    sbom = read_json(path)
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        raise ComparisonError(f"{path} is not a CycloneDX JSON SBOM")
    metadata = sbom.get("metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("component"), dict):
        raise ComparisonError(f"{path} has no CycloneDX subject component")
    components = sbom.get("components", [])
    dependencies = sbom.get("dependencies", [])
    if not isinstance(components, list) or not isinstance(dependencies, list):
        raise ComparisonError(f"{path} has malformed CycloneDX arrays")

    def canonical(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: canonical(value[key]) for key in sorted(value)}
        if isinstance(value, list):
            normalized = [canonical(item) for item in value]
            return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True))
        return value

    return {
        "bomFormat": sbom.get("bomFormat"),
        "specVersion": sbom.get("specVersion"),
        "subject": canonical(metadata["component"]),
        "components": canonical(components),
        "dependencies": canonical(dependencies),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--first-archive", type=Path, required=True)
    parser.add_argument("--second-archive", type=Path, required=True)
    parser.add_argument("--first-sbom", type=Path, required=True)
    parser.add_argument("--second-sbom", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    first_image = archive_contract(args.first_archive)
    second_image = archive_contract(args.second_archive)
    if first_image != second_image:
        raise ComparisonError("normalized image filesystems or runtime configs differ")
    first_sbom = normalized_sbom(args.first_sbom)
    second_sbom = normalized_sbom(args.second_sbom)
    if first_sbom != second_sbom:
        raise ComparisonError("normalized CycloneDX subjects or components differ")
    result = {
        "schemaVersion": 1,
        "imageEqual": True,
        "sbomEqual": True,
        "normalizedFileCount": len(first_image["filesystem"]),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
