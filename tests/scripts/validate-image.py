#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate a Docker archive against the immutable FileBelt image plan."""

from __future__ import annotations

import argparse
import io
import json
import struct
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


EXPECTED_LABELS = {
    "org.opencontainers.image.source": "https://github.com/OxiBelt/FileBelt",
    "org.opencontainers.image.url": "https://github.com/OxiBelt/FileBelt",
}
RUST_IMAGE_LICENSES = {
    "filebelt-api": "Apache-2.0 AND MIT AND CDLA-Permissive-2.0",
    "filebelt-worker-io": "Apache-2.0 AND MIT AND CDLA-Permissive-2.0",
    "filebelt-worker-maintenance": (
        "Apache-2.0 AND MIT AND MPL-2.0 AND CDLA-Permissive-2.0"
    ),
    "filebelt-media-controller": "Apache-2.0 AND MIT",
    "filebelt-collaboration": "Apache-2.0 AND MIT AND CDLA-Permissive-2.0",
    "filebelt-mcp-broker": "Apache-2.0 AND MIT AND CDLA-Permissive-2.0",
    "filebelt-controller": "Apache-2.0 AND MIT AND CDLA-Permissive-2.0",
    "filebelt-mcp-runner": "Apache-2.0 AND MIT",
    "filebelt-tools": "Apache-2.0 AND MIT AND MPL-2.0 AND CDLA-Permissive-2.0",
    "filebelt-vfs": "Apache-2.0 AND MIT AND CDLA-Permissive-2.0",
    "filebelt-headscale-sync": "Apache-2.0 AND MIT AND CDLA-Permissive-2.0",
}
WEB_IMAGE_LICENSE = "Apache-2.0 AND MIT AND ISC AND 0BSD"
OXIBELT_IMAGE = (
    "ghcr.io/oxibelt/oxibelt@"
    "sha256:e8556a0103feff47bf6135062e70e980e000176598fd438959ea55d99c844030"
)
OXIBELT_ENTRYPOINT = [
    "/usr/local/bin/oxibelt",
    "--config",
    "/etc/oxibelt/config/oxibelt.toml",
]
MACHINES = {"linux/amd64": 62, "linux/arm64": 183, "linux/riscv64": 243}
ARCHITECTURES = {
    "linux/amd64": "amd64",
    "linux/arm64": "arm64",
    "linux/riscv64": "riscv64",
}
BINARIES = {
    "filebelt-api": "/usr/local/bin/filebelt-api",
    "filebelt-worker-io": "/usr/local/bin/filebelt-worker-io",
    "filebelt-worker-maintenance": "/usr/local/bin/filebelt-worker-maintenance",
    "filebelt-media-controller": "/usr/local/bin/filebelt-media-controller",
    "filebelt-collaboration": "/usr/local/bin/filebelt-collaboration",
    "filebelt-mcp-broker": "/usr/local/bin/filebelt-mcp-broker",
    "filebelt-controller": "/usr/local/bin/filebelt-controller",
    "filebelt-mcp-runner": "/usr/local/bin/filebelt-mcp-runner",
    "filebelt-tools": "/usr/local/bin/filebeltctl",
    "filebelt-vfs": "/usr/local/bin/filebelt-vfs",
    "filebelt-headscale-sync": "/usr/local/bin/filebelt-headscale-sync",
}


class ValidationError(RuntimeError):
    """A deterministic image contract was violated."""


@dataclass(frozen=True)
class FileEntry:
    mode: int
    uid: int
    gid: int
    data: bytes
    link_target: str | None = None


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def normalized_path(name: str) -> str:
    path = PurePosixPath("/" + name.removeprefix("./").lstrip("/"))
    if ".." in path.parts:
        raise ValidationError(f"archive contains traversal path: {name}")
    return path.as_posix()


def normalized_link_target(path_name: str, link_name: str, *, hardlink: bool) -> str:
    if not link_name or "\x00" in link_name:
        raise ValidationError(f"archive contains an invalid link target: {path_name}")
    raw = PurePosixPath("/" + link_name.lstrip("/")) if hardlink else (
        PurePosixPath(link_name)
        if link_name.startswith("/")
        else PurePosixPath(path_name).parent / link_name
    )
    parts: list[str] = []
    for part in raw.parts:
        if part in ("", "/", "."):
            continue
        if part == "..":
            if not parts:
                raise ValidationError(f"archive link escapes the rootfs: {path_name}")
            parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def load_archive(path: Path) -> tuple[dict[str, Any], dict[str, FileEntry], str]:
    files: dict[str, FileEntry] = {}
    with tarfile.open(path, "r:*") as archive:
        manifest_file = archive.extractfile("manifest.json")
        if manifest_file is None:
            raise ValidationError("Docker archive has no manifest.json")
        manifest = json.load(manifest_file)
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise ValidationError("Docker archive must contain exactly one image")
        record = manifest[0]
        config_name = record.get("Config")
        layers = record.get("Layers")
        repo_tags = record.get("RepoTags")
        if not isinstance(config_name, str) or not isinstance(layers, list):
            raise ValidationError("Docker archive manifest is malformed")
        if not isinstance(repo_tags, list) or len(repo_tags) != 1:
            raise ValidationError("Docker archive must contain exactly one repository tag")
        config_file = archive.extractfile(config_name)
        if config_file is None:
            raise ValidationError("Docker archive config is missing")
        config = json.load(config_file)

        for layer_name in layers:
            if not isinstance(layer_name, str):
                raise ValidationError("Docker archive layer name is not a string")
            layer_file = archive.extractfile(layer_name)
            if layer_file is None:
                raise ValidationError(f"Docker archive layer is missing: {layer_name}")
            with tarfile.open(fileobj=io.BytesIO(layer_file.read()), mode="r:*") as layer:
                members = layer.getmembers()
                lower_paths = set(files)
                for member in members:
                    path_name = normalized_path(member.name)
                    base = PurePosixPath(path_name).name
                    if base == ".wh..wh..opq":
                        parent = PurePosixPath(path_name).parent.as_posix()
                        prefix = "/" if parent == "/" else f"{parent}/"
                        for lower_path in lower_paths:
                            if lower_path.startswith(prefix):
                                files.pop(lower_path, None)
                    elif base.startswith(".wh."):
                        target_name = base.removeprefix(".wh.")
                        if not target_name:
                            raise ValidationError(f"invalid whiteout entry: {path_name}")
                        target = (PurePosixPath(path_name).parent / target_name).as_posix()
                        prefix = f"{target}/"
                        for lower_path in lower_paths:
                            if lower_path == target or lower_path.startswith(prefix):
                                files.pop(lower_path, None)

                for member in members:
                    path_name = normalized_path(member.name)
                    base = PurePosixPath(path_name).name
                    if base.startswith(".wh."):
                        continue
                    if member.isfile():
                        content = layer.extractfile(member)
                        if content is None:
                            raise ValidationError(f"cannot read image file: {path_name}")
                        prefix = f"{path_name}/"
                        for existing in list(files):
                            if existing == path_name or existing.startswith(prefix):
                                files.pop(existing, None)
                        files[path_name] = FileEntry(
                            member.mode & 0o7777, member.uid, member.gid, content.read()
                        )
                    elif member.issym() or member.islnk():
                        prefix = f"{path_name}/"
                        for existing in list(files):
                            if existing == path_name or existing.startswith(prefix):
                                files.pop(existing, None)
                        files[path_name] = FileEntry(
                            member.mode & 0o7777,
                            member.uid,
                            member.gid,
                            b"",
                            normalized_link_target(
                                path_name, member.linkname, hardlink=member.islnk()
                            ),
                        )
                    elif member.isdir():
                        files.pop(path_name, None)
                    else:
                        raise ValidationError(
                            f"unsupported special archive entry: {path_name}"
                        )
    return config, files, repo_tags[0]


def required_file(
    files: dict[str, FileEntry], path: str, *, mode: int = 0o644
) -> FileEntry:
    entry = files.get(path)
    if entry is None:
        raise ValidationError(f"required image file is missing: {path}")
    if entry.link_target is not None:
        raise ValidationError(f"required image file must not be a link: {path}")
    if entry.uid != 0 or entry.gid != 0:
        raise ValidationError(f"required image file must be owned by 0:0: {path}")
    if entry.mode != mode:
        raise ValidationError(
            f"required image file mode is {entry.mode:#06o}, expected {mode:#06o}: {path}"
        )
    return entry


def assert_static_elf(data: bytes, platform: str) -> None:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValidationError("role executable is not an ELF binary")
    if data[4] != 2 or data[5] != 1:
        raise ValidationError("role executable must be little-endian ELF64")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != MACHINES[platform]:
        raise ValidationError(
            f"ELF machine {machine} does not match {platform} ({MACHINES[platform]})"
        )
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize = struct.unpack_from("<H", data, 54)[0]
    phnum = struct.unpack_from("<H", data, 56)[0]
    for index in range(phnum):
        offset = phoff + index * phentsize
        if offset + 4 > len(data):
            raise ValidationError("ELF program header is truncated")
        if struct.unpack_from("<I", data, offset)[0] == 3:
            raise ValidationError("role executable contains a dynamic interpreter")


def plan_image(plan: dict[str, Any], role: str) -> dict[str, Any]:
    images = plan.get("images")
    if not isinstance(images, list):
        raise ValidationError("image plan has no images array")
    matches = [item for item in images if isinstance(item, dict) and item.get("role") == role]
    if len(matches) != 1:
        raise ValidationError(f"image plan must contain exactly one {role} row")
    return matches[0]


def validate(
    plan: dict[str, Any], role: str, platform: str, config: dict[str, Any], files: dict[str, FileEntry]
) -> dict[str, Any]:
    image = plan_image(plan, role)
    if platform not in image.get("platforms", []):
        raise ValidationError(f"{role} does not declare {platform}")
    if config.get("os") != "linux" or config.get("architecture") != ARCHITECTURES[platform]:
        raise ValidationError("image config platform does not match the plan")
    runtime = config.get("config")
    if not isinstance(runtime, dict):
        raise ValidationError("image runtime config is missing")
    if runtime.get("User") != "10001:10001":
        raise ValidationError("image runtime user must be 10001:10001")
    labels = runtime.get("Labels")
    if not isinstance(labels, dict):
        raise ValidationError("image labels are missing")

    source = plan.get("source")
    if not isinstance(source, dict):
        raise ValidationError("image plan source identity is missing")
    expected = {
        **EXPECTED_LABELS,
        "org.opencontainers.image.licenses": image.get("license"),
        "org.opencontainers.image.version": plan.get("version"),
        "org.opencontainers.image.revision": source.get("revision"),
        "org.opencontainers.image.created": source.get("created"),
        "io.filebelt.image.role": role,
        "io.filebelt.build.source-ref": source.get("ref"),
        "io.filebelt.build.dirty": str(source.get("dirty")).lower(),
        "io.filebelt.build.kind": source.get("kind"),
        "org.opencontainers.image.title": image.get("title"),
        "org.opencontainers.image.description": image.get("description"),
    }
    for key, value in expected.items():
        if labels.get(key) != value:
            raise ValidationError(f"label {key} is {labels.get(key)!r}, expected {value!r}")
    common_files = [
        "/etc/passwd",
        "/etc/group",
        "/usr/share/licenses/FileBelt/LICENSE",
        "/usr/share/licenses/FileBelt/LICENSES/Apache-2.0.txt",
    ]
    for required in common_files:
        required_file(files, required)
    if role == "filebelt-web":
        if b"oxibelt:x:10001:10001:" not in required_file(files, "/etc/passwd").data:
            raise ValidationError("web image passwd does not declare the OxiBelt service user")
        if b"oxibelt:x:10001:" not in required_file(files, "/etc/group").data:
            raise ValidationError("web image group does not declare the OxiBelt service group")
        if image.get("license") != WEB_IMAGE_LICENSE:
            raise ValidationError("web edge license must cover OxiBelt and bundled UI code")
        if runtime.get("Entrypoint") != OXIBELT_ENTRYPOINT or runtime.get("Cmd") not in (None, []):
            raise ValidationError("web image must start the pinned OxiBelt edge configuration")
        if runtime.get("ExposedPorts") != {"8443/tcp": {}, "8443/udp": {}}:
            raise ValidationError("web image must retain only OxiBelt's declared edge ports")
        expected_base_labels = {
            "org.opencontainers.image.base.name": OXIBELT_IMAGE,
            "org.opencontainers.image.base.digest": OXIBELT_IMAGE.split("@", 1)[1],
            "io.filebelt.upstream.oxibelt.version": "0.7.1-beta.2",
            "io.filebelt.upstream.oxibelt.revision": "bf40172e40298325775ca9d708162a9d8d14e6d4",
        }
        for key, value in expected_base_labels.items():
            if labels.get(key) != value:
                raise ValidationError(f"web label {key} is not bound to the admitted OxiBelt base")
        for asset in (
            "/srv/filebelt/web/index.html",
            "/srv/filebelt/markdown-preview/index.html",
        ):
            if not required_file(files, asset).data:
                raise ValidationError(f"web artifact is missing: {asset}")
        edge_config = required_file(files, "/etc/oxibelt/config/oxibelt.toml").data
        for contract in [
            b'path_prefix = "/api/v1"',
            b'path_prefix = "/io/v1"',
            b'path_prefix = "/public/v1"',
            b'path_prefix = "/collaboration/v1/ws"',
            b'path_prefix = "/markdown-preview/"',
            b'mode = "overwrite"',
            b'retry_non_idempotent = false',
            b'value = "no-store"',
            b'spa_fallback = "/index.html"',
            b'http3 = false',
            b"require-trusted-types-for 'script'",
            b"trusted-types 'none'",
            b"trusted-types filebelt-markdown-generated",
        ]:
            if contract not in edge_config:
                raise ValidationError(f"web edge config is missing contract: {contract!r}")
        for forbidden_contract in [
            b"filebelt-development-oidc",
            b"/_filebelt-test-oidc/authorize",
            b'js = "public, max-age=31536000, immutable"',
        ]:
            if forbidden_contract in edge_config:
                raise ValidationError(
                    f"release web edge config contains development contract: {forbidden_contract!r}"
                )
        for evidence in [
            "/usr/share/licenses/FileBelt/LICENSES/MIT.txt",
            "/usr/share/licenses/FileBelt/THIRD_PARTY_NOTICES.md",
            "/usr/share/licenses/FileBelt/notices/OXIBELT_NOTICE.md",
            "/usr/share/licenses/FileBelt/notices/web/lucide-ISC.txt",
            "/usr/share/licenses/FileBelt/notices/web/tslib-0BSD.txt",
            "/usr/share/licenses/FileBelt/notices/web/web-production-licenses.json",
        ]:
            required_file(files, evidence)
        notice = required_file(
            files, "/usr/share/licenses/FileBelt/notices/OXIBELT_NOTICE.md"
        ).data
        if OXIBELT_IMAGE.split("@", 1)[1].encode() not in notice:
            raise ValidationError("OxiBelt notice is not bound to the admitted image digest")
        executable = "/usr/local/bin/oxibelt"
        assert_static_elf(required_file(files, executable, mode=0o755).data, platform)
    else:
        if b"filebelt:x:10001:10001:" not in required_file(files, "/etc/passwd").data:
            raise ValidationError("image passwd does not declare the service user")
        if b"filebelt:x:10001:" not in required_file(files, "/etc/group").data:
            raise ValidationError("image group does not declare the service group")
        expected_license = RUST_IMAGE_LICENSES.get(role)
        if image.get("license") != expected_license:
            raise ValidationError(f"static Rust artifact license is incorrect for {role}")
        executable = BINARIES.get(role)
        if executable is None:
            raise ValidationError(f"unknown executable role: {role}")
        if runtime.get("Entrypoint") != [executable] or runtime.get("Cmd") not in (None, []):
            raise ValidationError(f"unexpected runtime command for {role}")
        entry = required_file(files, executable, mode=0o755)
        rust_notice = required_file(
            files,
            "/usr/share/licenses/FileBelt/notices/Rust-COPYRIGHT-library.html",
        )
        musl_notice = required_file(
            files, "/usr/share/licenses/FileBelt/notices/musl-COPYRIGHT"
        )
        for required in [
            "/usr/share/licenses/FileBelt/LICENSES/MIT.txt",
            "/usr/share/licenses/FileBelt/THIRD_PARTY_NOTICES.md",
        ]:
            required_file(files, required)
        if "CDLA-Permissive-2.0" in expected_license:
            cdla = required_file(
                files,
                "/usr/share/licenses/FileBelt/LICENSES/CDLA-Permissive-2.0.txt",
            )
            required_file(
                files,
                "/usr/share/licenses/FileBelt/notices/webpki-roots-SOURCE.txt",
            )
            if b"Community Data License Agreement" not in cdla.data:
                raise ValidationError("Rust image has invalid WebPKI CDLA evidence")
        if "MPL-2.0" in expected_license:
            mpl = required_file(
                files, "/usr/share/licenses/FileBelt/LICENSES/MPL-2.0.txt"
            )
            required_file(
                files, "/usr/share/licenses/FileBelt/notices/option-ext-SOURCE.txt"
            )
            if b"Mozilla Public License Version 2.0" not in mpl.data:
                raise ValidationError("Rust image has invalid option-ext MPL evidence")
        if b"Copyright notices for The Rust Standard Library" not in rust_notice.data:
            raise ValidationError("Rust image has invalid Rust copyright evidence")
        if (
            b"Rich Felker" not in musl_notice.data
            or b"standard MIT license" not in musl_notice.data
        ):
            raise ValidationError("Rust image has invalid musl copyright evidence")
        assert_static_elf(entry.data, platform)

    forbidden = [path for path in files if path.startswith("/adapters/")]
    if forbidden:
        raise ValidationError("Apache image contains adapter paths")
    return {
        "schemaVersion": 1,
        "role": role,
        "platform": platform,
        "sourceRevision": source.get("revision"),
        "license": image.get("license"),
        "runtimeUser": runtime.get("User"),
        "executable": executable,
        "fileCount": len(files),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--platform", choices=sorted(MACHINES), required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    plan = load_json(args.plan)
    if not isinstance(plan, dict):
        raise ValidationError("image plan must be a JSON object")
    config, files, repo_tag = load_archive(args.archive)
    result = validate(plan, args.role, args.platform, config, files)
    result["repositoryTag"] = repo_tag
    serialized = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    if args.output is None:
        print(serialized, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
