#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for Docker overlay and file-metadata validation."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
import struct
from pathlib import Path
from types import ModuleType


def load_validator() -> ModuleType:
    path = Path(__file__).with_name("validate-image.py")
    spec = importlib.util.spec_from_file_location("validate_image", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load image validator module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VALIDATOR = load_validator()


def layer_bytes(entries: list[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for member, content in entries:
            member.mtime = 0
            if content is not None:
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
            else:
                archive.addfile(member)
    return buffer.getvalue()


def regular(name: str, content: bytes = b"data") -> tuple[tarfile.TarInfo, bytes]:
    member = tarfile.TarInfo(name)
    member.mode = 0o644
    return member, content


def write_docker_archive(path: Path, layers: list[bytes]) -> None:
    names = [f"layer-{index}.tar" for index in range(len(layers))]
    manifest = [{"Config": "config.json", "RepoTags": ["example:test"], "Layers": names}]
    config = {"os": "linux", "architecture": "amd64", "config": {}}
    with tarfile.open(path, mode="w") as archive:
        for name, content in [
            ("manifest.json", json.dumps(manifest).encode()),
            ("config.json", json.dumps(config).encode()),
            *zip(names, layers, strict=True),
        ]:
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))


class ImageOverlayTests(unittest.TestCase):
    @staticmethod
    def static_amd64_elf(*, isa_needed: int | None) -> bytes:
        program_headers = 2
        note_offset = 64 + 56 * program_headers
        note = b""
        if isa_needed is not None:
            descriptor = struct.pack("<III", 0xC0008002, 4, isa_needed) + b"\x00" * 4
            note = struct.pack("<III", 4, len(descriptor), 5) + b"GNU\x00" + descriptor
        data = bytearray(note_offset + len(note))
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", data, 16, 2)
        struct.pack_into("<H", data, 18, 62)
        struct.pack_into("<Q", data, 24, 0x1000)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<H", data, 54, 56)
        struct.pack_into("<H", data, 56, program_headers)
        struct.pack_into("<I", data, 64, 1)
        struct.pack_into("<Q", data, 72, 0)
        struct.pack_into("<Q", data, 96, len(data))
        struct.pack_into("<Q", data, 104, len(data))
        if note:
            note_header = 64 + 56
            struct.pack_into("<I", data, note_header, 4)
            struct.pack_into("<Q", data, note_header + 8, note_offset)
            struct.pack_into("<Q", data, note_header + 32, len(note))
            data[note_offset:] = note
        return bytes(data)

    def test_static_elf_check_rejects_a_header_without_loadable_program(self) -> None:
        fake = bytearray(64)
        fake[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", fake, 16, 2)
        struct.pack_into("<H", fake, 18, 62)
        struct.pack_into("<Q", fake, 24, 0x1000)
        struct.pack_into("<Q", fake, 32, 64)
        struct.pack_into("<H", fake, 54, 56)
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "no loadable segment"):
            VALIDATOR.assert_static_elf(bytes(fake), "linux/amd64")

    def test_static_elf_requires_exact_amd64_v3_isa_note(self) -> None:
        for value in (4, 5):
            VALIDATOR.assert_static_elf(
                self.static_amd64_elf(isa_needed=value), "linux/amd64", "x86-64-v3"
            )
        for value in (None, 1, 2, 3, 6, 7, 8, 9):
            with self.subTest(isa_needed=value):
                with self.assertRaisesRegex(VALIDATOR.ValidationError, "ISA-needed v3"):
                    VALIDATOR.assert_static_elf(
                        self.static_amd64_elf(isa_needed=value), "linux/amd64", "x86-64-v3"
                    )

    def test_opaque_whiteout_removes_only_lower_layer_children(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "image.tar"
            opaque = tarfile.TarInfo("tree/.wh..wh..opq")
            opaque.mode = 0o000
            write_docker_archive(
                archive,
                [
                    layer_bytes([regular("tree/old")]),
                    layer_bytes([(opaque, b""), regular("tree/new")]),
                ],
            )

            _, files, _ = VALIDATOR.load_archive(archive)

            self.assertNotIn("/tree/old", files)
            self.assertEqual(files["/tree/new"].data, b"data")

    def test_directory_whiteout_removes_lower_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "image.tar"
            whiteout = tarfile.TarInfo(".wh.tree")
            write_docker_archive(
                archive,
                [layer_bytes([regular("tree/old")]), layer_bytes([(whiteout, b"")])],
            )

            _, files, _ = VALIDATOR.load_archive(archive)

            self.assertNotIn("/tree/old", files)

    def test_unsupported_special_entry_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "image.tar"
            fifo = tarfile.TarInfo("run/unsafe")
            fifo.type = tarfile.FIFOTYPE
            write_docker_archive(archive, [layer_bytes([(fifo, None)])])

            with self.assertRaisesRegex(
                VALIDATOR.ValidationError, "unsupported special archive entry"
            ):
                VALIDATOR.load_archive(archive)

    def test_root_confined_symlink_is_recorded_without_following_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "image.tar"
            symlink = tarfile.TarInfo("bin/tool")
            symlink.type = tarfile.SYMTYPE
            symlink.linkname = "../usr/bin/tool"
            write_docker_archive(archive, [layer_bytes([(symlink, None)])])

            _, files, _ = VALIDATOR.load_archive(archive)

            self.assertEqual(files["/bin/tool"].link_target, "/usr/bin/tool")

    def test_symlink_that_escapes_rootfs_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "image.tar"
            symlink = tarfile.TarInfo("bin/tool")
            symlink.type = tarfile.SYMTYPE
            symlink.linkname = "../../outside"
            write_docker_archive(archive, [layer_bytes([(symlink, None)])])

            with self.assertRaisesRegex(VALIDATOR.ValidationError, "escapes the rootfs"):
                VALIDATOR.load_archive(archive)

    def test_required_file_rejects_mutable_or_non_root_metadata(self) -> None:
        for entry, message in [
            (VALIDATOR.FileEntry(0o666, 0, 0, b"data"), "mode"),
            (VALIDATOR.FileEntry(0o644, 10001, 10001, b"data"), "owned by 0:0"),
        ]:
            with self.subTest(message=message):
                with self.assertRaisesRegex(VALIDATOR.ValidationError, message):
                    VALIDATOR.required_file({"/evidence": entry}, "/evidence")

    def test_adapter_validator_rejects_a_blocked_image_plan(self) -> None:
        plan = {
            "schemaVersion": 3,
            "amd64IsaBaseline": "x86-64-v3",
            "roles": [{"role": "filebelt-git-adapter", "imageBuild": {"state": "blocked"}}],
        }
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "image-build gate is not eligible"):
            VALIDATOR.validate_adapter(plan, "filebelt-git-adapter", "linux/amd64", {}, {})

    def test_adapter_validator_binds_source_bundle_labels(self) -> None:
        revision = "1" * 40
        plan = {
            "schemaVersion": 3,
            "amd64IsaBaseline": "x86-64-v3",
            "source": {"created": "2026-08-15T00:00:00Z"},
            "roles": [{
                "role": "filebelt-git-adapter",
                "imageBuild": {"state": "eligible"},
                "platforms": ["linux/amd64"],
                "source": {
                    "url": "https://github.com/OxiBelt/FileBelt",
                    "ref": "refs/tags/0.1.0",
                    "revision": revision,
                },
                "sourceBundle": {"publicUrl": "https://example.test/0.1.0/source.tar.gz", "sha256": "a" * 64},
                "firstPartyLicense": "Apache-2.0",
                "imageLicense": "Apache-2.0 AND GPL-2.0-only AND MIT AND Zlib",
                "executablePaths": ["/usr/local/bin/filebelt-git-adapter"],
                "entrypoint": "/usr/local/bin/filebelt-git-adapter",
            }],
        }
        config = {
            "os": "linux",
            "architecture": "amd64",
            "config": {
                "User": "10001:10001",
                "Entrypoint": ["/usr/local/bin/filebelt-git-adapter"],
                "Labels": {
                    "org.opencontainers.image.source": "https://github.com/OxiBelt/FileBelt",
                    "org.opencontainers.image.version": "refs/tags/0.1.0",
                    "org.opencontainers.image.revision": revision,
                    "org.opencontainers.image.created": "2026-08-15T00:00:00Z",
                    "org.opencontainers.image.licenses": "Apache-2.0 AND GPL-2.0-only AND MIT AND Zlib",
                    "io.filebelt.image.role": "filebelt-git-adapter",
                    "io.filebelt.build.target-cpu": "x86-64-v3",
                    "io.filebelt.first-party-license": "Apache-2.0",
                    "io.filebelt.corresponding-source": "https://example.test/0.1.0/source.tar.gz",
                    "io.filebelt.corresponding-source.sha256": "b" * 64,
                    "io.filebelt.qualification.license": "qualified",
                    "io.filebelt.qualification.image-build": "eligible",
                },
            },
        }
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "corresponding-source.sha256"):
            VALIDATOR.validate_adapter(plan, "filebelt-git-adapter", "linux/amd64", config, {})


if __name__ == "__main__":
    unittest.main()
