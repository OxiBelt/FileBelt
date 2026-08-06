#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for normalized Docker archive comparison."""

from __future__ import annotations

import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


def load_comparator() -> ModuleType:
    path = Path(__file__).with_name("compare-image-artifacts.py")
    spec = importlib.util.spec_from_file_location("compare_image_artifacts", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load image comparison module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COMPARATOR = load_comparator()


def add_bytes(archive: tarfile.TarFile, name: str, value: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(value)
    member.mtime = 0
    archive.addfile(member, io.BytesIO(value))


def write_docker_archive(path: Path, layer_members: list[tarfile.TarInfo]) -> None:
    write_docker_archive_layers(path, [layer_members])


def write_docker_archive_layers(
    path: Path, layers: list[list[tarfile.TarInfo]]
) -> None:
    layer_values: list[tuple[str, bytes]] = []
    for index, layer_members in enumerate(layers):
        layer_buffer = io.BytesIO()
        with tarfile.open(fileobj=layer_buffer, mode="w") as layer:
            for member in layer_members:
                member.mtime = 0
                if member.isfile():
                    data = b"payload"
                    member.size = len(data)
                    layer.addfile(member, io.BytesIO(data))
                else:
                    layer.addfile(member)
        layer_values.append((f"layer-{index}.tar", layer_buffer.getvalue()))

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"User": "10001:10001", "Labels": {"example": "stable"}},
    }
    manifest = [
        {
            "Config": "config.json",
            "RepoTags": ["example:test"],
            "Layers": [name for name, _ in layer_values],
        }
    ]
    with tarfile.open(path, mode="w") as outer:
        add_bytes(outer, "config.json", json.dumps(config).encode())
        add_bytes(outer, "manifest.json", json.dumps(manifest).encode())
        for name, value in layer_values:
            add_bytes(outer, name, value)


class ArchiveContractTests(unittest.TestCase):
    def test_directory_metadata_changes_are_material(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.tar"
            second = Path(directory) / "second.tar"
            first_dir = tarfile.TarInfo("srv/")
            first_dir.type = tarfile.DIRTYPE
            first_dir.mode = 0o755
            first_dir.uid = 10001
            first_dir.gid = 10001
            second_dir = tarfile.TarInfo("srv/")
            second_dir.type = tarfile.DIRTYPE
            second_dir.mode = 0o700
            second_dir.uid = 10001
            second_dir.gid = 10001
            write_docker_archive(first, [first_dir])
            write_docker_archive(second, [second_dir])
            self.assertNotEqual(
                COMPARATOR.archive_contract(first), COMPARATOR.archive_contract(second)
            )

    def test_hardlinks_are_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            target = tarfile.TarInfo("bin/probe")
            target.mode = 0o755
            link = tarfile.TarInfo("bin/probe-link")
            link.type = tarfile.LNKTYPE
            link.linkname = "bin/probe"
            link.mode = 0o755
            write_docker_archive(path, [target, link])
            filesystem = COMPARATOR.archive_contract(path)["filesystem"]
            self.assertEqual(filesystem["/bin/probe-link"]["type"], "hardlink")
            self.assertEqual(filesystem["/bin/probe-link"]["target"], "bin/probe")
            self.assertEqual(
                filesystem["/bin/probe-link"]["sha256"],
                filesystem["/bin/probe"]["sha256"],
            )

    def test_special_entries_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            fifo = tarfile.TarInfo("run/unsafe")
            fifo.type = tarfile.FIFOTYPE
            write_docker_archive(path, [fifo])
            with self.assertRaises(COMPARATOR.ComparisonError):
                COMPARATOR.archive_contract(path)

    def test_opaque_whiteout_preserves_same_layer_entries_regardless_of_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            lower_file = tarfile.TarInfo("srv/lower.txt")
            same_layer_file = tarfile.TarInfo("srv/current.txt")
            opaque = tarfile.TarInfo("srv/.wh..wh..opq")
            write_docker_archive_layers(path, [[lower_file], [same_layer_file, opaque]])
            filesystem = COMPARATOR.archive_contract(path)["filesystem"]
            self.assertNotIn("/srv/lower.txt", filesystem)
            self.assertIn("/srv/current.txt", filesystem)

    def test_directory_whiteout_removes_lower_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            directory_entry = tarfile.TarInfo("opt/cache/")
            directory_entry.type = tarfile.DIRTYPE
            lower_file = tarfile.TarInfo("opt/cache/data.bin")
            whiteout = tarfile.TarInfo("opt/.wh.cache")
            write_docker_archive_layers(
                path, [[directory_entry, lower_file], [whiteout]]
            )
            filesystem = COMPARATOR.archive_contract(path)["filesystem"]
            self.assertNotIn("/opt/cache", filesystem)
            self.assertNotIn("/opt/cache/data.bin", filesystem)


if __name__ == "__main__":
    unittest.main()
