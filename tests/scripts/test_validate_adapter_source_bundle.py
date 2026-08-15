# SPDX-License-Identifier: Apache-2.0

import gzip
import io
import hashlib
import json
import pathlib
import tarfile
import tempfile
import unittest

from tests.scripts.adapter_source_bundle import BundleError, validate_bundle, validate_bundle_against_plan


ROLE = "filebelt-git-adapter"
VERSION = "1.2.3"
REVISION = "1" * 40
TIMESTAMP = 1_786_742_400


class ValidateAdapterSourceBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.temporary.name) / f"{ROLE}-source-{VERSION}.tar.gz"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_archive(self, entries: list[tuple[str, bytes]], *, timestamp: int = TIMESTAMP) -> None:
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, contents in entries:
                info = tarfile.TarInfo(name)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mode = 0o644
                info.mtime = timestamp
                info.size = len(contents)
                archive.addfile(info, io.BytesIO(contents))
        with self.path.open("wb") as raw:
            with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as stream:
                stream.write(tar_buffer.getvalue())

    def manifest_entry(self, revision: str = REVISION) -> tuple[str, bytes]:
        name = f"{ROLE}-source-{VERSION}/adapter-inputs/git/SOURCE-MANIFEST.json"
        return name, json.dumps({
            "sourceRevision": revision,
            "imageLicense": "Apache-2.0 AND GPL-2.0-only AND MIT AND Zlib",
        }).encode()

    def write_plan(self, *, revision: str = REVISION, license_expression: str = "Apache-2.0 AND GPL-2.0-only AND MIT AND Zlib") -> pathlib.Path:
        plan_path = pathlib.Path(self.temporary.name) / "plan.json"
        plan_path.write_text(json.dumps({
            "schemaVersion": 2,
            "version": VERSION,
            "roles": [{
                "role": ROLE,
                "imageLicense": license_expression,
                "source": {"revision": revision},
                "sourceBundle": {
                    "assetName": self.path.name,
                    "sha256": hashlib.sha256(self.path.read_bytes()).hexdigest(),
                },
            }],
        }))
        return plan_path

    def test_rejects_duplicate_entries(self) -> None:
        item = self.manifest_entry()
        self.write_archive([item, item])
        with self.assertRaisesRegex(BundleError, "duplicate archive entry"):
            validate_bundle(self.path, ROLE, VERSION, REVISION, TIMESTAMP)

    def test_rejects_unsafe_tar_path(self) -> None:
        prefix = f"{ROLE}-source-{VERSION}"
        self.write_archive([(f"{prefix}/../escape", b"bad"), self.manifest_entry()])
        with self.assertRaisesRegex(BundleError, "unsafe bundle path"):
            validate_bundle(self.path, ROLE, VERSION, REVISION, TIMESTAMP)

    def test_rejects_nondeterministic_metadata(self) -> None:
        self.write_archive([self.manifest_entry()], timestamp=TIMESTAMP + 1)
        with self.assertRaisesRegex(BundleError, "timestamp does not match"):
            validate_bundle(self.path, ROLE, VERSION, REVISION, TIMESTAMP)

    def test_rejects_revision_mismatch(self) -> None:
        self.write_archive([self.manifest_entry("2" * 40)])
        with self.assertRaisesRegex(BundleError, "source revision does not match"):
            validate_bundle(self.path, ROLE, VERSION, REVISION, TIMESTAMP)

    def test_plan_mapping_accepts_exact_bundle_identity(self) -> None:
        self.write_archive([self.manifest_entry()])
        validate_bundle_against_plan(self.path, self.write_plan(), ROLE)

    def test_plan_mapping_rejects_license_mismatch(self) -> None:
        self.write_archive([self.manifest_entry()])
        with self.assertRaisesRegex(BundleError, "license expressions differ"):
            validate_bundle_against_plan(
                self.path,
                self.write_plan(license_expression="GPL-2.0-only"),
                ROLE,
            )


if __name__ == "__main__":
    unittest.main()
