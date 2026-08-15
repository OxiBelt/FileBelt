# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import pathlib
import tempfile
import unittest

from tests.scripts.adapter_source_bundle import BundleError, package_bundle, validate_bundle


ROLE = "filebelt-git-adapter"
VERSION = "1.2.3"
REVISION = "1" * 40
TIMESTAMP = 1_786_742_400


class PackageAdapterSourceBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name) / "staging"
        self.inputs = self.root / "adapter-inputs" / "git"
        (self.root / "source" / "adapters" / "git").mkdir(parents=True)
        (self.root / "source" / "LICENSES").mkdir()
        (self.root / "source" / "adapters" / "git" / "Cargo.lock").write_text(
            'version = 4\n[[package]]\nname = "demo"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + "0" * 64 + '"\n',
            encoding="utf-8",
        )
        for directory in ("LICENSES", "NOTICES", "upstream", "patches", "vendor/cargo/demo", "build-inputs", ".cargo"):
            (self.inputs / directory).mkdir(parents=True, exist_ok=True)
        canonical_license = self.root / "source" / "LICENSES" / "GPL-2.0-only.txt"
        canonical_license.write_text("license\n", encoding="utf-8")
        (self.inputs / "LICENSES" / "GPL-2.0-only.txt").write_bytes(canonical_license.read_bytes())
        (self.inputs / "NOTICES" / "THIRD_PARTY_NOTICES.md").write_text("notice\n", encoding="utf-8")
        upstream = self.inputs / "upstream" / "demo.tar.xz"
        upstream.write_bytes(b"verified source")
        (self.inputs / "BUILD.md").write_text("build offline\n", encoding="utf-8")
        (self.inputs / ".cargo" / "config.toml").write_text(
            '[source.crates-io]\nreplace-with = "vendored-sources"\n[source.vendored-sources]\ndirectory = "vendor/cargo"\n[net]\noffline = true\n',
            encoding="utf-8",
        )
        vendor = self.inputs / "vendor" / "cargo" / "demo"
        (vendor / "Cargo.toml").write_text('[package]\nname = "demo"\nversion = "1.0.0"\n', encoding="utf-8")
        (vendor / ".cargo-checksum.json").write_text(
            '{"files":{},"package":"' + "0" * 64 + '"}\n', encoding="utf-8"
        )
        manifest = {
            "schemaVersion": 1,
            "role": ROLE,
            "version": VERSION,
            "sourceRevision": REVISION,
            "imageLicense": "Apache-2.0 AND GPL-2.0-only",
            "inputs": [
                {
                    "name": "demo",
                    "version": "1.0.0",
                    "spdx": "GPL-2.0-only",
                    "relationship": "separate-executable",
                    "upstreamUrl": "https://example.test/releases/download/1.0.0/demo.tar.xz",
                    "archivePath": "adapter-inputs/git/upstream/demo.tar.xz",
                    "sha256": hashlib.sha256(upstream.read_bytes()).hexdigest(),
                    "modified": False,
                    "patchPaths": [],
                    "buildInstructions": "See adapter-inputs/git/BUILD.md",
                    "platforms": ["linux/amd64"],
                    "systemLibrary": False,
                }
            ],
        }
        (self.inputs / "SOURCE-MANIFEST.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def output(self, directory: str) -> pathlib.Path:
        path = pathlib.Path(self.temporary.name) / directory / f"{ROLE}-source-{VERSION}.tar.gz"
        path.parent.mkdir()
        return path

    def test_package_is_deterministic(self) -> None:
        first = self.output("one")
        second = self.output("two")
        first_hash = package_bundle(self.root, first, ROLE, VERSION, REVISION, TIMESTAMP)
        second_hash = package_bundle(self.root, second, ROLE, VERSION, REVISION, TIMESTAMP)
        self.assertEqual(first_hash, second_hash)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(validate_bundle(first, ROLE, VERSION, REVISION, TIMESTAMP), first_hash)

    def test_rejects_wrong_upstream_checksum(self) -> None:
        manifest = json.loads((self.inputs / "SOURCE-MANIFEST.json").read_text())
        manifest["inputs"][0]["sha256"] = "f" * 64
        (self.inputs / "SOURCE-MANIFEST.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(BundleError, "checksum does not match"):
            package_bundle(self.root, self.output("one"), ROLE, VERSION, REVISION, TIMESTAMP)

    def test_rejects_mutable_upstream_url(self) -> None:
        manifest = json.loads((self.inputs / "SOURCE-MANIFEST.json").read_text())
        manifest["inputs"][0]["upstreamUrl"] = "https://example.test/tree/main/demo.tar.xz"
        (self.inputs / "SOURCE-MANIFEST.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(BundleError, "mutable upstream URL"):
            package_bundle(self.root, self.output("one"), ROLE, VERSION, REVISION, TIMESTAMP)

    def test_rejects_missing_license_or_notice(self) -> None:
        (self.inputs / "LICENSES" / "GPL-2.0-only.txt").unlink()
        with self.assertRaisesRegex(BundleError, "license-text inventory is empty"):
            package_bundle(self.root, self.output("one"), ROLE, VERSION, REVISION, TIMESTAMP)

    def test_rejects_incomplete_vendor_closure(self) -> None:
        (self.inputs / "vendor" / "cargo" / "demo" / "Cargo.toml").unlink()
        with self.assertRaisesRegex(BundleError, "Cargo vendor closure is incomplete"):
            package_bundle(self.root, self.output("one"), ROLE, VERSION, REVISION, TIMESTAMP)

    def test_rejects_unsafe_file_type(self) -> None:
        (self.root / "source" / "unsafe-link").symlink_to("Cargo.toml")
        with self.assertRaisesRegex(BundleError, "unsafe file type"):
            package_bundle(self.root, self.output("one"), ROLE, VERSION, REVISION, TIMESTAMP)


if __name__ == "__main__":
    unittest.main()
