#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for OxiBelt Helm configuration fixture staging."""

from __future__ import annotations

import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


IMAGE_REF = "ghcr.io/oxibelt/filebelt-web:test"
CASES = {
    "default": "success",
    "collaboration-webtransport": "success",
    "documents": "success",
    "default-world-readable-api-key": "failure",
    "default-missing-api-key": "failure",
    "default-missing-api-cert": "failure",
    "default-mismatched-api-cert-key": "failure",
}
CERTIFICATE_DIRECTORIES = (
    "public-tls",
    "api-client-tls",
    "io-client-tls",
    "collaboration-edge-client-tls",
    "onlyoffice-edge-client-tls",
)
API_CERTIFICATE = "etc/oxibelt/cert/api-client-tls/tls.crt"
API_KEY = "etc/oxibelt/cert/api-client-tls/tls.key"


class OxiBeltHelmConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="filebelt-oxibelt-helm-test-")
        self.directory = Path(self.temporary.name)
        self.fake_bin = self.directory / "bin"
        self.state = self.directory / "docker-state"
        self.helm_config = self.directory / "helm-config"
        self.helm_cache = self.directory / "helm-cache"
        self.helm_data = self.directory / "helm-data"
        self.fake_bin.mkdir()
        self.state.mkdir()
        self.helm_config.mkdir()
        self.helm_cache.mkdir()
        self.helm_data.mkdir()
        self.script = Path(__file__).with_name("check-oxibelt-helm-config.sh")
        self.archive = self.directory / "web-image.tar"
        self.write_image_archive()
        self.write_docker()
        if os.geteuid() == 0:
            # Keep the fixture private while allowing the dropped user to stage it.
            for path in (self.directory, *self.directory.rglob("*")):
                os.chown(path, 65534, 65534)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_image_archive(self) -> None:
        manifest = json.dumps([{"RepoTags": [IMAGE_REF]}]).encode("utf-8")
        with tarfile.open(self.archive, "w") as output:
            member = tarfile.TarInfo("manifest.json")
            member.size = len(manifest)
            member.mode = 0o644
            output.addfile(member, io.BytesIO(manifest))

    def write_docker(self) -> None:
        docker = self.fake_bin / "docker"
        docker.write_text(
            """#!/bin/sh
set -eu

state=${FAKE_DOCKER_STATE:?}
if [ ! -e "${state}/uid" ]; then
  id -u >"${state}/uid"
  id -g >"${state}/gid"
fi

command=${1-}
shift || true
case "${command}" in
  image)
    case "${1-}:${2-}" in
      inspect:*) exit 1 ;;
      rm:--force)
        printf 'image-rm %s\\n' "${3-}" >>"${state}/operations"
        exit 0
        ;;
    esac
    exit 2
    ;;
  load)
    [ "${1-}" = "--input" ]
    printf 'load %s\\n' "${2-}" >>"${state}/operations"
    printf 'Loaded image: %s\\n' "${MOCK_IMAGE_REF}"
    ;;
  create)
    [ "${1-}" = "--name" ]
    name=${2:?}
    : >"${state}/${name}.created"
    printf 'create %s\\n' "${name}" >>"${state}/operations"
    ;;
  cp)
    [ "${1-}" = "-" ]
    name=${2%:/}
    [ -e "${state}/${name}.created" ]
    cat >"${state}/${name}.tar"
    printf 'copy %s\\n' "${name}" >>"${state}/operations"
    ;;
  start)
    [ "${1-}" = "--attach" ]
    name=${2:?}
    [ -f "${state}/${name}.tar" ]
    case "${name}" in
      *-default-world-readable-api-key-*|*-default-missing-api-key-*|*-default-missing-api-cert-*|*-default-mismatched-api-cert-key-*)
        printf 'start failure %s\\n' "${name}" >>"${state}/operations"
        exit 1
        ;;
      *)
        printf 'start success %s\\n' "${name}" >>"${state}/operations"
        ;;
    esac
    ;;
  rm)
    [ "${1-}" = "--force" ]
    name=${2:?}
    [ -e "${state}/${name}.created" ]
    : >"${state}/${name}.removed"
    printf 'remove %s\\n' "${name}" >>"${state}/operations"
    ;;
  *) exit 2 ;;
esac
""",
            encoding="utf-8",
        )
        docker.chmod(0o755)

    def run_helper(self) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "PATH": f"{self.fake_bin}:{os.environ['PATH']}",
            "TMPDIR": str(self.directory),
            "FAKE_DOCKER_STATE": str(self.state),
            "MOCK_IMAGE_REF": IMAGE_REF,
            "HELM_CONFIG_HOME": str(self.helm_config),
            "HELM_CACHE_HOME": str(self.helm_cache),
            "HELM_DATA_HOME": str(self.helm_data),
        }
        arguments: dict[str, object] = {}
        if os.geteuid() == 0:
            arguments.update(user=65534, group=65534, extra_groups=[])
        return subprocess.run(
            ["bash", str(self.script), "--archive", str(self.archive)],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            **arguments,
        )

    def captured_archives(self) -> dict[str, Path]:
        archives: dict[str, Path] = {}
        prefix = "filebelt-oxibelt-helm-"
        for archive in self.state.glob("*.tar"):
            name = archive.name.removesuffix(".tar")
            self.assertTrue(name.startswith(prefix), name)
            suffix = name.removeprefix(prefix)
            matches = [
                case for case in sorted(CASES, key=len, reverse=True)
                if suffix.startswith(f"{case}-")
            ]
            self.assertTrue(matches, name)
            archives[matches[0]] = archive
        return archives

    def read_archive(self, path: Path) -> tuple[dict[str, bytes], dict[str, tuple[int, int, int]]]:
        contents: dict[str, bytes] = {}
        metadata: dict[str, tuple[int, int, int]] = {}
        with tarfile.open(path) as archive:
            for member in archive.getmembers():
                metadata[member.name] = (member.mode, member.uid, member.gid)
                if member.isfile():
                    source = archive.extractfile(member)
                    self.assertIsNotNone(source, member.name)
                    contents[member.name] = source.read()
        return contents, metadata

    def assert_normal_permissions(self, metadata: dict[str, tuple[int, int, int]]) -> None:
        self.assertEqual(metadata["etc/oxibelt/config/oxibelt.toml"], (0o444, 10001, 10001))
        for directory in CERTIFICATE_DIRECTORIES:
            for name, mode in (("server-ca.crt", 0o444), ("tls.crt", 0o444), ("tls.key", 0o440)):
                path = f"etc/oxibelt/cert/{directory}/{name}"
                self.assertEqual(metadata[path], (mode, 10001, 10001), path)

    def assert_key_matches_certificate(self, certificate: bytes, key: bytes, *, matching: bool) -> None:
        certificate_path = self.directory / "api.crt"
        key_path = self.directory / "api.key"
        certificate_path.write_bytes(certificate)
        key_path.write_bytes(key)
        certificate_public = subprocess.run(
            ["openssl", "x509", "-in", str(certificate_path), "-pubkey", "-noout"],
            check=True,
            capture_output=True,
        ).stdout
        key_public = subprocess.run(
            ["openssl", "pkey", "-in", str(key_path), "-pubout"],
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(certificate_public == key_public, matching)

    def test_unprivileged_helper_stages_independent_archives(self) -> None:
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        for case, outcome in CASES.items():
            self.assertIn(f"checking {case} OxiBelt configuration (expected {outcome})", result.stdout)
            self.assertIn(f"{case} OxiBelt configuration check passed ({outcome})", result.stdout)
        self.assertIn("native OxiBelt Helm configuration checks passed", result.stdout)

        uid = int((self.state / "uid").read_text(encoding="ascii"))
        self.assertNotEqual(uid, 0)
        if os.geteuid() == 0:
            self.assertEqual(uid, 65534)
            self.assertEqual((self.state / "gid").read_text(encoding="ascii").strip(), "65534")

        archives = self.captured_archives()
        self.assertEqual(set(archives), set(CASES))
        fixture = {case: self.read_archive(path) for case, path in archives.items()}
        default_contents, default_metadata = fixture["default"]
        self.assert_normal_permissions(default_metadata)
        self.assert_key_matches_certificate(default_contents[API_CERTIFICATE], default_contents[API_KEY], matching=True)

        for case in ("collaboration-webtransport", "documents"):
            contents, metadata = fixture[case]
            self.assert_normal_permissions(metadata)
            self.assert_key_matches_certificate(contents[API_CERTIFICATE], contents[API_KEY], matching=True)

        contents, metadata = fixture["default-world-readable-api-key"]
        self.assertEqual(contents, default_contents)
        self.assertEqual(set(metadata), set(default_metadata))
        for path, value in metadata.items():
            expected = (0o644, 10001, 10001) if path == API_KEY else default_metadata[path]
            self.assertEqual(value, expected, path)

        for case, missing in (("default-missing-api-key", API_KEY), ("default-missing-api-cert", API_CERTIFICATE)):
            contents, metadata = fixture[case]
            self.assertEqual(set(contents), set(default_contents) - {missing})
            self.assertEqual(set(metadata), set(default_metadata) - {missing})
            self.assertEqual(
                contents,
                {path: value for path, value in default_contents.items() if path != missing},
            )
            for path, value in metadata.items():
                self.assertEqual(value, default_metadata[path], f"{case}: {path}")

        contents, metadata = fixture["default-mismatched-api-cert-key"]
        self.assertEqual(set(contents), set(default_contents))
        self.assertEqual(set(metadata), set(default_metadata))
        self.assertNotEqual(contents[API_KEY], default_contents[API_KEY])
        self.assertEqual(
            {path: value for path, value in contents.items() if path != API_KEY},
            {path: value for path, value in default_contents.items() if path != API_KEY},
        )
        for path, value in metadata.items():
            self.assertEqual(value, default_metadata[path], path)
        self.assert_key_matches_certificate(contents[API_CERTIFICATE], contents[API_KEY], matching=False)

        operations = (self.state / "operations").read_text(encoding="utf-8").splitlines()
        creates = [line.removeprefix("create ") for line in operations if line.startswith("create ")]
        starts = [line.split(maxsplit=2)[2] for line in operations if line.startswith("start ")]
        removes = [line.removeprefix("remove ") for line in operations if line.startswith("remove ")]
        self.assertEqual(len(creates), len(CASES))
        self.assertEqual(set(creates), set(starts))
        self.assertEqual(set(creates), set(removes))
        self.assertEqual(operations.count(f"image-rm {IMAGE_REF}"), 1)
        for name in creates:
            self.assertTrue((self.state / f"{name}.removed").exists(), name)
        self.assertEqual(list(self.directory.glob("filebelt-oxibelt-helm.*")), [])


if __name__ == "__main__":
    unittest.main()
