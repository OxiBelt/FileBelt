#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


class PackageReleaseAssetsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.output = self.root / "output"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.script = Path(__file__).with_name("package-release-assets.sh")
        self.repo = self.script.resolve().parents[2]
        self.version = json.loads(
            (self.repo / "package.json").read_text(encoding="utf-8")
        )["version"]
        helm = self.bin / "helm"
        helm.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == lint ]]; then exit 0; fi
if [[ "$1" == package ]]; then
  destination=
  version=
  chart=
  while (( $# > 0 )); do
    case "$1" in
      --destination) destination=$2; shift 2 ;;
      --version) version=$2; shift 2 ;;
      --app-version) shift 2 ;;
      --*) shift ;;
      *) chart=${1##*/}; shift ;;
    esac
  done
  printf 'chart %s\n' "$version" >"$destination/$chart-$version.tgz"
  exit 0
fi
exit 1
""",
            encoding="utf-8",
        )
        helm.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_script(self) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PATH"] = f"{self.bin}:{environment['PATH']}"
        return subprocess.run(
            [self.script, "--output-dir", self.output],
            cwd=self.repo,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_packages_licensed_admin_assets_and_checksums(self) -> None:
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        chart = self.output / f"filebelt-{self.version}.tgz"
        onlyoffice_chart = self.output / f"filebelt-onlyoffice-{self.version}.tgz"
        admin = self.output / f"filebelt-postgresql-admin-{self.version}.tar.gz"
        checksums = self.output / "SHA256SUMS"
        self.assertTrue(chart.is_file())
        self.assertTrue(onlyoffice_chart.is_file())
        self.assertTrue(admin.is_file())
        with tarfile.open(admin, "r:gz") as archive:
            names = {
                name.removeprefix(f"filebelt-postgresql-admin-{self.version}/")
                for name in archive.getnames()
            }
        self.assertTrue({"LICENSE", "README.md", "roles.sql", "grants.sql"} <= names)
        expected = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (chart, onlyoffice_chart, admin)
        }
        observed = {
            line.split("  ", 1)[1]: line.split("  ", 1)[0]
            for line in checksums.read_text(encoding="ascii").splitlines()
        }
        self.assertEqual(observed, expected)

    def test_refuses_to_replace_an_existing_release_asset(self) -> None:
        first = self.run_script()
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self.run_script()
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("refusing to replace release asset", second.stderr)


if __name__ == "__main__":
    unittest.main()
