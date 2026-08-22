#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ACTIVE_ROLES = (
    "filebelt-api",
    "filebelt-worker-io",
    "filebelt-worker-maintenance",
    "filebelt-collaboration",
    "filebelt-mcp-broker",
    "filebelt-controller",
    "filebelt-mcp-runner",
    "filebelt-tools",
    "filebelt-vfs",
    "filebelt-headscale-sync",
    "filebelt-nfs-relay",
    "filebelt-document",
    "filebelt-revision",
    "filebelt-web",
)
PREVIEW_ROLES = (
    "filebelt-private-egress-gateway",
    "filebelt-tunnel-relay",
)
ARCHITECTURES = ("amd64", "arm64", "riscv64")
DIGEST = "sha256:" + "a" * 64
REVISION = "b" * 40


class PromoteReleaseArtifactsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / "artifacts"
        self.bin = self.root / "bin"
        self.artifacts.mkdir()
        self.bin.mkdir()
        self.state = self.root / "docker-state"
        self.log = self.root / "docker-log"
        self.state.write_text("", encoding="utf-8")
        self.log.write_text("", encoding="utf-8")
        self.script = Path(__file__).with_name("promote-release-artifacts.sh")
        self.plan = self.root / "plan.json"
        self.output = self.root / "subjects.json"
        self._write_plan()
        self._write_artifacts()
        self._write_fake_docker()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_plan(self) -> None:
        images = [
            {
                "role": role,
                "repository": f"ghcr.io/oxibelt/{role}",
                "platforms": [f"linux/{architecture}" for architecture in ARCHITECTURES],
                "artifact": {
                    "targetCpu": {
                        "linux/amd64": "x86-64-v3",
                        "linux/arm64": None,
                        "linux/riscv64": None,
                    }
                },
            }
            for role in (*ACTIVE_ROLES, "filebelt-media-controller", *PREVIEW_ROLES)
        ]
        self.plan.write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "amd64IsaBaseline": "x86-64-v3",
                    "channel": "release",
                    "version": "1.2.3",
                    "tag": "1.2.3",
                    "source": {
                        "kind": "release",
                        "dirty": False,
                        "url": "https://github.com/OxiBelt/FileBelt",
                        "ref": "refs/tags/1.2.3",
                        "revision": REVISION,
                        "created": "2026-08-07T00:00:00Z",
                    },
                    "runtime": {"uid": 10001, "gid": 10001},
                    "images": images,
                }
            ),
            encoding="utf-8",
        )

    def _write_artifacts(self) -> None:
        plan_sha = hashlib.sha256(self.plan.read_bytes()).hexdigest()
        for role in ACTIVE_ROLES:
            for architecture in ARCHITECTURES:
                directory = self.artifacts / architecture
                directory.mkdir(exist_ok=True)
                archive = directory / f"{role}-{architecture}.docker.tar"
                archive.write_bytes(f"{role}/{architecture}".encode())
                metadata = {
                    "role": role,
                    "platform": f"linux/{architecture}",
                    "planSha256": plan_sha,
                    "repository": f"ghcr.io/oxibelt/{role}",
                    "version": "1.2.3",
                    "tag": "1.2.3",
                    "sourceKind": "release",
                    "sourceDirty": False,
                    "sourceRevision": REVISION,
                    "sourceRef": "refs/tags/1.2.3",
                    "sourceCreated": "2026-08-07T00:00:00Z",
                    "localRef": f"ghcr.io/oxibelt/{role}:1.2.3-{architecture}",
                    "archive": archive.name,
                    "archiveSha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                    "schemaVersion": 2,
                    "targetCpu": "x86-64-v3" if architecture == "amd64" else None,
                }
                metadata_path = directory / f"{role}-{architecture}.build.json"
                metadata_path.write_text(
                    json.dumps(metadata), encoding="utf-8"
                )
                (directory / f"{role}-{architecture}.evidence.json").write_text(
                    json.dumps(
                        {
                            "schemaVersion": 2,
                            "planSha256": plan_sha,
                            "role": role,
                            "platform": f"linux/{architecture}",
                            "repository": metadata["repository"],
                            "tag": "1.2.3",
                            "localRef": metadata["localRef"],
                            "sourceRevision": REVISION,
                            "targetCpu": metadata["targetCpu"],
                            "archive": archive.name,
                            "archiveSha256": metadata["archiveSha256"],
                            "metadataSha256": hashlib.sha256(
                                metadata_path.read_bytes()
                            ).hexdigest(),
                        }
                    ),
                    encoding="utf-8",
                )
                (directory / f"{role}-{architecture}.docker.tar.sha256").write_text(
                    f"{metadata['archiveSha256']}  {archive.name}\n", encoding="ascii"
                )
                (directory / f"{role}-{architecture}.validation.json").write_text(
                    json.dumps(
                        {
                            "schemaVersion": 2,
                            "role": role,
                            "platform": f"linux/{architecture}",
                            "sourceRevision": REVISION,
                            "targetCpu": metadata["targetCpu"],
                            "repositoryTag": metadata["localRef"],
                        }
                    ),
                    encoding="utf-8",
                )
                (directory / f"{role}-{architecture}.smoke.json").write_text(
                    json.dumps(
                        {
                            "schemaVersion": 1,
                            "role": role,
                            "platform": f"linux/{architecture}",
                            "sourceRevision": REVISION,
                            "passed": True,
                        }
                    ),
                    encoding="utf-8",
                )
                (directory / f"{role}-{architecture}.vulnerability-decision.json").write_text(
                    json.dumps(
                        {"schemaVersion": 1, "allowed": True, "blockedFindings": []}
                    ),
                    encoding="utf-8",
                )
                (directory / f"{role}-{architecture}.cdx.json").write_text(
                    "{}\n", encoding="utf-8"
                )
                (directory / f"{role}-{architecture}.runtime.cdx.json").write_text(
                    "{}\n", encoding="utf-8"
                )

    def _write_fake_docker(self) -> None:
        docker = self.bin / "docker"
        docker.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
echo "$*" >>"$DOCKER_LOG"
if [[ "$1 ${2:-} ${3:-}" == "buildx imagetools inspect" ]]; then
  reference=$4
  if grep -Fx -- "$reference" "$DOCKER_STATE" >/dev/null; then
    if [[ "${5:-}" == --raw ]]; then
      printf '{"manifests":['
      separator=
      for architecture in amd64 arm64 riscv64; do
        printf '%s{"digest":"%s","platform":{"os":"linux","architecture":"%s"}}' \
          "$separator" "$DOCKER_DIGEST" "$architecture"
        separator=,
      done
      printf ']}\n'
      exit 0
    fi
    printf '{"digest":"%s"}\n' "$DOCKER_DIGEST"
    exit 0
  fi
  exit 1
fi
if [[ "$1" == load ]]; then
  archive=$3
  base=${archive##*/}
  role=${base%-*.docker.tar}
  architecture=${base##*-}
  architecture=${architecture%.docker.tar}
  echo "Loaded image: ghcr.io/oxibelt/${role}:1.2.3-${architecture}"
  exit 0
fi
if [[ "$1" == push ]]; then
  echo "$2" >>"$DOCKER_STATE"
  exit 0
fi
if [[ "$1 ${2:-} ${3:-}" == "buildx imagetools create" ]]; then
  while (( $# > 0 )); do
    if [[ "$1" == --tag ]]; then echo "$2" >>"$DOCKER_STATE"; exit 0; fi
    shift
  done
fi
exit 0
""",
            encoding="utf-8",
        )
        docker.chmod(0o755)

    def run_script(self) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.bin}:{environment['PATH']}",
                "DOCKER_STATE": str(self.state),
                "DOCKER_LOG": str(self.log),
                "DOCKER_DIGEST": DIGEST,
            }
        )
        return subprocess.run(
            [
                self.script,
                "--plan",
                self.plan,
                "--artifacts-root",
                self.artifacts,
                "--registry",
                "ghcr.io",
                "--output",
                self.output,
            ],
            check=False,
            text=True,
            capture_output=True,
            env=environment,
        )

    def test_promotes_only_active_roles_and_records_readback_digests(self) -> None:
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        subjects = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(subjects["schemaVersion"], 1)
        self.assertEqual(subjects["version"], "1.2.3")
        self.assertEqual(
            [subject["role"] for subject in subjects["subjects"]], list(ACTIVE_ROLES)
        )
        self.assertTrue(all(subject["digest"] == DIGEST for subject in subjects["subjects"]))
        log = self.log.read_text(encoding="utf-8")
        self.assertNotIn("filebelt-media-controller", log)
        for role in PREVIEW_ROLES:
            self.assertNotIn(role, log)
            self.assertNotIn(role, [subject["role"] for subject in subjects["subjects"]])
        self.assertEqual(log.count("buildx imagetools create --tag"), len(ACTIVE_ROLES))

    def test_refuses_to_replace_an_existing_release_tag(self) -> None:
        self.state.write_text("ghcr.io/oxibelt/filebelt-api:1.2.3\n", encoding="utf-8")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to replace existing release reference", result.stderr)

    def test_refuses_an_archive_whose_checksum_no_longer_matches(self) -> None:
        archive = self.artifacts / "amd64" / "filebelt-api-amd64.docker.tar"
        archive.write_bytes(b"changed after validation")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive checksum mismatch", result.stderr)

    def test_refuses_a_plan_that_changes_an_expected_repository(self) -> None:
        plan = json.loads(self.plan.read_text(encoding="utf-8"))
        plan["images"][0]["repository"] = "ghcr.io/attacker/filebelt-api"
        self.plan.write_text(json.dumps(plan), encoding="utf-8")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
