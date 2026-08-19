#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for retained OxiBelt admission evidence."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).with_name("validate-oxibelt-admission.py")
SPEC = importlib.util.spec_from_file_location("validate_oxibelt_admission", SCRIPT)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class OxiBeltAdmissionTests(unittest.TestCase):
    def test_repository_admission_is_valid(self) -> None:
        trusted_root = CHECKER.validate(REPO_ROOT, REPO_ROOT / CHECKER.ADMISSION_PATH)
        self.assertEqual(trusted_root, REPO_ROOT / CHECKER.TRUSTED_ROOT_PATH)

    def copy_admission(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        source = REPO_ROOT / "supply-chain"
        shutil.copytree(source / "attestations", root / "supply-chain/attestations")
        admission = root / CHECKER.ADMISSION_PATH
        shutil.copy2(source / "oxibelt-admission-v2.json", admission)
        (root / "ui/web").mkdir(parents=True)
        shutil.copy2(REPO_ROOT / "ui/web/Dockerfile", root / "ui/web/Dockerfile")
        return directory, root, admission

    def test_rejects_changed_bundle(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        bundle = root / "supply-chain/attestations/oxibelt/0.7.1-beta.2/amd64-rebuild.json"
        bundle.write_bytes(bundle.read_bytes() + b"\n")
        with self.assertRaisesRegex(CHECKER.AdmissionError, "sha256 does not match"):
            CHECKER.validate(root, admission)

    def test_rejects_untrusted_signer_policy(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        record = json.loads(admission.read_text(encoding="utf-8"))
        record["verification"]["denySelfHostedRunners"] = False
        admission.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.AdmissionError, "signer policy"):
            CHECKER.validate(root, admission)

    def test_rejects_repository_replacement_of_pinned_trusted_root(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        trusted_root = root / CHECKER.TRUSTED_ROOT_PATH
        trusted_root.write_bytes(trusted_root.read_bytes() + b"\n")
        with self.assertRaisesRegex(CHECKER.AdmissionError, "verifier-pinned sha256"):
            CHECKER.validate(root, admission)

    def test_rejects_missing_pinned_trusted_root(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        (root / CHECKER.TRUSTED_ROOT_PATH).unlink()
        with self.assertRaisesRegex(CHECKER.AdmissionError, "trusted root path is missing"):
            CHECKER.validate(root, admission)

    def test_rejects_admission_selected_trusted_root(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        attacker_root = root / "supply-chain/attestations/sigstore/attacker-root.jsonl"
        attacker_root.write_bytes((root / CHECKER.TRUSTED_ROOT_PATH).read_bytes())
        record = json.loads(admission.read_text(encoding="utf-8"))
        record["trustedRoot"] = {
            "path": str(attacker_root.relative_to(root)),
            "sha256": hashlib.sha256(attacker_root.read_bytes()).hexdigest(),
        }
        admission.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.AdmissionError, "admission record must contain exactly"):
            CHECKER.validate(root, admission)

    def test_rejects_legacy_schema(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        record = json.loads(admission.read_text(encoding="utf-8"))
        record["schemaVersion"] = 1
        admission.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.AdmissionError, "schema or baseline"):
            CHECKER.validate(root, admission)

    def test_rejects_web_base_digest_drift(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        dockerfile = root / "ui/web/Dockerfile"
        dockerfile.write_text(
            dockerfile.read_text(encoding="utf-8").replace(
                "sha256:e8556a0103feff47bf6135062e70e980e000176598fd438959ea55d99c844030",
                "sha256:" + "0" * 64,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(CHECKER.AdmissionError, "base does not match"):
            CHECKER.validate(root, admission)

    def test_offline_verifier_rejects_a_forged_dsse_signature(self) -> None:
        directory, root, admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        bundle = root / "supply-chain/attestations/oxibelt/0.7.1-beta.2/index-rebuild.json"
        parsed = json.loads(bundle.read_text(encoding="utf-8"))
        signature = parsed["dsseEnvelope"]["signatures"][0]["sig"]
        parsed["dsseEnvelope"]["signatures"][0]["sig"] = ("A" if signature[0] != "A" else "B") + signature[1:]
        bundle.write_text(json.dumps(parsed, separators=(",", ":")), encoding="utf-8")
        record = json.loads(admission.read_text(encoding="utf-8"))
        record["bundles"][0]["sha256"] = hashlib.sha256(bundle.read_bytes()).hexdigest()
        admission.write_text(json.dumps(record), encoding="utf-8")
        result = subprocess.run(
            [str(REPO_ROOT / "tests/scripts/verify-oxibelt-admission.sh"), str(root)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_offline_verifier_passes_only_the_pinned_root_to_gh(self) -> None:
        directory, root, _admission = self.copy_admission()
        self.addCleanup(directory.cleanup)
        fake_bin = root / "fake-bin"
        fake_bin.mkdir()
        capture = root / "gh-arguments.txt"
        fake_gh = fake_bin / "gh"
        fake_gh.write_text(
            "#!/usr/bin/env sh\n"
            "set -eu\n"
            "printf 'CALL\\n' >> \"${GH_CAPTURE}\"\n"
            "printf '%s\\n' \"$@\" >> \"${GH_CAPTURE}\"\n",
            encoding="utf-8",
        )
        fake_gh.chmod(0o755)
        environment = os.environ.copy()
        environment["GH_CAPTURE"] = str(capture)
        environment["PATH"] = f"{fake_bin}:{environment.get('PATH', '')}"
        result = subprocess.run(
            [str(REPO_ROOT / "tests/scripts/verify-oxibelt-admission.sh"), str(root)],
            capture_output=True,
            text=True,
            check=False,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = capture.read_text(encoding="utf-8").splitlines()
        custom_roots = [
            arguments[index + 1]
            for index, argument in enumerate(arguments)
            if argument == "--custom-trusted-root"
        ]
        self.assertEqual(custom_roots, [str(root / CHECKER.TRUSTED_ROOT_PATH)] * 2)


if __name__ == "__main__":
    unittest.main()
