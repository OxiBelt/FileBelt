#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tests/scripts/run-nfs-client-qualification.py"
SPEC = importlib.util.spec_from_file_location("run_nfs_client_qualification", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NfsClientCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.temporary_root = Path(self.temporary.name)
        self.configuration = {
            "adminDriver": "/qualification/admin",
            "server": "nfs.qualification.invalid",
            "exportPath": "/filebelt/qualification",
            "realm": "QUALIFICATION.INVALID",
            "imageIndexDigest": "sha256:" + "a" * 64,
            "releaseRevision": "b" * 40,
        }
        _, self.resource_prefix = MODULE.qualification_identity(
            "ubuntu", "amd64", self.configuration
        )
        self.commands: list[list[str]] = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_run(self, suffix: str) -> tuple[Path, Path, Path]:
        directory = self.temporary_root / f"{self.resource_prefix}-{suffix}"
        directory.mkdir(mode=0o700)
        mountpoint = directory / "mount"
        mountpoint.mkdir(mode=0o700)
        ticket_cache = directory / "krb5cc"
        ticket_cache.write_text("credential cache", encoding="utf-8")
        return directory, mountpoint, ticket_cache

    def admin(self, operation: str) -> subprocess.CompletedProcess[str]:
        self.commands.append(["admin", operation])
        stdout = json.dumps({"leftovers": []}) if operation == "assert-clean" else ""
        return subprocess.CompletedProcess(["admin", operation], 0, stdout=stdout, stderr="")

    def subprocess_run(
        self, arguments: list[object], **options: object
    ) -> subprocess.CompletedProcess[str]:
        command = [str(argument) for argument in arguments]
        self.commands.append(command)
        if command[0] == "umount":
            if options.get("check") is True:
                raise subprocess.CalledProcessError(32, command)
            return subprocess.CompletedProcess(command, 32, stdout="", stderr="still mounted")
        operation = command[1]
        stdout = json.dumps({"leftovers": []}) if operation == "assert-clean" else ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    def test_main_cleanup_preserves_export_after_failed_unmount(self) -> None:
        directory, mountpoint, ticket_cache = self.make_run("main-failure")
        victim = mountpoint / "foreign-export-victim.txt"
        victim.write_text("must survive", encoding="utf-8")

        with (
            mock.patch.object(MODULE, "unmount", side_effect=RuntimeError("still mounted")),
            mock.patch.object(Path, "is_mount", return_value=True),
            mock.patch.object(
                MODULE.subprocess,
                "run",
                side_effect=OSError("kdestroy failed"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "still mounted"):
                MODULE.cleanup_completed_run(
                    directory,
                    ticket_cache,
                    mounted=True,
                    admin=self.admin,
                )

        self.assertTrue(victim.exists())
        self.assertTrue(directory.exists())
        self.assertFalse(ticket_cache.exists())
        self.assertEqual(self.commands, [["admin", "cleanup"], ["admin", "assert-clean"]])

    def test_main_cleanup_removes_an_already_detached_exact_run(self) -> None:
        directory, _, ticket_cache = self.make_run("main-detached")

        def scrub_ticket(path: Path) -> None:
            path.unlink(missing_ok=True)

        with (
            mock.patch.object(MODULE, "destroy_ticket", side_effect=scrub_ticket),
            mock.patch.object(Path, "is_mount", return_value=False),
        ):
            MODULE.cleanup_completed_run(
                directory,
                ticket_cache,
                mounted=False,
                admin=self.admin,
            )

        self.assertFalse(directory.exists())
        self.assertEqual(self.commands, [["admin", "cleanup"], ["admin", "assert-clean"]])

    def test_cleanup_only_preserves_export_after_failed_unmount(self) -> None:
        directory, mountpoint, ticket_cache = self.make_run("reconciler-failure")
        victim = mountpoint / "foreign-export-victim.txt"
        victim.write_text("must survive", encoding="utf-8")

        with (
            mock.patch.object(Path, "glob", return_value=iter([directory])),
            mock.patch.object(Path, "is_mount", return_value=True),
            mock.patch.object(MODULE.subprocess, "run", side_effect=self.subprocess_run),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                MODULE.cleanup_abandoned_run(
                    "ubuntu",
                    "amd64",
                    self.temporary_root / "config.json",
                    self.configuration,
                )

        self.assertTrue(victim.exists())
        self.assertTrue(directory.exists())
        self.assertFalse(ticket_cache.exists())

    def test_cleanup_only_removes_an_already_detached_exact_run(self) -> None:
        directory, _, _ = self.make_run("detached")
        adjacent = self.temporary_root / "adjacent"
        adjacent.mkdir()

        with (
            mock.patch.object(Path, "glob", return_value=iter([directory])),
            mock.patch.object(Path, "is_mount", return_value=False),
            mock.patch.object(MODULE.subprocess, "run", side_effect=self.subprocess_run),
        ):
            MODULE.cleanup_abandoned_run(
                "ubuntu",
                "amd64",
                self.temporary_root / "config.json",
                self.configuration,
            )

        self.assertFalse(directory.exists())
        self.assertTrue(adjacent.exists())
        self.assertFalse(any(command[0] == "umount" for command in self.commands))

    def test_cleanup_only_rejects_a_mount_still_present_after_unmount(self) -> None:
        directory, mountpoint, ticket_cache = self.make_run("still-attached")
        victim = mountpoint / "foreign-export-victim.txt"
        victim.write_text("must survive", encoding="utf-8")

        def successful_run(
            arguments: list[object], **options: object
        ) -> subprocess.CompletedProcess[str]:
            command = [str(argument) for argument in arguments]
            self.commands.append(command)
            operation = command[1]
            stdout = json.dumps({"leftovers": []}) if operation == "assert-clean" else ""
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        with (
            mock.patch.object(Path, "glob", return_value=iter([directory])),
            mock.patch.object(Path, "is_mount", side_effect=[True, True]),
            mock.patch.object(MODULE.subprocess, "run", side_effect=successful_run),
        ):
            with self.assertRaisesRegex(RuntimeError, "mount remains attached"):
                MODULE.cleanup_abandoned_run(
                    "ubuntu",
                    "amd64",
                    self.temporary_root / "config.json",
                    self.configuration,
                )

        self.assertTrue(victim.exists())
        self.assertTrue(directory.exists())
        self.assertFalse(ticket_cache.exists())
        self.assertTrue(any(command[:2] == ["umount", "-fl"] for command in self.commands))

    def test_cleanup_only_scrubs_local_state_after_driver_failure(self) -> None:
        directory, _, ticket_cache = self.make_run("driver-failure")

        def failing_cleanup(
            arguments: list[object], **options: object
        ) -> subprocess.CompletedProcess[str]:
            command = [str(argument) for argument in arguments]
            self.commands.append(command)
            if command[1] == "cleanup":
                raise subprocess.CalledProcessError(1, command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps({"leftovers": []}),
                stderr="",
            )

        with (
            mock.patch.object(Path, "glob", return_value=iter([directory])),
            mock.patch.object(Path, "is_mount", return_value=False),
            mock.patch.object(MODULE.subprocess, "run", side_effect=failing_cleanup),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                MODULE.cleanup_abandoned_run(
                    "ubuntu",
                    "amd64",
                    self.temporary_root / "config.json",
                    self.configuration,
                )

        self.assertFalse(ticket_cache.exists())
        self.assertFalse(directory.exists())
        self.assertTrue(any(command[1] == "assert-clean" for command in self.commands))

    def test_cleanup_only_continues_after_one_stale_mount_fails(self) -> None:
        first, first_mount, first_ticket = self.make_run("first-mounted")
        victim = first_mount / "foreign-export-victim.txt"
        victim.write_text("must survive", encoding="utf-8")
        second, _, second_ticket = self.make_run("second-detached")

        with (
            mock.patch.object(Path, "glob", return_value=iter([first, second])),
            mock.patch.object(Path, "is_mount", side_effect=[True, False, False, False]),
            mock.patch.object(MODULE.subprocess, "run", side_effect=self.subprocess_run),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                MODULE.cleanup_abandoned_run(
                    "ubuntu",
                    "amd64",
                    self.temporary_root / "config.json",
                    self.configuration,
                )

        self.assertTrue(victim.exists())
        self.assertTrue(first.exists())
        self.assertFalse(first_ticket.exists())
        self.assertFalse(second.exists())
        self.assertFalse(second_ticket.exists())

    def test_main_cleanup_preserves_unexpected_local_entries(self) -> None:
        directory, _, ticket_cache = self.make_run("unexpected")
        unexpected = directory / "unexpected.log"
        unexpected.write_text("retain for recovery", encoding="utf-8")

        def scrub_ticket(path: Path) -> None:
            path.unlink(missing_ok=True)

        with (
            mock.patch.object(MODULE, "destroy_ticket", side_effect=scrub_ticket),
            mock.patch.object(Path, "is_mount", return_value=False),
        ):
            with self.assertRaisesRegex(RuntimeError, "unexpected local entries"):
                MODULE.cleanup_completed_run(
                    directory,
                    ticket_cache,
                    mounted=False,
                    admin=self.admin,
                )

        self.assertTrue(unexpected.exists())
        self.assertTrue((directory / "mount").exists())
        self.assertTrue(directory.exists())
        self.assertFalse(ticket_cache.exists())

    def test_unmount_retains_main_and_reconciler_modes(self) -> None:
        mountpoint = Path("/qualification/mount")
        with mock.patch.object(MODULE.subprocess, "run") as run:
            MODULE.unmount(mountpoint, force=True)
            run.assert_called_once_with(
                ["umount", "-f", str(mountpoint)], check=True, timeout=60
            )
        with mock.patch.object(MODULE.subprocess, "run") as run:
            MODULE.unmount(mountpoint, force=True, lazy=True)
            run.assert_called_once_with(
                ["umount", "-fl", str(mountpoint)], check=True, timeout=60
            )


if __name__ == "__main__":
    unittest.main()
