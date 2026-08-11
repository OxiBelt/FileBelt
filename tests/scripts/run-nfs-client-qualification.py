#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the destructive, real-client NFSv4.2 krb5p qualification suite."""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


ARCHITECTURES = {"amd64": "x86_64", "arm64": "aarch64"}
DISTRIBUTIONS = {"ubuntu", "debian", "rhel"}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
REQUIRED_ADMIN_OPERATIONS = (
    "prepare",
    "attest",
    "restart",
    "drain",
    "resume",
    "fence",
    "cleanup",
    "assert-clean",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distribution", required=True, choices=sorted(DISTRIBUTIONS))
    parser.add_argument("--architecture", required=True, choices=sorted(ARCHITECTURES))
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cleanup-only", action="store_true")
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("NFS client qualification must run as root on an isolated native runner")
    configuration = load_configuration(arguments.config)
    verify_runner(arguments.distribution, arguments.architecture)
    verify_commands(configuration)
    if arguments.cleanup_only:
        cleanup_abandoned_run(
            arguments.distribution,
            arguments.architecture,
            arguments.config.resolve(),
            configuration,
        )
        print("NFS client qualification cleanup passed")
        return 0
    verify_keytabs(configuration, arguments.output)
    result = run_suite(
        arguments.distribution,
        arguments.architecture,
        arguments.config.resolve(),
        configuration,
        arguments.output.resolve(),
    )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"NFS client qualification passed for {arguments.distribution}/{arguments.architecture}")
    return 0


def load_configuration(path: Path) -> dict[str, Any]:
    verify_root_controlled_path(path, "qualification config", final_forbidden_mode=0o077)
    try:
        configuration = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot read qualification config: {error}") from error
    if not isinstance(configuration, dict) or configuration.get("schemaVersion") != 1:
        raise SystemExit("qualification config must be a schemaVersion 1 object")
    required_strings = (
        "server",
        "exportPath",
        "realm",
        "userPrincipal",
        "userKeytab",
        "rootPrincipal",
        "rootKeytab",
        "crossRealmPrincipal",
        "crossRealmKeytab",
        "fixtureRelativePath",
        "fixtureSha256",
        "adminDriver",
        "rootfsDigestFile",
        "rootfsDigest",
        "imageIndexDigest",
        "releaseRevision",
    )
    for key in required_strings:
        if not isinstance(configuration.get(key), str) or not configuration[key]:
            raise SystemExit(f"qualification config {key} must be a non-empty string")
    realm = configuration["realm"]
    if configuration["userPrincipal"].count("@") != 1 or not configuration[
        "userPrincipal"
    ].endswith(f"@{realm}"):
        raise SystemExit("userPrincipal must be an exact principal in the configured realm")
    if configuration["rootPrincipal"] != f"root@{realm}":
        raise SystemExit("rootPrincipal must be the exact root principal in the configured realm")
    if configuration["crossRealmPrincipal"].endswith(f"@{realm}"):
        raise SystemExit("crossRealmPrincipal must be in a different realm")
    fixture = Path(configuration["fixtureRelativePath"])
    if fixture.is_absolute() or ".." in fixture.parts or not fixture.parts:
        raise SystemExit("fixtureRelativePath must stay below the export")
    if re.fullmatch(r"[0-9a-f]{64}", configuration["fixtureSha256"]) is None:
        raise SystemExit("fixtureSha256 must be a lowercase SHA-256 value")
    for key in ("rootfsDigest", "imageIndexDigest"):
        if DIGEST.fullmatch(configuration[key]) is None:
            raise SystemExit(f"{key} must be a lowercase sha256 digest")
    if re.fullmatch(r"[0-9a-f]{40}", configuration["releaseRevision"]) is None:
        raise SystemExit("releaseRevision must be a lowercase 40-character Git revision")
    timeout = configuration.get("fenceTimeoutSeconds", 300)
    if not isinstance(timeout, int) or not 30 <= timeout <= 300:
        raise SystemExit("fenceTimeoutSeconds must be an integer from 30 through 300")
    return configuration


def verify_runner(distribution: str, architecture: str) -> None:
    actual_machine = platform.machine()
    if actual_machine != ARCHITECTURES[architecture]:
        raise SystemExit(
            f"client must run natively on {ARCHITECTURES[architecture]}; runner is {actual_machine}"
        )
    binfmt = Path("/proc/sys/fs/binfmt_misc")
    if binfmt.is_dir() and any(binfmt.glob("qemu-*")):
        raise SystemExit("QEMU binfmt registration is forbidden for NFS client qualification")
    for process in Path("/proc").glob("[0-9]*/comm"):
        try:
            if process.read_text(encoding="utf-8").strip().startswith("qemu-"):
                raise SystemExit("QEMU processes are forbidden for NFS client qualification")
        except OSError:
            continue
    os_release = parse_os_release(Path("/etc/os-release"))
    if os_release.get("ID") != distribution:
        raise SystemExit(
            f"client runner distribution must be {distribution}; observed {os_release.get('ID', 'unknown')}"
        )
    if distribution == "rhel" and not os_release.get("VERSION_ID", "").startswith("10"):
        raise SystemExit("RHEL client runner must be major version 10")


def parse_os_release(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip().strip('"')
    return result


def verify_commands(configuration: dict[str, Any]) -> None:
    for command in (
        "getfattr",
        "fallocate",
        "kdestroy",
        "kinit",
        "mount",
        "nfs4_getfacl",
        "nfs4_setfacl",
        "setfattr",
        "umount",
    ):
        if shutil.which(command) is None:
            raise SystemExit(f"client runner is missing required command: {command}")
    driver = Path(configuration["adminDriver"])
    verify_root_controlled_path(driver, "adminDriver", final_forbidden_mode=0o022)
    if not os.access(driver, os.X_OK):
        raise SystemExit("adminDriver must be executable")


def verify_keytabs(configuration: dict[str, Any], output: Path) -> None:
    output_parent = output.resolve().parent
    digest_file = Path(configuration["rootfsDigestFile"])
    verify_root_controlled_path(
        digest_file,
        "rootfsDigestFile",
        final_forbidden_mode=0o022,
    )
    if digest_file.read_text(encoding="ascii").strip() != configuration["rootfsDigest"]:
        raise SystemExit("rootfsDigest does not match the admitted runner rootfs marker")
    for key in ("userKeytab", "rootKeytab", "crossRealmKeytab"):
        path = Path(configuration[key])
        verify_root_controlled_path(path, key, final_forbidden_mode=0o077)
        if path.resolve().is_relative_to(output_parent):
            raise SystemExit(f"{key} must not be below the retained evidence directory")


def run_suite(
    distribution: str,
    architecture: str,
    config_path: Path,
    configuration: dict[str, Any],
    output: Path,
) -> dict[str, Any]:
    run_id, resource_prefix = qualification_identity(distribution, architecture, configuration)
    temporary = Path(tempfile.mkdtemp(prefix=f"{resource_prefix}-", dir="/var/tmp"))
    mountpoint = temporary / "mount"
    mountpoint.mkdir(mode=0o700)
    ticket_cache = temporary / "krb5cc"
    cases: dict[str, bool] = {}
    mounted = False
    driver = Path(configuration["adminDriver"])
    driver_environment = clean_environment(configuration)
    cleanup_failure: Exception | None = None

    def admin(operation: str) -> subprocess.CompletedProcess[str]:
        if operation not in REQUIRED_ADMIN_OPERATIONS:
            raise RuntimeError(f"invalid admin operation: {operation}")
        result = subprocess.run(
            [driver, operation, resource_prefix, str(config_path)],
            env=driver_environment,
            text=True,
            capture_output=True,
            check=True,
            timeout=300,
        )
        if operation not in ("attest", "assert-clean") and (result.stdout or result.stderr):
            raise RuntimeError(f"admin driver {operation} emitted forbidden output")
        if result.stderr:
            raise RuntimeError(f"admin driver {operation} emitted forbidden stderr")
        if len(result.stdout.encode()) > 4096:
            raise RuntimeError(f"admin driver {operation} output exceeds 4096 bytes")
        return result

    try:
        admin("prepare")
        attestation = json.loads(admin("attest").stdout)
        expected_attestation = {
            "bridgeHasKeytab": False,
            "bridgeImageDigest": configuration["imageIndexDigest"],
            "bridgeRevision": configuration["releaseRevision"],
            "clientRootfsDigest": configuration["rootfsDigest"],
            "ganeshaHasKeytab": True,
            "ganeshaImageDigest": configuration["imageIndexDigest"],
            "ganeshaRevision": configuration["releaseRevision"],
            "ipcCarriesSecrets": False,
            "samePinnedImage": True,
        }
        if attestation != expected_attestation:
            raise RuntimeError("admin driver runtime image attestation does not match the release")
        authenticate(configuration["userPrincipal"], configuration["userKeytab"], ticket_cache)
        mount(configuration, mountpoint, "krb5p", ticket_cache)
        mounted = True
        cases["authenticate_krb5p"] = True

        fixture = mountpoint / configuration["fixtureRelativePath"]
        cases["list"] = fixture.name in os.listdir(fixture.parent)
        fixture_bytes = fixture.read_bytes()
        cases["read"] = hashlib.sha256(fixture_bytes).hexdigest() == configuration["fixtureSha256"]
        require_pass(cases, "list")
        require_pass(cases, "read")

        test_root = mountpoint / resource_prefix
        test_root.mkdir(mode=0o700)
        cases["mkdir"] = test_root.is_dir()
        require_pass(cases, "mkdir")
        data_path = test_root / "data.bin"
        payload = b"filebelt-nfs-qualification\n"
        with data_path.open("w+b", buffering=0) as handle:
            written = handle.write(payload)
            cases["write"] = written == len(payload)
            handle.flush()
            os.fsync(handle.fileno())
            cases["commit"] = True
        cases["create"] = data_path.is_file()
        require_pass(cases, "create")
        require_pass(cases, "write")
        cases["read"] = cases["read"] and data_path.read_bytes() == payload

        renamed = test_root / "renamed.bin"
        descriptor = os.open(data_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.rename(data_path, renamed)
            os.lseek(descriptor, 0, os.SEEK_SET)
            cases["rename"] = os.read(descriptor, len(payload)) == payload
        finally:
            os.close(descriptor)
        require_pass(cases, "rename")

        symlink = test_root / "relative-link"
        os.symlink("renamed.bin", symlink)
        cases["symlink_readlink"] = (
            os.readlink(symlink) == "renamed.bin" and symlink.read_bytes() == payload
        )
        require_pass(cases, "symlink_readlink")

        os.chmod(renamed, 0o640)
        cases["setattr_mode"] = stat.S_IMODE(renamed.stat().st_mode) == 0o640
        require_pass(cases, "setattr_mode")
        cases["reject_special_mode_bits"] = rejects_os_operation(lambda: os.chmod(renamed, 0o4640))
        require_pass(cases, "reject_special_mode_bits")
        cases["reject_unauthorized_chown"] = rejects_os_operation(lambda: os.chown(renamed, 0, 0))
        require_pass(cases, "reject_unauthorized_chown")

        subprocess.run(
            ["setfattr", "-n", "user.filebelt.qualification", "-v", run_id, renamed],
            check=True,
        )
        xattr = subprocess.run(
            ["getfattr", "--only-values", "-n", "user.filebelt.qualification", renamed],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        cases["xattr"] = xattr == run_id
        require_pass(cases, "xattr")
        cases["xattr_list_remove"] = "user.filebelt.qualification" in os.listxattr(renamed)
        os.removexattr(renamed, "user.filebelt.qualification")
        cases["xattr_list_remove"] = cases["xattr_list_remove"] and (
            "user.filebelt.qualification" not in os.listxattr(renamed)
        )
        require_pass(cases, "xattr_list_remove")
        cases["reject_non_user_xattr"] = rejects_os_operation(
            lambda: os.setxattr(renamed, "security.filebelt.qualification", run_id.encode())
        )
        require_pass(cases, "reject_non_user_xattr")

        principal = configuration["userPrincipal"]
        ace = f"A::{principal}:rwatTnNcCy"
        subprocess.run(["nfs4_setfacl", "-a", ace, renamed], check=True)
        acl = subprocess.run(
            ["nfs4_getfacl", renamed], text=True, capture_output=True, check=True
        ).stdout
        cases["acl"] = principal in acl
        require_pass(cases, "acl")

        sparse = test_root / "sparse.bin"
        with sparse.open("w+b", buffering=0) as handle:
            handle.write(b"start")
            handle.seek(8 * 1024 * 1024, os.SEEK_SET)
            handle.write(b"end")
            os.fsync(handle.fileno())
        sparse_stat = sparse.stat()
        with sparse.open("rb", buffering=0) as handle:
            handle.seek(4 * 1024 * 1024)
            hole = handle.read(4096)
        cases["sparse"] = (
            sparse_stat.st_size == 8 * 1024 * 1024 + 3
            and sparse_stat.st_blocks * 512 < sparse_stat.st_size
            and hole == bytes(4096)
        )
        require_pass(cases, "sparse")
        with sparse.open("rb", buffering=0) as handle:
            first_data = os.lseek(handle.fileno(), 0, os.SEEK_DATA)
            first_hole = os.lseek(handle.fileno(), 0, os.SEEK_HOLE)
            last_data = os.lseek(handle.fileno(), 8 * 1024 * 1024, os.SEEK_DATA)
        cases["seek_data_hole"] = (
            first_data == 0
            and 0 < first_hole <= 8 * 1024 * 1024
            and last_data == 8 * 1024 * 1024
        )
        require_pass(cases, "seek_data_hole")

        allocated = test_root / "allocated.bin"
        subprocess.run(["fallocate", "--length", "1048576", allocated], check=True)
        cases["allocate"] = allocated.stat().st_size == 1048576
        require_pass(cases, "allocate")
        with allocated.open("r+b", buffering=0) as handle:
            handle.seek(262144)
            handle.write(b"x" * 4096)
            os.fsync(handle.fileno())
        subprocess.run(
            [
                "fallocate",
                "--punch-hole",
                "--keep-size",
                "--offset",
                "262144",
                "--length",
                "262144",
                allocated,
            ],
            check=True,
        )
        with allocated.open("rb", buffering=0) as handle:
            handle.seek(262144)
            cases["punch_hole"] = handle.read(4096) == bytes(4096)
        require_pass(cases, "punch_hole")
        os.truncate(allocated, 131072)
        cases["truncate"] = allocated.stat().st_size == 131072
        require_pass(cases, "truncate")

        open_unlinked = test_root / "open-unlinked.bin"
        open_descriptor = os.open(
            open_unlinked,
            os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            os.unlink(open_unlinked)
            os.write(open_descriptor, payload)
            os.fsync(open_descriptor)
            os.lseek(open_descriptor, 0, os.SEEK_SET)
            cases["open_unlinked"] = (
                os.read(open_descriptor, len(payload)) == payload
                and not open_unlinked.exists()
            )
        finally:
            os.close(open_descriptor)
        require_pass(cases, "open_unlinked")

        lock_path = test_root / "locks.bin"
        lock_path.write_bytes(bytes(4096))
        with lock_path.open("r+b", buffering=0) as handle:
            fcntl.lockf(handle.fileno(), fcntl.LOCK_EX, 0, 1024, os.SEEK_SET)
            cases["lock_conflict"] = not child_lock_attempt(lock_path, 2048)
            cases["lock_to_eof"] = cases["lock_conflict"]
            fcntl.lockf(handle.fileno(), fcntl.LOCK_UN, 0, 1024, os.SEEK_SET)
        cases["lock_unlock"] = child_lock_attempt(lock_path, 2048)
        require_pass(cases, "lock_conflict")
        require_pass(cases, "lock_to_eof")
        require_pass(cases, "lock_unlock")

        reclaim = test_root / "reclaim.bin"
        with reclaim.open("w+b", buffering=0) as handle:
            fcntl.lockf(handle.fileno(), fcntl.LOCK_EX)
            handle.write(payload)
            os.fsync(handle.fileno())
            admin("restart")
            handle.seek(0)
            cases["restart_reclaim"] = handle.read() == payload
            fcntl.lockf(handle.fileno(), fcntl.LOCK_UN)
        require_pass(cases, "restart_reclaim")

        unmount(mountpoint)
        mounted = False
        admin("drain")
        cases["drain"] = mount_must_fail(configuration, mountpoint, "krb5p", ticket_cache)
        require_pass(cases, "drain")
        admin("resume")
        mount(configuration, mountpoint, "krb5p", ticket_cache)
        mounted = True

        stale = os.open(
            mountpoint / resource_prefix / "renamed.bin",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            admin("fence")
            cases["fence"] = True
            drop_client_caches(stale)
            deadline = time.monotonic() + configuration.get("fenceTimeoutSeconds", 300)
            stale_observed = False
            while time.monotonic() < deadline:
                try:
                    drop_client_caches(stale)
                    os.lseek(stale, 0, os.SEEK_SET)
                    os.read(stale, 1)
                except OSError as error:
                    if error.errno in (errno.ESTALE, errno.EIO, errno.EACCES):
                        stale_observed = True
                        break
                    raise
                time.sleep(1)
            cases["stale_handle"] = stale_observed
        finally:
            os.close(stale)
        require_pass(cases, "stale_handle")
        unmount(mountpoint, force=True)
        mounted = False
        admin("resume")

        destroy_ticket(ticket_cache)
        cases["reject_auth_sys"] = mount_must_fail(configuration, mountpoint, "sys", ticket_cache)
        require_pass(cases, "reject_auth_sys")
        cases["reject_root_principal"] = rejected_principal_mount(
            configuration,
            mountpoint,
            configuration["rootPrincipal"],
            configuration["rootKeytab"],
            ticket_cache,
        )
        require_pass(cases, "reject_root_principal")
        cases["reject_cross_realm_principal"] = rejected_principal_mount(
            configuration,
            mountpoint,
            configuration["crossRealmPrincipal"],
            configuration["crossRealmKeytab"],
            ticket_cache,
        )
        require_pass(cases, "reject_cross_realm_principal")
    finally:
        if mounted:
            try:
                unmount(mountpoint, force=True)
            except Exception as error:  # cleanup must continue to the authority driver
                cleanup_failure = error
        destroy_ticket(ticket_cache)
        try:
            admin("cleanup")
            cleanup_result = admin("assert-clean")
            cleanup_evidence = json.loads(cleanup_result.stdout)
            if cleanup_evidence != {"leftovers": []}:
                raise RuntimeError("admin driver reported qualification leftovers")
        except Exception as error:
            cleanup_failure = cleanup_failure or error
        for child in sorted(temporary.rglob("*"), key=lambda path: len(path.parts), reverse=True):
            if child.is_symlink() or child.is_file():
                child.unlink()
            elif child.is_dir():
                child.rmdir()
        temporary.rmdir()
        if cleanup_failure is not None:
            raise cleanup_failure

    required = required_cases()
    missing = sorted(required - set(cases))
    if missing:
        raise RuntimeError(f"NFS qualification scaffold lacks required cases: {', '.join(missing)}")
    if not all(cases.values()):
        raise RuntimeError("client suite did not produce every required passing case")
    os_release = parse_os_release(Path("/etc/os-release"))
    return {
        "schemaVersion": 1,
        "distribution": distribution,
        "version": os_release.get("VERSION_ID", "unknown"),
        "architecture": architecture,
        "runnerArchitecture": platform.machine(),
        "native": True,
        "emulation": "none",
        "rootfsDigest": configuration["rootfsDigest"],
        "imageIndexDigest": configuration["imageIndexDigest"],
        "securityFlavor": "krb5p",
        "runtimeAttestation": expected_attestation,
        "cases": cases,
        "cleanup": {
            "complete": True,
            "leftovers": [],
            "resourcePrefix": resource_prefix,
        },
        "secretIsolation": {
            "keytabsExcluded": True,
            "ticketsExcluded": True,
            "privateKeysExcluded": True,
        },
    }


def verify_root_controlled_path(
    path: Path,
    label: str,
    *,
    final_forbidden_mode: int,
) -> None:
    if not path.is_absolute():
        raise SystemExit(f"{label} must be an absolute path")
    current = Path("/")
    parts = path.parts[1:]
    if not parts:
        raise SystemExit(f"{label} must not be the filesystem root")
    for index, part in enumerate(parts):
        current /= part
        try:
            metadata = os.lstat(current)
        except OSError as error:
            raise SystemExit(f"cannot inspect {label} path component: {error}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise SystemExit(f"{label} path must not traverse a symlink")
        if metadata.st_uid != 0:
            raise SystemExit(f"{label} path must be root-owned")
        final = index == len(parts) - 1
        forbidden = final_forbidden_mode if final else 0o022
        if metadata.st_mode & forbidden:
            raise SystemExit(f"{label} path has group/world writable or readable authority")
        if final and not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"{label} must be a regular file")


def qualification_identity(
    distribution: str, architecture: str, configuration: dict[str, Any]
) -> tuple[str, str]:
    run_id = hashlib.sha256(
        f"{configuration['imageIndexDigest']}:{distribution}:{architecture}".encode()
    ).hexdigest()[:16]
    return run_id, f"filebelt-nfs-qualification-{run_id}"


def cleanup_abandoned_run(
    distribution: str,
    architecture: str,
    config_path: Path,
    configuration: dict[str, Any],
) -> None:
    _, resource_prefix = qualification_identity(distribution, architecture, configuration)
    driver = Path(configuration["adminDriver"])
    environment = clean_environment(configuration)
    for operation in ("cleanup", "assert-clean"):
        result = subprocess.run(
            [driver, operation, resource_prefix, str(config_path)],
            env=environment,
            text=True,
            capture_output=True,
            check=True,
            timeout=240,
        )
        if result.stderr or len(result.stdout.encode()) > 4096:
            raise RuntimeError(f"admin driver {operation} emitted forbidden output")
        if operation == "cleanup" and result.stdout:
            raise RuntimeError("admin driver cleanup emitted forbidden output")
        if operation == "assert-clean" and json.loads(result.stdout) != {"leftovers": []}:
            raise RuntimeError("admin driver reported qualification leftovers")
    temporary_root = Path("/var/tmp")
    for directory in temporary_root.glob(f"{resource_prefix}-*"):
        metadata = os.lstat(directory)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError("refusing non-directory qualification cleanup target")
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise RuntimeError("refusing unowned qualification cleanup target")
        mountpoint = directory / "mount"
        subprocess.run(
            ["umount", "-fl", mountpoint],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
        )
        shutil.rmtree(directory)


def required_cases() -> set[str]:
    root = Path(__file__).resolve().parents[2]
    value = json.loads(
        (root / "tests/nfs/qualification/required-cases.json").read_text(
            encoding="utf-8"
        )
    )
    return set(value["positive"] + value["negative"])


def clean_environment(configuration: dict[str, Any]) -> dict[str, str]:
    return {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "FILEBELT_NFS_SERVER": configuration["server"],
        "FILEBELT_NFS_EXPORT": configuration["exportPath"],
        "FILEBELT_NFS_REALM": configuration["realm"],
        "FILEBELT_NFS_IMAGE_DIGEST": configuration["imageIndexDigest"],
        "FILEBELT_NFS_RELEASE_REVISION": configuration["releaseRevision"],
    }


def ticket_environment(ticket_cache: Path) -> dict[str, str]:
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    }
    environment["KRB5CCNAME"] = f"FILE:{ticket_cache}"
    return environment


def authenticate(principal: str, keytab: str, ticket_cache: Path) -> None:
    destroy_ticket(ticket_cache)
    subprocess.run(
        ["kinit", "-k", "-t", keytab, principal],
        env=ticket_environment(ticket_cache),
        check=True,
        timeout=30,
    )


def destroy_ticket(ticket_cache: Path) -> None:
    subprocess.run(
        ["kdestroy"],
        env=ticket_environment(ticket_cache),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    ticket_cache.unlink(missing_ok=True)


def mount(
    configuration: dict[str, Any],
    mountpoint: Path,
    security: str,
    ticket_cache: Path,
) -> None:
    subprocess.run(
        [
            "mount",
            "-t",
            "nfs4",
            "-o",
            f"vers=4.2,sec={security},hard,timeo=50,retrans=2",
            f"{configuration['server']}:{configuration['exportPath']}",
            mountpoint,
        ],
        env=ticket_environment(ticket_cache),
        check=True,
        timeout=60,
    )


def mount_must_fail(
    configuration: dict[str, Any], mountpoint: Path, security: str, ticket_cache: Path
) -> bool:
    result = subprocess.run(
        [
            "mount",
            "-t",
            "nfs4",
            "-o",
            f"vers=4.2,sec={security},soft,timeo=20,retrans=1",
            f"{configuration['server']}:{configuration['exportPath']}",
            mountpoint,
        ],
        env=ticket_environment(ticket_cache),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )
    if result.returncode == 0:
        unmount(mountpoint, force=True)
        return False
    return True


def rejected_principal_mount(
    configuration: dict[str, Any],
    mountpoint: Path,
    principal: str,
    keytab: str,
    ticket_cache: Path,
) -> bool:
    authenticate(principal, keytab, ticket_cache)
    try:
        return mount_must_fail(configuration, mountpoint, "krb5p", ticket_cache)
    finally:
        destroy_ticket(ticket_cache)


def unmount(mountpoint: Path, *, force: bool = False) -> None:
    arguments = ["umount"]
    if force:
        arguments.append("-f")
    arguments.append(str(mountpoint))
    subprocess.run(arguments, check=True, timeout=60)


def require_pass(cases: dict[str, bool], name: str) -> None:
    if cases.get(name) is not True:
        raise RuntimeError(f"NFS qualification case failed: {name}")


def rejects_os_operation(operation: Any) -> bool:
    try:
        operation()
    except OSError:
        return True
    return False


def child_lock_attempt(path: Path, start: int) -> bool:
    reader, writer = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(reader)
        acquired = False
        try:
            descriptor = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                fcntl.lockf(
                    descriptor,
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                    0,
                    start,
                    os.SEEK_SET,
                )
                acquired = True
                if acquired:
                    fcntl.lockf(descriptor, fcntl.LOCK_UN, 0, start, os.SEEK_SET)
            finally:
                os.close(descriptor)
        except OSError:
            acquired = False
        os.write(writer, b"1" if acquired else b"0")
        os.close(writer)
        os._exit(0)
    os.close(writer)
    try:
        result = os.read(reader, 1)
    finally:
        os.close(reader)
        _, status = os.waitpid(child, 0)
    if status != 0 or result not in (b"0", b"1"):
        raise RuntimeError("lock-conflict child did not complete safely")
    return result == b"1"


def drop_client_caches(descriptor: int) -> None:
    if hasattr(os, "posix_fadvise") and hasattr(os, "POSIX_FADV_DONTNEED"):
        os.posix_fadvise(descriptor, 0, 0, os.POSIX_FADV_DONTNEED)
    os.sync()
    Path("/proc/sys/vm/drop_caches").write_text("3\n", encoding="ascii")


if __name__ == "__main__":
    raise SystemExit(main())
