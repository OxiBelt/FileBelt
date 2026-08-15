#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage tracked FileBelt source plus previously verified adapter inputs."""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile

from adapter_source_bundle import BundleError, REVISION, ROLES, validate_staging_tree


def stage(arguments: argparse.Namespace) -> None:
    if arguments.role not in ROLES:
        raise BundleError(f"unknown adapter role: {arguments.role}")
    if not REVISION.fullmatch(arguments.revision):
        raise BundleError("revision must be a 40-character lowercase Git object ID")
    if arguments.output.exists():
        raise BundleError(f"refusing to replace staging output: {arguments.output}")
    result = subprocess.run(
        ["git", "-C", str(arguments.repo_root), "cat-file", "-e", f"{arguments.revision}^{{commit}}"],
        check=False,
    )
    if result.returncode != 0:
        raise BundleError("revision is not an available Git commit")
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="filebelt-source-stage-", dir=arguments.output.parent
    ) as temporary:
        temporary_path = pathlib.Path(temporary)
        archive_path = temporary_path / "source.tar"
        staged_output = temporary_path / "staging"
        with archive_path.open("wb") as archive_file:
            subprocess.run(
                ["git", "-C", str(arguments.repo_root), "archive", "--format=tar", arguments.revision],
                check=True,
                stdout=archive_file,
            )
        staged_output.mkdir()
        source = staged_output / "source"
        source.mkdir()
        with tarfile.open(archive_path, mode="r:") as archive:
            archive.extractall(source, filter="data")
        destination = staged_output / "adapter-inputs" / ROLES[arguments.role]
        shutil.copytree(arguments.inputs_dir, destination, symlinks=True)
        validate_staging_tree(
            staged_output,
            arguments.role,
            arguments.version,
            arguments.revision,
        )
        staged_output.rename(arguments.output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=pathlib.Path, required=True)
    parser.add_argument("--inputs-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    arguments = parser.parse_args()
    try:
        stage(arguments)
    except (BundleError, OSError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
