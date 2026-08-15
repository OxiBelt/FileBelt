#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build one adapter OCI archive only after its pre-image gate qualifies."""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile

from adapter_source_bundle import (
    BundleError,
    ROLES,
    validate_bundle,
    validate_bundle_against_plan,
    validate_canonical_adapter_plan,
    read_bundle_manifest,
    walk_tree,
)

PLATFORMS = {"linux/amd64", "linux/arm64", "linux/riscv64"}
RUST_TARGETS = {
    "linux/amd64": "x86_64-unknown-linux-musl",
    "linux/arm64": "aarch64-unknown-linux-musl",
}
BUILD_ARGUMENTS = {
    "filebelt-git-adapter": {
        "FILEBELT_GIT_BUILDER_IMAGE",
        "RUST_TARGET",
        "ZLIB_TARBALL_SHA256",
    },
    "filebelt-onlyoffice-adapter": {
        "FILEBELT_ONLYOFFICE_BUILDER_IMAGE",
        "RUST_TARGET",
    },
}


def fail(message: str) -> None:
    raise ValueError(message)


def read_role(plan_path: pathlib.Path, role: str) -> tuple[dict[str, object], dict[str, object]]:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if plan.get("schemaVersion") != 2 or not isinstance(plan.get("roles"), list):
        fail("adapter plan schemaVersion must be 2")
    matches = [row for row in plan["roles"] if isinstance(row, dict) and row.get("role") == role]
    if len(matches) != 1:
        fail("adapter plan must contain exactly one requested role")
    return plan, matches[0]


def validate_tracked_source_revision(
    staged_source: pathlib.Path, revision: str, temporary_root: pathlib.Path
) -> None:
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    expected_archive = temporary_root / "expected-source.tar"
    expected_source = temporary_root / "expected-source"
    expected_source.mkdir()
    with expected_archive.open("wb") as stream:
        subprocess.run(
            ["git", "-C", str(repo_root), "archive", "--format=tar", revision],
            check=True,
            stdout=stream,
        )
    with tarfile.open(expected_archive, mode="r:") as archive:
        archive.extractall(expected_source, filter="data")
    staged_files = {
        path.relative_to(staged_source).as_posix(): path for path in walk_tree(staged_source)
    }
    expected_files = {
        path.relative_to(expected_source).as_posix(): path for path in walk_tree(expected_source)
    }
    if set(staged_files) != set(expected_files):
        fail("source bundle tracked-file inventory differs from the exact Git revision")
    for name, path in staged_files.items():
        expected = expected_files[name]
        if path.read_bytes() != expected.read_bytes() or path.stat().st_mode & 0o111 != expected.stat().st_mode & 0o111:
            fail(f"source bundle file differs from the exact Git revision: {name}")


def build(arguments: argparse.Namespace) -> None:
    if arguments.role not in ROLES or arguments.platform not in PLATFORMS:
        fail("unknown adapter role or platform")
    validate_canonical_adapter_plan(arguments.plan)
    plan, row = read_role(arguments.plan, arguments.role)
    image_build = row.get("imageBuild")
    if not isinstance(image_build, dict):
        fail("adapter image-build decision is malformed")
    if image_build.get("state") == "blocked":
        if arguments.output.exists() or arguments.validation_output.exists():
            fail("blocked adapter has pre-existing image evidence")
        print(f"{arguments.role}: pre-image gate blocked; no image produced")
        return
    if image_build.get("state") != "eligible":
        fail("adapter image-build decision is invalid")
    if arguments.role not in BUILD_ARGUMENTS:
        fail(f"{arguments.role} has no qualified bundle-image build contract")
    if arguments.platform not in row.get("platforms", []):
        fail(f"{arguments.role} does not publish {arguments.platform}")
    source = row.get("source")
    bundle = row.get("sourceBundle")
    build_contract = row.get("build")
    evidence = row.get("evidence")
    if not all(isinstance(value, dict) for value in (source, bundle, build_contract, evidence)):
        fail("adapter source or build contract is malformed")
    if arguments.validation_output.name != evidence.get("imageValidation"):
        fail("image validation output name differs from the canonical plan")
    created = plan.get("source", {}).get("created")
    if not isinstance(created, str):
        fail("adapter plan creation time is missing")
    try:
        commit_timestamp = int(datetime.datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp())
    except ValueError as error:
        raise ValueError("adapter plan creation time is invalid") from error
    revision = source.get("revision")
    version = plan.get("version")
    if not isinstance(revision, str) or not isinstance(version, str):
        fail("adapter source identity is malformed")
    if arguments.output.resolve() == arguments.validation_output.resolve():
        fail("image and validation outputs must be distinct")
    for output in (arguments.output, arguments.validation_output):
        if any(character in str(output) for character in (",", "\n", "\r")):
            fail("output paths must not contain buildx option separators")
    if arguments.output.exists():
        fail(f"refusing to replace image output: {arguments.output}")
    platform_arguments = build_contract.get("platformArguments")
    if not isinstance(platform_arguments, dict):
        fail("adapter plan omits digest-bound platform build arguments")
    custom = platform_arguments.get(arguments.platform)
    if not isinstance(custom, dict) or not all(
        isinstance(name, str) and name.replace("_", "").isalnum() and name.upper() == name
        and isinstance(item, str) and item
        for name, item in custom.items()
    ):
        fail("platform build arguments are malformed")
    allowed_arguments = BUILD_ARGUMENTS[arguments.role]
    if set(custom) != allowed_arguments:
        fail(
            f"{arguments.role} build arguments must be exactly "
            + ", ".join(sorted(allowed_arguments))
        )
    if custom["RUST_TARGET"] != RUST_TARGETS.get(arguments.platform):
        fail("RUST_TARGET does not match the requested native platform")
    builder_name = next(name for name in custom if name.endswith("_BUILDER_IMAGE"))
    builder = custom[builder_name]
    if "@sha256:" not in builder or len(builder.rsplit("@sha256:", 1)[1]) != 64 or not all(
        character in "0123456789abcdef" for character in builder.rsplit("@sha256:", 1)[1]
    ):
        fail("builder image must be pinned by a lowercase SHA-256 digest")
    if "ZLIB_TARBALL_SHA256" in custom and (
        len(custom["ZLIB_TARBALL_SHA256"]) != 64
        or not all(character in "0123456789abcdef" for character in custom["ZLIB_TARBALL_SHA256"])
    ):
        fail("ZLIB_TARBALL_SHA256 must be lowercase SHA-256")
    common = {
        "SOURCE_URL": str(source.get("url")),
        "SOURCE_REF": str(source.get("ref")),
        "SOURCE_REVISION": revision,
        "CREATED": created,
        "IMAGE_LICENSES": str(row.get("imageLicense")),
        "LICENSE_EXPRESSION": str(row.get("imageLicense")),
        "CORRESPONDING_SOURCE_URL": str(bundle.get("publicUrl")),
        "CORRESPONDING_SOURCE_SHA256": str(bundle.get("sha256")),
        "LICENSE_QUALIFICATION": "qualified",
        "IMAGE_BUILD_STATE": "eligible",
        "CHART_VERSION": version,
    }
    if set(common).intersection(custom):
        fail("custom build arguments must not override plan-derived arguments")
    common.update(custom)
    with tempfile.TemporaryDirectory(prefix="filebelt-adapter-context-") as temporary:
        temporary_path = pathlib.Path(temporary)
        bundle_copy = temporary_path / arguments.bundle.name
        shutil.copyfile(arguments.bundle, bundle_copy)
        validate_bundle(bundle_copy, arguments.role, version, revision, commit_timestamp)
        validate_bundle_against_plan(bundle_copy, arguments.plan, arguments.role)
        if arguments.role == "filebelt-git-adapter":
            manifest = read_bundle_manifest(bundle_copy, arguments.role, version)
            inputs = manifest.get("inputs")
            zlib_inputs = [
                item
                for item in inputs if isinstance(item, dict)
                and item.get("name") == "zlib"
                and item.get("version") == "1.3.1"
                and item.get("archivePath") == "adapter-inputs/git/upstream/zlib-1.3.1.tar.gz"
            ] if isinstance(inputs, list) else []
            if len(zlib_inputs) != 1 or zlib_inputs[0].get("sha256") != custom["ZLIB_TARBALL_SHA256"]:
                fail("Git zlib build checksum differs from the validated source manifest")
        extract_root = temporary_path / "extract"
        context = temporary_path / "context"
        extract_root.mkdir()
        context.mkdir()
        with tarfile.open(bundle_copy, mode="r:gz") as archive:
            archive.extractall(extract_root, filter="data")
        roots = list(extract_root.iterdir())
        if len(roots) != 1 or not roots[0].is_dir():
            fail("source bundle must contain exactly one root directory")
        staged = roots[0]
        validate_tracked_source_revision(staged / "source", revision, temporary_path)
        shutil.copytree(staged / "source", context, dirs_exist_ok=True)
        shutil.copytree(staged / "adapter-inputs", context / "adapter-inputs")
        expected_dockerfile = pathlib.PurePosixPath("adapters") / ROLES[arguments.role] / "Dockerfile"
        if (
            build_contract.get("dockerfile") != expected_dockerfile.as_posix()
            or build_contract.get("context") != "."
            or build_contract.get("stagedInputs") != f"adapter-inputs/{ROLES[arguments.role]}"
        ):
            fail("adapter build contract differs from the closed repository layout")
        dockerfile = context.joinpath(*expected_dockerfile.parts)
        if not dockerfile.is_file():
            fail("adapter Dockerfile is absent from the source bundle")
        command = [
            "docker", "buildx", "build", "--network=none", "--platform", arguments.platform,
            "--file", str(dockerfile), "--output", f"type=docker,dest={arguments.output}",
        ]
        for name, value in sorted(common.items()):
            command.extend(("--build-arg", f"{name}={value}"))
        command.append(str(context))
        if arguments.dry_run:
            print(json.dumps(command))
            return
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(command, check=True)
        subprocess.run(
            [
                sys.executable,
                str(pathlib.Path(__file__).with_name("validate-image.py")),
                "--plan",
                str(arguments.plan),
                "--role",
                arguments.role,
                "--platform",
                arguments.platform,
                "--archive",
                str(arguments.output),
                "--output",
                str(arguments.validation_output),
            ],
            check=True,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=pathlib.Path, required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--bundle", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--validation-output", type=pathlib.Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()
    try:
        build(arguments)
    except (BundleError, OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
