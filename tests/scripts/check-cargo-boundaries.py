#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate FileBelt's reviewed production Cargo dependency graphs."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, Sequence


MAXIMUM_CARGO_OUTPUT_BYTES = 16 * 1024 * 1024
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]*$")
VERSION_RE = re.compile(r"^[^()\s|]+$")
FEATURE_RE = re.compile(r"^[A-Za-z0-9_+.-]+$")
WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
POLICY_FILENAME = "supply-chain/cargo-boundaries-v1.toml"


class BoundaryError(ValueError):
    """A malformed graph, policy, or repository-boundary violation."""


@dataclass(frozen=True)
class GraphProfile:
    label: str
    package: str
    manifest: str
    feature_arguments: tuple[str, ...]
    first_party_features: tuple[tuple[str, frozenset[str]], ...]
    forbidden_packages: frozenset[str]
    forbidden_package_prefixes: tuple[str, ...]


@dataclass(frozen=True)
class RepositoryPolicy:
    production_source_roots: tuple[str, ...]
    excluded_source_roots: tuple[str, ...]
    apache_manifest_roots: tuple[str, ...]
    adapter_root: str
    registered_adapter_manifests: frozenset[str]


@dataclass(frozen=True)
class CargoBoundaryPolicy:
    schema_version: int
    repository: RepositoryPolicy
    profiles: tuple[GraphProfile, ...]

    @property
    def first_party_packages(self) -> frozenset[str]:
        return frozenset(profile.package for profile in self.profiles)


@dataclass(frozen=True)
class ParsedCargoTree:
    features_by_package: dict[str, frozenset[str]]
    local_packages: frozenset[str]


@dataclass(frozen=True)
class GraphSummary:
    packages: int
    first_party_packages: int


@dataclass(frozen=True)
class WorkspaceMetadata:
    packages_by_name: dict[str, str]
    workspace_packages: frozenset[str]


def _fail(message: str) -> NoReturn:
    raise BoundaryError(message)


def _expect_table(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{context} must be a table")
    return value


def _expect_exact_keys(
    table: dict[str, Any], expected: frozenset[str], context: str
) -> None:
    actual = frozenset(table)
    if actual != expected:
        _fail(
            f"{context} keys differ: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def _expect_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{context} must be a non-empty string")
    return value


def _expect_string_list(value: Any, context: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        _fail(f"{context} must be an array")
    strings = tuple(_expect_string(item, f"{context} item") for item in value)
    if len(strings) != len(set(strings)):
        _fail(f"{context} must not contain duplicates")
    return strings


def _expect_relative_path(value: Any, context: str) -> str:
    path = _expect_string(value, context)
    pure = PurePosixPath(path)
    if pure.is_absolute() or path != pure.as_posix() or ".." in pure.parts:
        _fail(f"{context} must be a normalized repository-relative path: {path!r}")
    return path


def _expect_package(value: Any, context: str) -> str:
    package = _expect_string(value, context)
    if PACKAGE_NAME_RE.fullmatch(package) is None:
        _fail(f"{context} is not a valid Cargo package name: {package!r}")
    return package


def _parse_profile(value: Any, index: int) -> GraphProfile:
    context = f"graph_profiles[{index}]"
    table = _expect_table(value, context)
    _expect_exact_keys(
        table,
        frozenset(
            {
                "label",
                "package",
                "manifest",
                "feature_arguments",
                "first_party_features",
                "forbidden_packages",
                "forbidden_package_prefixes",
            }
        ),
        context,
    )
    package = _expect_package(table["package"], f"{context}.package")
    manifest = _expect_relative_path(table["manifest"], f"{context}.manifest")
    if not manifest.endswith("/Cargo.toml") and manifest != "Cargo.toml":
        _fail(f"{context}.manifest must name Cargo.toml")

    feature_arguments = _expect_string_list(
        table["feature_arguments"], f"{context}.feature_arguments"
    )
    if feature_arguments:
        _fail(
            f"{context}.feature_arguments must stay empty in schema version 1; "
            "add a reviewed schema version before introducing graph variants"
        )

    feature_table = _expect_table(
        table["first_party_features"], f"{context}.first_party_features"
    )
    first_party_features: list[tuple[str, frozenset[str]]] = []
    for dependency, features_value in feature_table.items():
        dependency = _expect_package(
            dependency, f"{context}.first_party_features key"
        )
        features = _expect_string_list(
            features_value, f"{context}.first_party_features.{dependency}"
        )
        invalid = [feature for feature in features if FEATURE_RE.fullmatch(feature) is None]
        if invalid:
            _fail(f"{context} has invalid feature names: {invalid}")
        first_party_features.append((dependency, frozenset(features)))
    first_party_features.sort()
    if package not in feature_table:
        _fail(f"{context}.first_party_features must include root package {package}")

    forbidden_packages = frozenset(
        _expect_package(item, f"{context}.forbidden_packages item")
        for item in _expect_string_list(
            table["forbidden_packages"], f"{context}.forbidden_packages"
        )
    )
    forbidden_prefixes = _expect_string_list(
        table["forbidden_package_prefixes"],
        f"{context}.forbidden_package_prefixes",
    )
    for prefix in forbidden_prefixes:
        if PACKAGE_NAME_RE.fullmatch(prefix) is None:
            _fail(f"{context} has invalid forbidden package prefix: {prefix!r}")

    return GraphProfile(
        label=_expect_string(table["label"], f"{context}.label"),
        package=package,
        manifest=manifest,
        feature_arguments=feature_arguments,
        first_party_features=tuple(first_party_features),
        forbidden_packages=forbidden_packages,
        forbidden_package_prefixes=forbidden_prefixes,
    )


def load_policy(path: Path) -> CargoBoundaryPolicy:
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        _fail(f"Cargo boundary policy is invalid TOML: {error}")

    _expect_exact_keys(
        document,
        frozenset(
            {
                "schema_version",
                "repository",
                "graph_profiles",
                "source_boundaries",
                "public_surfaces",
            }
        ),
        "policy",
    )
    if document["schema_version"] != 1:
        _fail(
            "unsupported Cargo boundary policy schema_version: "
            f"{document['schema_version']!r}"
        )

    repository = _expect_table(document["repository"], "repository")
    _expect_exact_keys(
        repository,
        frozenset(
            {
                "production_source_roots",
                "excluded_source_roots",
                "apache_manifest_roots",
                "adapter_root",
                "registered_adapter_manifests",
            }
        ),
        "repository",
    )
    production_source_roots = tuple(
        _expect_relative_path(item, "repository.production_source_roots item")
        for item in _expect_string_list(
            repository["production_source_roots"],
            "repository.production_source_roots",
        )
    )
    excluded_source_roots = tuple(
        _expect_relative_path(item, "repository.excluded_source_roots item")
        for item in _expect_string_list(
            repository["excluded_source_roots"],
            "repository.excluded_source_roots",
        )
    )
    apache_manifest_roots = tuple(
        _expect_relative_path(item, "repository.apache_manifest_roots item")
        for item in _expect_string_list(
            repository["apache_manifest_roots"],
            "repository.apache_manifest_roots",
        )
    )
    adapter_root = _expect_relative_path(
        repository["adapter_root"], "repository.adapter_root"
    )
    registered_adapters = frozenset(
        _expect_relative_path(item, "registered adapter manifest")
        for item in _expect_string_list(
            repository["registered_adapter_manifests"],
            "repository.registered_adapter_manifests",
        )
    )
    for manifest in registered_adapters:
        if not manifest.startswith(f"{adapter_root}/") or not manifest.endswith(
            "/Cargo.toml"
        ):
            _fail(
                "registered adapter manifest must be a Cargo.toml below "
                f"{adapter_root}: {manifest}"
            )

    raw_profiles = document["graph_profiles"]
    if not isinstance(raw_profiles, list) or not raw_profiles:
        _fail("graph_profiles must be a non-empty array of tables")
    profiles = tuple(_parse_profile(value, index) for index, value in enumerate(raw_profiles))
    packages = [profile.package for profile in profiles]
    manifests = [profile.manifest for profile in profiles]
    labels = [profile.label for profile in profiles]
    for values, label in [
        (packages, "package"),
        (manifests, "manifest"),
        (labels, "label"),
    ]:
        if len(values) != len(set(values)):
            _fail(f"graph profile {label} values must be unique")

    first_party = frozenset(packages)
    for profile in profiles:
        expected_packages = frozenset(
            package for package, _features in profile.first_party_features
        )
        unknown = expected_packages - first_party
        if unknown:
            _fail(
                f"{profile.label} references unregistered first-party packages: "
                + ", ".join(sorted(unknown))
            )

    # The Rust contract owns the detailed AST policy, but loading must still fail
    # closed if these versioned sections disappear or change shape entirely.
    for section_name in ("source_boundaries", "public_surfaces"):
        section = document[section_name]
        if not isinstance(section, list) or not section:
            _fail(f"{section_name} must be a non-empty array of tables")
        if any(not isinstance(item, dict) for item in section):
            _fail(f"{section_name} entries must be tables")

    return CargoBoundaryPolicy(
        schema_version=1,
        repository=RepositoryPolicy(
            production_source_roots=production_source_roots,
            excluded_source_roots=excluded_source_roots,
            apache_manifest_roots=apache_manifest_roots,
            adapter_root=adapter_root,
            registered_adapter_manifests=registered_adapters,
        ),
        profiles=profiles,
    )


def _relative(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        _fail(f"path escapes repository root: {path}")


def _manifest_paths(repo_root: Path, roots: Sequence[str]) -> frozenset[str]:
    manifests: set[str] = set()
    for relative in roots:
        root = repo_root / relative
        if root.is_file():
            if root.name != "Cargo.toml":
                _fail(f"manifest root is not Cargo.toml: {relative}")
            manifests.add(_relative(repo_root, root))
            continue
        if not root.is_dir():
            _fail(f"manifest root does not exist: {relative}")
        for manifest in root.rglob("Cargo.toml"):
            if any(part in {".git", "target"} for part in manifest.parts):
                continue
            manifests.add(_relative(repo_root, manifest))
    return frozenset(manifests)


def discover_adapter_manifests(repo_root: Path, adapter_root: str) -> frozenset[str]:
    root = repo_root / adapter_root
    if not root.is_dir():
        _fail(f"adapter root does not exist: {adapter_root}")
    return _manifest_paths(repo_root, (adapter_root,))


def validate_adapter_registration(
    discovered: frozenset[str], registered: frozenset[str]
) -> None:
    if discovered != registered:
        _fail(
            "adapter manifest registration differs: "
            f"unregistered={sorted(discovered - registered)}, "
            f"missing={sorted(registered - discovered)}"
        )


def validate_repository_layout(repo_root: Path, policy: CargoBoundaryPolicy) -> None:
    repo_root = repo_root.resolve()
    if not (repo_root / "Cargo.toml").is_file():
        _fail(f"repository root does not contain Cargo.toml: {repo_root}")
    for relative in (
        *policy.repository.production_source_roots,
        *policy.repository.excluded_source_roots,
    ):
        if not (repo_root / relative).exists():
            _fail(f"policy source root does not exist: {relative}")

    apache = _manifest_paths(repo_root, policy.repository.apache_manifest_roots)
    adapters = discover_adapter_manifests(repo_root, policy.repository.adapter_root)
    registered_adapters = policy.repository.registered_adapter_manifests
    validate_adapter_registration(adapters, registered_adapters)
    expected = apache | registered_adapters
    registered = frozenset(profile.manifest for profile in policy.profiles)
    if registered != expected:
        _fail(
            "production graph profile manifests differ: "
            f"unregistered={sorted(expected - registered)}, "
            f"missing={sorted(registered - expected)}"
        )


def _bounded_output(output: str, label: str) -> str:
    size = len(output.encode("utf-8"))
    if size > MAXIMUM_CARGO_OUTPUT_BYTES:
        _fail(
            f"{label} output is {size} bytes and exceeds "
            f"{MAXIMUM_CARGO_OUTPUT_BYTES} bytes"
        )
    return output


def _is_local_source(source: str) -> bool:
    return source.startswith(
        ("/", "\\\\", "./", "../", "file://", "path+file://")
    ) or WINDOWS_PATH_RE.match(source) is not None


def parse_cargo_tree(output: str) -> ParsedCargoTree:
    """Parse `cargo tree --prefix none --format {p}|{f}` output."""

    _bounded_output(output, "cargo tree")
    packages: dict[str, set[str]] = {}
    local_packages: set[str] = set()
    for line_number, raw_line in enumerate(output.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        if line.endswith(" (*)"):
            line = line[:-4]
        if line.count("|") != 1:
            _fail(
                f"cargo tree line {line_number} must contain exactly one "
                f"package/features separator: {raw_line!r}"
            )
        descriptor, feature_text = line.split("|", 1)
        if " v" not in descriptor:
            _fail(
                f"cargo tree line {line_number} lacks a package version: {raw_line!r}"
            )
        package, version_and_source = descriptor.split(" v", 1)
        if PACKAGE_NAME_RE.fullmatch(package) is None:
            _fail(
                f"cargo tree line {line_number} has an invalid package name: {package!r}"
            )
        version, separator, source_annotation = version_and_source.partition(" ")
        if VERSION_RE.fullmatch(version) is None:
            _fail(
                f"cargo tree line {line_number} has an invalid package version: {version!r}"
            )
        if separator:
            source_annotation = source_annotation.strip()
            if (
                len(source_annotation) < 3
                or not source_annotation.startswith("(")
                or not source_annotation.endswith(")")
            ):
                _fail(
                    f"cargo tree line {line_number} has an invalid package source: "
                    f"{source_annotation!r}"
                )
            if _is_local_source(source_annotation[1:-1]):
                local_packages.add(package)

        features: set[str] = set()
        if feature_text:
            feature_values = feature_text.split(",")
            if any(FEATURE_RE.fullmatch(feature) is None for feature in feature_values):
                _fail(
                    f"cargo tree line {line_number} has an invalid feature list: "
                    f"{feature_text!r}"
                )
            if len(set(feature_values)) != len(feature_values):
                _fail(
                    f"cargo tree line {line_number} repeats an enabled feature: "
                    f"{feature_text!r}"
                )
            features.update(feature_values)
        packages.setdefault(package, set()).update(features)

    if not packages:
        _fail("cargo tree output did not contain any package nodes")
    return ParsedCargoTree(
        features_by_package={
            package: frozenset(features)
            for package, features in sorted(packages.items())
        },
        local_packages=frozenset(local_packages),
    )


def validate_profile_graph(
    profile: GraphProfile,
    output: str,
    first_party_packages: frozenset[str],
) -> GraphSummary:
    parsed = parse_cargo_tree(output)
    graph = parsed.features_by_package
    violations: list[str] = []
    if profile.package not in graph:
        violations.append(f"root package {profile.package!r} is missing")

    unknown_local = sorted(parsed.local_packages - first_party_packages)
    if unknown_local:
        violations.append("unknown local/path packages: " + ", ".join(unknown_local))

    expected_features = dict(profile.first_party_features)
    actual_first_party = frozenset(graph).intersection(first_party_packages)
    expected_first_party = frozenset(expected_features)
    if actual_first_party != expected_first_party:
        violations.append(
            "first-party package closure differs: "
            f"missing={sorted(expected_first_party - actual_first_party)}, "
            f"unexpected={sorted(actual_first_party - expected_first_party)}"
        )

    for package, expected in sorted(expected_features.items()):
        actual = graph.get(package)
        if actual is None:
            continue
        if actual != expected:
            violations.append(
                f"{package} features are [{', '.join(sorted(actual))}] but "
                f"must be [{', '.join(sorted(expected))}]"
            )

    forbidden = sorted(set(graph).intersection(profile.forbidden_packages))
    forbidden.extend(
        sorted(
            package
            for package in graph
            if package not in profile.forbidden_packages
            and any(
                package.startswith(prefix)
                for prefix in profile.forbidden_package_prefixes
            )
        )
    )
    if forbidden:
        violations.append("forbidden transitive packages: " + ", ".join(forbidden))

    if violations:
        _fail(
            f"{profile.label} boundary failed:\n  - "
            + "\n  - ".join(violations)
        )
    return GraphSummary(
        packages=len(graph), first_party_packages=len(actual_first_party)
    )


def parse_workspace_metadata(output: str, repo_root: Path) -> WorkspaceMetadata:
    _bounded_output(output, "cargo metadata")
    try:
        document = json.loads(output)
    except json.JSONDecodeError as error:
        _fail(f"cargo metadata is not valid JSON: {error}")
    if not isinstance(document, dict):
        _fail("cargo metadata root must be an object")
    packages = document.get("packages")
    workspace_members = document.get("workspace_members")
    if not isinstance(packages, list) or not isinstance(workspace_members, list):
        _fail("cargo metadata must contain package and workspace member arrays")

    by_id: dict[str, tuple[str, str]] = {}
    names: set[str] = set()
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            _fail(f"cargo metadata package {index} must be an object")
        package_id = package.get("id")
        name = package.get("name")
        manifest_path = package.get("manifest_path")
        if not all(isinstance(item, str) for item in (package_id, name, manifest_path)):
            _fail(
                f"cargo metadata package {index} needs string id, name, and manifest_path"
            )
        assert isinstance(package_id, str)
        assert isinstance(name, str)
        assert isinstance(manifest_path, str)
        if name in names:
            _fail(f"Cargo workspace package name is duplicated: {name}")
        names.add(name)
        by_id[package_id] = (name, _relative(repo_root, Path(manifest_path)))

    workspace_names: set[str] = set()
    packages_by_name: dict[str, str] = {}
    for index, member in enumerate(workspace_members):
        if not isinstance(member, str):
            _fail(f"cargo metadata workspace member {index} must be a string")
        resolved = by_id.get(member)
        if resolved is None:
            _fail(f"cargo metadata workspace member is unresolved: {member}")
        name, manifest = resolved
        if name in workspace_names:
            _fail(f"Cargo workspace package name is duplicated: {name}")
        workspace_names.add(name)
        packages_by_name[name] = manifest
    if not workspace_names:
        _fail("cargo metadata did not contain workspace packages")
    return WorkspaceMetadata(
        packages_by_name=packages_by_name,
        workspace_packages=frozenset(workspace_names),
    )


def validate_metadata(
    metadata: WorkspaceMetadata, policy: CargoBoundaryPolicy
) -> None:
    adapter_manifests = policy.repository.registered_adapter_manifests
    violations: list[str] = []
    for profile in policy.profiles:
        actual_manifest = metadata.packages_by_name.get(profile.package)
        if profile.manifest in adapter_manifests:
            if actual_manifest is not None:
                violations.append(
                    f"adapter package {profile.package} must stay outside the root workspace"
                )
            continue
        if actual_manifest is None:
            violations.append(f"production package {profile.package} is not a workspace member")
        elif actual_manifest != profile.manifest:
            violations.append(
                f"{profile.package} manifest is {actual_manifest}, expected {profile.manifest}"
            )
    if violations:
        _fail("Cargo metadata boundary failed:\n  - " + "\n  - ".join(violations))


def cargo_tree_command(profile: GraphProfile) -> tuple[str, ...]:
    return (
        "cargo",
        "tree",
        "--manifest-path",
        profile.manifest,
        "-p",
        profile.package,
        "--locked",
        "--target",
        "all",
        "--color",
        "never",
        "-e",
        "normal,build",
        "--prefix",
        "none",
        "--format",
        "{p}|{f}",
        *profile.feature_arguments,
    )


def _run(command: Sequence[str], repo_root: Path) -> str:
    print(f"+ {shlex.join(command)}", flush=True)
    result = subprocess.run(
        list(command),
        cwd=repo_root,
        check=False,
        stdout=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        _fail(
            f"command exited with status {result.returncode}: {shlex.join(command)}"
        )
    return result.stdout if result.stdout is not None else ""


def validate_repository(repo_root: Path, policy_path: Path) -> None:
    repo_root = repo_root.resolve()
    policy_path = policy_path.resolve()
    policy = load_policy(policy_path)
    validate_repository_layout(repo_root, policy)

    metadata_output = _run(
        (
            "cargo",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
        ),
        repo_root,
    )
    metadata = parse_workspace_metadata(metadata_output, repo_root)
    validate_metadata(metadata, policy)

    for profile in policy.profiles:
        graph = _run(cargo_tree_command(profile), repo_root)
        summary = validate_profile_graph(
            profile, graph, policy.first_party_packages
        )
        print(
            f"FileBelt {profile.label} Cargo boundary passed "
            f"({summary.packages} packages; "
            f"{summary.first_party_packages} first-party packages)."
        )


def parse_arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate FileBelt production Cargo package boundaries."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root (defaults to the script's repository)",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        help=f"policy path (defaults to {POLICY_FILENAME} below the repository root)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
    repo_root = arguments.repo_root.resolve()
    policy_path = (
        arguments.policy.resolve()
        if arguments.policy is not None
        else repo_root / POLICY_FILENAME
    )
    try:
        validate_repository(repo_root, policy_path)
    except (BoundaryError, OSError) as error:
        print(f"Cargo boundary check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
