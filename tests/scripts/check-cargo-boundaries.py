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
from urllib.parse import unquote, urlparse


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
class PackageIdentity:
    """A reviewed local Cargo package, bound to its metadata manifest."""

    cargo_id: str
    name: str
    version: str
    manifest: str
    source_path: str

    def display(self) -> str:
        return f"{self.name} v{self.version} ({self.source_path})"


@dataclass(frozen=True)
class TreePackageIdentity:
    """A Cargo tree package identity; local paths are repository-relative."""

    name: str
    version: str
    source_path: str | None
    source_annotation: str | None

    def display(self) -> str:
        if self.source_path is not None:
            return f"{self.name} v{self.version} ({self.source_path})"
        if self.source_annotation is not None:
            return f"{self.name} v{self.version} ({self.source_annotation})"
        return f"{self.name} v{self.version}"


@dataclass(frozen=True)
class ParsedCargoTree:
    features_by_identity: dict[TreePackageIdentity, frozenset[str]]


@dataclass(frozen=True)
class IdentityCatalog:
    by_manifest: dict[str, PackageIdentity]
    by_name: dict[str, PackageIdentity]

    @property
    def identities(self) -> frozenset[PackageIdentity]:
        return frozenset(self.by_manifest.values())

    def for_profile(self, profile: GraphProfile) -> PackageIdentity:
        identity = self.by_manifest.get(profile.manifest)
        if identity is None:
            _fail(f"missing reviewed Cargo identity for {profile.manifest}")
        if identity.name != profile.package:
            _fail(
                f"reviewed Cargo identity at {profile.manifest} is "
                f"{identity.name}, expected {profile.package}"
            )
        return identity


@dataclass(frozen=True)
class GraphSummary:
    packages: int
    first_party_packages: int


@dataclass(frozen=True)
class WorkspaceMetadata:
    packages_by_id: dict[str, PackageIdentity]
    workspace_members: frozenset[PackageIdentity]


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


def _canonical_local_source(source: str, repo_root: Path, context: str) -> str:
    """Turn a Cargo local-source annotation into a repository-relative path."""

    windows_path = WINDOWS_PATH_RE.match(source) is not None or source.startswith("\\\\")
    if windows_path and sys.platform != "win32":
        _fail(f"{context} uses a non-native Windows path: {source!r}")

    if windows_path:
        path_text = source
    elif source.startswith(("file://", "path+file://")):
        parsed = urlparse(source)
        if parsed.scheme not in {"file", "path+file"}:
            _fail(f"{context} has an unsupported local source: {source!r}")
        if parsed.netloc not in {"", "localhost"} or parsed.params or parsed.query:
            _fail(f"{context} has an ambiguous local source URL: {source!r}")
        if parsed.fragment:
            _fail(f"{context} must not include a source fragment: {source!r}")
        path_text = unquote(parsed.path)
        if not path_text:
            _fail(f"{context} has an empty local source path: {source!r}")
        if sys.platform == "win32" and re.match(r"^/[A-Za-z]:/", path_text):
            path_text = path_text[1:]
    else:
        path_text = source

    path = Path(path_text)
    if not path.is_absolute():
        path = repo_root / path
    return _relative(repo_root, path)


def _tree_identity_matches(
    tree_identity: TreePackageIdentity, expected: PackageIdentity
) -> bool:
    return (
        tree_identity.name == expected.name
        and tree_identity.version == expected.version
        and tree_identity.source_path == expected.source_path
    )


def parse_cargo_tree(output: str, repo_root: Path) -> ParsedCargoTree:
    """Parse `cargo tree --prefix none --format {p}|{f}` output."""

    _bounded_output(output, "cargo tree")
    packages: dict[TreePackageIdentity, set[str]] = {}
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
        source_path: str | None = None
        source: str | None = None
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
            source = source_annotation[1:-1]
            if _is_local_source(source):
                source_path = _canonical_local_source(
                    source, repo_root, f"cargo tree line {line_number}"
                )

        identity = TreePackageIdentity(
            name=package,
            version=version,
            source_path=source_path,
            source_annotation=source,
        )

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
        packages.setdefault(identity, set()).update(features)

    if not packages:
        _fail("cargo tree output did not contain any package nodes")
    return ParsedCargoTree(
        features_by_identity={
            identity: frozenset(features)
            for identity, features in sorted(
                packages.items(), key=lambda item: item[0].display()
            )
        },
    )


def validate_profile_graph(
    profile: GraphProfile,
    output: str,
    catalog: IdentityCatalog,
    repo_root: Path,
) -> GraphSummary:
    parsed = parse_cargo_tree(output, repo_root)
    graph = parsed.features_by_identity
    expected_root = catalog.for_profile(profile)
    expected_features = {
        catalog.by_name[package]: features
        for package, features in profile.first_party_features
    }
    expected_identities = frozenset(expected_features)
    registered_identities = catalog.identities
    violations: list[str] = []
    if not any(_tree_identity_matches(identity, expected_root) for identity in graph):
        violations.append(f"root package {profile.package!r} is missing")

    unknown_local = sorted(
        (
            identity.display()
            for identity in graph
            if identity.source_path is not None
            and not any(
                _tree_identity_matches(identity, expected)
                for expected in registered_identities
            )
        )
    )
    if unknown_local:
        violations.append("unknown local/path packages: " + ", ".join(unknown_local))

    reserved_collisions = sorted(
        identity.display()
        for identity in graph
        if identity.name in catalog.by_name
        and not _tree_identity_matches(identity, catalog.by_name[identity.name])
    )
    if reserved_collisions:
        violations.append(
            "reserved first-party package identities differ: "
            + ", ".join(reserved_collisions)
        )

    actual_first_party = frozenset(
        expected
        for expected in registered_identities
        if any(_tree_identity_matches(identity, expected) for identity in graph)
    )
    expected_first_party = expected_identities
    if actual_first_party != expected_first_party:
        def display(identities: frozenset[PackageIdentity]) -> list[str]:
            return sorted(identity.display() for identity in identities)

        violations.append(
            "first-party package closure differs: "
            f"missing={display(expected_first_party - actual_first_party)}, "
            f"unexpected={display(actual_first_party - expected_first_party)}"
        )

    for expected_identity, expected in sorted(
        expected_features.items(), key=lambda item: item[0].display()
    ):
        actual = set()
        for identity, enabled in graph.items():
            if _tree_identity_matches(identity, expected_identity):
                actual.update(enabled)
        if not actual and not any(
            _tree_identity_matches(identity, expected_identity) for identity in graph
        ):
            continue
        actual_features = frozenset(actual)
        if actual_features != expected:
            violations.append(
                f"{expected_identity.name} features are "
                f"[{', '.join(sorted(actual_features))}] but "
                f"must be [{', '.join(sorted(expected))}]"
            )

    names = {identity.name for identity in graph}
    forbidden = sorted(names.intersection(profile.forbidden_packages))
    forbidden.extend(
        sorted(
            package
            for package in names
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

    by_id: dict[str, PackageIdentity] = {}
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            _fail(f"cargo metadata package {index} must be an object")
        package_id = package.get("id")
        name = package.get("name")
        version = package.get("version")
        if "source" not in package:
            _fail(f"cargo metadata package {index} is missing source")
        source = package["source"]
        manifest_path = package.get("manifest_path")
        if not all(
            isinstance(item, str) for item in (package_id, name, version, manifest_path)
        ):
            _fail(
                "cargo metadata package "
                f"{index} needs string id, name, version, and manifest_path"
            )
        assert isinstance(package_id, str)
        assert isinstance(name, str)
        assert isinstance(version, str)
        assert isinstance(manifest_path, str)
        if package_id in by_id:
            _fail(f"cargo metadata package id is duplicated: {package_id}")
        if PACKAGE_NAME_RE.fullmatch(name) is None:
            _fail(f"cargo metadata package {index} has invalid name: {name!r}")
        if VERSION_RE.fullmatch(version) is None:
            _fail(f"cargo metadata package {index} has invalid version: {version!r}")
        if source is not None:
            _fail(f"cargo metadata package {name} must be a local package")
        manifest = _relative(repo_root, Path(manifest_path))
        if not manifest.endswith("/Cargo.toml") and manifest != "Cargo.toml":
            _fail(f"cargo metadata package {name} manifest is not Cargo.toml: {manifest}")
        by_id[package_id] = PackageIdentity(
            cargo_id=package_id,
            name=name,
            version=version,
            manifest=manifest,
            source_path=PurePosixPath(manifest).parent.as_posix(),
        )

    members: set[PackageIdentity] = set()
    for index, member in enumerate(workspace_members):
        if not isinstance(member, str):
            _fail(f"cargo metadata workspace member {index} must be a string")
        resolved = by_id.get(member)
        if resolved is None:
            _fail(f"cargo metadata workspace member is unresolved: {member}")
        if resolved in members:
            _fail(f"cargo metadata workspace member is duplicated: {resolved.cargo_id}")
        members.add(resolved)
    if not members:
        _fail("cargo metadata did not contain workspace packages")
    return WorkspaceMetadata(
        packages_by_id=by_id,
        workspace_members=frozenset(members),
    )


def validate_metadata(
    root_metadata: WorkspaceMetadata,
    adapter_metadata: dict[str, WorkspaceMetadata],
    policy: CargoBoundaryPolicy,
) -> IdentityCatalog:
    adapter_manifests = policy.repository.registered_adapter_manifests
    profiles_by_manifest = {profile.manifest: profile for profile in policy.profiles}
    root_profiles = {
        manifest: profile
        for manifest, profile in profiles_by_manifest.items()
        if manifest not in adapter_manifests
    }
    violations: list[str] = []
    identities_by_manifest: dict[str, PackageIdentity] = {}

    def is_excluded_manifest(manifest: str) -> bool:
        path = PurePosixPath(manifest)
        return any(
            path == PurePosixPath(root)
            or PurePosixPath(root) in path.parents
            for root in policy.repository.excluded_source_roots
        )

    def collect(
        metadata: WorkspaceMetadata,
        expected: dict[str, GraphProfile],
        context: str,
    ) -> None:
        actual_by_manifest = {
            identity.manifest: identity for identity in metadata.workspace_members
        }
        if len(actual_by_manifest) != len(metadata.workspace_members):
            violations.append(f"{context} has duplicate workspace manifest identities")
        extras = set(actual_by_manifest) - set(expected)
        if context == "root Cargo workspace":
            extras = {manifest for manifest in extras if not is_excluded_manifest(manifest)}
        for manifest in sorted(extras):
            violations.append(f"{context} has unregistered workspace manifest: {manifest}")
        for manifest, profile in sorted(expected.items()):
            identity = actual_by_manifest.get(manifest)
            if identity is None:
                violations.append(
                    f"{context} does not contain registered manifest: {manifest}"
                )
                continue
            if identity.name != profile.package:
                violations.append(
                    f"{context} manifest {manifest} is package {identity.name}, "
                    f"expected {profile.package}"
                )
                continue
            identities_by_manifest[manifest] = identity

    collect(root_metadata, root_profiles, "root Cargo workspace")
    for manifest in sorted(adapter_manifests):
        metadata = adapter_metadata.get(manifest)
        if metadata is None:
            violations.append(f"missing Cargo metadata for adapter manifest: {manifest}")
            continue
        collect(
            metadata,
            {manifest: profiles_by_manifest[manifest]},
            f"adapter {manifest}",
        )
    for manifest in sorted(set(adapter_metadata) - adapter_manifests):
        violations.append(f"Cargo metadata was collected for unregistered adapter: {manifest}")
    if violations:
        _fail("Cargo metadata boundary failed:\n  - " + "\n  - ".join(violations))

    by_name: dict[str, PackageIdentity] = {}
    for identity in sorted(
        identities_by_manifest.values(), key=lambda item: item.manifest
    ):
        existing = by_name.get(identity.name)
        if existing is not None:
            _fail(
                "Cargo metadata boundary failed:\n  - reserved first-party package name "
                f"is ambiguous: {identity.name} at {existing.manifest} and {identity.manifest}"
            )
        by_name[identity.name] = identity
    return IdentityCatalog(
        by_manifest=dict(sorted(identities_by_manifest.items())),
        by_name=dict(sorted(by_name.items())),
    )


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


def cargo_metadata_command(manifest: str | None = None) -> tuple[str, ...]:
    command = (
        "cargo",
        "metadata",
        "--locked",
        "--no-deps",
        "--format-version",
        "1",
    )
    if manifest is None:
        return command
    return (*command, "--manifest-path", manifest)


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

    root_metadata = parse_workspace_metadata(
        _run(cargo_metadata_command(), repo_root), repo_root
    )
    adapter_metadata = {
        manifest: parse_workspace_metadata(
            _run(cargo_metadata_command(manifest), repo_root), repo_root
        )
        for manifest in sorted(policy.repository.registered_adapter_manifests)
    }
    catalog = validate_metadata(root_metadata, adapter_metadata, policy)

    for profile in policy.profiles:
        graph = _run(cargo_tree_command(profile), repo_root)
        summary = validate_profile_graph(
            profile, graph, catalog, repo_root
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
