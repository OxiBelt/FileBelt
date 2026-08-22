#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate directional license policy against locked Cargo metadata."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, Sequence


POLICY_FILENAME = "supply-chain/license-compatibility-v1.toml"
MAXIMUM_METADATA_BYTES = 64 * 1024 * 1024
PACKAGE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]*$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
SPDX_TOKEN_RE = re.compile(r"\(|\)|AND|OR|WITH|[A-Za-z0-9.+-]+")
PRODUCED_EVIDENCE = frozenset(
    {
        "source-bundle",
        "image",
        "image-sbom",
        "image-provenance",
        "image-validation",
        "vulnerability-decision",
        "rebuild",
        "notices",
        "chart-digest",
        "promotion-subject",
    }
)
IMAGE_EVIDENCE = frozenset(
    {
        "image",
        "image-sbom",
        "image-provenance",
        "image-validation",
        "vulnerability-decision",
        "rebuild",
        "notices",
        "chart-digest",
        "promotion-subject",
    }
)
REQUIRED_ELIGIBLE_EVIDENCE = frozenset(
    {
        "source-bundle",
        "image",
        "image-sbom",
        "image-provenance",
        "image-validation",
        "vulnerability-decision",
        "rebuild",
        "notices",
    }
)


class CompatibilityError(ValueError):
    """A malformed policy, metadata graph, or qualification violation."""


@dataclass(frozen=True)
class LocalDependency:
    package: str
    license: str
    relationship: str


@dataclass(frozen=True)
class LicenseException:
    package: str
    version: str
    license: str
    relationship: str


@dataclass(frozen=True)
class WorkspacePolicy:
    id: str
    manifest: str
    lockfile: str
    region: str
    license: str
    package_licenses: dict[str, str]
    allowed_local_dependencies: tuple[LocalDependency, ...]
    restricted_license_exceptions: tuple[LicenseException, ...]


@dataclass(frozen=True)
class ComponentPolicy:
    id: str
    version: str
    relationship: str
    license: str
    path: str
    source_required: bool


@dataclass(frozen=True)
class ArtifactPolicy:
    id: str
    workspace: str
    minimum_license_expression: str
    components: tuple[ComponentPolicy, ...]


@dataclass(frozen=True)
class CompatibilityPolicy:
    schema_version: int
    metadata_format_version: int
    relationship_types: frozenset[str]
    restricted_licenses: frozenset[str]
    forbidden_git_packages: frozenset[str]
    forbidden_git_prefixes: tuple[str, ...]
    image_build_preconditions: tuple[str, ...]
    workspaces: tuple[WorkspacePolicy, ...]
    artifacts: tuple[ArtifactPolicy, ...]


@dataclass(frozen=True)
class Package:
    id: str
    name: str
    version: str
    license: str
    source: str | None
    manifest_path: Path

    @property
    def local(self) -> bool:
        return self.source is None


def _fail(message: str) -> NoReturn:
    raise CompatibilityError(message)


def _table(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{context} must be a table")
    return value


def _exact_keys(value: dict[str, Any], keys: set[str], context: str) -> None:
    actual = set(value)
    if actual != keys:
        _fail(
            f"{context} keys differ: missing={sorted(keys - actual)}, "
            f"unexpected={sorted(actual - keys)}"
        )


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{context} must be a non-empty string")
    return value


def _strings(value: Any, context: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        _fail(f"{context} must be an array")
    result = tuple(_string(item, f"{context} item") for item in value)
    if len(result) != len(set(result)):
        _fail(f"{context} must not contain duplicates")
    return result


def _relative(value: Any, context: str) -> str:
    result = _string(value, context)
    path = PurePosixPath(result)
    if path.is_absolute() or path.as_posix() != result or ".." in path.parts:
        _fail(f"{context} must be a normalized repository-relative path")
    return result


def _package(value: Any, context: str) -> str:
    result = _string(value, context)
    if PACKAGE_RE.fullmatch(result) is None:
        _fail(f"{context} is not a valid package name: {result!r}")
    return result


def _parse_relationship(value: Any, allowed: frozenset[str], context: str) -> str:
    relationship = _string(value, context)
    if relationship not in allowed:
        _fail(f"{context} has unknown relationship {relationship!r}")
    return relationship


def _parse_local_dependency(
    value: Any, relationships: frozenset[str], context: str
) -> LocalDependency:
    table = _table(value, context)
    _exact_keys(table, {"package", "license", "relationship"}, context)
    relationship = _parse_relationship(table["relationship"], relationships, context)
    if relationship not in {"linked", "build-only"}:
        _fail(f"{context} Cargo relationship must be linked or build-only")
    return LocalDependency(
        package=_package(table["package"], f"{context}.package"),
        license=_string(table["license"], f"{context}.license"),
        relationship=relationship,
    )


def _parse_exception(
    value: Any, relationships: frozenset[str], context: str
) -> LicenseException:
    table = _table(value, context)
    _exact_keys(table, {"package", "version", "license", "relationship"}, context)
    version = _string(table["version"], f"{context}.version")
    if VERSION_RE.fullmatch(version) is None:
        _fail(f"{context}.version must be exact SemVer")
    relationship = _parse_relationship(table["relationship"], relationships, context)
    if relationship not in {"linked", "build-only"}:
        _fail(f"{context} Cargo relationship must be linked or build-only")
    return LicenseException(
        package=_package(table["package"], f"{context}.package"),
        version=version,
        license=_string(table["license"], f"{context}.license"),
        relationship=relationship,
    )


def load_policy(path: Path) -> CompatibilityPolicy:
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        _fail(f"license compatibility policy cannot be loaded: {error}")
    _exact_keys(document, {"schema_version", "repository", "workspaces", "artifacts"}, "policy")
    if document["schema_version"] != 1:
        _fail(f"unsupported schema_version: {document['schema_version']!r}")

    repository = _table(document["repository"], "repository")
    _exact_keys(
        repository,
        {
            "metadata_format_version",
            "relationship_types",
            "restricted_licenses",
            "forbidden_git_implementation_packages",
            "forbidden_git_implementation_prefixes",
            "image_build_preconditions",
        },
        "repository",
    )
    if repository["metadata_format_version"] != 1:
        _fail("repository.metadata_format_version must be 1")
    relationships = frozenset(_strings(repository["relationship_types"], "relationship_types"))
    expected_relationships = {
        "linked",
        "copied",
        "separate-executable",
        "external",
        "build-only",
    }
    if relationships != expected_relationships:
        _fail("relationship_types must define the closed version-1 relationship set")
    restricted = frozenset(_strings(repository["restricted_licenses"], "restricted_licenses"))
    preconditions = _strings(repository["image_build_preconditions"], "image_build_preconditions")
    if not restricted or not preconditions:
        _fail("restricted licenses and image-build preconditions must be non-empty")

    raw_workspaces = document["workspaces"]
    if not isinstance(raw_workspaces, list) or not raw_workspaces:
        _fail("workspaces must be a non-empty array")
    workspaces: list[WorkspacePolicy] = []
    for index, value in enumerate(raw_workspaces):
        context = f"workspaces[{index}]"
        table = _table(value, context)
        _exact_keys(
            table,
            {
                "id",
                "manifest",
                "lockfile",
                "region",
                "license",
                "package_licenses",
                "allowed_local_dependencies",
                "restricted_license_exceptions",
            },
            context,
        )
        package_licenses = _table(table["package_licenses"], f"{context}.package_licenses")
        normalized_packages = {
            _package(name, f"{context}.package_licenses key"): _string(
                license_name, f"{context}.package_licenses.{name}"
            )
            for name, license_name in package_licenses.items()
        }
        if not normalized_packages:
            _fail(f"{context}.package_licenses must not be empty")
        local_dependencies = tuple(
            _parse_local_dependency(item, relationships, f"{context}.allowed_local_dependencies[{item_index}]")
            for item_index, item in enumerate(table["allowed_local_dependencies"])
        )
        exceptions = tuple(
            _parse_exception(item, relationships, f"{context}.restricted_license_exceptions[{item_index}]")
            for item_index, item in enumerate(table["restricted_license_exceptions"])
        )
        if any(exception.license not in restricted for exception in exceptions):
            _fail(f"{context} has an exception for a non-restricted license")
        workspaces.append(
            WorkspacePolicy(
                id=_string(table["id"], f"{context}.id"),
                manifest=_relative(table["manifest"], f"{context}.manifest"),
                lockfile=_relative(table["lockfile"], f"{context}.lockfile"),
                region=_string(table["region"], f"{context}.region"),
                license=_string(table["license"], f"{context}.license"),
                package_licenses=normalized_packages,
                allowed_local_dependencies=local_dependencies,
                restricted_license_exceptions=exceptions,
            )
        )
    workspace_ids = [workspace.id for workspace in workspaces]
    manifests = [workspace.manifest for workspace in workspaces]
    if len(workspace_ids) != len(set(workspace_ids)) or len(manifests) != len(set(manifests)):
        _fail("workspace ids and manifests must be unique")
    if set(workspace_ids) != {
        "root",
        "smb",
        "ftp-ftps",
        "onlyoffice",
        "git",
        "directory-repository",
        "nfs",
        "wireguard",
        "transcode",
    }:
        _fail("policy must register the root and all eight adapter workspaces")

    raw_artifacts = document["artifacts"]
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        _fail("artifacts must be a non-empty array")
    artifacts: list[ArtifactPolicy] = []
    for index, value in enumerate(raw_artifacts):
        context = f"artifacts[{index}]"
        table = _table(value, context)
        _exact_keys(table, {"id", "workspace", "minimum_license_expression", "components"}, context)
        components_value = table["components"]
        if not isinstance(components_value, list) or not components_value:
            _fail(f"{context}.components must be a non-empty array")
        components: list[ComponentPolicy] = []
        for component_index, component_value in enumerate(components_value):
            component_context = f"{context}.components[{component_index}]"
            component = _table(component_value, component_context)
            _exact_keys(
                component,
                {"id", "version", "relationship", "license", "path", "source_required"},
                component_context,
            )
            relationship = _parse_relationship(component["relationship"], relationships, component_context)
            component_path = _string(component["path"], f"{component_context}.path")
            if relationship == "external":
                if not component_path.startswith("external://"):
                    _fail(f"{component_context}.path must use external://")
            elif not component_path.startswith("/"):
                _fail(f"{component_context}.path must be absolute")
            source_required = component["source_required"]
            if not isinstance(source_required, bool):
                _fail(f"{component_context}.source_required must be boolean")
            if relationship != "external" and not source_required:
                _fail(f"{component_context} distributed component requires source evidence")
            components.append(
                ComponentPolicy(
                    id=_string(component["id"], f"{component_context}.id"),
                    version=_string(component["version"], f"{component_context}.version"),
                    relationship=relationship,
                    license=_string(component["license"], f"{component_context}.license"),
                    path=component_path,
                    source_required=source_required,
                )
            )
        component_ids = [component.id for component in components]
        if len(component_ids) != len(set(component_ids)):
            _fail(f"{context}.component ids must be unique")
        artifacts.append(
            ArtifactPolicy(
                id=_string(table["id"], f"{context}.id"),
                workspace=_string(table["workspace"], f"{context}.workspace"),
                minimum_license_expression=_string(
                    table["minimum_license_expression"],
                    f"{context}.minimum_license_expression",
                ),
                components=tuple(components),
            )
        )
    artifact_ids = [artifact.id for artifact in artifacts]
    if len(artifact_ids) != len(set(artifact_ids)):
        _fail("artifact ids must be unique")
    adapter_ids = set(workspace_ids) - {"root"}
    if {artifact.workspace for artifact in artifacts} != adapter_ids:
        _fail("artifacts must cover every adapter workspace exactly")
    workspace_by_id = {workspace.id: workspace for workspace in workspaces}
    for artifact in artifacts:
        workspace = workspace_by_id[artifact.workspace]
        component_by_id = {component.id: component for component in artifact.components}
        required_components = set(workspace.package_licenses) | {
            dependency.package for dependency in workspace.allowed_local_dependencies
        }
        missing_components = required_components - set(component_by_id)
        if missing_components:
            _fail(
                f"{artifact.id} omits Cargo/local components: "
                f"{sorted(missing_components)}"
            )
        for package_name, license_name in workspace.package_licenses.items():
            if component_by_id[package_name].license != license_name:
                _fail(f"{artifact.id} first-party component license differs")
        for dependency in workspace.allowed_local_dependencies:
            component = component_by_id[dependency.package]
            if (component.license, component.relationship) != (
                dependency.license,
                dependency.relationship,
            ):
                _fail(f"{artifact.id} local dependency component differs")
        if workspace.license not in artifact.minimum_license_expression:
            _fail(f"{artifact.id} minimum license omits its workspace license")
        for component in artifact.components:
            for restricted_license in restricted:
                if (
                    component.relationship != "external"
                    and restricted_license in component.license
                    and _license_requires(component.license, restricted_license)
                    and restricted_license not in artifact.minimum_license_expression
                ):
                    _fail(
                        f"{artifact.id} minimum license omits distributed "
                        f"{restricted_license} component {component.id}"
                    )
                if (
                    workspace.license == "Apache-2.0"
                    and component.relationship == "linked"
                    and restricted_license in component.license
                    and _license_requires(component.license, restricted_license)
                ):
                    _fail(
                        f"Apache artifact {artifact.id} links restricted "
                        f"component {component.id} ({restricted_license})"
                    )

    return CompatibilityPolicy(
        schema_version=1,
        metadata_format_version=1,
        relationship_types=relationships,
        restricted_licenses=restricted,
        forbidden_git_packages=frozenset(
            _strings(repository["forbidden_git_implementation_packages"], "forbidden Git packages")
        ),
        forbidden_git_prefixes=_strings(
            repository["forbidden_git_implementation_prefixes"], "forbidden Git prefixes"
        ),
        image_build_preconditions=preconditions,
        workspaces=tuple(workspaces),
        artifacts=tuple(artifacts),
    )


def _repo_relative(repo_root: Path, path: Path, context: str) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        _fail(f"{context} escapes repository root: {path}")


def _dependency_relationship(dependency: dict[str, Any]) -> str:
    dep_kinds = dependency.get("dep_kinds")
    if not isinstance(dep_kinds, list) or not dep_kinds:
        _fail("Cargo resolve dependency has no dep_kinds")
    if any(not isinstance(item, dict) for item in dep_kinds):
        _fail("Cargo resolve dependency has malformed dep_kinds")
    kinds = {item.get("kind") for item in dep_kinds}
    if not kinds <= {None, "normal", "build", "dev"}:
        _fail("Cargo resolve dependency has an unknown dependency kind")
    return "build-only" if kinds == {"build"} else "linked"


def _license_requires(expression: str, restricted_license: str) -> bool:
    """Return true when no SPDX OR branch avoids the restricted license."""

    tokens = SPDX_TOKEN_RE.findall(expression)
    if not tokens or "".join(tokens) != re.sub(r"\s+", "", expression):
        _fail(f"invalid SPDX expression: {expression!r}")
    position = 0

    def primary() -> bool:
        nonlocal position
        if position >= len(tokens):
            _fail(f"truncated SPDX expression: {expression!r}")
        token = tokens[position]
        if token == "(":
            position += 1
            value = disjunction()
            if position >= len(tokens) or tokens[position] != ")":
                _fail(f"unbalanced SPDX expression: {expression!r}")
            position += 1
        elif token in {"AND", "OR", "WITH", ")"}:
            _fail(f"invalid SPDX expression token {token!r}: {expression!r}")
        else:
            position += 1
            value = token != restricted_license
        if position < len(tokens) and tokens[position] == "WITH":
            position += 1
            if position >= len(tokens) or tokens[position] in {"AND", "OR", "WITH", "(", ")"}:
                _fail(f"invalid SPDX WITH expression: {expression!r}")
            position += 1
        return value

    def conjunction() -> bool:
        nonlocal position
        value = primary()
        while position < len(tokens) and tokens[position] == "AND":
            position += 1
            value = primary() and value
        return value

    def disjunction() -> bool:
        nonlocal position
        value = conjunction()
        while position < len(tokens) and tokens[position] == "OR":
            position += 1
            value = conjunction() or value
        return value

    usable_without_restricted_license = disjunction()
    if position != len(tokens):
        _fail(f"invalid trailing SPDX expression: {expression!r}")
    return not usable_without_restricted_license


def validate_metadata_document(
    document: Any,
    workspace: WorkspacePolicy,
    policy: CompatibilityPolicy,
    repo_root: Path,
) -> None:
    metadata = _table(document, f"{workspace.id} metadata")
    if metadata.get("version") != policy.metadata_format_version:
        _fail(f"{workspace.id} metadata format version differs")
    expected_root = (repo_root / workspace.manifest).resolve().parent
    workspace_root = Path(_string(metadata.get("workspace_root"), "metadata.workspace_root"))
    if workspace_root.resolve() != expected_root:
        _fail(f"{workspace.id} metadata workspace_root differs from {expected_root}")
    packages_value = metadata.get("packages")
    if not isinstance(packages_value, list) or not packages_value:
        _fail(f"{workspace.id} metadata packages must be non-empty")
    packages: dict[str, Package] = {}
    for index, value in enumerate(packages_value):
        package_table = _table(value, f"{workspace.id}.packages[{index}]")
        package = Package(
            id=_string(package_table.get("id"), "package.id"),
            name=_package(package_table.get("name"), "package.name"),
            version=_string(package_table.get("version"), "package.version"),
            license=_string(package_table.get("license"), "package.license"),
            source=package_table.get("source"),
            manifest_path=Path(_string(package_table.get("manifest_path"), "package.manifest_path")),
        )
        if package.source is not None and not isinstance(package.source, str):
            _fail(f"{package.name} source must be a string or null")
        if package.id in packages:
            _fail(f"duplicate Cargo package id: {package.id}")
        if package.local:
            _repo_relative(repo_root, package.manifest_path, f"{package.name} manifest")
        packages[package.id] = package

    member_ids = metadata.get("workspace_members")
    if not isinstance(member_ids, list) or any(not isinstance(item, str) for item in member_ids):
        _fail(f"{workspace.id} workspace_members must be an array of ids")
    try:
        members = [packages[package_id] for package_id in member_ids]
    except KeyError as error:
        _fail(f"{workspace.id} workspace member has no package: {error.args[0]}")
    actual_package_licenses = {package.name: package.license for package in members}
    if actual_package_licenses != workspace.package_licenses:
        _fail(
            f"{workspace.id} workspace package licenses differ: "
            f"expected={workspace.package_licenses}, actual={actual_package_licenses}"
        )
    if any(not package.local for package in members):
        _fail(f"{workspace.id} workspace member is not a local package")

    resolve = _table(metadata.get("resolve"), f"{workspace.id}.resolve")
    nodes_value = resolve.get("nodes")
    if not isinstance(nodes_value, list):
        _fail(f"{workspace.id} resolve.nodes must be an array")
    nodes: dict[str, dict[str, Any]] = {}
    for value in nodes_value:
        node = _table(value, "resolve node")
        node_id = _string(node.get("id"), "resolve node id")
        if node_id in nodes:
            _fail(f"duplicate Cargo resolve node: {node_id}")
        nodes[node_id] = node
    if any(package_id not in nodes for package_id in member_ids):
        _fail(f"{workspace.id} metadata is missing workspace resolve nodes")

    reachable: set[str] = set()
    pending = list(member_ids)
    relationship_by_id: dict[str, set[str]] = {package_id: set() for package_id in member_ids}
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        reachable.add(package_id)
        node = nodes.get(package_id)
        if node is None:
            _fail(f"reachable package has no resolve node: {package_id}")
        dependencies = node.get("deps")
        if not isinstance(dependencies, list):
            _fail(f"resolve node deps must be an array: {package_id}")
        for dependency_value in dependencies:
            dependency = _table(dependency_value, "resolve dependency")
            dependency_id = _string(dependency.get("pkg"), "resolve dependency pkg")
            if dependency_id not in packages:
                _fail(f"resolve dependency has no package: {dependency_id}")
            relationship = _dependency_relationship(dependency)
            relationship_by_id.setdefault(dependency_id, set()).add(relationship)
            pending.append(dependency_id)

    member_names = set(workspace.package_licenses)
    allowed_local = {
        (item.package, item.license, item.relationship)
        for item in workspace.allowed_local_dependencies
    }
    exceptions = {
        (item.package, item.version, item.license, item.relationship)
        for item in workspace.restricted_license_exceptions
    }
    used_local: set[tuple[str, str, str]] = set()
    used_exceptions: set[tuple[str, str, str, str]] = set()
    for package_id in reachable:
        package = packages[package_id]
        relationships = relationship_by_id.get(package_id) or {"linked"}
        if package.name in policy.forbidden_git_packages or any(
            package.name.startswith(prefix) for prefix in policy.forbidden_git_prefixes
        ):
            _fail(f"{workspace.id} reaches forbidden Git implementation package {package.name}")
        if package.local and package.name not in member_names:
            for relationship in relationships:
                key = (package.name, package.license, relationship)
                if key not in allowed_local:
                    _fail(
                        f"{workspace.id} has undeclared local dependency "
                        f"{package.name} ({package.license}, {relationship})"
                    )
                used_local.add(key)
        restricted_tokens = {
            license_name
            for license_name in policy.restricted_licenses
            if license_name in package.license
            and _license_requires(package.license, license_name)
        }
        if restricted_tokens and package.name not in member_names:
            for license_name in restricted_tokens:
                for relationship in relationships:
                    key = (package.name, package.version, license_name, relationship)
                    if key not in exceptions:
                        _fail(
                            f"{workspace.id} has undeclared restricted license: "
                            f"{package.name}@{package.version} {license_name} ({relationship})"
                        )
                    used_exceptions.add(key)
    stale_local = allowed_local - used_local
    stale_exceptions = exceptions - used_exceptions
    if stale_local:
        _fail(f"{workspace.id} has stale allowed local dependencies: {sorted(stale_local)}")
    if stale_exceptions:
        _fail(f"{workspace.id} has stale restricted license exceptions: {sorted(stale_exceptions)}")


def validate_repository_layout(repo_root: Path, policy: CompatibilityPolicy) -> None:
    for workspace in policy.workspaces:
        if not (repo_root / workspace.manifest).is_file():
            _fail(f"missing workspace manifest: {workspace.manifest}")
        if not (repo_root / workspace.lockfile).is_file():
            _fail(f"missing workspace lockfile: {workspace.lockfile}")


def validate_pre_image_evidence(document: Any, policy: CompatibilityPolicy) -> None:
    evidence = _table(document, "pre-image evidence")
    _exact_keys(evidence, {"schema_version", "artifacts"}, "pre-image evidence")
    if evidence["schema_version"] != 1:
        _fail("pre-image evidence schema_version must be 1")
    entries = evidence["artifacts"]
    if not isinstance(entries, list):
        _fail("pre-image evidence artifacts must be an array")
    expected = {artifact.id for artifact in policy.artifacts}
    seen: set[str] = set()
    for index, value in enumerate(entries):
        context = f"pre-image evidence artifacts[{index}]"
        entry = _table(value, context)
        _exact_keys(entry, {"id", "image_build_state", "preconditions", "produced"}, context)
        artifact_id = _string(entry["id"], f"{context}.id")
        if artifact_id not in expected or artifact_id in seen:
            _fail(f"{context} has unknown or duplicate id {artifact_id}")
        seen.add(artifact_id)
        state = _string(entry["image_build_state"], f"{context}.image_build_state")
        if state not in {"blocked", "eligible"}:
            _fail(f"{context}.image_build_state must be blocked or eligible")
        preconditions = _table(entry["preconditions"], f"{context}.preconditions")
        if set(preconditions) != set(policy.image_build_preconditions):
            _fail(f"{context}.preconditions differ from policy")
        if any(value not in {"blocked", "qualified"} for value in preconditions.values()):
            _fail(f"{context}.preconditions contain an unknown state")
        expected_state = (
            "eligible" if all(value == "qualified" for value in preconditions.values()) else "blocked"
        )
        if state != expected_state:
            _fail(f"{context}.image_build_state is {state}, expected {expected_state}")
        produced = frozenset(_strings(entry["produced"], f"{context}.produced"))
        unknown = produced - PRODUCED_EVIDENCE
        if unknown:
            _fail(f"{context}.produced has unknown evidence: {sorted(unknown)}")
        if state == "blocked" and produced & IMAGE_EVIDENCE:
            _fail(f"{context} produced image evidence while blocked")
        if state == "eligible" and not REQUIRED_ELIGIBLE_EVIDENCE <= produced:
            _fail(f"{context} eligible image build did not produce required evidence")
    if seen != expected:
        _fail(f"pre-image evidence artifact ids differ: missing={sorted(expected - seen)}")


def _run_metadata(repo_root: Path, workspace: WorkspacePolicy) -> dict[str, Any]:
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--offline",
        "--format-version",
        "1",
        "--manifest-path",
        str((repo_root / workspace.manifest).resolve()),
    ]
    try:
        result = subprocess.run(
            command,
            cwd=repo_root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
        )
    except OSError as error:
        _fail(f"cannot execute cargo metadata for {workspace.id}: {error}")
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")[-4000:]
        _fail(f"cargo metadata failed for {workspace.id}: {stderr}")
    if len(result.stdout) > MAXIMUM_METADATA_BYTES:
        _fail(f"cargo metadata output is too large for {workspace.id}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        _fail(f"cargo metadata output is invalid JSON for {workspace.id}: {error}")


def _load_supplied_metadata(path: Path, workspace: WorkspacePolicy) -> dict[str, Any]:
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        _fail(f"cannot load supplied metadata {path}: {error}")
    envelope = _table(envelope, f"supplied metadata {path}")
    _exact_keys(envelope, {"schema_version", "workspace", "command", "metadata"}, "supplied metadata")
    expected_command = ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"]
    if envelope["schema_version"] != 1 or envelope["workspace"] != workspace.id:
        _fail(f"supplied metadata identity differs for {workspace.id}")
    if envelope["command"] != expected_command:
        _fail(f"supplied metadata for {workspace.id} lacks locked/offline provenance")
    return _table(envelope["metadata"], f"supplied metadata {workspace.id}.metadata")


def validate_all(
    repo_root: Path,
    policy: CompatibilityPolicy,
    metadata_directory: Path | None = None,
) -> None:
    validate_repository_layout(repo_root, policy)
    for workspace in policy.workspaces:
        if metadata_directory is None:
            metadata = _run_metadata(repo_root, workspace)
        else:
            metadata = _load_supplied_metadata(metadata_directory / f"{workspace.id}.json", workspace)
        validate_metadata_document(metadata, workspace, policy, repo_root)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--metadata-directory", type=Path)
    parser.add_argument("--pre-image-evidence", type=Path)
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    policy_path = args.policy or repo_root / POLICY_FILENAME
    try:
        policy = load_policy(policy_path)
        validate_all(repo_root, policy, args.metadata_directory)
        if args.pre_image_evidence is not None:
            validate_pre_image_evidence(
                json.loads(args.pre_image_evidence.read_text(encoding="utf-8")), policy
            )
    except (CompatibilityError, OSError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("FileBelt license compatibility contracts passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
