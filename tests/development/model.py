#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Versioned configuration and non-secret session state for local deployments."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import stat
import tempfile
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SESSION_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
ROLE = re.compile(r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
SECRET_KEY = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
KUBERNETES_VERSIONS = ("v1.34.10", "v1.35.5", "v1.36.1")
CNIS = ("calico", "cilium")
COMPOSE_PROFILES = ("core", "mcp", "iggy", "fault")
PREVIEW_FEATURES = (
    "collaboration",
    "documents",
    "mcp",
    "mcp-runners",
    "mount-ftp-ftps",
    "mount-nfs",
    "mount-smb",
    "revisions",
)
MAXIMUM_CONFIGURATION_BYTES = 1_048_576
PREVIEW_FEATURE_ROLES = {
    "collaboration": frozenset({"filebelt-collaboration"}),
    "documents": frozenset({"filebelt-document"}),
    "mcp": frozenset({"filebelt-mcp-broker"}),
    "mcp-runners": frozenset({"filebelt-controller", "filebelt-mcp-runner"}),
    "mount-ftp-ftps": frozenset(
        {"filebelt-ftp-ftps-gateway", "filebelt-headscale-sync", "filebelt-vfs", "tailscaled"}
    ),
    "mount-nfs": frozenset(
        {
            "filebelt-headscale-sync",
            "filebelt-nfs-gateway",
            "filebelt-nfs-relay",
            "filebelt-vfs",
            "tailscaled",
        }
    ),
    "mount-smb": frozenset(
        {"filebelt-headscale-sync", "filebelt-smb-gateway", "filebelt-vfs", "tailscaled"}
    ),
    "revisions": frozenset({"filebelt-revision"}),
}


class ConfigurationError(ValueError):
    """A development configuration violated the fail-closed input contract."""


def _mapping(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{field} must be a table")
    return value


def _closed(document: dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = set(document) - allowed
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ConfigurationError(f"{field} contains unknown keys: {names}")


def _text(value: object, field: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise ConfigurationError(f"{field} must be a non-empty string")
    return value


def _absolute_file(value: object, field: str, *, optional: bool = False) -> Path | None:
    if value in (None, "") and optional:
        return None
    path = Path(_text(value, field))
    if not path.is_absolute():
        raise ConfigurationError(f"{field} must be an absolute path")
    resolved = path.resolve(strict=False)
    if not resolved.is_file() or path.is_symlink():
        raise ConfigurationError(f"{field} must name an existing non-symlink file")
    return resolved


def _string_array(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ConfigurationError(f"{field} must be a string array")
    result = tuple(value)
    if len(result) != len(set(result)):
        raise ConfigurationError(f"{field} must not contain duplicates")
    return result


@dataclasses.dataclass(frozen=True)
class ImageConfiguration:
    mode: str = "source"
    directory: Path | None = None
    channel: str | None = None


@dataclasses.dataclass(frozen=True)
class ExternalOidcConfiguration:
    network: str
    filebelt_config: Path
    collaboration_config: Path
    mcp_config: Path
    edge_config: Path
    client_secret: Path
    ca_certificate: Path | None


@dataclasses.dataclass(frozen=True)
class ComposeConfiguration:
    profiles: tuple[str, ...] = ("core",)
    published_port: int = 8443
    external_oidc: ExternalOidcConfiguration | None = None


@dataclasses.dataclass(frozen=True)
class PreviewImage:
    role: str
    digest: str
    source: str
    license: str


@dataclasses.dataclass(frozen=True)
class PreviewSecret:
    namespace: str
    name: str
    key: str
    path: Path


@dataclasses.dataclass(frozen=True)
class PreviewObject:
    namespace: str
    name: str


@dataclasses.dataclass(frozen=True)
class PreviewConfiguration:
    features: tuple[str, ...] = ()
    images: tuple[PreviewImage, ...] = ()
    secrets: tuple[PreviewSecret, ...] = ()
    claims: tuple[PreviewObject, ...] = ()
    config_maps: tuple[PreviewObject, ...] = ()


@dataclasses.dataclass(frozen=True)
class MinikubeConfiguration:
    kubernetes_version: str = "v1.36.1"
    cni: str = "calico"
    cpus: int = 4
    memory_mb: int = 8192
    values_files: tuple[Path, ...] = ()
    prerequisite_manifests: tuple[Path, ...] = ()
    helm_binary: Path | None = None


@dataclasses.dataclass(frozen=True)
class DevelopmentConfiguration:
    images: ImageConfiguration
    compose: ComposeConfiguration
    minikube: MinikubeConfiguration
    preview: PreviewConfiguration
    sha256: str


def _load_images(document: dict[str, Any]) -> ImageConfiguration:
    _closed(document, {"mode", "directory", "channel"}, "images")
    mode = document.get("mode", "source")
    if mode not in {"source", "artifacts"}:
        raise ConfigurationError("images.mode must be source or artifacts")
    raw_directory = document.get("directory")
    directory = None
    if raw_directory not in (None, ""):
        candidate = Path(_text(raw_directory, "images.directory"))
        if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_dir():
            raise ConfigurationError("images.directory must name an existing absolute non-symlink directory")
        directory = candidate.resolve()
    channel = document.get("channel")
    if mode == "source" and (directory is not None or channel is not None):
        raise ConfigurationError("source images must not set directory or channel")
    if mode == "artifacts" and (directory is None or channel not in {"build", "release"}):
        raise ConfigurationError("artifact images require directory and build or release channel")
    return ImageConfiguration(mode=mode, directory=directory, channel=channel)


def _load_external_oidc(value: object) -> ExternalOidcConfiguration | None:
    if value is None:
        return None
    document = _mapping(value, "compose.external_oidc")
    _closed(
        document,
        {
            "network",
            "filebelt_config",
            "collaboration_config",
            "mcp_config",
            "edge_config",
            "client_secret",
            "ca_certificate",
        },
        "compose.external_oidc",
    )
    network = _text(document.get("network"), "compose.external_oidc.network")
    if ROLE.fullmatch(network) is None:
        raise ConfigurationError("compose.external_oidc.network is not a bounded Docker name")
    return ExternalOidcConfiguration(
        network=network,
        filebelt_config=_absolute_file(
            document.get("filebelt_config"), "compose.external_oidc.filebelt_config"
        ),
        collaboration_config=_absolute_file(
            document.get("collaboration_config"),
            "compose.external_oidc.collaboration_config",
        ),
        mcp_config=_absolute_file(
            document.get("mcp_config"), "compose.external_oidc.mcp_config"
        ),
        edge_config=_absolute_file(
            document.get("edge_config"), "compose.external_oidc.edge_config"
        ),
        client_secret=_absolute_file(
            document.get("client_secret"), "compose.external_oidc.client_secret"
        ),
        ca_certificate=_absolute_file(
            document.get("ca_certificate"),
            "compose.external_oidc.ca_certificate",
            optional=True,
        ),
    )


def _load_compose(document: dict[str, Any]) -> ComposeConfiguration:
    _closed(document, {"profiles", "published_port", "external_oidc"}, "compose")
    profiles = _string_array(document.get("profiles", ["core"]), "compose.profiles")
    published_port = document.get("published_port", 8443)
    if not profiles or profiles[0] != "core" or not set(profiles) <= set(COMPOSE_PROFILES):
        raise ConfigurationError("compose.profiles must begin with core and use supported profiles")
    if not isinstance(published_port, int) or not 1024 <= published_port <= 65535:
        raise ConfigurationError(
            "compose.published_port must be between 1024 and 65535"
        )
    return ComposeConfiguration(
        profiles=profiles,
        published_port=published_port,
        external_oidc=_load_external_oidc(document.get("external_oidc")),
    )


def _load_minikube(document: dict[str, Any]) -> MinikubeConfiguration:
    _closed(
        document,
        {
            "kubernetes_version",
            "cni",
            "cpus",
            "memory_mb",
            "values_files",
            "prerequisite_manifests",
            "helm_binary",
        },
        "minikube",
    )
    version = document.get("kubernetes_version", "v1.36.1")
    cni = document.get("cni", "calico")
    cpus = document.get("cpus", 4)
    memory = document.get("memory_mb", 8192)
    if version not in KUBERNETES_VERSIONS:
        raise ConfigurationError("minikube.kubernetes_version is unsupported")
    if cni not in CNIS:
        raise ConfigurationError("minikube.cni must be calico or cilium")
    if not isinstance(cpus, int) or not 2 <= cpus <= 32:
        raise ConfigurationError("minikube.cpus must be between 2 and 32")
    if not isinstance(memory, int) or not 4096 <= memory <= 131072:
        raise ConfigurationError("minikube.memory_mb must be between 4096 and 131072")
    raw_values = _string_array(document.get("values_files", []), "minikube.values_files")
    values = tuple(
        _absolute_file(value, f"minikube.values_files[{index}]")
        for index, value in enumerate(raw_values)
    )
    raw_manifests = _string_array(
        document.get("prerequisite_manifests", []), "minikube.prerequisite_manifests"
    )
    manifests = tuple(
        _absolute_file(value, f"minikube.prerequisite_manifests[{index}]")
        for index, value in enumerate(raw_manifests)
    )
    helm = _absolute_file(
        document.get("helm_binary"), "minikube.helm_binary", optional=True
    )
    return MinikubeConfiguration(version, cni, cpus, memory, values, manifests, helm)


def _array_of_tables(value: object, field: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ConfigurationError(f"{field} must be an array of tables")
    return value


def _load_preview(document: dict[str, Any]) -> PreviewConfiguration:
    _closed(document, {"features", "images", "secrets", "claims", "config_maps"}, "preview")
    features = _string_array(document.get("features", []), "preview.features")
    if not set(features) <= set(PREVIEW_FEATURES):
        raise ConfigurationError("preview.features contains an unsupported feature")
    images: list[PreviewImage] = []
    for index, row in enumerate(_array_of_tables(document.get("images"), "preview.images")):
        _closed(row, {"role", "digest", "source", "license"}, f"preview.images[{index}]")
        role = _text(row.get("role"), f"preview.images[{index}].role")
        digest = _text(row.get("digest"), f"preview.images[{index}].digest")
        if ROLE.fullmatch(role) is None or DIGEST.fullmatch(digest) is None:
            raise ConfigurationError(f"preview.images[{index}] requires a bounded role and exact digest")
        images.append(
            PreviewImage(
                role,
                digest,
                _text(row.get("source"), f"preview.images[{index}].source"),
                _text(row.get("license"), f"preview.images[{index}].license"),
            )
        )
    image_roles = [image.role for image in images]
    if len(image_roles) != len(set(image_roles)):
        raise ConfigurationError("preview.images must not repeat an image role")
    secrets: list[PreviewSecret] = []
    for index, row in enumerate(_array_of_tables(document.get("secrets"), "preview.secrets")):
        _closed(row, {"namespace", "name", "key", "path"}, f"preview.secrets[{index}]")
        namespace = _text(row.get("namespace"), f"preview.secrets[{index}].namespace")
        name = _text(row.get("name"), f"preview.secrets[{index}].name")
        key = _text(row.get("key"), f"preview.secrets[{index}].key")
        if (
            (namespace != "core" and ROLE.fullmatch(namespace) is None)
            or ROLE.fullmatch(name) is None
            or SECRET_KEY.fullmatch(key) is None
        ):
            raise ConfigurationError(f"preview.secrets[{index}] has an invalid namespace, name, or key")
        secrets.append(
            PreviewSecret(
                namespace,
                name,
                key,
                _absolute_file(row.get("path"), f"preview.secrets[{index}].path"),
            )
        )
    objects: dict[str, list[PreviewObject]] = {"claims": [], "config_maps": []}
    for field in objects:
        for index, row in enumerate(_array_of_tables(document.get(field), f"preview.{field}")):
            _closed(row, {"namespace", "name"}, f"preview.{field}[{index}]")
            namespace = _text(row.get("namespace"), f"preview.{field}[{index}].namespace")
            name = _text(row.get("name"), f"preview.{field}[{index}].name")
            if (namespace != "core" and ROLE.fullmatch(namespace) is None) or ROLE.fullmatch(name) is None:
                raise ConfigurationError(f"preview.{field}[{index}] has an invalid object identity")
            objects[field].append(PreviewObject(namespace, name))
        object_names = [(item.namespace, item.name) for item in objects[field]]
        if len(object_names) != len(set(object_names)):
            raise ConfigurationError(f"preview.{field} must not repeat an object identity")
    image_role_set = set(image_roles)
    required_roles = set().union(*(PREVIEW_FEATURE_ROLES[feature] for feature in features))
    missing_roles = sorted(required_roles - image_role_set)
    if missing_roles:
        raise ConfigurationError(
            "preview features lack exact image evidence for: " + ", ".join(missing_roles)
        )
    if "mcp-runners" in features and "mcp" not in features:
        raise ConfigurationError("preview feature mcp-runners requires mcp")
    return PreviewConfiguration(
        features,
        tuple(images),
        tuple(secrets),
        tuple(objects["claims"]),
        tuple(objects["config_maps"]),
    )


def load_configuration(path: Path | None) -> DevelopmentConfiguration:
    if path is None:
        raw = b"schema_version = 1\n"
        document: dict[str, Any] = {"schema_version": 1}
    else:
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise ConfigurationError("--config must name an existing absolute non-symlink file")
        if path.stat().st_size > MAXIMUM_CONFIGURATION_BYTES:
            raise ConfigurationError("--config exceeds the 1 MiB input bound")
        raw = path.read_bytes()
        document = tomllib.loads(raw.decode("utf-8"))
    _closed(document, {"schema_version", "images", "compose", "minikube", "preview"}, "configuration")
    if document.get("schema_version") != 1:
        raise ConfigurationError("configuration must use schema_version = 1")
    return DevelopmentConfiguration(
        images=_load_images(_mapping(document.get("images", {}), "images")),
        compose=_load_compose(_mapping(document.get("compose", {}), "compose")),
        minikube=_load_minikube(_mapping(document.get("minikube", {}), "minikube")),
        preview=_load_preview(_mapping(document.get("preview", {}), "preview")),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def validate_session_name(value: str) -> str:
    if SESSION_NAME.fullmatch(value) is None:
        raise ConfigurationError(
            "session name must use 1-32 lower-case letters, digits, or interior hyphens"
        )
    return value


def development_root() -> Path:
    configured = os.environ.get("FILEBELT_DEVELOPMENT_ROOT")
    if configured:
        path = Path(configured)
        if not path.is_absolute():
            raise ConfigurationError("FILEBELT_DEVELOPMENT_ROOT must be absolute")
        return path
    return ROOT / "tests/development/.state"


def _reject_symlink_chain(path: Path) -> None:
    current = path
    while current != current.parent:
        if current.exists() and stat.S_ISLNK(current.lstat().st_mode):
            raise ConfigurationError(f"unsafe symlink in development path: {current}")
        current = current.parent


def prepare_root(path: Path) -> Path:
    forbidden = {Path("/"), Path("/tmp"), Path.home(), ROOT}
    if path in forbidden:
        raise ConfigurationError("refusing broad development root")
    _reject_symlink_chain(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    if path.is_symlink() or not path.is_dir():
        raise ConfigurationError("development root must be a private directory")
    return path.resolve()


@dataclasses.dataclass
class Session:
    schema_version: int
    name: str
    topology: str
    phase: str
    created_at: str
    source_revision: str
    configuration_sha256: str
    qualification: dict[str, Any]
    resources: dict[str, Any]

    @classmethod
    def create(
        cls,
        name: str,
        topology: str,
        source_revision: str,
        configuration: DevelopmentConfiguration,
    ) -> "Session":
        if topology not in {"compose", "minikube"}:
            raise ConfigurationError("topology must be compose or minikube")
        return cls(
            schema_version=1,
            name=validate_session_name(name),
            topology=topology,
            phase="creating",
            created_at=datetime.now(UTC).isoformat(),
            source_revision=source_revision,
            configuration_sha256=configuration.sha256,
            qualification={
                "accepted": False,
                "reason": "local development and debugging only",
                "features": list(configuration.preview.features),
                "previewImages": [
                    dataclasses.asdict(image) for image in configuration.preview.images
                ],
            },
            resources={},
        )

    @classmethod
    def load(cls, path: Path) -> "Session":
        if path.is_symlink() or not path.is_file():
            raise ConfigurationError("session manifest is unavailable or unsafe")
        document = json.loads(path.read_text(encoding="utf-8"))
        required = {field.name for field in dataclasses.fields(cls)}
        if not isinstance(document, dict) or set(document) != required or document.get("schema_version") != 1:
            raise ConfigurationError("session manifest contract is invalid")
        session = cls(**document)
        if not all(
            (
                isinstance(session.name, str),
                isinstance(session.topology, str),
                isinstance(session.phase, str),
                isinstance(session.created_at, str),
                isinstance(session.source_revision, str),
                isinstance(session.configuration_sha256, str),
                isinstance(session.qualification, dict),
                isinstance(session.resources, dict),
            )
        ):
            raise ConfigurationError("session manifest field types are invalid")
        validate_session_name(session.name)
        if (
            session.topology not in {"compose", "minikube"}
            or session.phase not in {"creating", "running", "quiesced", "failed", "stopping", "cleanup-failed"}
            or REVISION.fullmatch(session.source_revision) is None
            or DIGEST.fullmatch(f"sha256:{session.configuration_sha256}") is None
            or session.qualification.get("accepted") is not False
        ):
            raise ConfigurationError("session manifest topology or resources are invalid")
        return session

    def save(self, path: Path) -> None:
        if path.exists() and path.is_symlink():
            raise ConfigurationError("refusing to replace a symlink session manifest")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.parent.chmod(0o700)
        payload = (json.dumps(dataclasses.asdict(self), indent=2, sort_keys=True) + "\n").encode()
        descriptor, temporary_name = tempfile.mkstemp(prefix=".session.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as destination:
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
            temporary.replace(path)
        finally:
            if temporary.exists():
                temporary.unlink()


def session_directory(root: Path, name: str) -> Path:
    sessions = root / "sessions"
    if sessions.is_symlink():
        raise ConfigurationError("development sessions directory must not be a symlink")
    sessions.mkdir(mode=0o700, parents=False, exist_ok=True)
    sessions.chmod(0o700)
    if not sessions.is_dir() or sessions.resolve() != root.resolve() / "sessions":
        raise ConfigurationError("development sessions directory is unsafe")
    return sessions / validate_session_name(name)


def session_manifest(root: Path, name: str) -> Path:
    return session_directory(root, name) / "session.json"
