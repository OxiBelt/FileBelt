#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed, helper-owned Minikube backend for local FileBelt debugging."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Sequence

from .diagnostics import remember_secret, scrub, secret_values
from .model import ConfigurationError, DevelopmentConfiguration, Session
from .runner import CommandFailure, Runner


HELM_VERSION = "v4.2.4"
HELM_CHECKSUMS = {
    "amd64": "c306b46f719b0a4da32d0f78ee21bf90ce8d602f15b22ab753f0674d1670a7f3",
    "arm64": "564de2191b881e9f71b5606b25345821ea1682f06ab90499d3ab22b530176da1",
}
MAXIMUM_HELM_ARCHIVE_BYTES = 64 * 1024 * 1024
MINIKUBE_ATTEMPTS = 2
MINIKUBE_RETRY_DELAY_SECONDS = 5
MINIKUBE_CLEANUP_TIMEOUT_SECONDS = 120
MINIKUBE_TERMINATION_GRACE_SECONDS = 30
START_TIMEOUT_SECONDS = 600
NAMESPACE_PREFIX = "filebelt-dev-"
RELEASE_NAME = "filebelt-dev"
COMPONENTS = {
    "web": "filebelt-web",
    "api": "filebelt-api",
    "io": "filebelt-worker-io",
    "maintenance": "filebelt-worker-maintenance",
}
CORE_ROLES = (*COMPONENTS.values(), "filebelt-tools")
CHART_IMAGE_ROLES = {
    "filebelt-api",
    "filebelt-collaboration",
    "filebelt-controller",
    "filebelt-document",
    "filebelt-ftp-ftps-gateway",
    "filebelt-headscale-sync",
    "filebelt-mcp-broker",
    "filebelt-mcp-runner",
    "filebelt-nfs-gateway",
    "filebelt-nfs-relay",
    "filebelt-revision",
    "filebelt-smb-gateway",
    "filebelt-tools",
    "filebelt-vfs",
    "filebelt-web",
    "filebelt-worker-io",
    "filebelt-worker-maintenance",
    "tailscaled",
}
ADAPTER_IMAGE_ROLES = frozenset(
    {"filebelt-ftp-ftps-gateway", "filebelt-nfs-gateway", "filebelt-smb-gateway"}
)
PREREQUISITE_KINDS = {
    "ConfigMap",
    "Deployment",
    "Job",
    "Namespace",
    "NetworkPolicy",
    "PersistentVolumeClaim",
    "Role",
    "RoleBinding",
    "Service",
    "ServiceAccount",
    "StatefulSet",
}
PREREQUISITE_API_VERSIONS = {
    "ConfigMap": "v1",
    "Deployment": "apps/v1",
    "Job": "batch/v1",
    "Namespace": "v1",
    "NetworkPolicy": "networking.k8s.io/v1",
    "PersistentVolumeClaim": "v1",
    "Role": "rbac.authorization.k8s.io/v1",
    "RoleBinding": "rbac.authorization.k8s.io/v1",
    "Service": "v1",
    "ServiceAccount": "v1",
    "StatefulSet": "apps/v1",
}
RESTRICTED_NAMESPACE_LABELS = {
    "pod-security.kubernetes.io/enforce": "restricted",
    "pod-security.kubernetes.io/enforce-version": "latest",
    "pod-security.kubernetes.io/audit": "restricted",
    "pod-security.kubernetes.io/warn": "restricted",
}
RUNTIME_DIGEST = re.compile(r"^(?P<repository>[a-z0-9][a-z0-9._/-]*)@(?P<digest>sha256:[0-9a-f]{64})$")
SAFE_SESSION = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
KUBERNETES_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
ARCHITECTURES = {"x86_64": "amd64", "aarch64": "arm64"}
FEATURE_SETTINGS = {
    "collaboration": "collaboration.enabled=true",
    "documents": "documents.enabled=true",
    "mcp": "mcp.enabled=true",
    "mcp-runners": "mcp.runners.enabled=true",
    "mount-ftp-ftps": "mounts.ftpFtps.enabled=true",
    "mount-nfs": "mounts.nfs.enabled=true",
    "mount-smb": "mounts.smb.enabled=true",
    "revisions": "revisions.enabled=true",
}


def _load_image_module(root: Path):
    units = root / "tests/docker/units"
    if str(units) not in sys.path:
        sys.path.insert(0, str(units))
    specification = importlib.util.spec_from_file_location(
        "filebelt_development_minikube_images", units / "images.py"
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("could not load the exact artifact validator")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class MinikubeUnavailable(RuntimeError):
    """The local environment cannot provide live Minikube evidence."""


class MinikubeBackend:
    """Own exactly one Minikube profile, kubeconfig, namespace, and release."""

    def __init__(self, root: Path, work_dir: Path, runner: Runner):
        self.root = root.resolve()
        self.work_dir = work_dir.resolve()
        self.runner = runner
        self._images = _load_image_module(self.root)

    def _identity(self, session: Session) -> tuple[str, str, str]:
        if SAFE_SESSION.fullmatch(session.name) is None:
            raise ConfigurationError("unsafe Minikube session name")
        profile = f"{NAMESPACE_PREFIX}{session.name}"
        namespace = profile
        if session.resources:
            recorded = session.resources.get("minikube")
            if isinstance(recorded, dict):
                profile = self._recorded(recorded, "profile", profile)
                namespace = self._recorded(recorded, "namespace", namespace)
                release = self._recorded(recorded, "release", RELEASE_NAME)
                return profile, namespace, release
        return profile, namespace, RELEASE_NAME

    @staticmethod
    def _recorded(resources: dict[str, object], name: str, expected: str) -> str:
        value = resources.get(name, expected)
        if value != expected:
            raise ConfigurationError(f"session has an unsafe Minikube {name}")
        return expected

    def _paths(self, session: Session) -> tuple[Path, Path, Path]:
        state = self.work_dir / "state" / "minikube"
        return state / "home", state / "kubeconfig", state / "helm"

    def _environment(self, session: Session) -> dict[str, str]:
        home, kubeconfig, _ = self._paths(session)
        environment = os.environ.copy()
        environment.update({"MINIKUBE_HOME": str(home), "KUBECONFIG": str(kubeconfig)})
        return environment

    def _kubectl(self, session: Session, *arguments: str) -> list[str]:
        _, kubeconfig, _ = self._paths(session)
        return ["kubectl", "--kubeconfig", str(kubeconfig), *arguments]

    def _helm(self, session: Session, helm: str, *arguments: str) -> list[str]:
        _, kubeconfig, _ = self._paths(session)
        return [helm, "--kubeconfig", str(kubeconfig), *arguments]

    @staticmethod
    def _run_id(session: Session) -> str:
        return session.name

    def _require_tools(self, session: Session) -> None:
        environment = self._environment(session)
        checks = (
            ("kubectl", "version", "--client"),
            ("minikube", "version"),
            ("docker", "version"),
            ("timeout", "--version"),
        )
        for command in checks:
            self.runner.run(command, environment=environment)

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def _helm_version(self, session: Session, candidate: Path) -> str | None:
        try:
            return self.runner.run(
                [str(candidate), "version", "--template", "{{ .Version }}"],
                environment=self._environment(session),
            ).stdout.decode().strip()
        except CommandFailure:
            return None

    def _bootstrap_helm(self, session: Session) -> Path:
        architecture = ARCHITECTURES.get(platform.machine().lower())
        if architecture is None:
            raise ConfigurationError("verified Helm bootstrap supports Linux amd64 and arm64 only")
        if platform.system() != "Linux":
            raise ConfigurationError("verified Helm bootstrap supports Linux only")
        _, _, destination = self._paths(session)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.parent.chmod(0o700)
        if destination.exists():
            if destination.is_symlink() or self._helm_version(session, destination) != HELM_VERSION:
                raise ConfigurationError("cached Helm executable is unsafe or has the wrong version")
            return destination
        url = f"https://get.helm.sh/helm-{HELM_VERSION}-linux-{architecture}.tar.gz"
        request = urllib.request.Request(url, headers={"User-Agent": "FileBelt-development-helper/1"})
        descriptor, archive_name = tempfile.mkstemp(prefix="helm.", suffix=".tar.gz", dir=destination.parent)
        archive = Path(archive_name)
        downloaded = 0
        try:
            with os.fdopen(descriptor, "wb") as output, urllib.request.urlopen(request, timeout=60) as response:
                while block := response.read(1024 * 1024):
                    downloaded += len(block)
                    if downloaded > MAXIMUM_HELM_ARCHIVE_BYTES:
                        raise ConfigurationError("Helm archive exceeds the bounded download size")
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
            if self._sha256(archive) != HELM_CHECKSUMS[architecture]:
                raise ConfigurationError("Helm archive checksum does not match the approved release")
            member_name = f"linux-{architecture}/helm"
            with tarfile.open(archive, mode="r:gz") as source:
                members = source.getmembers()
                if any(
                    member.issym()
                    or member.islnk()
                    or member.name.startswith("/")
                    or ".." in Path(member.name).parts
                    for member in members
                ):
                    raise ConfigurationError("Helm archive contains an unsafe member")
                matches = [member for member in members if member.name == member_name and member.isfile()]
                if len(matches) != 1 or matches[0].size > MAXIMUM_HELM_ARCHIVE_BYTES:
                    raise ConfigurationError("Helm archive executable contract is invalid")
                extracted = source.extractfile(matches[0])
                if extracted is None:
                    raise ConfigurationError("Helm archive executable is unreadable")
                output_descriptor = os.open(
                    destination,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                    0o700,
                )
                with os.fdopen(output_descriptor, "wb") as output:
                    shutil.copyfileobj(extracted, output)
                    output.flush()
                    os.fsync(output.fileno())
            if self._helm_version(session, destination) != HELM_VERSION:
                raise ConfigurationError("verified Helm executable reports the wrong version")
            return destination
        finally:
            archive.unlink(missing_ok=True)

    def _helm_binary(self, session: Session, configuration: DevelopmentConfiguration) -> str:
        if configuration.minikube.helm_binary is not None:
            candidate = configuration.minikube.helm_binary.resolve()
            if self._helm_version(session, candidate) != HELM_VERSION:
                raise ConfigurationError(f"configured Helm executable must be {HELM_VERSION}")
            return str(candidate)
        discovered = shutil.which("helm")
        if discovered is not None:
            candidate = Path(discovered).resolve()
            if self._helm_version(session, candidate) == HELM_VERSION:
                return str(candidate)
        return str(self._bootstrap_helm(session))

    def _record(self, session: Session, helm: str) -> None:
        profile, namespace, release = self._identity(session)
        home, kubeconfig, _ = self._paths(session)
        session.resources["minikube"] = {
            "profile": profile,
            "namespace": namespace,
            "release": release,
            "kubeconfig": str(kubeconfig),
            "minikube_home": str(home),
            "helm": helm,
            "helm_sha256": self._sha256(Path(helm)),
            "qualification": "non-qualifying local development and debugging only",
        }
        session.save(self.work_dir / "session.json")

    def _safe_state_directories(self, session: Session) -> None:
        for path in self._paths(session)[:2]:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.parent.chmod(0o700)
            if path.exists() and path.is_symlink():
                raise ConfigurationError("refusing a symlink Minikube state path")

    def _recorded_helm(self, session: Session) -> str:
        resources = session.resources.get("minikube")
        if not isinstance(resources, dict):
            raise ConfigurationError("Minikube resource manifest is unavailable")
        helm = resources.get("helm")
        checksum = resources.get("helm_sha256")
        if not isinstance(helm, str) or not isinstance(checksum, str):
            raise ConfigurationError("Minikube Helm ownership record is invalid")
        candidate = Path(helm)
        if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_file():
            raise ConfigurationError("recorded Helm executable is unsafe")
        if self._sha256(candidate) != checksum:
            raise ConfigurationError("recorded Helm executable changed after session creation")
        return helm

    def _profile_exists(self, session: Session) -> bool:
        profile, _, _ = self._identity(session)
        result = self.runner.run(
            ["minikube", "profile", "list", "--output", "json"],
            environment=self._environment(session),
        )
        document = json.loads(result.stdout)
        rows = document.get("valid", []) if isinstance(document, dict) else []
        return any(
            isinstance(row, dict) and (row.get("Name") == profile or row.get("name") == profile)
            for row in rows
        )

    def _delete_profile(self, session: Session) -> None:
        profile, _, _ = self._identity(session)
        if not profile.startswith(NAMESPACE_PREFIX):
            raise ConfigurationError("refusing to delete a non-development Minikube profile")
        if not self._profile_exists(session):
            return
        self.runner.run(
            [
                "timeout",
                f"--kill-after={MINIKUBE_TERMINATION_GRACE_SECONDS}s",
                f"{MINIKUBE_CLEANUP_TIMEOUT_SECONDS}s",
                "minikube",
                "delete",
                "--profile",
                profile,
            ],
            environment=self._environment(session),
        )

    def _start(self, session: Session, configuration: DevelopmentConfiguration) -> None:
        profile, _, _ = self._identity(session)
        _, kubeconfig, _ = self._paths(session)
        environment = self._environment(session)
        failures: list[str] = []
        for attempt in range(1, MINIKUBE_ATTEMPTS + 1):
            if kubeconfig.exists():
                kubeconfig.unlink()
            command = [
                "minikube",
                "start",
                "--profile",
                profile,
                "--driver=docker",
                "--container-runtime=containerd",
                f"--cni={configuration.minikube.cni}",
                f"--kubernetes-version={configuration.minikube.kubernetes_version}",
                f"--cpus={configuration.minikube.cpus}",
                f"--memory={configuration.minikube.memory_mb}",
                "--wait=all",
                f"--wait-timeout={START_TIMEOUT_SECONDS}s",
                "--output=json",
            ]
            try:
                self.runner.run(command, environment=environment)
                if kubeconfig.is_file() and kubeconfig.stat().st_size:
                    self.runner.run(
                        self._kubectl(session, "get", "--raw", "/readyz"),
                        environment=environment,
                    )
                    return
                failures.append("Minikube reported success without a fresh kubeconfig")
            except CommandFailure as error:
                failures.append(error.stderr.decode(errors="replace")[-512:])
            if attempt < MINIKUBE_ATTEMPTS:
                try:
                    self._delete_profile(session)
                except CommandFailure as error:
                    raise MinikubeUnavailable("Minikube cleanup before retry failed") from error
                time.sleep(MINIKUBE_RETRY_DELAY_SECONDS)
        raise MinikubeUnavailable("Minikube did not start after two bounded attempts: " + " | ".join(failures))

    def _source_image_rows(self, session: Session) -> list[dict[str, str]]:
        architecture = self.runner.run(
            ["docker", "version", "--format", "{{.Server.Arch}}"],
            environment=self._environment(session),
        ).stdout.decode().strip()
        if architecture not in {"amd64", "arm64"}:
            raise ConfigurationError("Minikube source builds support Docker amd64 and arm64 only")
        output = self.work_dir / "state/minikube/images"
        output.mkdir(mode=0o700, parents=True, exist_ok=True)
        plan = output / "image-plan.json"
        self.runner.run(
            [str(self.root / "tests/scripts/prepare-image-plan.sh"), "--channel", "build", "--output", str(plan)]
        )
        rows: list[dict[str, str]] = []
        for role in CORE_ROLES:
            self.runner.run(
                [
                    str(self.root / "tests/scripts/build-docker-image-artifact.sh"),
                    "--plan", str(plan),
                    "--role", role,
                    "--platform", f"linux/{architecture}",
                    "--output-dir", str(output),
                ]
            )
            archive = output / f"{role}-{architecture}.docker.tar"
            metadata = output / f"{role}-{architecture}.build.json"
            document = json.loads(metadata.read_text(encoding="utf-8"))
            local_ref = document.get("localRef")
            if (
                not archive.is_file()
                or document.get("role") != role
                or document.get("platform") != f"linux/{architecture}"
                or document.get("sourceRevision") != session.source_revision
                or not isinstance(local_ref, str)
                or "@" in local_ref
            ):
                raise ConfigurationError(f"source build metadata is invalid for {role}")
            rows.append({"role": role, "archive": str(archive), "local_ref": local_ref})
        return rows

    def _artifact_image_rows(self, session: Session, configuration: DevelopmentConfiguration) -> list[dict[str, str]]:
        if configuration.images.directory is None or configuration.images.channel is None:
            raise ConfigurationError("artifact image configuration is incomplete")
        architecture = self.runner.run(
            ["docker", "version", "--format", "{{.Server.Arch}}"],
            environment=self._environment(session),
        ).stdout.decode().strip()
        if architecture != "amd64":
            raise ConfigurationError("validated artifact mode currently supports Docker amd64 only")
        directory = configuration.images.directory
        plan = directory / "image-plan.json"
        if not plan.is_file():
            raise ConfigurationError("artifact image directory must contain image-plan.json")
        rows: list[dict[str, str]] = []
        for role in CORE_ROLES:
            archive, reference = self._images.validate_role(
                self.root,
                directory,
                plan,
                role,
                configuration.images.channel,
                session.source_revision,
            )
            rows.append({"role": role, "archive": str(archive), "local_ref": reference})
        return rows

    def _image_rows(self, session: Session, configuration: DevelopmentConfiguration) -> list[dict[str, str]]:
        if configuration.images.mode == "source":
            return self._source_image_rows(session)
        return self._artifact_image_rows(session, configuration)

    def _load_images(self, session: Session, rows: Sequence[dict[str, str]]) -> list[tuple[str, str, str]]:
        profile, _, _ = self._identity(session)
        environment = self._environment(session)
        resolved: list[tuple[str, str, str]] = []
        for row in rows:
            self.runner.run(
                ["minikube", "image", "load", "--profile", profile, row["archive"]],
                environment=environment,
            )
            listing = self.runner.run(
                ["minikube", "image", "ls", "--profile", profile, "--format", "json"],
                environment=environment,
            )
            document = json.loads(listing.stdout)
            matches = [
                item
                for item in document
                if isinstance(item, dict)
                and row["local_ref"] in item.get("repoTags", [])
            ] if isinstance(document, list) else []
            digests = matches[0].get("repoDigests", []) if len(matches) == 1 else []
            expected_repository = row["local_ref"].rsplit(":", 1)[0]
            exact = [
                value
                for value in digests
                if isinstance(value, str)
                and value.startswith(expected_repository + "@")
                and RUNTIME_DIGEST.fullmatch(value)
            ]
            if len(exact) != 1:
                raise ConfigurationError(f"{row['role']} has no unique exact Minikube runtime digest")
            match = RUNTIME_DIGEST.fullmatch(exact[0])
            assert match is not None
            full_repository = match.group("repository")
            registry, separator, repository = full_repository.partition("/")
            if not separator or not repository:
                raise ConfigurationError(f"{row['role']} runtime repository is invalid")
            resolved.append((registry, repository, match.group("digest")))
        return resolved

    def _values(
        self,
        configuration: DevelopmentConfiguration,
        images: Sequence[tuple[str, str, str]],
    ) -> list[str]:
        arguments: list[str] = []
        for path in configuration.minikube.values_files:
            contents = path.read_text(encoding="utf-8", errors="strict").casefold()
            secret_markers = (
                "kind: secret",
                "stringdata:",
                "client_secret",
                "private_key",
                "password:",
            )
            if any(marker in contents for marker in secret_markers):
                raise ConfigurationError("Minikube values files must not contain secret material")
            arguments.extend(["--values", str(path)])
        arguments.extend(
            ["--set", "deployment.quiesced=true", "--set", "operation.type=none"]
        )
        for feature in configuration.preview.features:
            arguments.extend(["--set", FEATURE_SETTINGS[feature]])
        for role, (registry, repository, digest) in zip(CORE_ROLES, images, strict=True):
            arguments.extend(["--set-string", f"images.{role}.registryMirror={registry}"])
            arguments.extend(["--set-string", f"images.{role}.repository={repository}"])
            arguments.extend(["--set-string", f"images.{role}.digest={digest}"])
        for image in configuration.preview.images:
            if image.role not in CHART_IMAGE_ROLES:
                raise ConfigurationError(f"preview image role is not part of the FileBelt chart: {image.role}")
            if image.role in CORE_ROLES:
                raise ConfigurationError(f"preview image must not replace a core source/artifact image: {image.role}")
            arguments.extend(["--set-string", f"images.{image.role}.digest={image.digest}"])
            if image.role in ADAPTER_IMAGE_ROLES:
                arguments.extend(
                    ["--set-json", f"images.{image.role}.source={json.dumps(image.source)}"]
                )
                arguments.extend(
                    ["--set-json", f"images.{image.role}.license={json.dumps(image.license)}"]
                )
        return arguments

    def _create_namespace(self, session: Session) -> None:
        _, namespace, _ = self._identity(session)
        environment = self._environment(session)
        self.runner.run(self._kubectl(session, "create", "namespace", namespace), environment=environment)
        self.runner.run(
            self._kubectl(
                session, "label", "--overwrite", "namespace", namespace,
                "pod-security.kubernetes.io/enforce=restricted", "pod-security.kubernetes.io/enforce-version=latest",
                "pod-security.kubernetes.io/audit=restricted", "pod-security.kubernetes.io/warn=restricted",
            ), environment=environment
        )

    def _manifest_items(self, document: object) -> list[dict[str, object]]:
        if not isinstance(document, dict):
            raise ConfigurationError("prerequisite manifest dry-run output must be an object")
        if document.get("kind") == "List":
            items = document.get("items")
            if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
                raise ConfigurationError("prerequisite manifest List is invalid")
            return items
        return [document]

    def _validate_manifest_item(self, session: Session, item: dict[str, object]) -> None:
        kind = item.get("kind")
        metadata = item.get("metadata")
        if (
            kind not in PREREQUISITE_KINDS
            or item.get("apiVersion") != PREREQUISITE_API_VERSIONS[kind]
            or not isinstance(metadata, dict)
        ):
            raise ConfigurationError("prerequisite manifests contain a forbidden Kubernetes kind")
        name = metadata.get("name")
        namespace = metadata.get("namespace")
        labels = metadata.get("labels")
        if not isinstance(name, str) or KUBERNETES_NAME.fullmatch(name) is None:
            raise ConfigurationError("prerequisite manifest object name is unsafe")
        if not isinstance(labels, dict) or labels.get("filebelt.dev/development-session") != session.name:
            raise ConfigurationError("prerequisite manifest lacks the exact development-session label")
        if kind == "Namespace":
            if not name.startswith("filebelt-"):
                raise ConfigurationError("prerequisite Namespace must be FileBelt-scoped")
            if any(labels.get(key) != value for key, value in RESTRICTED_NAMESPACE_LABELS.items()):
                raise ConfigurationError("prerequisite Namespace must enforce restricted Pod Security")
        elif not isinstance(namespace, str) or not namespace.startswith("filebelt-"):
            raise ConfigurationError("prerequisite object must use an explicit FileBelt namespace")
        if kind == "Service":
            specification = item.get("spec")
            if (
                not isinstance(specification, dict)
                or specification.get("type", "ClusterIP") != "ClusterIP"
                or specification.get("externalIPs") not in (None, [])
                or "loadBalancerIP" in specification
            ):
                raise ConfigurationError("prerequisite Services must remain cluster-internal")

    def _apply_prerequisite_manifests(
        self, session: Session, configuration: DevelopmentConfiguration
    ) -> None:
        environment = self._environment(session)
        for path in configuration.minikube.prerequisite_manifests:
            rendered = self.runner.run(
                self._kubectl(session, "apply", "--dry-run=client", "--filename", str(path), "--output", "json"),
                environment=environment,
            )
            for item in self._manifest_items(json.loads(rendered.stdout)):
                self._validate_manifest_item(session, item)
            self.runner.run(
                self._kubectl(
                    session,
                    "apply",
                    "--server-side",
                    "--field-manager=filebelt-development-helper",
                    "--filename",
                    str(path),
                ),
                environment=environment,
            )

    def _preview_namespace(self, session: Session, value: str) -> str:
        _, core, _ = self._identity(session)
        if value == "core":
            return core
        if not value.startswith("filebelt-") or KUBERNETES_NAME.fullmatch(value) is None:
            raise ConfigurationError("preview prerequisite namespace must be FileBelt-scoped")
        return value

    def _copy_preview_secrets(
        self, session: Session, configuration: DevelopmentConfiguration
    ) -> None:
        grouped: dict[tuple[str, str], dict[str, str]] = {}
        total = 0
        for index, secret in enumerate(configuration.preview.secrets):
            namespace = self._preview_namespace(session, secret.namespace)
            contents = secret.path.read_bytes()
            total += len(contents)
            if len(contents) > 1_048_576 or total > 1_048_576:
                raise ConfigurationError("preview Secret inputs exceed the bounded Kubernetes Secret size")
            keys = grouped.setdefault((namespace, secret.name), {})
            if secret.key in keys:
                raise ConfigurationError("preview Secret inputs contain a duplicate key")
            remember_secret(self.work_dir, f"preview-secret-{index}", contents)
            keys[secret.key] = base64.b64encode(contents).decode("ascii")
        for (namespace, name), data in grouped.items():
            document = {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                    "labels": {"filebelt.dev/development-session": session.name},
                },
                "immutable": True,
                "type": "Opaque",
                "data": data,
            }
            self.runner.run(
                self._kubectl(
                    session,
                    "apply",
                    "--server-side",
                    "--field-manager=filebelt-development-helper",
                    "--filename",
                    "-",
                ),
                environment=self._environment(session),
                input_data=json.dumps(document, separators=(",", ":")).encode(),
            )

    def _validate_preview_objects(
        self, session: Session, configuration: DevelopmentConfiguration
    ) -> None:
        environment = self._environment(session)
        for resource, kind in (
            (configuration.preview.claims, "persistentvolumeclaim"),
            (configuration.preview.config_maps, "configmap"),
        ):
            for item in resource:
                namespace = self._preview_namespace(session, item.namespace)
                self.runner.run(
                    self._kubectl(
                        session,
                        "get",
                        kind,
                        item.name,
                        "--namespace",
                        namespace,
                        "--output",
                        "name",
                    ),
                    environment=environment,
                )

    def up(self, session: Session, configuration: DevelopmentConfiguration) -> None:
        self._safe_state_directories(session)
        self._require_tools(session)
        helm = self._helm_binary(session, configuration)
        self._record(session, helm)
        self._start(session, configuration)
        self._create_namespace(session)
        self._apply_prerequisite_manifests(session, configuration)
        self._copy_preview_secrets(session, configuration)
        self._validate_preview_objects(session, configuration)
        rows = self._image_rows(session, configuration)
        images = self._load_images(session, rows)
        _, namespace, release = self._identity(session)
        command = self._helm(
            session,
            helm,
            "upgrade",
            "--install",
            release,
            str(self.root / "deploy/helm/filebelt"),
            "--namespace",
            namespace,
            "--atomic",
            "--wait",
            "--timeout",
            "300s",
            *self._values(configuration, images),
        )
        self.runner.run(command, environment=self._environment(session))
        session.phase = "quiesced"
        session.qualification["accepted"] = False
        session.qualification["reason"] = (
            "local development and debugging only; quiesced deployment is not qualification"
        )

    def status(self, session: Session) -> dict[str, object]:
        _, namespace, release = self._identity(session)
        environment = self._environment(session)
        deployments = self.runner.run(
            self._kubectl(
                session, "get", "deployment", "--namespace", namespace, "-o", "json"
            ),
            environment=environment,
        )
        releases = self.runner.run(
            self._helm(
                session,
                self._recorded_helm(session),
                "list",
                "--namespace",
                namespace,
                "--filter",
                f"^{release}$",
                "--output",
                "json",
            ),
            environment=environment,
        )
        return {
            "qualification": "non-qualifying",
            "deployments": json.loads(deployments.stdout),
            "helm_releases": json.loads(releases.stdout),
        }

    def _component(self, component: str) -> str:
        try:
            return COMPONENTS[component]
        except KeyError as error:
            raise ConfigurationError("component must be one of api, io, maintenance, or web") from error

    def logs(self, session: Session, component: str, tail: int) -> bytes:
        if session.phase == "quiesced":
            raise ConfigurationError("Minikube helper workloads are quiesced; use diagnose")
        if not 1 <= tail <= 500:
            raise ConfigurationError("log tail must be between 1 and 500")
        _, namespace, _ = self._identity(session)
        output = self.runner.run(
            self._kubectl(
                session,
                "logs",
                "--namespace",
                namespace,
                f"deployment/{self._component(component)}",
                "--all-containers=true",
                f"--tail={tail}",
            ),
            environment=self._environment(session),
        ).stdout
        return scrub(output, secret_values(self.work_dir))

    def restart(self, session: Session, component: str) -> None:
        if session.phase == "quiesced":
            raise ConfigurationError("Minikube helper workloads are quiesced and cannot restart")
        _, namespace, _ = self._identity(session)
        self.runner.run(
            self._kubectl(
                session,
                "rollout",
                "restart",
                "--namespace",
                namespace,
                f"deployment/{self._component(component)}",
            ),
            environment=self._environment(session),
        )

    def diagnose(self, session: Session) -> dict[str, bytes]:
        _, namespace, release = self._identity(session)
        environment = self._environment(session)
        helm = self._recorded_helm(session)
        requests = {
            "resources": self._kubectl(
                session,
                "get",
                "all,configmap,networkpolicy,poddisruptionbudget",
                "--namespace",
                namespace,
                "-o",
                "wide",
            ),
            "events": self._kubectl(
                session,
                "get",
                "events",
                "--namespace",
                namespace,
                "--sort-by=.lastTimestamp",
            ),
            "helm-history": self._helm(
                session, str(helm), "history", release, "--namespace", namespace
            ),
        }
        result: dict[str, bytes] = {}
        for name, command in requests.items():
            try:
                result[name] = scrub(
                    self.runner.run(command, environment=environment).stdout,
                    secret_values(self.work_dir),
                )
            except CommandFailure as error:
                result[name] = scrub(error.stderr or error.stdout, secret_values(self.work_dir))
        return result

    def port_forward(self, session: Session, port: int) -> int:
        if session.phase == "quiesced":
            raise ConfigurationError("Minikube helper has no serving endpoint while quiesced")
        if not 1024 <= port <= 65535:
            raise ConfigurationError("local web port must be between 1024 and 65535")
        _, namespace, _ = self._identity(session)
        return self.runner.stream(
            self._kubectl(
                session,
                "port-forward",
                "--namespace",
                namespace,
                "--address",
                "127.0.0.1",
                "service/filebelt-web",
                f"{port}:8443",
            ),
            environment=self._environment(session),
        )

    def down(self, session: Session) -> None:
        if not isinstance(session.resources.get("minikube"), dict):
            return
        # The exact helper-owned profile is the authoritative ownership boundary.
        # Deleting it also removes the release and remains possible if the cached
        # Helm executable has been removed or changed since session creation.
        self._delete_profile(session)
        session.phase = "down"
