#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Bounded Docker Compose backend for named local development sessions."""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
import re
import socket
import sys
import time
from pathlib import Path
from typing import Any, Sequence

from .diagnostics import remember_secret, scrub, secret_values
from .model import ConfigurationError, DevelopmentConfiguration, Session
from .runner import CommandFailure, Runner


PROJECT_PREFIX = "filebelt-dev-"
RESOURCE_SCHEMA_VERSION = 4
LOOPBACK_ADDRESS = "127.0.0.1"
RELAY_SERVICE = "filebelt-acceptance-relay"
CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
MAXIMUM_BIND_INPUT_BYTES = 1_048_576
COMPOSE_COMPONENTS = frozenset(
    {
        "filebelt-api",
        "filebelt-bootstrap",
        "filebelt-collaboration",
        "filebelt-mcp-broker",
        "filebelt-mcp-egress",
        "filebelt-migrate",
        "filebelt-payload-init",
        "filebelt-web",
        "filebelt-worker-io",
        "filebelt-worker-maintenance",
        RELAY_SERVICE,
    }
)
RESTARTABLE_COMPONENTS = frozenset(
    {
        "filebelt-api",
        "filebelt-collaboration",
        "filebelt-mcp-broker",
        "filebelt-web",
        "filebelt-worker-io",
        "filebelt-worker-maintenance",
    }
)
CORE_LONG_LIVED_SERVICES = frozenset(
    {
        "postgres",
        "filebelt-oidc",
        "filebelt-api",
        "filebelt-collaboration",
        "filebelt-web",
        "filebelt-worker-io",
        "filebelt-worker-maintenance",
        RELAY_SERVICE,
    }
)
PROFILE_LONG_LIVED_SERVICES = {
    "mcp": frozenset({"filebelt-mcp-broker", "filebelt-mcp-egress"}),
    "iggy": frozenset({"filebelt-iggy"}),
    "fault": frozenset({"filebelt-io-database-unavailable"}),
}


def _load_unit_module(root: Path, name: str) -> Any:
    """Load an existing standalone Docker-unit helper without changing it."""
    units = root / "tests" / "docker" / "units"
    if str(units) not in sys.path:
        sys.path.insert(0, str(units))
    path = units / f"{name}.py"
    specification = importlib.util.spec_from_file_location(
        f"filebelt_development_{name.replace('-', '_')}", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError(f"could not load Docker helper: {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class ComposeBackend:
    """Own exactly one detached Compose project for one named session."""

    def __init__(self, root: Path, work_dir: Path, runner: Runner):
        self.root = root.resolve()
        self.work_dir = work_dir.resolve()
        self.runner = runner
        self._images = _load_unit_module(self.root, "images")
        self._lifecycle = _load_unit_module(self.root, "lifecycle")
        self._run_unit = _load_unit_module(self.root, "run-unit")
        self._tcp_proxy = _load_unit_module(self.root, "tcp_proxy")
        self._cached_host_root: Path | None = None

    def _project(self, session: Session) -> str:
        return self._lifecycle.validate_project(f"{PROJECT_PREFIX}{session.name}")

    @staticmethod
    def _suffix(session: Session) -> str:
        return f"dev-{session.name}"

    def _roles(self, profiles: Sequence[str]) -> tuple[str, ...]:
        roles = (
            "filebelt-api",
            "filebelt-collaboration",
            "filebelt-tools",
            "filebelt-web",
            "filebelt-worker-io",
            "filebelt-worker-maintenance",
        )
        return roles + (("filebelt-mcp-broker",) if "mcp" in profiles else ())

    def _suffixes(self, session: Session, profiles: Sequence[str]) -> dict[str, str]:
        return {role: self._suffix(session) for role in self._roles(profiles)}

    def _role_images(self, session: Session, profiles: Sequence[str]) -> list[str]:
        return [f"{role}:{self._suffix(session)}" for role in self._roles(profiles)]

    def _override_path(self) -> Path:
        return self.work_dir / "compose.override.json"

    def _compose_files(self, configuration: DevelopmentConfiguration) -> tuple[Path, ...]:
        files = [self.root / "deploy/compose/compose.yaml"]
        if "mcp" in configuration.compose.profiles:
            files.append(self.root / "deploy/compose/compose.mcp.yaml")
        if configuration.compose.external_oidc is not None:
            files.append(self.root / "deploy/compose/compose.external-oidc.yaml")
        files.append(self._override_path())
        return tuple(files)

    def _override(self, session: Session, profiles: Sequence[str]) -> dict[str, object]:
        suffixes = self._suffixes(session, profiles)
        images = {
            "filebelt-api": "filebelt-api",
            "filebelt-bootstrap": "filebelt-tools",
            "filebelt-collaboration": "filebelt-collaboration",
            "filebelt-io-database-unavailable": "filebelt-worker-io",
            "filebelt-mcp-broker": "filebelt-mcp-broker",
            "filebelt-migrate": "filebelt-tools",
            "filebelt-web": "filebelt-web",
            "filebelt-worker-io": "filebelt-worker-io",
            "filebelt-worker-maintenance": "filebelt-worker-maintenance",
        }
        return {
            "services": {
                service: {"image": f"{role}:{suffixes[role]}"}
                for service, role in images.items()
                if role in suffixes
            }
        }

    def _write_override(self, session: Session, profiles: Sequence[str]) -> Path:
        path = self._override_path()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists() and path.is_symlink():
            raise ConfigurationError("refusing to replace a symlink Compose override")
        path.write_text(
            json.dumps(self._override(session, profiles), sort_keys=True), encoding="utf-8"
        )
        path.chmod(0o600)
        return path

    @staticmethod
    def _external_resources(
        configuration: DevelopmentConfiguration,
    ) -> dict[str, str | None] | None:
        external = configuration.compose.external_oidc
        if external is None:
            return None
        return {
            "network": external.network,
            "filebelt_config": str(external.filebelt_config),
            "collaboration_config": str(external.collaboration_config),
            "mcp_config": str(external.mcp_config),
            "edge_config": str(external.edge_config),
            "client_secret": str(external.client_secret),
            "ca_certificate": (
                str(external.ca_certificate) if external.ca_certificate else None
            ),
        }

    def _resources(self, session: Session, configuration: DevelopmentConfiguration) -> dict[str, Any]:
        project = self._project(session)
        fixture_project = f"{project}-fixture"
        fixtures = {
            "oidc": self._lifecycle.fixture_tag("oidc", f"{fixture_project}-oidc"),
            "payload": self._lifecycle.fixture_tag("oidc", f"{fixture_project}-payload"),
            "relay": self._lifecycle.fixture_tag("oidc", f"{fixture_project}-relay"),
        }
        if "mcp" in configuration.compose.profiles:
            fixtures["mcp-egress"] = self._lifecycle.fixture_tag(
                "mcp-egress", f"{fixture_project}-mcp"
            )
        artifact_inputs: dict[str, str] | None = None
        if configuration.images.mode == "artifacts":
            if configuration.images.directory is None or configuration.images.channel is None:
                raise ConfigurationError("artifact configuration is incomplete")
            artifact_inputs = {
                "directory": str(configuration.images.directory),
                "channel": configuration.images.channel,
            }
        return {
            "schema_version": RESOURCE_SCHEMA_VERSION,
            "project": project,
            "compose_files": [str(path) for path in self._compose_files(configuration)],
            "profiles": list(configuration.compose.profiles),
            "edge_port": configuration.compose.published_port,
            "state_dir": str(self.work_dir / "state"),
            "override": str(self._override_path()),
            "fixtures": fixtures,
            "role_images": self._role_images(session, configuration.compose.profiles),
            "artifact_inputs": artifact_inputs,
            "external_oidc": self._external_resources(configuration),
        }

    @staticmethod
    def _validate_artifact_inputs(inputs: object) -> None:
        if inputs is None:
            return
        if not isinstance(inputs, dict) or set(inputs) != {"directory", "channel"}:
            raise ConfigurationError("Compose artifact inputs are invalid")
        directory = inputs["directory"]
        channel = inputs["channel"]
        if (
            not isinstance(directory, str)
            or not Path(directory).is_absolute()
            or channel not in {"build", "release"}
        ):
            raise ConfigurationError("Compose artifact inputs are invalid")

    @staticmethod
    def _validate_external(external: object) -> None:
        if external is None:
            return
        keys = {
            "network",
            "filebelt_config",
            "collaboration_config",
            "mcp_config",
            "edge_config",
            "client_secret",
            "ca_certificate",
        }
        if (
            not isinstance(external, dict)
            or set(external) != keys
            or not isinstance(external["network"], str)
            or not external["network"]
        ):
            raise ConfigurationError("Compose external OIDC manifest is invalid")
        for name in keys - {"network", "ca_certificate"}:
            path = Path(external[name])
            if not path.is_absolute() or path.is_symlink():
                raise ConfigurationError("Compose external OIDC path is invalid")
        if external["ca_certificate"] is not None:
            path = Path(external["ca_certificate"])
            if not path.is_absolute() or path.is_symlink():
                raise ConfigurationError("Compose external OIDC CA path is invalid")

    def _validate_resources(self, session: Session) -> dict[str, Any]:
        resources = session.resources
        required = {
            "schema_version",
            "project",
            "compose_files",
            "profiles",
            "edge_port",
            "state_dir",
            "override",
            "fixtures",
            "role_images",
            "artifact_inputs",
            "external_oidc",
        }
        if (
            not isinstance(resources, dict)
            or set(resources) != required
            or resources["schema_version"] != RESOURCE_SCHEMA_VERSION
        ):
            raise ConfigurationError("Compose resource manifest is invalid")
        if resources["project"] != self._project(session):
            raise ConfigurationError("Compose resource manifest project is not session-owned")
        profiles = resources["profiles"]
        if (
            not isinstance(profiles, list)
            or not profiles
            or profiles[0] != "core"
            or len(profiles) != len(set(profiles))
            or not set(profiles) <= {"core", "mcp", "iggy", "fault"}
        ):
            raise ConfigurationError("Compose resource manifest profiles are invalid")
        edge_port = resources["edge_port"]
        if not isinstance(edge_port, int) or not 1024 <= edge_port <= 65535:
            raise ConfigurationError("Compose resource manifest port is invalid")
        override = self._override_path()
        if resources["override"] != str(override) or override.is_symlink() or not override.is_file():
            raise ConfigurationError("Compose resource manifest override is invalid")
        try:
            override_document = json.loads(override.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ConfigurationError("Compose resource manifest override is invalid") from error
        if override_document != self._override(session, profiles):
            raise ConfigurationError("Compose resource manifest override is invalid")
        self._validate_external(resources["external_oidc"])
        expected_files = [str(self.root / "deploy/compose/compose.yaml")]
        if "mcp" in profiles:
            expected_files.append(str(self.root / "deploy/compose/compose.mcp.yaml"))
        if resources["external_oidc"] is not None:
            expected_files.append(str(self.root / "deploy/compose/compose.external-oidc.yaml"))
        expected_files.append(str(override))
        if resources["compose_files"] != expected_files:
            raise ConfigurationError("Compose resource manifest files are invalid")
        state = Path(resources["state_dir"])
        if not state.is_absolute() or state != self.work_dir / "state" or state.is_symlink():
            raise ConfigurationError("Compose resource manifest state directory is invalid")
        fixtures = resources["fixtures"]
        expected_fixture_names = {"oidc", "payload", "relay"} | (
            {"mcp-egress"} if "mcp" in profiles else set()
        )
        if not isinstance(fixtures, dict) or set(fixtures) != expected_fixture_names:
            raise ConfigurationError("Compose resource manifest fixtures are invalid")
        for name, reference in fixtures.items():
            expected = self._lifecycle.fixture_tag(
                "mcp-egress" if name == "mcp-egress" else "oidc",
                f"{resources['project']}-fixture-{'mcp' if name == 'mcp-egress' else name}",
            )
            if reference != expected:
                raise ConfigurationError("Compose fixture tag is not session-owned")
        if resources["role_images"] != self._role_images(session, profiles):
            raise ConfigurationError("Compose role image manifest is not session-owned")
        self._validate_artifact_inputs(resources["artifact_inputs"])
        return resources

    def _host_path(self, path: Path) -> Path:
        """Map a checked-out path to Docker's host or reject an inaccessible bind."""
        if self._cached_host_root is None:
            self._cached_host_root = self._run_unit.docker_host_root(self.root)
        host_root = self._cached_host_root
        if host_root == self.root:
            return path
        try:
            relative = path.resolve().relative_to(self.root)
        except ValueError as error:
            raise ConfigurationError(
                "containerized executor cannot bind a development path outside "
                "the Docker-host checkout"
            ) from error
        return host_root / relative

    def _compose_command(self, resources: dict[str, Any], *arguments: str) -> list[str]:
        command = ["docker", "compose", "--project-name", resources["project"]]
        for file in resources["compose_files"]:
            # Compose itself runs in the executor and must read executor paths.
            # Only bind-mount values are translated to Docker-daemon host paths.
            command.extend(("--file", file))
        for profile in resources["profiles"]:
            command.extend(("--profile", profile))
        return [*command, *arguments]

    def _environment(self, resources: dict[str, Any], *, host_paths: bool) -> dict[str, str]:
        state = Path(resources["state_dir"])
        bound_state = self._host_path(state) if host_paths else state
        environment = os.environ.copy()
        environment.update(
            {
                "FILEBELT_STATE_DIR": str(bound_state),
                "FILEBELT_HTTPS_BIND_ADDRESS": LOOPBACK_ADDRESS,
                "FILEBELT_HTTPS_PORT": str(resources["edge_port"]),
                "FILEBELT_OIDC_FIXTURE_IMAGE": resources["fixtures"]["oidc"],
                "FILEBELT_PAYLOAD_INIT_IMAGE": resources["fixtures"]["payload"],
                "FILEBELT_ACCEPTANCE_RELAY_IMAGE": resources["fixtures"]["relay"],
            }
        )
        if host_paths:
            bind_inputs = {
                "FILEBELT_CONFIG_FILE": self.root / "deploy/compose/filebelt.toml",
                "FILEBELT_COLLABORATION_CONFIG_FILE": self.root
                / "deploy/compose/filebelt-collaboration.toml",
                "FILEBELT_MCP_CONFIG_FILE": self.root / "deploy/compose/filebelt-mcp.toml",
                "FILEBELT_EDGE_CONFIG_FILE": self.root
                / "ui/web/edge/oxibelt.acceptance.toml",
                "FILEBELT_POSTGRES_ROLE_SCRIPT_FILE": self.root
                / "deploy/compose/postgres/bootstrap-runtime-roles.sh",
                "FILEBELT_POSTGRES_ROLES_FILE": self.root
                / "source/migrations/postgres/roles.sql",
                "FILEBELT_POSTGRES_GRANTS_FILE": self.root
                / "source/migrations/postgres/grants.sql",
            }
            for name, path in bind_inputs.items():
                environment[name] = str(self._host_path(path))
        environment.pop("FILEBELT_UNSAFE_NON_LOOPBACK_ACK", None)
        if "mcp-egress" in resources["fixtures"]:
            environment["FILEBELT_MCP_EGRESS_FIXTURE_IMAGE"] = resources["fixtures"]["mcp-egress"]
        external = resources["external_oidc"]
        if external is not None:
            environment["FILEBELT_OIDC_EGRESS_NETWORK"] = external["network"]
            paths = {
                "FILEBELT_CONFIG_FILE": self.work_dir / "inputs/filebelt.toml",
                "FILEBELT_COLLABORATION_CONFIG_FILE": self.work_dir
                / "inputs/filebelt-collaboration.toml",
                "FILEBELT_MCP_CONFIG_FILE": self.work_dir / "inputs/filebelt-mcp.toml",
                "FILEBELT_EDGE_CONFIG_FILE": self.work_dir / "inputs/oxibelt.toml",
            }
            for name, path in paths.items():
                environment[name] = str(self._host_path(path) if host_paths else path)
            staged_secret = self.work_dir / "secrets/external-oidc-client-secret"
            environment["FILEBELT_OIDC_CLIENT_SECRET_FILE"] = str(
                self._host_path(staged_secret) if host_paths else staged_secret
            )
            if external["ca_certificate"] is not None:
                ca_path = self.work_dir / "inputs/oidc-ca.crt"
                environment["FILEBELT_OIDC_CA_FILE"] = str(
                    self._host_path(ca_path) if host_paths else ca_path
                )
        return environment

    @staticmethod
    def _copy_bind_input(source: Path, destination: Path) -> None:
        if source.is_symlink() or not source.is_file():
            raise ConfigurationError("Compose external OIDC input is unsafe")
        value = source.read_bytes()
        if len(value) > MAXIMUM_BIND_INPUT_BYTES:
            raise ConfigurationError("Compose external OIDC input exceeds 1 MiB")
        descriptor = os.open(
            destination,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())

    def _stage_external_inputs(self, resources: dict[str, Any]) -> None:
        external = resources["external_oidc"]
        if external is None:
            return
        directory = self.work_dir / "inputs"
        if directory.is_symlink():
            raise ConfigurationError("Compose external OIDC input directory is unsafe")
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        sources = {
            "filebelt.toml": external["filebelt_config"],
            "filebelt-collaboration.toml": external["collaboration_config"],
            "filebelt-mcp.toml": external["mcp_config"],
            "oxibelt.toml": external["edge_config"],
        }
        if external["ca_certificate"] is not None:
            sources["oidc-ca.crt"] = external["ca_certificate"]
        for name, source in sources.items():
            self._copy_bind_input(Path(source), directory / name)
        remember_secret(
            self.work_dir,
            "external-oidc-client-secret",
            Path(external["client_secret"]).read_bytes(),
        )

    @staticmethod
    def _make_bind_inputs_readable(work_dir: Path) -> None:
        """Permit service UIDs to read files below otherwise-private session paths."""
        for directory in (
            work_dir / "state/secrets",
            work_dir / "state/tls",
            work_dir / "inputs",
            work_dir / "secrets",
        ):
            if not directory.exists():
                continue
            if directory.is_symlink() or not directory.is_dir():
                raise ConfigurationError("Compose state input directory is unsafe")
            for path in directory.iterdir():
                if path.is_symlink() or not path.is_file():
                    raise ConfigurationError("Compose state input file is unsafe")
                path.chmod(0o644)

    def _ensure_images_absent(self, references: Sequence[str]) -> None:
        for reference in references:
            try:
                self.runner.run(["docker", "image", "inspect", reference])
            except CommandFailure:
                continue
            raise ConfigurationError(
                f"refusing to replace existing session image: {reference}"
            )

    def _remove_images(self, references: Sequence[str]) -> None:
        for reference in reversed(references):
            try:
                self.runner.run(["docker", "image", "inspect", reference])
            except CommandFailure:
                continue
            self.runner.run(["docker", "image", "rm", "--force", reference])

    def _build_fixtures(self, session: Session, resources: dict[str, Any]) -> None:
        contexts = {
            "oidc": self.root / "tests/docker/oidc",
            "payload": self.root / "tests/docker/oidc",
            "relay": self.root / "tests/docker/oidc",
            "mcp-egress": self.root / "tests/docker/mcp-egress",
        }
        for name, reference in resources["fixtures"].items():
            self._validate_resources(session)
            # The Docker CLI, rather than the daemon, reads build contexts.
            context = contexts[name]
            self.runner.run(
                [
                    "docker",
                    "build",
                    "--file",
                    str(context / "Dockerfile"),
                    "--tag",
                    reference,
                    str(context),
                ]
            )

    def up(self, session: Session, configuration: DevelopmentConfiguration) -> None:
        if session.topology != "compose":
            raise ConfigurationError("Compose backend requires a Compose session")
        self._write_override(session, configuration.compose.profiles)
        session.resources = self._resources(session, configuration)
        session.save(self.work_dir / "session.json")
        resources = self._validate_resources(session)
        compose_environment = self._environment(resources, host_paths=True)
        if resources["external_oidc"] is not None:
            self.runner.run(
                ["docker", "network", "inspect", resources["external_oidc"]["network"]]
            )
        if configuration.images.mode == "source":
            self._run_unit.configure_source_build_cpu(compose_environment, True)
        self._validate_resources(session)
        self.runner.run(
            [str(self.root / "deploy/compose/prepare-state.sh")],
            environment=self._environment(resources, host_paths=False),
        )
        if resources["external_oidc"] is not None:
            self._stage_external_inputs(resources)
        self._make_bind_inputs_readable(self.work_dir)
        transient_artifact_images: list[str] = []
        try:
            if configuration.images.mode == "artifacts":
                if configuration.images.directory is None or configuration.images.channel is None:
                    raise ConfigurationError("artifact configuration is incomplete")
                self._validate_resources(session)
                loaded = self._images.load_roles(
                    self.root,
                    configuration.images.directory,
                    self._roles(resources["profiles"]),
                    self._suffixes(session, resources["profiles"]),
                    configuration.images.channel,
                    session.source_revision,
                )
                transient_artifact_images = loaded[::2]
                if loaded[1::2] != resources["role_images"]:
                    raise ConfigurationError("loaded Compose images are not session-owned")
                self._remove_images(transient_artifact_images)
                transient_artifact_images.clear()
                self._validate_resources(session)
            else:
                self._ensure_images_absent(resources["role_images"])
            self._ensure_images_absent(tuple(resources["fixtures"].values()))
            if configuration.images.mode == "artifacts":
                self._build_fixtures(session, resources)
            build = "--build" if configuration.images.mode == "source" else "--no-build"
            self._validate_resources(session)
            self.runner.run(
                self._compose_command(resources, "up", build, "--wait"),
                environment=compose_environment,
            )
            time.sleep(3)
            ready, degraded = self._readiness(
                self._status_rows(resources), resources["profiles"]
            )
            session.qualification["composeReady"] = ready
            session.qualification["degradedComponents"] = degraded
        except Exception:
            self._remove_images(transient_artifact_images)
            raise

    def _status_rows(self, resources: dict[str, Any]) -> list[dict[str, object]]:
        result = self.runner.run(
            self._compose_command(resources, "ps", "--format", "json"),
            environment=self._environment(resources, host_paths=True),
        )
        payload = result.stdout.decode("utf-8")
        try:
            parsed = json.loads(payload)
            rows = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            rows = [json.loads(line) for line in payload.splitlines() if line.strip()]
        if not all(isinstance(row, dict) for row in rows):
            raise RuntimeError("Compose status output is invalid")
        return rows

    @staticmethod
    def _long_lived_services(profiles: Sequence[str]) -> frozenset[str]:
        expected = set(CORE_LONG_LIVED_SERVICES)
        for profile in profiles:
            expected.update(PROFILE_LONG_LIVED_SERVICES.get(profile, ()))
        return frozenset(expected)

    @classmethod
    def _readiness(
        cls, rows: Sequence[dict[str, object]], profiles: Sequence[str]
    ) -> tuple[bool, list[str]]:
        expected = cls._long_lived_services(profiles)
        observed = {
            str(row.get("Service")): row
            for row in rows
            if row.get("Service") in expected
        }
        degraded = set(expected - observed.keys())
        degraded.update(
            service
            for service, row in observed.items()
            if row.get("State") != "running"
            or row.get("Health") not in {None, "", "healthy"}
        )
        return not degraded, sorted(degraded)

    def status(self, session: Session) -> dict[str, object]:
        resources = self._validate_resources(session)
        rows = self._status_rows(resources)
        ready, degraded = self._readiness(rows, resources["profiles"])
        return {
            "degradedComponents": degraded,
            "project": resources["project"],
            "ready": ready,
            "services": rows,
        }

    def logs(self, session: Session, component: str, tail: int) -> bytes:
        resources = self._validate_resources(session)
        if component not in COMPOSE_COMPONENTS or not 1 <= tail <= 500:
            raise ConfigurationError("Compose log request is not allowlisted or bounded")
        result = self.runner.run(
            self._compose_command(
                resources, "logs", "--no-color", "--tail", str(tail), component
            ),
            environment=self._environment(resources, host_paths=True),
        )
        return scrub(result.stdout + result.stderr, secret_values(self.work_dir))

    def restart(self, session: Session, component: str) -> None:
        resources = self._validate_resources(session)
        if component not in RESTARTABLE_COMPONENTS:
            raise ConfigurationError("Compose component is not restartable")
        self.runner.run(
            self._compose_command(resources, "restart", component),
            environment=self._environment(resources, host_paths=True),
        )

    def diagnose(self, session: Session) -> dict[str, bytes]:
        resources = self._validate_resources(session)
        environment = self._environment(resources, host_paths=True)
        secrets = secret_values(self.work_dir)
        outputs: dict[str, bytes] = {}
        requests = (
            ("compose-ps", ("ps", "--all")),
            ("compose-logs", ("logs", "--no-color", "--tail", "200")),
        )
        for name, arguments in requests:
            try:
                result = self.runner.run(
                    self._compose_command(resources, *arguments), environment=environment
                )
                outputs[name] = scrub(result.stdout + result.stderr, secrets)
            except CommandFailure as error:
                outputs[name] = scrub(error.stdout + error.stderr, secrets)
        return outputs

    def port_forward(self, session: Session, port: int) -> int:
        resources = self._validate_resources(session)
        published_port = resources["edge_port"]
        if port != 8443:
            raise ConfigurationError("FileBelt's development origin uses local port 8443")
        result = self.runner.run(
            self._compose_command(resources, "ps", "--quiet", RELAY_SERVICE),
            environment=self._environment(resources, host_paths=True),
        )
        container = result.stdout.decode().strip()
        if CONTAINER_ID.fullmatch(container) is None:
            raise RuntimeError("Compose relay container identity is invalid")
        publication = self.runner.run(["docker", "port", container, "8443/tcp"])
        lines = [
            line.strip()
            for line in publication.stdout.decode().splitlines()
            if line.strip()
        ]
        if lines != [f"{LOOPBACK_ADDRESS}:{published_port}"]:
            raise RuntimeError("Compose relay is not published exactly on IPv4 loopback")
        host_root = self._cached_host_root or self._run_unit.docker_host_root(self.root)
        self._cached_host_root = host_root
        containerized = self._run_unit.executor_is_containerized(self.root, host_root)
        if not containerized and published_port == port:
            print("verified direct Docker-host loopback publication")
            return 0
        network = f"{resources['project']}_edge"
        executor = self._executor_container_id()
        if containerized and executor is None:
            raise RuntimeError("containerized executor identity is unavailable")
        bridge = None
        connected = False
        try:
            target = (LOOPBACK_ADDRESS, published_port)
            if containerized:
                membership = self.runner.run(
                    [
                        "docker",
                        "network",
                        "inspect",
                        "--format",
                        "{{json .Containers}}",
                        network,
                    ]
                )
                try:
                    members = json.loads(membership.stdout or b"{}")
                except json.JSONDecodeError as error:
                    raise RuntimeError(
                        "Compose edge network membership is invalid"
                    ) from error
                if not isinstance(members, dict):
                    raise RuntimeError("Compose edge network membership is invalid")
                if any(
                    container_id == executor for container_id in members
                ):
                    raise ConfigurationError(
                        "the executor is already attached to this session edge network"
                    )
                self.runner.run(["docker", "network", "connect", network, executor])
                connected = True
                address = self.runner.run(
                    [
                        "docker",
                        "inspect",
                        "--format",
                        f'{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}',
                        container,
                    ]
                ).stdout.decode().strip()
                try:
                    ipaddress.IPv4Address(address)
                except ipaddress.AddressValueError as error:
                    raise RuntimeError("Compose relay edge address is invalid") from error
                target = (address, 8443)
            bridge = self._tcp_proxy.ManagedTcpBridge(target, port=port)
            bridge.start()
            print("loopback bridge ready; press Ctrl-C to stop")
            try:
                while True:
                    bridge.check()
                    time.sleep(0.25)
            except KeyboardInterrupt:
                return 0
        finally:
            if bridge is not None:
                bridge.stop()
            if connected:
                try:
                    self.runner.run(
                        ["docker", "network", "disconnect", network, executor]
                    )
                except CommandFailure:
                    pass
        return 0

    def _disconnect_orphaned_bridge(self, resources: dict[str, Any]) -> None:
        network = f"{resources['project']}_edge"
        executor = self._executor_container_id()
        if executor is None:
            return
        try:
            membership = self.runner.run(
                ["docker", "network", "inspect", "--format", "{{json .Containers}}", network]
            )
            members = json.loads(membership.stdout or b"{}")
        except (CommandFailure, json.JSONDecodeError):
            return
        if not isinstance(members, dict):
            return
        if any(
            container_id == executor for container_id in members
        ):
            try:
                self.runner.run(["docker", "network", "disconnect", network, executor])
            except CommandFailure:
                pass

    def _executor_container_id(self) -> str | None:
        try:
            result = self.runner.run(
                ["docker", "inspect", "--format", "{{.Id}}", socket.gethostname()]
            )
        except CommandFailure:
            return None
        identity = result.stdout.decode().strip()
        return identity if len(identity) == 64 and CONTAINER_ID.fullmatch(identity) else None

    def _cleanup(self, session: Session, environment: dict[str, str]) -> None:
        resources = self._validate_resources(session)
        self._disconnect_orphaned_bridge(resources)
        self.runner.run(
            self._compose_command(
                resources,
                "down",
                "--volumes",
                "--remove-orphans",
                "--timeout",
                "35",
            ),
            environment=environment,
        )
        owned = resources["role_images"] + list(resources["fixtures"].values())
        for reference in reversed(owned):
            self._validate_resources(session)
            self._remove_images((reference,))

    def down(self, session: Session) -> None:
        resources = self._validate_resources(session)
        self._cleanup(session, self._environment(resources, host_paths=True))
