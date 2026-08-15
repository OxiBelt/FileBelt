#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Run one isolated cataloged Docker integration unit."""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from catalog import load_catalog
from diagnostics import secret_values, write_scrubbed
from images import load_roles
from lifecycle import fixture_tag, validate_project
from tcp_proxy import ManagedTcpBridge


ROOT = Path(__file__).resolve().parents[3]
CATALOG = ROOT / "tests/docker/units.toml"
PREPARE = ROOT / "deploy/compose/prepare-state.sh"
COMPOSE_SUFFIX = {
    "filebelt-collaboration": "phase5",
    "filebelt-mcp-broker": "phase4",
}
LOOPBACK_EDGE_HOST = "127.0.0.1"
EDGE_NO_PROXY_HOSTS = ("filebelt.localhost", "localhost", "127.0.0.1", "::1")
EDGE_PORT = 8443
EDGE_RELAY_SERVICE = "filebelt-acceptance-relay"
EDGE_SERVER_NAME = "filebelt.localhost"
OUTSIDE_EDGE_PORT_START = 49152
OUTSIDE_EDGE_PORT_END = 65535
OUTSIDE_EDGE_PORT_RANGE = f"{OUTSIDE_EDGE_PORT_START}-{OUTSIDE_EDGE_PORT_END}"
MAXIMUM_PROXY_ERROR_DETAIL = 240


def docker_host_root(root: Path) -> Path:
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{range .Mounts}}{{println .Source \"|\" .Destination}}{{end}}", socket.gethostname()],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return root
    candidates: list[tuple[int, Path]] = []
    root_text = str(root)
    for line in result.stdout.splitlines():
        fields = line.split(" | ", 1)
        if len(fields) != 2:
            continue
        source, destination = fields
        if root_text == destination or root_text.startswith(destination.rstrip("/") + "/"):
            candidates.append((len(destination), Path(source + root_text[len(destination):])))
    return max(candidates, default=(0, root))[1]


def compose_command(compose_files: tuple[Path, ...], profiles: tuple[str, ...], project: str, *arguments: str) -> list[str]:
    command = ["docker", "compose", "--project-name", project]
    for path in compose_files:
        command.extend(("--file", str(path)))
    for profile in profiles:
        command.extend(("--profile", profile))
    command.extend(arguments)
    return command


def proxy_error_detail(error: BaseException) -> str:
    """Keep bridge failures printable and safe to retain in runner diagnostics."""
    return "".join(
        character if character.isprintable() and character not in "\r\n\t" else "?"
        for character in str(error)
    )[:MAXIMUM_PROXY_ERROR_DETAIL]


def probe_proxy(address: str, certificate: Path, port: int = EDGE_PORT) -> int:
    """Exercise the TLS edge over the local bridge using the public origin name."""
    context = ssl.create_default_context(cafile=str(certificate))
    with socket.create_connection((address, port), timeout=1) as connection:
        with context.wrap_socket(connection, server_hostname=EDGE_SERVER_NAME) as tls_connection:
            tls_connection.sendall(
                b"GET /api/v1/session HTTP/1.1\r\n"
                b"Host: filebelt.localhost\r\n"
                b"Accept: application/json\r\n"
                b"Connection: close\r\n\r\n"
            )
            response = bytearray()
            while b"\r\n" not in response and len(response) < 4096:
                chunk = tls_connection.recv(1024)
                if not chunk:
                    break
                response.extend(chunk)
    status_line = bytes(response).split(b"\r\n", 1)[0]
    parts = status_line.split(b" ", 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/") or len(parts[1]) != 3 or not parts[1].isdigit():
        raise RuntimeError("browser TCP proxy returned an invalid HTTP status line")
    return int(parts[1])


def wait_proxy(address: str, bridge: ManagedTcpBridge, certificate: Path) -> None:
    deadline = time.monotonic() + 10
    last_error = "no TLS/HTTP response"
    while time.monotonic() < deadline:
        bridge.check()
        try:
            status = probe_proxy(address, certificate)
        except (OSError, RuntimeError, ssl.SSLError) as error:
            last_error = proxy_error_detail(error)
            time.sleep(0.1)
            continue
        bridge.check()
        if status in {200, 401}:
            return
        last_error = f"unexpected HTTP status {status}"
        time.sleep(0.1)
    raise RuntimeError(f"browser TCP proxy did not become ready: {last_error}")


def append_no_proxy(value: str) -> str:
    """Preserve an inherited bypass list while adding the local edge route."""
    entries = [entry.strip() for entry in value.split(",") if entry.strip()]
    known = {entry.casefold() for entry in entries}
    for host in EDGE_NO_PROXY_HOSTS:
        if host.casefold() not in known:
            entries.append(host)
            known.add(host.casefold())
    return ",".join(entries)


def configure_outside_edge(environment: dict[str, str]) -> None:
    """Route the fixed-origin browser client through the local DoD TCP bridge."""
    environment["FILEBELT_ACCEPTANCE_CONNECT_HOST"] = LOOPBACK_EDGE_HOST
    for name in ("NO_PROXY", "no_proxy"):
        environment[name] = append_no_proxy(environment.get(name, ""))


def configure_topology_environment(
    environment: dict[str, str], topology: str
) -> None:
    """Own the Compose bind and acceptance route for the selected topology."""
    environment["FILEBELT_HTTPS_BIND_ADDRESS"] = LOOPBACK_EDGE_HOST
    if topology == "outside":
        # A nonempty range is portable across the supported Docker runners and
        # lets the daemon atomically select an available loopback port.
        environment["FILEBELT_HTTPS_PORT"] = OUTSIDE_EDGE_PORT_RANGE
        configure_outside_edge(environment)
    else:
        environment["FILEBELT_HTTPS_PORT"] = str(EDGE_PORT)
        environment.pop("FILEBELT_ACCEPTANCE_CONNECT_HOST", None)


def select_topology(requested: str, root: Path, host_root: Path) -> str:
    """Resolve local auto-detection without allowing CI to depend on it."""
    if requested == "auto":
        return "outside" if host_root != root else "host"
    return requested


def executor_is_containerized(root: Path, host_root: Path) -> bool:
    """Detect an executor namespace that cannot use Docker-host loopback."""
    return host_root != root or any(
        marker.exists() for marker in (Path("/.dockerenv"), Path("/run/.containerenv"))
    )


def validate_topology(topology: str, executor_containerized: bool) -> None:
    if topology == "host" and executor_containerized:
        raise ValueError("host topology cannot be used from a containerized executor")


def parse_published_edge(value: str) -> tuple[str, int]:
    """Accept the one relay-owned IPv4 loopback publication from Docker."""
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError("Docker acceptance relay publication is unavailable")
    host, separator, port_text = lines[0].rpartition(":")
    if not separator or host != LOOPBACK_EDGE_HOST or not port_text.isdigit():
        raise RuntimeError("Docker acceptance relay is not on IPv4 loopback")
    port = int(port_text)
    if not OUTSIDE_EDGE_PORT_START <= port <= OUTSIDE_EDGE_PORT_END:
        raise RuntimeError("Docker acceptance relay is outside the runner-owned range")
    return host, port


def run_driver(
    command: tuple[str, ...],
    environment: dict[str, str],
    bridge: ManagedTcpBridge | None,
) -> None:
    """Run the acceptance driver while continuously checking bridge health."""
    process = subprocess.Popen(command, cwd=ROOT, env=environment)
    while True:
        return_code = process.poll()
        if return_code is not None:
            if return_code != 0:
                raise subprocess.CalledProcessError(return_code, command)
            return
        if bridge is not None:
            try:
                bridge.check()
            except RuntimeError:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                raise
        time.sleep(0.1)


def transport_report(status: dict[str, str]) -> bytes:
    """Render stable, bounded, non-secret bridge lifecycle evidence."""
    return "".join(f"{name}={status[name]}\n" for name in sorted(status)).encode()


def retain_transport_diagnostics(
    diagnostics: Path,
    status: dict[str, str],
    secrets: tuple[bytes, ...],
    failed: bool,
) -> None:
    if failed:
        write_scrubbed(
            diagnostics / "transport-status.txt",
            transport_report(status),
            secrets,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unit", choices=("core", "collaboration", "mcp"), required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--image-dir", type=Path)
    source.add_argument("--build", action="store_true")
    source.add_argument("--reuse-images", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--image-channel", choices=("build", "release"))
    parser.add_argument("--diagnostics-dir", type=Path)
    parser.add_argument("--project-name")
    parser.add_argument(
        "--docker-topology",
        choices=("auto", "host", "outside"),
        default="auto",
        help="select direct-host or isolated-bridge acceptance transport",
    )
    arguments = parser.parse_args()
    if (arguments.image_dir is None) != (arguments.image_channel is None):
        parser.error("--image-dir and --image-channel must be supplied together")
    for command in ("docker", "openssl", "python3"):
        if shutil.which(command) is None:
            raise SystemExit(f"required command is unavailable: {command}")

    unit = load_catalog(ROOT, CATALOG)[arguments.unit]
    if unit.status != "ready":
        raise SystemExit(f"Docker integration unit {unit.name} is blocked: {unit.blocker}")
    project = arguments.project_name or f"filebelt-{unit.name}-{uuid.uuid4().hex[:12]}"
    try:
        project = validate_project(project)
    except ValueError as error:
        raise SystemExit(str(error)) from error

    host_root = docker_host_root(ROOT)
    topology = select_topology(arguments.docker_topology, ROOT, host_root)
    outside = topology == "outside"
    executor_containerized = executor_is_containerized(ROOT, host_root)
    if executor_containerized and host_root == ROOT:
        raise SystemExit(
            "containerized executor Docker-host checkout mapping is unavailable"
        )
    try:
        validate_topology(topology, executor_containerized)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    local_state = Path(tempfile.mkdtemp(prefix=f".state.{unit.name}.", dir=ROOT / "deploy/compose"))
    unit_temp = Path(tempfile.mkdtemp(prefix=f"filebelt-{unit.name}-"))
    diagnostics = arguments.diagnostics_dir.resolve() if arguments.diagnostics_dir else unit_temp / "diagnostics"
    host_state = host_root / local_state.relative_to(ROOT)
    environment = os.environ.copy()
    environment.update({
        "FILEBELT_STATE_DIR": str(host_state),
        "FILEBELT_CONFIG_FILE": str(host_root / "deploy/compose/filebelt.toml"),
        "FILEBELT_MCP_CONFIG_FILE": str(host_root / "deploy/compose/filebelt-mcp.toml"),
        "FILEBELT_COLLABORATION_CONFIG_FILE": str(host_root / "deploy/compose/filebelt-collaboration.toml"),
        "FILEBELT_EDGE_CONFIG_FILE": str(host_root / "ui/web/edge/oxibelt.acceptance.toml"),
        "FILEBELT_POSTGRES_ROLE_SCRIPT_FILE": str(host_root / "deploy/compose/postgres/bootstrap-runtime-roles.sh"),
        "FILEBELT_POSTGRES_ROLES_FILE": str(host_root / "source/migrations/postgres/roles.sql"),
        "FILEBELT_POSTGRES_GRANTS_FILE": str(host_root / "source/migrations/postgres/grants.sql"),
        "FILEBELT_ACCEPTANCE_PROJECT": project,
        "FILEBELT_ACCEPTANCE_COMPOSE_FILES": os.pathsep.join(str(path) for path in unit.compose_files),
        "FILEBELT_ACCEPTANCE_PROFILES": os.pathsep.join(unit.profiles),
        "FILEBELT_UNIT_TEMP": str(unit_temp),
        "FILEBELT_DOCKER_DIAGNOSTICS_DIR": str(diagnostics),
        "FILEBELT_MCP_INTEGRATION_HOST": "filebelt-mcp-integration.example.test" if unit.name == "mcp" else "",
        "FILEBELT_OIDC_FIXTURE_IMAGE": fixture_tag("oidc", project),
        "FILEBELT_MCP_EGRESS_FIXTURE_IMAGE": fixture_tag("mcp-egress", project),
    })
    configure_topology_environment(environment, topology)

    loaded_images: list[str] = []
    fixture_images = [environment["FILEBELT_OIDC_FIXTURE_IMAGE"]]
    if unit.name == "mcp":
        fixture_images.append(environment["FILEBELT_MCP_EGRESS_FIXTURE_IMAGE"])
    connected = False
    bridge: ManagedTcpBridge | None = None
    started = False
    fixture_tags_owned = False
    status = 1
    failure_detail: str | None = None
    transport = {
        "bridge_admission_rejections": "0",
        "bridge_cleanup": "not-started",
        "bridge_fatal": "none",
        "bridge_listeners": "0",
        "bridge_retry_exhaustions": "0",
        "bridge_upstream_attempts": "0",
        "bridge_upstream_failures": "0",
        "connect_endpoint": f"{EDGE_SERVER_NAME}:{EDGE_PORT}",
        "published_edge": "not-resolved",
        "requested_topology": arguments.docker_topology,
        "selected_topology": topology,
        "target_edge": "not-resolved",
    }
    print(
        f"Docker acceptance transport topology={topology} "
        f"executor={'container' if executor_containerized else 'host'}",
        flush=True,
    )
    try:
        subprocess.run([str(PREPARE)], cwd=ROOT, env={**environment, "FILEBELT_STATE_DIR": str(local_state)}, check=True)
        for path in (local_state, local_state / "secrets", local_state / "tls"):
            path.chmod(0o711)
        for directory in (local_state / "secrets", local_state / "tls"):
            for path in directory.iterdir():
                if path.is_file():
                    path.chmod(0o644)
        if arguments.image_dir is not None:
            revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
            loaded_images = load_roles(ROOT, arguments.image_dir.resolve(), unit.roles, COMPOSE_SUFFIX, arguments.image_channel, revision)
        for fixture in fixture_images:
            exists = subprocess.run(["docker", "image", "inspect", fixture], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
            if exists:
                raise ValueError(f"refusing to replace existing runner fixture image: {fixture}")
        fixture_tags_owned = True
        if not arguments.build:
            fixture_contexts = [(environment["FILEBELT_OIDC_FIXTURE_IMAGE"], ROOT / "tests/docker/oidc")]
            if unit.name == "mcp":
                fixture_contexts.append((environment["FILEBELT_MCP_EGRESS_FIXTURE_IMAGE"], ROOT / "tests/docker/mcp-egress"))
            for fixture, context in fixture_contexts:
                subprocess.run(["docker", "build", "--file", str(context / "Dockerfile"), "--tag", fixture, str(context)], cwd=ROOT, check=True)
        build_option = "--build" if arguments.build else "--no-build"
        # An unsuccessful `compose up` can still create networks, volumes, and
        # containers. Mark the project as started before invoking Compose so
        # failure diagnostics and deterministic cleanup cover that case too.
        started = True
        subprocess.run(compose_command(unit.compose_files, unit.profiles, project, "up", build_option, "--wait"), cwd=ROOT, env=environment, check=True)
        if outside:
            network = f"{project}_edge"
            if executor_containerized:
                subprocess.run(["docker", "network", "connect", network, socket.gethostname()], check=True)
                connected = True
            relay_container = subprocess.run(
                compose_command(
                    unit.compose_files,
                    unit.profiles,
                    project,
                    "ps",
                    "--quiet",
                    EDGE_RELAY_SERVICE,
                ),
                cwd=ROOT,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if not relay_container or "\n" in relay_container:
                raise RuntimeError("Docker acceptance relay identity is unavailable")
            publication = subprocess.run(
                ["docker", "port", relay_container, f"{EDGE_PORT}/tcp"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            published_target = parse_published_edge(publication)
            transport["published_edge"] = (
                f"{published_target[0]}:{published_target[1]}"
            )
            if executor_containerized:
                address = subprocess.run(
                    ["docker", "inspect", "--format", f"{{{{(index .NetworkSettings.Networks \"{network}\").IPAddress}}}}", relay_container],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
                if not address:
                    raise RuntimeError("Docker acceptance relay edge address is empty")
                target = (address, EDGE_PORT)
            else:
                target = published_target
            transport["target_edge"] = f"{target[0]}:{target[1]}"
            transport["connect_endpoint"] = f"{LOOPBACK_EDGE_HOST}:{EDGE_PORT}"
            bridge = ManagedTcpBridge(target)
            bridge.start()
            transport["bridge_listeners"] = str(bridge.listener_count)
            wait_proxy(LOOPBACK_EDGE_HOST, bridge, local_state / "tls/filebelt.crt")
        run_driver(unit.driver, environment, bridge)
        status = 0
    except (OSError, subprocess.CalledProcessError, ValueError, RuntimeError) as error:
        failure_detail = f"Docker integration unit {unit.name} failed: {error}"
        print(failure_detail, file=sys.stderr)
        status = 1
    finally:
        if bridge is not None:
            transport["bridge_fatal"] = bridge.fatal_error or "none"
            try:
                transport["bridge_cleanup"] = bridge.stop()
            except RuntimeError as error:
                transport["bridge_cleanup"] = proxy_error_detail(error)
                if status == 0:
                    failure_detail = f"Docker integration unit {unit.name} failed: {error}"
                    print(failure_detail, file=sys.stderr)
                    status = 1
            for name, value in bridge.statistics.items():
                transport[f"bridge_{name}"] = str(value)
        if status != 0:
            secrets = secret_values(local_state)
            write_scrubbed(
                diagnostics / "runner-error.txt",
                ((failure_detail or f"Docker integration unit {unit.name} failed") + "\n").encode(),
                secrets,
            )
            retain_transport_diagnostics(diagnostics, transport, secrets, failed=True)
        if status != 0 and started:
            secrets = secret_values(local_state)
            for name, arguments_tail in (
                ("compose-ps.txt", ("ps", "--all")),
                ("compose-logs.txt", ("logs", "--no-color", "--tail", "200")),
            ):
                result = subprocess.run(compose_command(unit.compose_files, unit.profiles, project, *arguments_tail), cwd=ROOT, env=environment, capture_output=True)
                write_scrubbed(diagnostics / name, result.stdout + result.stderr, secrets)
        if connected:
            subprocess.run(["docker", "network", "disconnect", f"{project}_edge", socket.gethostname()], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if started:
            subprocess.run(compose_command(unit.compose_files, unit.profiles, project, "down", "--volumes", "--timeout", "35"), cwd=ROOT, env=environment, check=False)
        for reference in reversed(loaded_images):
            subprocess.run(["docker", "image", "rm", "--force", reference], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if fixture_tags_owned:
            for reference in reversed(fixture_images):
                subprocess.run(["docker", "image", "rm", "--force", reference], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(local_state, ignore_errors=True)
        if arguments.diagnostics_dir is None or status == 0:
            shutil.rmtree(unit_temp, ignore_errors=True)
    if status == 0:
        print(f"Docker integration unit {unit.name} passed")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
