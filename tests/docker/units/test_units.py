#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for catalog, diagnostic, evidence, and lifecycle refusal."""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import io
import json
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from catalog import load_catalog  # noqa: E402
from diagnostics import MAXIMUM_DIAGNOSTIC_BYTES, scrub  # noqa: E402
from images import validate_role  # noqa: E402
from lifecycle import fixture_tag, validate_project  # noqa: E402
import tcp_proxy as TCP_PROXY  # noqa: E402


RUN_UNIT_SPEC = importlib.util.spec_from_file_location(
    "filebelt_docker_run_unit", ROOT / "tests/docker/units/run-unit.py"
)
if RUN_UNIT_SPEC is None or RUN_UNIT_SPEC.loader is None:
    raise RuntimeError("could not load the Docker unit runner")
RUN_UNIT = importlib.util.module_from_spec(RUN_UNIT_SPEC)
RUN_UNIT_SPEC.loader.exec_module(RUN_UNIT)
ACCEPTANCE_SPEC = importlib.util.spec_from_file_location(
    "filebelt_docker_acceptance", ROOT / "tests/docker/phase2/acceptance.py"
)
if ACCEPTANCE_SPEC is None or ACCEPTANCE_SPEC.loader is None:
    raise RuntimeError("could not load Docker acceptance")
ACCEPTANCE = importlib.util.module_from_spec(ACCEPTANCE_SPEC)
sys.modules[ACCEPTANCE_SPEC.name] = ACCEPTANCE
ACCEPTANCE_SPEC.loader.exec_module(ACCEPTANCE)


class CatalogTest(unittest.TestCase):
    def test_catalog_defines_isolated_exact_artifact_units(self) -> None:
        units = load_catalog(ROOT, ROOT / "tests/docker/units.toml")
        self.assertEqual(
            set(units), {"core", "collaboration", "mcp", "phase8-qualification"}
        )
        self.assertTrue(all(unit.exact_artifacts for unit in units.values()))
        expected_tiers = ("pull_request", "push", "scheduled", "manual", "release")
        self.assertTrue(
            all(
                unit.event_tiers == expected_tiers
                for name, unit in units.items()
                if name != "phase8-qualification"
            )
        )
        self.assertEqual(units["phase8-qualification"].event_tiers, ("manual",))
        self.assertEqual(units["collaboration"].browser_projects, ("chromium", "firefox"))
        self.assertIn("filebelt-mcp-broker", units["mcp"].roles)
        collaboration = (ROOT / "ui/web/browser/docker-integration.spec.mjs").read_text(
            encoding="utf-8"
        )
        for required in (
            "CommitExternalHead",
            "Live collaboration disconnected.",
            "Save local edits as a copy",
            "timeout: 60_000",
        ):
            self.assertIn(required, collaboration)
        mcp_fixture = (ROOT / "tests/docker/mcp-egress/Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "install -d -o 10001 -g 10001 -m 0555 /opt/filebelt-mcp-egress",
            mcp_fixture,
        )

    def test_catalog_rejects_path_escape(self) -> None:
        document = (ROOT / "tests/docker/units.toml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "units.toml"
            path.write_text(document.replace('"deploy/compose/compose.yaml"', '"../compose.yaml"', 1), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "escapes"):
                load_catalog(ROOT, path)


class LifecycleTest(unittest.TestCase):
    def test_source_build_cpu_mapping_is_exact_and_fail_closed(self) -> None:
        self.assertEqual(
            RUN_UNIT.target_cpu_for_docker_architecture("amd64"), "x86-64-v3"
        )
        for architecture in ("arm64", "riscv64"):
            with self.subTest(architecture=architecture):
                self.assertEqual(
                    RUN_UNIT.target_cpu_for_docker_architecture(architecture),
                    "architecture-default",
                )
        for architecture in ("", "x86_64", "aarch64", "ppc64le", "amd64\narm64"):
            with self.subTest(architecture=architecture), self.assertRaisesRegex(
                ValueError, "unsupported Docker server architecture"
            ):
                RUN_UNIT.target_cpu_for_docker_architecture(architecture)

    def test_source_build_cpu_is_detected_only_for_source_builds(self) -> None:
        inherited = {"FILEBELT_TARGET_CPU": "caller-controlled"}
        with mock.patch.object(
            RUN_UNIT, "docker_server_architecture", return_value="amd64"
        ) as architecture:
            RUN_UNIT.configure_source_build_cpu(inherited, source_build=False)
            architecture.assert_not_called()
            self.assertEqual(inherited["FILEBELT_TARGET_CPU"], "caller-controlled")

            RUN_UNIT.configure_source_build_cpu(inherited, source_build=True)
            architecture.assert_called_once_with()
            self.assertEqual(inherited["FILEBELT_TARGET_CPU"], "x86-64-v3")

    def test_source_build_cpu_uses_docker_server_architecture(self) -> None:
        with mock.patch.object(
            RUN_UNIT.subprocess,
            "run",
            return_value=mock.Mock(stdout="arm64\n"),
        ) as run:
            self.assertEqual(RUN_UNIT.docker_server_architecture(), "arm64")
        run.assert_called_once_with(
            ["docker", "version", "--format", "{{.Server.Arch}}"],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_compose_propagates_source_build_cpu_to_native_images(self) -> None:
        compose = (ROOT / "deploy/compose/compose.yaml").read_text(encoding="utf-8")
        target_cpu_argument = (
            "FILEBELT_TARGET_CPU: "
            "${FILEBELT_TARGET_CPU:-architecture-default}"
        )
        self.assertEqual(compose.count(target_cpu_argument), 2)
        self.assertIn(target_cpu_argument, compose.split("x-filebelt-build:", 1)[0])
        web_start = compose.index("  filebelt-web:")
        web_end = compose.index("\n  filebelt-acceptance-relay:", web_start)
        web = compose[web_start:web_end]
        self.assertIn(target_cpu_argument, web)

    def test_cleanup_names_are_runner_owned_and_bounded(self) -> None:
        project = validate_project("filebelt-core-a1b2c3")
        self.assertEqual(fixture_tag("oidc", project), "filebelt-oidc-fixture:filebelt-core-a1b2c3")
        for unsafe in ("core", "FileBelt-core", "filebelt-core/escape", "filebelt-" + "a" * 64):
            with self.assertRaises(ValueError):
                validate_project(unsafe)
        with self.assertRaises(ValueError):
            fixture_tag("production", project)

    def test_diagnostics_are_bounded_and_redacted(self) -> None:
        secret = b"fixture-secret-value"
        source = b"prefix\nAuthorization: Bearer exposed\n" + secret + b"\n" + b"x" * (MAXIMUM_DIAGNOSTIC_BYTES + 100)
        result = scrub(source, (secret,))
        self.assertLessEqual(len(result), MAXIMUM_DIAGNOSTIC_BYTES)
        self.assertNotIn(secret, result)
        self.assertNotIn(b"Bearer exposed", result)

    def test_all_units_route_outside_browser_requests_through_loopback(self) -> None:
        for unit in ("core", "collaboration", "mcp"):
            with self.subTest(unit=unit):
                environment = {
                    "NO_PROXY": "example.test,LOCALHOST",
                    "no_proxy": "ci.internal,127.0.0.1",
                }
                RUN_UNIT.configure_outside_edge(environment)
                self.assertEqual(
                    environment["FILEBELT_ACCEPTANCE_CONNECT_HOST"], "127.0.0.1"
                )
                self.assertEqual(
                    environment["NO_PROXY"],
                    "example.test,LOCALHOST,filebelt.localhost,127.0.0.1,::1",
                )
                self.assertEqual(
                    environment["no_proxy"],
                    "ci.internal,127.0.0.1,filebelt.localhost,localhost,::1",
                )
        self.assertEqual(
            RUN_UNIT.select_topology("auto", ROOT, Path("/host/FileBelt")),
            "outside",
        )
        self.assertEqual(RUN_UNIT.select_topology("auto", ROOT, ROOT), "host")
        self.assertEqual(RUN_UNIT.select_topology("outside", ROOT, ROOT), "outside")
        with mock.patch.object(RUN_UNIT.Path, "exists", return_value=False):
            self.assertFalse(RUN_UNIT.executor_is_containerized(ROOT, ROOT))
        with mock.patch.object(RUN_UNIT.Path, "exists", return_value=True):
            self.assertTrue(RUN_UNIT.executor_is_containerized(ROOT, ROOT))
        self.assertTrue(
            RUN_UNIT.executor_is_containerized(ROOT, Path("/host/FileBelt"))
        )
        RUN_UNIT.validate_topology("outside", executor_containerized=True)
        with self.assertRaisesRegex(ValueError, "containerized executor"):
            RUN_UNIT.validate_topology("host", executor_containerized=True)

    def test_topology_environment_overrides_inherited_edge_bindings(self) -> None:
        environment = {
            "FILEBELT_ACCEPTANCE_CONNECT_HOST": "untrusted.example",
            "FILEBELT_HTTPS_BIND_ADDRESS": "0.0.0.0",
            "FILEBELT_HTTPS_PORT": "0",
        }
        RUN_UNIT.configure_topology_environment(environment, "host")
        self.assertEqual(environment["FILEBELT_HTTPS_BIND_ADDRESS"], "127.0.0.1")
        self.assertEqual(environment["FILEBELT_HTTPS_PORT"], "8443")
        self.assertNotIn("FILEBELT_ACCEPTANCE_CONNECT_HOST", environment)

        RUN_UNIT.configure_topology_environment(environment, "outside")
        self.assertEqual(environment["FILEBELT_HTTPS_BIND_ADDRESS"], "127.0.0.1")
        self.assertEqual(
            environment["FILEBELT_HTTPS_PORT"], RUN_UNIT.OUTSIDE_EDGE_PORT_RANGE
        )
        self.assertEqual(
            environment["FILEBELT_ACCEPTANCE_CONNECT_HOST"], "127.0.0.1"
        )

    def test_published_edge_parser_requires_one_ipv4_loopback_port(self) -> None:
        for port in (
            RUN_UNIT.OUTSIDE_EDGE_PORT_START,
            RUN_UNIT.OUTSIDE_EDGE_PORT_END,
        ):
            with self.subTest(port=port):
                self.assertEqual(
                    RUN_UNIT.parse_published_edge(f"127.0.0.1:{port}\n"),
                    ("127.0.0.1", port),
                )
        for invalid in (
            "",
            "0.0.0.0:49152",
            "127.0.0.1:0",
            "127.0.0.1:49151",
            "127.0.0.1:65536",
            "::1:49152",
            "127.0.0.1:49152\n127.0.0.1:49153",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                RUN_UNIT.parse_published_edge(invalid)

    def test_published_edge_waits_for_docker_port_metadata(self) -> None:
        unavailable = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="port metadata unavailable"
        )
        available = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="127.0.0.1:49152\n", stderr=""
        )
        with (
            mock.patch.object(
                RUN_UNIT.subprocess, "run", side_effect=(unavailable, available)
            ) as run,
            mock.patch.object(RUN_UNIT.time, "sleep") as sleep,
        ):
            self.assertEqual(
                RUN_UNIT.wait_published_edge("relay-container"),
                ("127.0.0.1", 49152),
            )
        self.assertEqual(run.call_count, 2)
        sleep.assert_called_once_with(0.1)

    def test_tcp_proxy_forwards_synthetic_connection(self) -> None:
        try:
            upstream_listener = socket.create_server(("127.0.0.1", 0))
        except PermissionError as error:
            self.skipTest(f"sandbox prohibits synthetic TCP listener: {error}")
        upstream_address = upstream_listener.getsockname()
        payload = b"ready" * (256 * 1024)

        def upstream() -> None:
            connection, _ = upstream_listener.accept()
            with connection:
                request = bytearray()
                while len(request) < len(payload):
                    chunk = connection.recv(64 * 1024)
                    if not chunk:
                        break
                    request.extend(chunk)
                connection.sendall(b"edge:" + str(len(request)).encode())

        upstream_thread = threading.Thread(target=upstream, daemon=True)
        upstream_thread.start()
        bridge = TCP_PROXY.ManagedTcpBridge(
            (str(upstream_address[0]), int(upstream_address[1])), port=0
        )
        bridge.start()
        try:
            with socket.create_connection(("127.0.0.1", bridge.bound_port)) as client:
                client.sendall(payload)
                self.assertEqual(
                    client.recv(64 * 1024),
                    b"edge:" + str(len(payload)).encode(),
                )
        finally:
            self.assertEqual(bridge.stop(), "stopped")
            upstream_listener.close()
        upstream_thread.join(timeout=2)
        self.assertFalse(upstream_thread.is_alive())
        self.assertEqual(bridge.statistics, {
            "admission_rejections": 0,
            "retry_exhaustions": 0,
            "upstream_attempts": 1,
            "upstream_failures": 0,
        })

    def test_tcp_proxy_retries_before_forwarding_without_losing_client_bytes(self) -> None:
        try:
            reservation = socket.create_server(("127.0.0.1", 0))
        except PermissionError as error:
            self.skipTest(f"sandbox prohibits synthetic TCP listener: {error}")
        upstream_port = int(reservation.getsockname()[1])
        reservation.close()
        bridge = TCP_PROXY.ManagedTcpBridge(("127.0.0.1", upstream_port), port=0)
        bridge.start()
        client = socket.create_connection(("127.0.0.1", bridge.bound_port))
        client.settimeout(3)
        client.sendall(b"buffered-before-upstream")
        deadline = time.monotonic() + 2
        while bridge.statistics["upstream_failures"] == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertGreaterEqual(bridge.statistics["upstream_failures"], 1)
        upstream_listener = socket.create_server(("127.0.0.1", upstream_port))
        try:
            upstream, _ = upstream_listener.accept()
            with upstream:
                self.assertEqual(upstream.recv(64 * 1024), b"buffered-before-upstream")
                upstream.sendall(b"recovered")
            self.assertEqual(client.recv(64 * 1024), b"recovered")
        finally:
            client.close()
            self.assertEqual(bridge.stop(), "stopped")
            upstream_listener.close()
        self.assertGreaterEqual(bridge.statistics["upstream_attempts"], 2)
        self.assertEqual(bridge.statistics["retry_exhaustions"], 0)

    def test_tcp_proxy_bounds_exhausted_retry_to_one_client(self) -> None:
        try:
            reservation = socket.create_server(("127.0.0.1", 0))
        except PermissionError as error:
            self.skipTest(f"sandbox prohibits synthetic TCP listener: {error}")
        upstream_port = int(reservation.getsockname()[1])
        reservation.close()
        bridge = TCP_PROXY.ManagedTcpBridge(("127.0.0.1", upstream_port), port=0)
        with (
            mock.patch.object(TCP_PROXY, "UPSTREAM_CONNECT_TIMEOUT_SECONDS", 0.05),
            mock.patch.object(TCP_PROXY, "UPSTREAM_RETRY_DELAY_SECONDS", 0.02),
            mock.patch.object(TCP_PROXY, "UPSTREAM_RETRY_WINDOW_SECONDS", 0.2),
        ):
            bridge.start()
            client = socket.create_connection(("127.0.0.1", bridge.bound_port))
            client.settimeout(2)
            self.assertEqual(client.recv(1), b"")
            client.close()
            bridge.check()
            self.assertEqual(bridge.stop(), "stopped")
        self.assertGreaterEqual(bridge.statistics["upstream_attempts"], 1)
        self.assertEqual(
            bridge.statistics["upstream_failures"],
            bridge.statistics["upstream_attempts"],
        )
        self.assertEqual(bridge.statistics["retry_exhaustions"], 1)
        self.assertIsNone(bridge.fatal_error)

    def test_tcp_proxy_bounds_admission_and_rebinds_after_cleanup(self) -> None:
        try:
            upstream_listener = socket.create_server(("127.0.0.1", 0))
            reservation = socket.create_server(("127.0.0.1", 0))
        except PermissionError as error:
            self.skipTest(f"sandbox prohibits synthetic TCP listener: {error}")
        bridge_port = int(reservation.getsockname()[1])
        reservation.close()
        accepted = threading.Event()

        def upstream() -> None:
            connection, _ = upstream_listener.accept()
            accepted.set()
            with connection:
                while connection.recv(1024):
                    pass

        upstream_thread = threading.Thread(target=upstream, daemon=True)
        upstream_thread.start()
        bridge = TCP_PROXY.ManagedTcpBridge(
            (
                str(upstream_listener.getsockname()[0]),
                int(upstream_listener.getsockname()[1]),
            ),
            port=bridge_port,
            maximum_connections=1,
        )
        bridge.start()
        first = socket.create_connection(("127.0.0.1", bridge_port))
        self.assertTrue(accepted.wait(timeout=2))
        second = socket.create_connection(("127.0.0.1", bridge_port))
        second.settimeout(2)
        self.assertEqual(second.recv(1), b"")
        second.close()
        self.assertEqual(bridge.stop(), "stopped")
        first.close()
        upstream_listener.close()
        upstream_thread.join(timeout=2)
        self.assertFalse(upstream_thread.is_alive())
        self.assertEqual(bridge.statistics["admission_rejections"], 1)
        replacement = TCP_PROXY.create_listener(
            socket.AF_INET, ("127.0.0.1", bridge_port)
        )
        replacement.close()

    def test_tcp_proxy_start_failure_releases_listeners(self) -> None:
        try:
            reservation = socket.create_server(("127.0.0.1", 0))
        except PermissionError as error:
            self.skipTest(f"sandbox prohibits synthetic TCP listener: {error}")
        bridge_port = int(reservation.getsockname()[1])
        reservation.close()
        bridge = TCP_PROXY.ManagedTcpBridge(("127.0.0.1", 1), port=bridge_port)
        with (
            mock.patch.object(
                TCP_PROXY.threading.Thread,
                "start",
                side_effect=RuntimeError("thread start failed"),
            ),
            self.assertRaisesRegex(RuntimeError, "thread start failed"),
        ):
            bridge.start()
        replacement = TCP_PROXY.create_listener(
            socket.AF_INET, ("127.0.0.1", bridge_port)
        )
        replacement.close()

    def test_tcp_proxy_ipv6_unavailable_keeps_mandatory_ipv4_listener(self) -> None:
        ipv4 = mock.Mock()
        with mock.patch.object(
            TCP_PROXY,
            "create_listener",
            side_effect=[ipv4, OSError(errno.EAFNOSUPPORT, "unsupported")],
        ):
            self.assertEqual(TCP_PROXY.create_listeners(), (ipv4,))
        ipv4.close.assert_not_called()

    def test_tcp_proxy_ipv6_conflict_closes_partial_listener(self) -> None:
        ipv4 = mock.Mock()
        with mock.patch.object(
            TCP_PROXY,
            "create_listener",
            side_effect=[ipv4, OSError(errno.EADDRINUSE, "in use")],
        ):
            with self.assertRaisesRegex(RuntimeError, "IPv6 loopback"):
                TCP_PROXY.create_listeners()
        ipv4.close.assert_called_once_with()

    def test_tcp_proxy_ipv4_conflict_fails_without_ipv6_fallback(self) -> None:
        with mock.patch.object(
            TCP_PROXY,
            "create_listener",
            side_effect=OSError(errno.EADDRINUSE, "in use"),
        ) as create_listener:
            with self.assertRaisesRegex(OSError, "in use"):
                TCP_PROXY.create_listeners()
        create_listener.assert_called_once_with(
            socket.AF_INET, ("127.0.0.1", TCP_PROXY.LOOPBACK_PORT)
        )

    def test_proxy_readiness_requires_liveness_and_accepted_status(self) -> None:
        bridge = mock.Mock()
        bridge.check.side_effect = RuntimeError("bridge failed")
        with self.assertRaisesRegex(RuntimeError, "bridge failed"):
            RUN_UNIT.wait_proxy("127.0.0.1", bridge, Path("certificate.pem"))

        bridge.check.side_effect = None
        with (
            mock.patch.object(RUN_UNIT, "probe_proxy", side_effect=[503, 401]) as probe,
            mock.patch.object(RUN_UNIT.time, "monotonic", side_effect=[0, 0, 0]),
            mock.patch.object(RUN_UNIT.time, "sleep"),
        ):
            RUN_UNIT.wait_proxy("127.0.0.1", bridge, Path("certificate.pem"))
        self.assertEqual(probe.call_count, 2)

        with (
            mock.patch.object(RUN_UNIT, "probe_proxy", return_value=503),
            mock.patch.object(RUN_UNIT.time, "monotonic", side_effect=[0, 0, 11]),
            mock.patch.object(RUN_UNIT.time, "sleep"),
        ):
            with self.assertRaisesRegex(RuntimeError, "unexpected HTTP status 503"):
                RUN_UNIT.wait_proxy("127.0.0.1", bridge, Path("certificate.pem"))

        bridge.check.reset_mock()
        with mock.patch.object(RUN_UNIT, "probe_proxy", return_value=401) as probe:
            RUN_UNIT.wait_proxy("127.0.0.1", bridge, Path("certificate.pem"))
        self.assertEqual(bridge.check.call_count, 2)
        probe.assert_called_once_with("127.0.0.1", Path("certificate.pem"))

    def test_proxy_readiness_forwards_tls_http_request(self) -> None:
        if shutil.which("openssl") is None:
            self.skipTest("openssl is unavailable for the TLS test certificate")
        try:
            upstream_listener = socket.create_server(("127.0.0.1", 0))
        except PermissionError as error:
            self.skipTest(f"sandbox prohibits synthetic TCP listener: {error}")
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "certificate.pem"
            key = Path(directory) / "key.pem"
            try:
                subprocess.run(
                    [
                        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-subj", "/CN=filebelt.localhost",
                        "-addext", "subjectAltName=DNS:filebelt.localhost",
                        "-keyout", str(key), "-out", str(certificate),
                    ],
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as error:
                self.skipTest(f"openssl could not create TLS test certificate: {error}")
            received = bytearray()
            server_names: list[str | None] = []
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            context.set_servername_callback(
                lambda _connection, server_name, _context: server_names.append(server_name)
            )
            def upstream() -> None:
                for _ in range(2):
                    connection, _ = upstream_listener.accept()
                    with context.wrap_socket(connection, server_side=True) as tls_connection:
                        received.extend(tls_connection.recv(4096))
                        tls_connection.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")

            upstream_thread = threading.Thread(target=upstream, daemon=True)
            upstream_thread.start()
            bridge = TCP_PROXY.ManagedTcpBridge(
                (
                    str(upstream_listener.getsockname()[0]),
                    int(upstream_listener.getsockname()[1]),
                ),
                port=0,
            )
            bridge.start()
            try:
                for _ in range(2):
                    self.assertEqual(
                        RUN_UNIT.probe_proxy(
                            "127.0.0.1", certificate, bridge.bound_port
                        ),
                        401,
                    )
            finally:
                bridge.stop()
                upstream_listener.close()
            upstream_thread.join(timeout=2)
            self.assertFalse(upstream_thread.is_alive())
            self.assertEqual(received.count(b"GET /api/v1/session HTTP/1.1\r\n"), 2)
            self.assertEqual(received.count(b"Host: filebelt.localhost\r\n"), 2)
            self.assertEqual(server_names, ["filebelt.localhost", "filebelt.localhost"])

    def test_transport_diagnostics_are_scrubbed_and_failure_only(self) -> None:
        secret = b"bridge-secret-value"
        with tempfile.TemporaryDirectory() as directory:
            diagnostics = Path(directory)
            RUN_UNIT.retain_transport_diagnostics(
                diagnostics,
                {"target_edge": "success"},
                (),
                failed=False,
            )
            self.assertFalse((diagnostics / "transport-status.txt").exists())
            RUN_UNIT.retain_transport_diagnostics(
                diagnostics,
                {
                    "bridge_cleanup": "stopped",
                    "bridge_fatal": "none",
                    "bridge_retry_exhaustions": "1",
                    "bridge_upstream_attempts": "4",
                    "bridge_upstream_failures": "4",
                    "published_edge": "127.0.0.1:49152",
                    "target_edge": secret.decode(),
                },
                (secret,),
                failed=True,
            )
            output = (diagnostics / "transport-status.txt").read_bytes()
        self.assertLessEqual(len(output), MAXIMUM_DIAGNOSTIC_BYTES)
        self.assertNotIn(secret, output)
        self.assertIn(b"published_edge=127.0.0.1:49152", output)
        self.assertIn(b"bridge_retry_exhaustions=1", output)

    def test_driver_is_terminated_and_reaped_when_bridge_fails(self) -> None:
        process = mock.Mock()
        process.poll.return_value = None
        bridge = mock.Mock()
        bridge.check.side_effect = RuntimeError("listener failed")
        with (
            mock.patch.object(RUN_UNIT.subprocess, "Popen", return_value=process),
            self.assertRaisesRegex(RuntimeError, "listener failed"),
        ):
            RUN_UNIT.run_driver(("driver",), {}, bridge)
        process.terminate.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=5)

    def test_readiness_error_is_bounded_and_sanitized(self) -> None:
        reason = "transport\nsecret" + "x" * 400
        browser = mock.Mock()
        browser.request.side_effect = ACCEPTANCE.urllib.error.URLError(reason)
        with (
            mock.patch.object(ACCEPTANCE.time, "monotonic", side_effect=[0, 0, 61]),
            mock.patch.object(ACCEPTANCE.time, "sleep"),
            self.assertRaisesRegex(
                AssertionError,
                r"last transport error: transport\?secretx+",
            ) as caught,
        ):
            ACCEPTANCE.wait_api(browser)
        detail = str(caught.exception).split("last transport error: ", 1)[1]
        self.assertEqual(len(detail), ACCEPTANCE.MAXIMUM_READY_ERROR_DETAIL)
        self.assertNotIn("\n", detail)


class ImageEvidenceTest(unittest.TestCase):
    REVISION = "a" * 40
    ROLE = "filebelt-api"
    REPOSITORY = f"ghcr.io/oxibelt/{ROLE}"
    TAG = "0.1.0-build.aaaaaaaaaaaa"

    def write_json(self, path: Path, value: object) -> None:
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")

    def write_v2_fixture(self, root: Path) -> dict[str, Path]:
        plan = root / "image-plan.json"
        plan_value = {
            "schemaVersion": 2,
            "amd64IsaBaseline": "x86-64-v3",
            "channel": "build",
            "version": "0.1.0",
            "tag": self.TAG,
            "source": {
                "url": "https://github.com/OxiBelt/FileBelt",
                "ref": "refs/heads/main",
                "revision": self.REVISION,
                "created": "2026-08-17T00:00:00Z",
                "dirty": False,
                "kind": "ci",
            },
            "runtime": {"uid": 10001, "gid": 10001},
            "images": [
                {
                    "role": self.ROLE,
                    "repository": self.REPOSITORY,
                    "platforms": ["linux/amd64", "linux/arm64", "linux/riscv64"],
                    "build": {
                        "dockerfile": "source/ops/Dockerfile.roles",
                        "target": self.ROLE,
                    },
                    "artifact": {
                        "kind": "rust-binary",
                        "targetCpu": {
                            "linux/amd64": "x86-64-v3",
                            "linux/arm64": None,
                            "linux/riscv64": None,
                        },
                    },
                }
            ],
        }
        self.write_json(plan, plan_value)

        archive = root / f"{self.ROLE}-amd64.docker.tar"
        reference = f"{self.REPOSITORY}:{self.TAG}-amd64"
        manifest = json.dumps([{"RepoTags": [reference]}]).encode()
        with tarfile.open(archive, "w") as output:
            member = tarfile.TarInfo("manifest.json")
            member.size = len(manifest)
            output.addfile(member, io.BytesIO(manifest))
        archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
        checksum = root / f"{archive.name}.sha256"
        checksum.write_text(f"{archive_sha}  {archive.name}\n", encoding="ascii")

        plan_sha = hashlib.sha256(plan.read_bytes()).hexdigest()
        metadata = root / f"{self.ROLE}-amd64.build.json"
        metadata_value = {
            "schemaVersion": 2,
            "planSha256": plan_sha,
            "role": self.ROLE,
            "platform": "linux/amd64",
            "repository": self.REPOSITORY,
            "version": "0.1.0",
            "tag": self.TAG,
            "localRef": reference,
            "sourceRevision": self.REVISION,
            "sourceRef": "refs/heads/main",
            "sourceCreated": "2026-08-17T00:00:00Z",
            "sourceDirty": False,
            "sourceKind": "ci",
            "targetCpu": "x86-64-v3",
            "dockerfile": "source/ops/Dockerfile.roles",
            "buildTarget": self.ROLE,
            "archive": archive.name,
            "archiveSha256": archive_sha,
        }
        self.write_json(metadata, metadata_value)
        metadata_sha = hashlib.sha256(metadata.read_bytes()).hexdigest()

        evidence = root / f"{self.ROLE}-amd64.evidence.json"
        self.write_json(
            evidence,
            {
                "schemaVersion": 2,
                "planSha256": plan_sha,
                "role": self.ROLE,
                "platform": "linux/amd64",
                "repository": self.REPOSITORY,
                "tag": self.TAG,
                "localRef": reference,
                "sourceRevision": self.REVISION,
                "targetCpu": "x86-64-v3",
                "archive": archive.name,
                "archiveSha256": archive_sha,
                "metadataSha256": metadata_sha,
            },
        )
        validation = root / f"{self.ROLE}-amd64.validation.json"
        self.write_json(
            validation,
            {
                "schemaVersion": 2,
                "role": self.ROLE,
                "platform": "linux/amd64",
                "sourceRevision": self.REVISION,
                "targetCpu": "x86-64-v3",
                "repositoryTag": reference,
            },
        )
        smoke = root / f"{self.ROLE}-amd64.smoke.json"
        self.write_json(
            smoke,
            {
                "schemaVersion": 1,
                "role": self.ROLE,
                "platform": "linux/amd64",
                "sourceRevision": self.REVISION,
                "passed": True,
            },
        )
        decision = root / f"{self.ROLE}-amd64.vulnerability-decision.json"
        self.write_json(
            decision,
            {"schemaVersion": 1, "allowed": True, "blockedFindings": []},
        )
        for suffix in ("cdx.json", "runtime.cdx.json"):
            self.write_json(root / f"{self.ROLE}-amd64.{suffix}", {})
        return {
            "plan": plan,
            "archive": archive,
            "metadata": metadata,
            "evidence": evidence,
            "validation": validation,
        }

    def assert_rejected(self, root: Path, message: str) -> None:
        with self.assertRaisesRegex(ValueError, message):
            validate_role(
                ROOT,
                root,
                root / "image-plan.json",
                self.ROLE,
                "build",
                self.REVISION,
            )

    def test_v2_artifact_evidence_contract_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self.write_v2_fixture(root)
            with mock.patch("images.subprocess.run") as run:
                self.assertEqual(
                    validate_role(
                        ROOT,
                        root,
                        fixture["plan"],
                        self.ROLE,
                        "build",
                        self.REVISION,
                    ),
                    (fixture["archive"], f"{self.REPOSITORY}:{self.TAG}-amd64"),
                )
            run.assert_called_once_with(
                [
                    "python3",
                    str(ROOT / "tests/scripts/validate-image.py"),
                    "--plan",
                    str(fixture["plan"]),
                    "--role",
                    self.ROLE,
                    "--platform",
                    "linux/amd64",
                    "--archive",
                    str(fixture["archive"]),
                ],
                cwd=ROOT,
                check=True,
            )

    def test_v2_artifact_evidence_rejects_target_cpu_drift(self) -> None:
        mutations = {
            "metadata": "build metadata",
            "evidence": "image evidence",
            "validation": "validation evidence",
        }
        for name, message in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fixture = self.write_v2_fixture(root)
                value = json.loads(fixture[name].read_text(encoding="utf-8"))
                value["targetCpu"] = "x86-64-v2"
                self.write_json(fixture[name], value)
                self.assert_rejected(root, message)

    def test_legacy_or_altered_plan_contract_fails_before_archive_loading(self) -> None:
        mutations = {
            "legacy schema": ("schemaVersion", 1),
            "altered baseline": ("amd64IsaBaseline", "x86-64-v2"),
        }
        for name, (key, value) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fixture = self.write_v2_fixture(root)
                plan_value = json.loads(fixture["plan"].read_text(encoding="utf-8"))
                plan_value[key] = value
                self.write_json(fixture["plan"], plan_value)
                self.assert_rejected(root, "schema or AMD64 ISA contract")

    def test_wrong_channel_fails_before_archive_loading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "image-plan.json"
            plan.write_text(json.dumps({
                "schemaVersion": 2,
                "amd64IsaBaseline": "x86-64-v3",
                "channel": "release",
                "source": {"kind": "release", "dirty": False, "revision": "a" * 40},
                "images": [],
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source contract"):
                validate_role(ROOT, root, plan, "filebelt-api", "build", "a" * 40)


if __name__ == "__main__":
    unittest.main()
