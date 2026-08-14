#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for catalog, diagnostic, evidence, and lifecycle refusal."""

from __future__ import annotations

import errno
import importlib.util
import json
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
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
    def test_catalog_defines_three_isolated_exact_artifact_units(self) -> None:
        units = load_catalog(ROOT, ROOT / "tests/docker/units.toml")
        self.assertEqual(set(units), {"core", "collaboration", "mcp"})
        self.assertTrue(all(unit.exact_artifacts for unit in units.values()))
        expected_tiers = ("pull_request", "push", "scheduled", "manual", "release")
        self.assertTrue(all(unit.event_tiers == expected_tiers for unit in units.values()))
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
        self.assertEqual(environment["FILEBELT_HTTPS_PORT"], "")
        self.assertEqual(
            environment["FILEBELT_ACCEPTANCE_CONNECT_HOST"], "127.0.0.1"
        )

    def test_published_edge_parser_requires_one_ipv4_loopback_port(self) -> None:
        self.assertEqual(
            RUN_UNIT.parse_published_edge("127.0.0.1:49152\n"),
            ("127.0.0.1", 49152),
        )
        for invalid in ("", "0.0.0.0:49152", "127.0.0.1:0", "::1:49152"):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                RUN_UNIT.parse_published_edge(invalid)

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
                    "target_edge": secret.decode(),
                },
                (secret,),
                failed=True,
            )
            output = (diagnostics / "transport-status.txt").read_bytes()
        self.assertLessEqual(len(output), MAXIMUM_DIAGNOSTIC_BYTES)
        self.assertNotIn(secret, output)

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
    def test_wrong_channel_fails_before_archive_loading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "image-plan.json"
            plan.write_text(json.dumps({
                "schemaVersion": 1,
                "channel": "release",
                "source": {"kind": "release", "dirty": False, "revision": "a" * 40},
                "images": [],
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source contract"):
                validate_role(ROOT, root, plan, "filebelt-api", "build", "a" * 40)


if __name__ == "__main__":
    unittest.main()
