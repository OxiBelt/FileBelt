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


RUN_UNIT_SPEC = importlib.util.spec_from_file_location(
    "filebelt_docker_run_unit", ROOT / "tests/docker/units/run-unit.py"
)
if RUN_UNIT_SPEC is None or RUN_UNIT_SPEC.loader is None:
    raise RuntimeError("could not load the Docker unit runner")
RUN_UNIT = importlib.util.module_from_spec(RUN_UNIT_SPEC)
RUN_UNIT_SPEC.loader.exec_module(RUN_UNIT)
TCP_PROXY_SPEC = importlib.util.spec_from_file_location(
    "filebelt_docker_tcp_proxy", ROOT / "tests/docker/units/tcp-proxy.py"
)
if TCP_PROXY_SPEC is None or TCP_PROXY_SPEC.loader is None:
    raise RuntimeError("could not load the Docker TCP proxy")
TCP_PROXY = importlib.util.module_from_spec(TCP_PROXY_SPEC)
TCP_PROXY_SPEC.loader.exec_module(TCP_PROXY)
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
            RUN_UNIT.proxy_command("172.31.0.8"),
            [
                "python3",
                str(ROOT / "tests/docker/units/tcp-proxy.py"),
                "--target",
                "172.31.0.8:8443",
            ],
        )

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
        client, proxy_side = socket.socketpair()
        admission = threading.BoundedSemaphore(1)
        self.assertTrue(admission.acquire(blocking=False))
        proxy_thread = threading.Thread(
            target=TCP_PROXY.forward,
            args=(proxy_side, (str(upstream_address[0]), int(upstream_address[1])), admission),
            daemon=True,
        )
        proxy_thread.start()
        try:
            client.sendall(payload)
            self.assertEqual(
                client.recv(64 * 1024),
                b"edge:" + str(len(payload)).encode(),
            )
        finally:
            client.close()
            upstream_listener.close()
        proxy_thread.join(timeout=2)
        upstream_thread.join(timeout=2)
        self.assertFalse(proxy_thread.is_alive())
        self.assertFalse(upstream_thread.is_alive())

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
        process = mock.Mock()
        process.poll.return_value = 9
        with self.assertRaisesRegex(RuntimeError, "exited with status 9"):
            RUN_UNIT.wait_proxy("127.0.0.1", process, Path("certificate.pem"))

        process.poll.return_value = None
        with (
            mock.patch.object(RUN_UNIT, "probe_proxy", side_effect=[503, 401]) as probe,
            mock.patch.object(RUN_UNIT.time, "monotonic", side_effect=[0, 0, 0]),
            mock.patch.object(RUN_UNIT.time, "sleep"),
        ):
            RUN_UNIT.wait_proxy("127.0.0.1", process, Path("certificate.pem"))
        self.assertEqual(probe.call_count, 2)

        process.poll.return_value = None
        with (
            mock.patch.object(RUN_UNIT, "probe_proxy", return_value=503),
            mock.patch.object(RUN_UNIT.time, "monotonic", side_effect=[0, 0, 11]),
            mock.patch.object(RUN_UNIT.time, "sleep"),
        ):
            with self.assertRaisesRegex(RuntimeError, "unexpected HTTP status 503"):
                RUN_UNIT.wait_proxy("127.0.0.1", process, Path("certificate.pem"))

        process.poll.side_effect = [None, 11]
        with mock.patch.object(RUN_UNIT, "probe_proxy", return_value=401):
            with self.assertRaisesRegex(RuntimeError, "exited with status 11"):
                RUN_UNIT.wait_proxy("127.0.0.1", process, Path("certificate.pem"))

        process.poll.reset_mock()
        process.poll.side_effect = None
        process.poll.return_value = None
        with mock.patch.object(RUN_UNIT, "probe_proxy", return_value=401) as probe:
            RUN_UNIT.wait_proxy("127.0.0.1", process, Path("certificate.pem"))
        self.assertEqual(process.poll.call_count, 2)
        probe.assert_called_once_with("127.0.0.1", Path("certificate.pem"))

    def test_proxy_readiness_forwards_tls_http_request(self) -> None:
        if shutil.which("openssl") is None:
            self.skipTest("openssl is unavailable for the TLS test certificate")
        try:
            upstream_listener = socket.create_server(("127.0.0.1", 0))
            bridge_listener = socket.create_server(("127.0.0.1", 0))
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
            admission = threading.BoundedSemaphore(1)
            self.assertTrue(admission.acquire(blocking=False))

            def upstream() -> None:
                connection, _ = upstream_listener.accept()
                with context.wrap_socket(connection, server_side=True) as tls_connection:
                    received.extend(tls_connection.recv(4096))
                    tls_connection.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")

            def bridge() -> None:
                connection, _ = bridge_listener.accept()
                TCP_PROXY.forward(
                    connection,
                    (str(upstream_listener.getsockname()[0]), int(upstream_listener.getsockname()[1])),
                    admission,
                )

            upstream_thread = threading.Thread(target=upstream, daemon=True)
            bridge_thread = threading.Thread(target=bridge, daemon=True)
            upstream_thread.start()
            bridge_thread.start()
            try:
                self.assertEqual(
                    RUN_UNIT.probe_proxy(
                        "127.0.0.1", certificate, int(bridge_listener.getsockname()[1])
                    ),
                    401,
                )
            finally:
                bridge_listener.close()
                upstream_listener.close()
            bridge_thread.join(timeout=2)
            upstream_thread.join(timeout=2)
            self.assertFalse(bridge_thread.is_alive())
            self.assertFalse(upstream_thread.is_alive())
            self.assertIn(b"GET /api/v1/session HTTP/1.1\r\n", received)
            self.assertIn(b"Host: filebelt.localhost\r\n", received)
            self.assertEqual(server_names, ["filebelt.localhost"])

    def test_proxy_teardown_scrubs_failure_output_and_discards_success_output(self) -> None:
        secret = b"bridge-secret-value"
        process = mock.Mock()
        process.communicate.return_value = (
            b"Authorization: Bearer exposed\n" + secret + b"\n" + b"x" * (MAXIMUM_DIAGNOSTIC_BYTES + 100),
            b"",
        )
        with tempfile.TemporaryDirectory() as directory:
            diagnostics = Path(directory)
            RUN_UNIT.stop_proxy(process, diagnostics, (secret,), retain_diagnostics=True)
            output = (diagnostics / "proxy-output.txt").read_bytes()
            success = mock.Mock()
            success.communicate.return_value = (b"ready", b"")
            RUN_UNIT.stop_proxy(success, diagnostics, (), retain_diagnostics=False)
        self.assertLessEqual(len(output), MAXIMUM_DIAGNOSTIC_BYTES)
        self.assertNotIn(secret, output)
        self.assertNotIn(b"Bearer exposed", output)
        process.terminate.assert_called_once_with()
        process.communicate.assert_called_once_with(timeout=5)
        success.terminate.assert_called_once_with()

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
