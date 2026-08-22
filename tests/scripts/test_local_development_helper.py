#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Contract tests for the bounded local development deployment helper."""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))

from development import diagnostics  # noqa: E402
from development import model  # noqa: E402
from development import run as helper  # noqa: E402
from development.compose_backend import ComposeBackend  # noqa: E402
from development.minikube_backend import MinikubeBackend  # noqa: E402
from development import minikube_backend  # noqa: E402


REVISION = "1" * 40


class FakeBackend:
    def __init__(self, *, fail_up: bool = False, fail_down: bool = False):
        self.fail_up = fail_up
        self.fail_down = fail_down
        self.down_calls = 0
        self.restart_calls: list[str] = []

    def up(self, session: model.Session, configuration: model.DevelopmentConfiguration) -> None:
        session.resources["owned"] = "filebelt-dev-" + session.name
        if self.fail_up:
            raise RuntimeError("failure password=development-secret")

    def status(self, session: model.Session) -> dict[str, object]:
        return {"ready": session.phase == "running"}

    def logs(self, session: model.Session, component: str, tail: int) -> bytes:
        return f"{component}:{tail}\n".encode()

    def restart(self, session: model.Session, component: str) -> None:
        self.restart_calls.append(component)

    def diagnose(self, session: model.Session) -> dict[str, bytes]:
        return {"owned-status": b"Authorization: bearer-value\npassword=development-secret\n"}

    def port_forward(self, session: model.Session, port: int) -> int:
        return 0

    def down(self, session: model.Session) -> None:
        self.down_calls += 1
        if self.fail_down:
            raise RuntimeError("down failed")


class ScriptedRunner:
    def __init__(self, handler=None):
        self.commands: list[tuple[tuple[str, ...], bytes | None]] = []
        self.handler = handler

    def run(self, command, **keywords):
        selected = tuple(str(value) for value in command)
        input_data = keywords.get("input_data")
        self.commands.append((selected, input_data))
        if self.handler is not None:
            output = self.handler(selected, keywords)
            if output is not None:
                return subprocess.CompletedProcess(selected, 0, stdout=output, stderr=b"")
        return subprocess.CompletedProcess(selected, 0, stdout=b"", stderr=b"")

    def stream(self, command, **keywords):
        self.commands.append((tuple(str(value) for value in command), None))
        return 0


class ConfigurationTests(unittest.TestCase):
    def test_defaults_are_source_compose_and_supported_minikube(self) -> None:
        configuration = model.load_configuration(None)
        self.assertEqual(configuration.images.mode, "source")
        self.assertEqual(configuration.compose.profiles, ("core",))
        self.assertEqual(configuration.compose.published_port, 8443)
        self.assertEqual(configuration.minikube.kubernetes_version, "v1.36.1")
        self.assertEqual(configuration.minikube.cni, "calico")
        self.assertEqual(configuration.preview.features, ())

    def test_unknown_and_mutable_preview_inputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "development.toml"
            path.write_text("schema_version = 1\nunknown = true\n", encoding="utf-8")
            with self.assertRaisesRegex(model.ConfigurationError, "unknown keys"):
                model.load_configuration(path.resolve())
            path.write_text(
                """schema_version = 1
[preview]
features = ["documents"]
[[preview.images]]
role = "filebelt-document"
digest = "latest"
source = "https://example.invalid/source"
license = "Apache-2.0"
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(model.ConfigurationError, "exact digest"):
                model.load_configuration(path.resolve())

    def test_preview_features_require_their_exact_image_roles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "development.toml"
            path.write_text(
                f"""schema_version = 1
[preview]
features = ["documents"]
[[preview.images]]
role = "filebelt-collaboration"
digest = "sha256:{'a' * 64}"
source = "https://example.invalid/source"
license = "Apache-2.0"
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(model.ConfigurationError, "filebelt-document"):
                model.load_configuration(path.resolve())

    def test_preview_image_roles_must_be_unique(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "development.toml"
            image = f'''[[preview.images]]
role = "filebelt-document"
digest = "sha256:{'a' * 64}"
source = "https://example.invalid/source"
license = "Apache-2.0"
'''
            path.write_text(f"schema_version = 1\n[preview]\n{image}{image}", encoding="utf-8")
            with self.assertRaisesRegex(model.ConfigurationError, "repeat an image role"):
                model.load_configuration(path.resolve())

    def test_compose_port_is_bounded_and_configurable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "development.toml"
            path.write_text(
                "schema_version = 1\n[compose]\npublished_port = 18443\n",
                encoding="utf-8",
            )
            self.assertEqual(
                model.load_configuration(path.resolve()).compose.published_port, 18443
            )
            path.write_text(
                "schema_version = 1\n[compose]\npublished_port = 443\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(model.ConfigurationError, "between 1024"):
                model.load_configuration(path.resolve())

    def test_session_names_must_end_in_a_letter_or_digit(self) -> None:
        with self.assertRaises(model.ConfigurationError):
            model.validate_session_name("trailing-")

    def test_preview_secrets_are_paths_and_kubernetes_keys_allow_dots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret = root / "ca.crt"
            secret.write_text("certificate\n", encoding="utf-8")
            path = root / "development.toml"
            path.write_text(
                f"""schema_version = 1
[preview]
features = ["documents"]
[[preview.images]]
role = "filebelt-document"
digest = "sha256:{'a' * 64}"
source = "https://example.invalid/source"
license = "Apache-2.0"
[[preview.secrets]]
namespace = "core"
name = "filebelt-document-ca"
key = "ca.crt"
path = "{secret}"
""",
                encoding="utf-8",
            )
            configuration = model.load_configuration(path.resolve())
            self.assertEqual(configuration.preview.secrets[0].namespace, "core")
            self.assertEqual(configuration.preview.secrets[0].key, "ca.crt")

    def test_development_root_rejects_broad_or_relative_paths(self) -> None:
        with mock.patch.dict(os.environ, {"FILEBELT_DEVELOPMENT_ROOT": "relative"}):
            with self.assertRaisesRegex(model.ConfigurationError, "must be absolute"):
                model.development_root()
        with self.assertRaisesRegex(model.ConfigurationError, "broad"):
            model.prepare_root(Path("/tmp"))

    def test_session_directory_symlink_cannot_redirect_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = model.prepare_root(base / "development")
            redirected = base / "redirected"
            victim = redirected / "example"
            victim.mkdir(parents=True)
            (victim / "keep").write_text("caller-owned\n", encoding="utf-8")
            (root / "sessions").symlink_to(redirected, target_is_directory=True)
            with self.assertRaisesRegex(model.ConfigurationError, "must not be a symlink"):
                model.session_directory(root, "example")
            with self.assertRaisesRegex(model.ConfigurationError, "unsafe"):
                helper.remove_session_directory(root, "example")
            self.assertTrue((victim / "keep").is_file())


class SessionTests(unittest.TestCase):
    def test_manifest_is_private_versioned_and_non_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = model.prepare_root(Path(temporary) / "development")
            configuration = model.load_configuration(None)
            session = model.Session.create("example", "compose", REVISION, configuration)
            path = model.session_manifest(root, session.name)
            session.save(path)
            payload = path.read_text(encoding="utf-8")
            self.assertNotIn("password", payload)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(model.Session.load(path), session)

    def test_preview_source_and_license_evidence_is_retained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "development.toml"
            config.write_text(
                f'''schema_version = 1
[preview]
features = ["documents"]
[[preview.images]]
role = "filebelt-document"
digest = "sha256:{'a' * 64}"
source = "https://example.invalid/document"
license = "Apache-2.0"
''',
                encoding="utf-8",
            )
            configuration = model.load_configuration(config.resolve())
            session = model.Session.create("preview", "minikube", REVISION, configuration)
            self.assertEqual(
                session.qualification["previewImages"][0]["source"],
                "https://example.invalid/document",
            )

    def test_session_names_and_manifest_shape_are_closed(self) -> None:
        with self.assertRaises(model.ConfigurationError):
            model.validate_session_name("../escape")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "session.json"
            path.write_text('{"schema_version": 1}\n', encoding="utf-8")
            with self.assertRaisesRegex(model.ConfigurationError, "contract"):
                model.Session.load(path)

    def test_malformed_session_field_types_fail_as_configuration_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "session.json"
            session = model.Session.create(
                "example", "compose", REVISION, model.load_configuration(None)
            )
            document = dataclasses.asdict(session)
            document["name"] = []
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(model.ConfigurationError, "field types"):
                model.Session.load(path)

    def test_quiesced_minikube_session_can_be_reloaded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = model.prepare_root(Path(temporary) / "development")
            configuration = model.load_configuration(None)
            session = model.Session.create("preview", "minikube", REVISION, configuration)
            session.phase = "quiesced"
            path = model.session_manifest(root, session.name)
            session.save(path)
            self.assertEqual(model.Session.load(path).phase, "quiesced")


class DiagnosticTests(unittest.TestCase):
    def test_diagnostics_are_tail_bounded_and_scrub_credentials(self) -> None:
        secret = b"development-secret"
        data = b"prefix\n" + b"x" * diagnostics.MAXIMUM_DIAGNOSTIC_BYTES
        data += b"\nAuthorization: bearer\npostgresql://user:pass@db/filebelt\n" + secret
        scrubbed = diagnostics.scrub(data, (secret,))
        self.assertLessEqual(len(scrubbed), diagnostics.MAXIMUM_DIAGNOSTIC_BYTES)
        self.assertNotIn(secret, scrubbed)
        self.assertNotIn(b"bearer", scrubbed)
        self.assertNotIn(b"user:pass", scrubbed)

    def test_remembered_secret_is_private_and_scrubbed_regardless_of_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work_dir = Path(temporary)
            diagnostics.remember_secret(work_dir, "preview-certificate-pem", b"private-material")
            remembered = work_dir / "secrets/preview-certificate-pem"
            self.assertEqual(stat.S_IMODE(remembered.stat().st_mode), 0o600)
            self.assertEqual(
                diagnostics.scrub(b"value=private-material", diagnostics.secret_values(work_dir)),
                b"value=[REDACTED]",
            )


class ComposeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temporary.name) / "session"
        self.work_dir.mkdir()
        self.configuration = model.load_configuration(None)
        self.session = model.Session.create("example", "compose", REVISION, self.configuration)
        self.runner = ScriptedRunner()
        self.backend = ComposeBackend(ROOT, self.work_dir, self.runner)
        self.backend._write_override(self.session, self.configuration.compose.profiles)
        self.session.resources = self.backend._resources(self.session, self.configuration)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_role_images_are_exactly_session_owned_in_source_mode(self) -> None:
        resources = self.backend._validate_resources(self.session)
        self.assertEqual(
            resources["role_images"],
            [f"{role}:dev-example" for role in self.backend._roles(("core",))],
        )
        resources["role_images"].append("unrelated:latest")
        with self.assertRaisesRegex(model.ConfigurationError, "session-owned"):
            self.backend._validate_resources(self.session)

    def test_compose_files_are_executor_local_but_bind_inputs_map_to_the_host(self) -> None:
        resources = self.backend._validate_resources(self.session)
        self.backend._cached_host_root = Path("/host/filebelt")
        command = self.backend._compose_command(resources, "config")
        self.assertIn(str(ROOT / "deploy/compose/compose.yaml"), command)
        self.assertNotIn("/host/filebelt/deploy/compose/compose.yaml", command)
        self.assertEqual(
            self.backend._host_path(ROOT / "source/migrations/postgres/roles.sql"),
            Path("/host/filebelt/source/migrations/postgres/roles.sql"),
        )
        state_root = ROOT / "tests/development/.state"
        state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=state_root) as temporary:
            work_dir = Path(temporary)
            backend = ComposeBackend(ROOT, work_dir, ScriptedRunner())
            backend._cached_host_root = Path("/host/filebelt")
            backend._write_override(self.session, self.configuration.compose.profiles)
            mapped = backend._resources(self.session, self.configuration)
            environment = backend._environment(mapped, host_paths=True)
            relative_state = Path(mapped["state_dir"]).relative_to(ROOT)
            self.assertEqual(
                environment["FILEBELT_STATE_DIR"], str(Path("/host/filebelt") / relative_state)
            )
            self.assertEqual(
                environment["FILEBELT_POSTGRES_ROLES_FILE"],
                "/host/filebelt/source/migrations/postgres/roles.sql",
            )

    def test_fixture_build_context_is_read_from_the_executor_checkout(self) -> None:
        self.backend._cached_host_root = Path("/host/filebelt")
        self.backend._build_fixtures(self.session, self.session.resources)
        builds = [command for command, _ in self.runner.commands if command[:2] == ("docker", "build")]
        self.assertTrue(builds)
        self.assertEqual(builds[0][-1], str(ROOT / "tests/docker/oidc"))

    def test_state_bind_inputs_are_readable_below_a_private_session(self) -> None:
        self.work_dir.chmod(0o700)
        for directory in (self.work_dir / "state/secrets", self.work_dir / "state/tls"):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            path = directory / "input"
            path.write_text("development-only\n", encoding="utf-8")
            path.chmod(0o600)
        self.backend._make_bind_inputs_readable(self.work_dir)
        self.assertEqual(stat.S_IMODE(self.work_dir.stat().st_mode), 0o700)
        self.assertEqual(
            stat.S_IMODE((self.work_dir / "state/secrets/input").stat().st_mode), 0o644
        )

    def test_external_oidc_bind_inputs_are_staged_for_the_docker_host(self) -> None:
        inputs = self.work_dir / "caller-inputs"
        inputs.mkdir()
        names = (
            "filebelt.toml",
            "filebelt-collaboration.toml",
            "filebelt-mcp.toml",
            "oxibelt.toml",
            "client-secret",
            "ca.crt",
        )
        for name in names:
            (inputs / name).write_text(f"development {name}\n", encoding="utf-8")
        config = self.work_dir / "external.toml"
        config.write_text(
            f'''schema_version = 1
[compose.external_oidc]
network = "filebelt-oidc"
filebelt_config = "{inputs / 'filebelt.toml'}"
collaboration_config = "{inputs / 'filebelt-collaboration.toml'}"
mcp_config = "{inputs / 'filebelt-mcp.toml'}"
edge_config = "{inputs / 'oxibelt.toml'}"
client_secret = "{inputs / 'client-secret'}"
ca_certificate = "{inputs / 'ca.crt'}"
''',
            encoding="utf-8",
        )
        configuration = model.load_configuration(config.resolve())
        session = model.Session.create("external", "compose", REVISION, configuration)
        backend = ComposeBackend(ROOT, self.work_dir, ScriptedRunner())
        backend._cached_host_root = ROOT
        backend._write_override(session, configuration.compose.profiles)
        session.resources = backend._resources(session, configuration)
        backend._stage_external_inputs(session.resources)
        backend._make_bind_inputs_readable(self.work_dir)
        environment = backend._environment(session.resources, host_paths=True)
        self.assertEqual(
            environment["FILEBELT_CONFIG_FILE"],
            str(self.work_dir / "inputs/filebelt.toml"),
        )
        self.assertEqual(
            environment["FILEBELT_OIDC_CLIENT_SECRET_FILE"],
            str(self.work_dir / "secrets/external-oidc-client-secret"),
        )
        self.assertEqual(
            stat.S_IMODE((self.work_dir / "secrets/external-oidc-client-secret").stat().st_mode),
            0o644,
        )

    def test_ownership_manifest_precedes_compose_provisioning(self) -> None:
        session = model.Session.create("durable", "compose", REVISION, self.configuration)
        runner = ScriptedRunner(lambda _command, _keywords: (_ for _ in ()).throw(RuntimeError("stop")))
        backend = ComposeBackend(ROOT, self.work_dir, runner)
        backend._cached_host_root = ROOT
        with mock.patch.object(backend._run_unit, "configure_source_build_cpu"):
            with self.assertRaisesRegex(RuntimeError, "stop"):
                backend.up(session, self.configuration)
        recorded = model.Session.load(self.work_dir / "session.json")
        self.assertEqual(recorded.resources["project"], "filebelt-dev-durable")

    def test_readiness_reports_a_restarting_long_lived_service(self) -> None:
        services = self.backend._long_lived_services(("core",))
        healthy = [
            {"Service": service, "State": "running", "Health": ""}
            for service in services
        ]
        healthy.append(
            {"Service": "filebelt-bootstrap", "State": "exited", "ExitCode": 0}
        )
        self.assertEqual(
            self.backend._readiness(healthy, ("core",)),
            (True, []),
        )
        restarting = [dict(row) for row in healthy]
        next(
            row
            for row in restarting
            if row["Service"] == "filebelt-worker-maintenance"
        )["State"] = "restarting"
        self.assertEqual(
            self.backend._readiness(restarting, ("core",)),
            (False, ["filebelt-worker-maintenance"]),
        )
        unhealthy = [dict(row) for row in healthy]
        next(row for row in unhealthy if row["Service"] == "filebelt-oidc")[
            "Health"
        ] = "unhealthy"
        self.assertEqual(
            self.backend._readiness(unhealthy, ("core",)),
            (False, ["filebelt-oidc"]),
        )

    def test_containerized_port_forward_owns_and_releases_edge_attachment(self) -> None:
        container = "a" * 64
        executor = "b" * 64

        def handler(command, _keywords):
            if "--quiet" in command:
                return container.encode()
            if command[:2] == ("docker", "port"):
                return b"127.0.0.1:8443\n"
            if command[:3] == ("docker", "network", "inspect"):
                return b"{}"
            if command[:4] == ("docker", "inspect", "--format", "{{.Id}}"):
                return executor.encode()
            if command[:2] == ("docker", "inspect"):
                return b"172.27.0.6\n"
            return b""

        class InterruptingBridge:
            def __init__(self, target, port):
                self.target = target
                self.port = port
                self.started = False
                self.stopped = False

            def start(self):
                self.started = True

            def check(self):
                raise KeyboardInterrupt

            def stop(self):
                self.stopped = True

        runner = ScriptedRunner(handler)
        backend = ComposeBackend(ROOT, self.work_dir, runner)
        backend._cached_host_root = ROOT
        backend._tcp_proxy.ManagedTcpBridge = InterruptingBridge
        backend._write_override(self.session, self.configuration.compose.profiles)
        self.session.resources = backend._resources(self.session, self.configuration)
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(
            backend._run_unit, "executor_is_containerized", return_value=True
        ):
            self.assertEqual(backend.port_forward(self.session, 8443), 0)
        commands = [command for command, _ in runner.commands]
        self.assertTrue(any(command[:3] == ("docker", "network", "connect") for command in commands))
        self.assertTrue(
            any(command[:3] == ("docker", "network", "disconnect") for command in commands)
        )
        self.assertTrue(
            all(
                command[-1] == executor
                for command in commands
                if command[:3]
                in {
                    ("docker", "network", "connect"),
                    ("docker", "network", "disconnect"),
                }
            )
        )

    def test_orphaned_bridge_cleanup_matches_executor_container_id(self) -> None:
        executor = "b" * 64

        def handler(command, _keywords):
            if command[:4] == ("docker", "inspect", "--format", "{{.Id}}"):
                return executor.encode()
            if command[:3] == ("docker", "network", "inspect"):
                return json.dumps(
                    {executor: {"Name": "descriptive-devcontainer-name"}}
                ).encode()
            return b""

        runner = ScriptedRunner(handler)
        backend = ComposeBackend(ROOT, self.work_dir, runner)
        backend._disconnect_orphaned_bridge(self.session.resources)
        self.assertIn(
            (
                "docker",
                "network",
                "disconnect",
                "filebelt-dev-example_edge",
                executor,
            ),
            [command for command, _ in runner.commands],
        )

    def test_cleanup_removes_role_and_fixture_images_but_not_artifact_references(self) -> None:
        resources = self.backend._validate_resources(self.session)
        expected = set(resources["role_images"]) | set(resources["fixtures"].values())
        with mock.patch.object(self.backend._run_unit, "docker_host_root", return_value=ROOT):
            environment = self.backend._environment(resources, host_paths=True)
        self.backend._cleanup(self.session, environment)
        removed = {
            command[-1]
            for command, _ in self.runner.commands
            if command[:4] == ("docker", "image", "rm", "--force")
        }
        self.assertEqual(removed, expected)
        self.assertTrue(all(not reference.startswith("ghcr.io/") for reference in removed))

    def test_artifact_input_directory_is_not_a_cleanup_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as artifact_temporary:
            artifact_dir = Path(artifact_temporary)
            config_path = self.work_dir / "artifact.toml"
            config_path.write_text(
                f'''schema_version = 1
[images]
mode = "artifacts"
directory = "{artifact_dir}"
channel = "build"
''',
                encoding="utf-8",
            )
            configuration = model.load_configuration(config_path.resolve())
            session = model.Session.create("artifact", "compose", REVISION, configuration)
            backend = ComposeBackend(ROOT, self.work_dir, ScriptedRunner())
            backend._write_override(session, configuration.compose.profiles)
            session.resources = backend._resources(session, configuration)
        self.assertEqual(backend._validate_resources(session)["artifact_inputs"]["channel"], "build")


class MinikubeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temporary.name) / "session"
        self.work_dir.mkdir()
        self.configuration = model.load_configuration(None)
        self.session = model.Session.create("example", "minikube", REVISION, self.configuration)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_runtime_image_digest_is_resolved_inside_minikube(self) -> None:
        local_ref = "ghcr.io/oxibelt/filebelt-api:development-amd64"
        digest = "sha256:" + "a" * 64

        def handler(command, _keywords):
            if command[-2:] == ("--format", "json"):
                return json.dumps(
                    [
                        {
                            "id": "sha256:" + "b" * 64,
                            "repoDigests": [f"ghcr.io/oxibelt/filebelt-api@{digest}"],
                            "repoTags": [local_ref],
                            "size": "1",
                        }
                    ]
                ).encode()
            return b""

        runner = ScriptedRunner(handler)
        backend = MinikubeBackend(ROOT, self.work_dir, runner)
        resolved = backend._load_images(
            self.session,
            [{"role": "filebelt-api", "archive": "/tmp/api.tar", "local_ref": local_ref}],
        )
        self.assertEqual(resolved, [("ghcr.io", "oxibelt/filebelt-api", digest)])
        self.assertFalse(any("docker" in command[:1] for command, _ in runner.commands))

    def test_values_files_cannot_override_quiescence_or_exact_images(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = root / "values.yaml"
            values.write_text("deployment:\n  quiesced: false\n", encoding="utf-8")
            config = root / "development.toml"
            config.write_text(
                f"""schema_version = 1
[minikube]
values_files = ["{values}"]
[preview]
features = ["documents"]
[[preview.images]]
role = "filebelt-document"
digest = "sha256:{'c' * 64}"
source = "https://example.invalid/source"
license = "Apache-2.0"
""",
                encoding="utf-8",
            )
            configuration = model.load_configuration(config.resolve())
            backend = MinikubeBackend(ROOT, self.work_dir, ScriptedRunner())
            core = [("ghcr.io", f"oxibelt/{role}", "sha256:" + "d" * 64) for role in minikube_backend.CORE_ROLES]
            arguments = backend._values(configuration, core)
            self.assertLess(arguments.index("--values"), arguments.index("deployment.quiesced=true"))
            self.assertIn("documents.enabled=true", arguments)
            digest_setting = f"images.filebelt-document.digest=sha256:{'c' * 64}"
            self.assertIn(digest_setting, arguments)
            self.assertNotIn(
                'images.filebelt-document.source="https://example.invalid/source"',
                arguments,
            )
            self.assertNotIn('images.filebelt-document.license="Apache-2.0"', arguments)

    def test_adapter_preview_passes_chart_source_and_license_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "development.toml"
            config.write_text(
                f'''schema_version = 1
[preview]
[[preview.images]]
role = "filebelt-smb-gateway"
digest = "sha256:{'c' * 64}"
source = "https://example.invalid/smb"
license = "GPL-3.0-or-later"
''',
                encoding="utf-8",
            )
            configuration = model.load_configuration(config.resolve())
            backend = MinikubeBackend(ROOT, self.work_dir, ScriptedRunner())
            core = [
                ("ghcr.io", f"oxibelt/{role}", "sha256:" + "d" * 64)
                for role in minikube_backend.CORE_ROLES
            ]
            arguments = backend._values(configuration, core)
            self.assertIn(
                'images.filebelt-smb-gateway.source="https://example.invalid/smb"',
                arguments,
            )
            self.assertIn(
                'images.filebelt-smb-gateway.license="GPL-3.0-or-later"', arguments
            )

    def test_minikube_ownership_record_is_durable(self) -> None:
        helm = self.work_dir / "helm"
        helm.write_bytes(b"helm")
        backend = MinikubeBackend(ROOT, self.work_dir, ScriptedRunner())
        backend._record(self.session, str(helm))
        recorded = model.Session.load(self.work_dir / "session.json")
        self.assertEqual(
            recorded.resources["minikube"]["profile"], "filebelt-dev-example"
        )

    def test_values_files_reject_common_secret_material(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = root / "values.yaml"
            values.write_text("database_password: exposed\n", encoding="utf-8")
            config = root / "development.toml"
            config.write_text(
                f'schema_version = 1\n[minikube]\nvalues_files = ["{values}"]\n',
                encoding="utf-8",
            )
            configuration = model.load_configuration(config.resolve())
            backend = MinikubeBackend(ROOT, self.work_dir, ScriptedRunner())
            core = [("ghcr.io", f"oxibelt/{role}", "sha256:" + "d" * 64) for role in minikube_backend.CORE_ROLES]
            with self.assertRaisesRegex(model.ConfigurationError, "secret material"):
                backend._values(configuration, core)

    def test_verified_helm_bootstrap_uses_approved_archive_digest(self) -> None:
        executable = b"#!/bin/sh\nexit 0\n"
        archive_buffer = io.BytesIO()
        with tarfile.open(fileobj=archive_buffer, mode="w:gz") as archive:
            member = tarfile.TarInfo("linux-amd64/helm")
            member.mode = 0o755
            member.size = len(executable)
            archive.addfile(member, io.BytesIO(executable))
        archive_bytes = archive_buffer.getvalue()

        def handler(command, _keywords):
            if len(command) > 1 and command[1] == "version":
                return b"v4.2.4"
            return b""

        backend = MinikubeBackend(ROOT, self.work_dir, ScriptedRunner(handler))
        response = io.BytesIO(archive_bytes)
        with mock.patch.object(
            minikube_backend.platform, "machine", return_value="x86_64"
        ), mock.patch.object(
            minikube_backend.platform, "system", return_value="Linux"
        ), mock.patch.object(
            minikube_backend.urllib.request, "urlopen", return_value=response
        ), mock.patch.dict(
            minikube_backend.HELM_CHECKSUMS,
            {"amd64": hashlib.sha256(archive_bytes).hexdigest()},
        ):
            helm = backend._bootstrap_helm(self.session)
        self.assertEqual(helm.read_bytes(), executable)
        self.assertEqual(stat.S_IMODE(helm.stat().st_mode), 0o700)

    def test_prerequisite_manifest_rejects_secret_or_unowned_object(self) -> None:
        backend = MinikubeBackend(ROOT, self.work_dir, ScriptedRunner())
        with self.assertRaisesRegex(model.ConfigurationError, "forbidden"):
            backend._validate_manifest_item(
                self.session,
                {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "filebelt-secret"}},
            )
        with self.assertRaisesRegex(model.ConfigurationError, "development-session label"):
            backend._validate_manifest_item(
                self.session,
                {
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {"name": "filebelt-config", "namespace": "filebelt-preview"},
                },
            )
        backend._validate_manifest_item(
            self.session,
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "filebelt-development-configuration-with-a-long-name",
                    "namespace": "filebelt-preview",
                    "labels": {"filebelt.dev/development-session": "example"},
                },
            },
        )
        with self.assertRaisesRegex(model.ConfigurationError, "cluster-internal"):
            backend._validate_manifest_item(
                self.session,
                {
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": {
                        "name": "filebelt-preview",
                        "namespace": "filebelt-preview",
                        "labels": {"filebelt.dev/development-session": "example"},
                    },
                    "spec": {"type": "NodePort"},
                },
            )
        with self.assertRaisesRegex(model.ConfigurationError, "restricted Pod Security"):
            backend._validate_manifest_item(
                self.session,
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {
                        "name": "filebelt-preview",
                        "labels": {"filebelt.dev/development-session": "example"},
                    },
                },
            )

    def test_preview_secret_bytes_travel_only_on_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret = root / "tls.key"
            secret.write_bytes(b"private-development-bytes")
            config = root / "development.toml"
            config.write_text(
                f"""schema_version = 1
[preview]
[[preview.secrets]]
namespace = "core"
name = "filebelt-preview-tls"
key = "tls.key"
path = "{secret}"
""",
                encoding="utf-8",
            )
            configuration = model.load_configuration(config.resolve())
            runner = ScriptedRunner()
            backend = MinikubeBackend(ROOT, self.work_dir, runner)
            backend._copy_preview_secrets(self.session, configuration)
            command, input_data = runner.commands[-1]
            self.assertNotIn("private-development-bytes", " ".join(command))
            self.assertIn(base64_value := "cHJpdmF0ZS1kZXZlbG9wbWVudC1ieXRlcw==", input_data.decode())
            self.assertNotEqual(base64_value, "private-development-bytes")

    def test_down_deletes_the_owned_profile_without_requiring_cached_helm(self) -> None:
        profile = "filebelt-dev-example"

        def handler(command, _keywords):
            if command[:4] == ("minikube", "profile", "list", "--output"):
                return json.dumps({"valid": [{"Name": profile}]}).encode()
            return b""

        runner = ScriptedRunner(handler)
        backend = MinikubeBackend(ROOT, self.work_dir, runner)
        self.session.resources["minikube"] = {
            "profile": profile,
            "namespace": profile,
            "release": "filebelt-dev",
        }
        backend.down(self.session)
        commands = [command for command, _ in runner.commands]
        self.assertTrue(any("delete" in command for command in commands))
        self.assertFalse(any("helm" in command[0] for command in commands))

    def test_quiesced_preview_rejects_serving_operations(self) -> None:
        self.session.phase = "quiesced"
        backend = MinikubeBackend(ROOT, self.work_dir, ScriptedRunner())
        with self.assertRaisesRegex(model.ConfigurationError, "no serving endpoint"):
            backend.port_forward(self.session, 8443)
        with self.assertRaisesRegex(model.ConfigurationError, "use diagnose"):
            backend.logs(self.session, "web", 20)


class LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = model.prepare_root(Path(self.temporary.name) / "development")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def arguments(self, **updates: object) -> Namespace:
        values: dict[str, object] = {
            "name": "example",
            "topology": "compose",
            "config": None,
        }
        values.update(updates)
        return Namespace(**values)

    def test_up_records_non_qualifying_running_session(self) -> None:
        backend = FakeBackend()
        output = io.StringIO()
        with mock.patch.object(helper, "source_revision", return_value=REVISION), mock.patch.object(
            helper, "backend_for", return_value=backend
        ), contextlib.redirect_stdout(output):
            self.assertEqual(helper.command_up(self.arguments(), self.root, mock.Mock()), 0)
        session = model.Session.load(model.session_manifest(self.root, "example"))
        self.assertEqual(session.phase, "running")
        self.assertFalse(json.loads(output.getvalue())["accepted"])

    def test_failed_up_retains_only_scrubbed_diagnostics_and_cleans_owned_session(self) -> None:
        backend = FakeBackend(fail_up=True)
        with mock.patch.object(helper, "source_revision", return_value=REVISION), mock.patch.object(
            helper, "backend_for", return_value=backend
        ):
            with self.assertRaisesRegex(RuntimeError, "scrubbed diagnostics"):
                helper.command_up(self.arguments(), self.root, mock.Mock())
        self.assertEqual(backend.down_calls, 1)
        self.assertFalse(model.session_directory(self.root, "example").exists())
        retained = b"\n".join(path.read_bytes() for path in (self.root / "diagnostics/example").rglob("*.txt"))
        self.assertNotIn(b"development-secret", retained)
        self.assertNotIn(b"bearer-value", retained)

    def test_cleanup_failure_retains_retryable_manifest(self) -> None:
        backend = FakeBackend(fail_up=True, fail_down=True)
        with mock.patch.object(helper, "source_revision", return_value=REVISION), mock.patch.object(
            helper, "backend_for", return_value=backend
        ):
            with self.assertRaises(RuntimeError):
                helper.command_up(self.arguments(), self.root, mock.Mock())
        session = model.Session.load(model.session_manifest(self.root, "example"))
        self.assertEqual(session.phase, "cleanup-failed")
        self.assertEqual(session.qualification["cleanupError"], "RuntimeError")


if __name__ == "__main__":
    unittest.main()
