#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Render and validate the Phase 5 Docker trust and mount boundaries."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "deploy/compose/compose.yaml"
MCP_COMPOSE = ROOT / "deploy/compose/compose.mcp.yaml"
PREPARE = ROOT / "deploy/compose/prepare-state.sh"
POSTGRES_18_6 = (
    "docker.io/library/postgres@"
    "sha256:ae6c78831cbc35fa3a4aaf4d763ddacf6183d6004774cc2dc28b3920410d1d1a"
)
IGGY = (
    "docker.io/apache/iggy@"
    "sha256:99b42016a898381d4bab3c2d4613456eb04ad06a7a0688314823d798a685636b"
)


def targets(entries: Any, kind: str) -> set[str]:
    if not isinstance(entries, list):
        return set()
    return {
        str(entry.get("target"))
        for entry in entries
        if isinstance(entry, dict) and entry.get("type", kind) == kind
    }


def secret_sources(service: dict[str, Any]) -> set[str]:
    return {
        str(entry["source"])
        for entry in service.get("secrets", [])
        if isinstance(entry, dict) and "source" in entry
    }


def main() -> int:
    for test in (
        ROOT / "tests/docker/mcp-egress/policy.test.mjs",
        ROOT / "tests/docker/oidc/relay.test.mjs",
    ):
        subprocess.run(["node", "--test", str(test)], cwd=ROOT, check=True)
    configurations = {}
    for path in (
        ROOT / "deploy/compose/filebelt.toml",
        ROOT / "deploy/compose/filebelt-mcp.toml",
        ROOT / "deploy/compose/filebelt-collaboration.toml",
        ROOT / "ui/web/edge/oxibelt.toml",
    ):
        with path.open("rb") as source:
            configurations[path.name] = tomllib.load(source)
    for name in ("filebelt.toml", "filebelt-mcp.toml"):
        collaboration_settings = configurations[name]["collaboration"]
        assert collaboration_settings["enabled"] is True, name
        signing = collaboration_settings["capability_signing"]
        assert signing["current_generation"] == 1, name
        assert signing["public_keyset_file"].endswith(
            "collaboration-storage-capability-public-keyset"
        ), name
        assert collaboration_settings["io_url"] == "http://filebelt-worker-io:8081/", name
    integration_profile = configurations["filebelt-mcp.toml"]["mcp"]["trust_profiles"]["integration"]
    assert integration_profile == {
        "public_webpki": True,
        "hosts": ["filebelt-mcp-integration.example.test"],
        "ports": [443],
    }
    with tempfile.TemporaryDirectory(prefix="filebelt-phase2-compose-") as directory:
        state = Path(directory) / "state"
        environment = {**os.environ, "FILEBELT_STATE_DIR": str(state)}
        environment.pop("FILEBELT_HTTPS_BIND_ADDRESS", None)
        environment.pop("FILEBELT_HTTPS_PORT", None)
        subprocess.run([str(PREPARE)], cwd=ROOT, env=environment, check=True)
        purposes = {
            "api-storage": "api-storage",
            "api-collaboration-grant": "api-collaboration-grant",
            "api-mcp-delegation": "api-mcp-delegation",
            "collaboration-storage": "collaboration-storage",
            "media-storage": "media-storage",
        }
        public_keys: set[str] = set()
        for purpose, name in purposes.items():
            lines = (
                state / "secrets" / f"{name}-capability-public-keyset"
            ).read_text(encoding="utf-8").splitlines()
            assert lines[0] == "filebelt-capability-keyset-v2", purpose
            assert lines[1] == f"purpose={purpose}", purpose
            assert lines[2].startswith("1:"), purpose
            assert len(lines) == 3, purpose
            public_keys.add(lines[2])
        assert len(public_keys) == len(purposes), "public key bytes must be disjoint"
        base_rendered = subprocess.run(
            [
                "docker",
                "compose",
                "--file",
                str(COMPOSE),
                "--profile",
                "core",
                "config",
                "--format",
                "json",
            ],
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        compose_config_command = [
            "docker",
            "compose",
            "--file",
            str(COMPOSE),
            "--file",
            str(MCP_COMPOSE),
            "--profile",
            "core",
            "--profile",
            "iggy",
            "--profile",
            "fault",
            "--profile",
            "mcp",
            "config",
            "--format",
            "json",
        ]
        rendered = subprocess.run(
            compose_config_command,
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        outside_rendered = subprocess.run(
            compose_config_command,
            cwd=ROOT,
            env={**environment, "FILEBELT_HTTPS_PORT": "49152-65535"},
            check=True,
            capture_output=True,
            text=True,
        )

    base_model = json.loads(base_rendered.stdout)
    assert secret_sources(base_model["services"]["filebelt-api"]) == {
        "api-database-url",
        "oidc-client-secret",
        "api-storage-capability-private-key",
        "api-storage-capability-public-keyset",
        "api-collaboration-grant-capability-private-key",
        "api-collaboration-grant-capability-public-keyset",
        "digest-key",
    }
    model = json.loads(rendered.stdout)
    services = model["services"]
    outside_services = json.loads(outside_rendered.stdout)["services"]
    assert model["networks"]["acceptance-publication"].get("internal", False) is False
    assert model["networks"]["control"]["internal"] is True
    assert model["networks"]["edge"]["internal"] is True
    assert model["networks"]["internet-egress"].get("internal", False) is False
    for name in ("postgres", "postgres-migrator-role", "postgres-runtime-roles"):
        assert services[name]["image"] == POSTGRES_18_6, name
    assert services["postgres"]["user"] == "999:999"
    assert services["postgres-runtime-roles"]["user"] == "999:999"
    assert services["filebelt-iggy"]["image"] == IGGY

    hardened = {
        "filebelt-acceptance-relay",
        "filebelt-api",
        "filebelt-bootstrap",
        "filebelt-migrate",
        "filebelt-payload-init",
        "filebelt-web",
        "filebelt-worker-io",
        "filebelt-worker-maintenance",
        "filebelt-io-database-unavailable",
        "filebelt-mcp-broker",
        "filebelt-collaboration",
        "filebelt-mcp-egress",
    }
    for name in hardened:
        service = services[name]
        assert service["user"] == "10001:10001", name
        assert service["read_only"] is True, name
        assert service["cap_drop"] == ["ALL"], name
        assert "no-new-privileges:true" in service["security_opt"], name
        assert service["pids_limit"] == 256, name

    api = services["filebelt-api"]
    io = services["filebelt-worker-io"]
    maintenance = services["filebelt-worker-maintenance"]
    broker = services["filebelt-mcp-broker"]
    collaboration = services["filebelt-collaboration"]
    gateway = services["filebelt-mcp-egress"]
    relay = services["filebelt-acceptance-relay"]
    web = services["filebelt-web"]
    assert not api.get("volumes"), "the API must not mount payload storage"
    assert targets(io.get("volumes"), "volume") == {"/var/lib/filebelt/payloads"}
    assert targets(maintenance.get("volumes"), "volume") == {"/var/lib/filebelt/payloads"}
    assert set(api["networks"]) == {"control", "edge"}
    assert set(io["networks"]) == {"control", "edge"}
    assert set(maintenance["networks"]) == {"control"}
    assert set(relay["networks"]) == {"acceptance-publication", "edge"}
    assert set(web["networks"]) == {"edge"}
    assert set(broker["networks"]) == {"control"}
    assert set(collaboration["networks"]) == {"control", "edge"}
    assert set(gateway["networks"]) == {"control", "internet-egress"}
    assert not broker.get("volumes"), "the MCP broker must not mount payload storage"
    assert not collaboration.get("volumes"), "collaboration must not mount payload storage"
    assert not gateway.get("volumes"), "the egress gateway must not mount payload storage"
    assert not relay.get("volumes"), "the acceptance relay must not mount storage"
    assert not relay.get("secrets"), "the acceptance relay must not mount secrets"
    assert not relay.get("configs"), "the acceptance relay must not mount configs"
    assert relay["image"] == services["filebelt-oidc"]["image"]
    assert relay["entrypoint"] == ["node", "/opt/filebelt-oidc/relay.mjs"]
    assert relay["depends_on"]["filebelt-web"]["condition"] == "service_started"
    assert gateway["environment"] == {"FILEBELT_MCP_INTEGRATION_HOST": ""}
    assert not web.get("volumes")
    assert secret_sources(web) == {
        "filebelt-tls-certificate",
        "filebelt-tls-private-key",
    }
    assert targets(web.get("configs"), "config") == {
        "/etc/oxibelt/config/oxibelt.toml"
    }

    assert secret_sources(api) == {
        "api-database-url",
        "oidc-client-secret",
        "api-storage-capability-private-key",
        "api-storage-capability-public-keyset",
        "api-collaboration-grant-capability-private-key",
        "api-collaboration-grant-capability-public-keyset",
        "api-mcp-delegation-capability-private-key",
        "api-mcp-delegation-capability-public-keyset",
        "digest-key",
    }
    assert secret_sources(io) == {
        "io-database-url",
        "api-storage-capability-public-keyset",
        "collaboration-storage-capability-public-keyset",
    }
    assert secret_sources(maintenance) == {"maintenance-database-url"}
    assert secret_sources(broker) == {
        "mcp-database-url",
        "mcp-vault-keyring",
        "api-mcp-delegation-capability-public-keyset",
        "mcp-egress-client-certificate",
        "mcp-egress-client-private-key",
        "mcp-egress-ca-certificate",
    }
    broker_vault_secret = next(
        secret
        for secret in broker["secrets"]
        if isinstance(secret, dict) and secret["source"] == "mcp-vault-keyring"
    )
    assert broker_vault_secret["target"] == "/run/secrets/mcp-vault-keyring.json"
    assert broker_vault_secret["mode"] == "0400"
    assert secret_sources(collaboration) == {
        "collaboration-database-url",
        "collaboration-storage-capability-private-key",
        "collaboration-storage-capability-public-keyset",
        "api-storage-capability-public-keyset",
        "api-collaboration-grant-capability-public-keyset",
    }
    collaboration_config = next(
        config
        for config in collaboration["configs"]
        if config["target"] == "/etc/filebelt/filebelt.toml"
    )
    assert collaboration_config["source"] == "filebelt-collaboration-config"
    assert collaboration["profiles"] == ["core"]
    assert collaboration["expose"] == ["8085", "9090"]
    assert all(
        not str(port).endswith("/udp")
        for service in services.values()
        for port in service.get("ports", []) + service.get("expose", [])
    )
    assert secret_sources(gateway) == {
        "mcp-egress-server-certificate",
        "mcp-egress-server-private-key",
        "mcp-egress-ca-certificate",
    }

    for name, service in services.items():
        if name != "filebelt-mcp-egress":
            assert "internet-egress" not in service.get("networks", {}), name
        if name != "filebelt-acceptance-relay":
            assert "acceptance-publication" not in service.get("networks", {}), name

    for name, service in services.items():
        if name != "filebelt-acceptance-relay":
            assert not service.get("ports"), f"service {name} publishes a host port"
    assert relay["ports"] == [
        {
            "mode": "ingress",
            "host_ip": "127.0.0.1",
            "target": 8443,
            "published": "8443",
            "protocol": "tcp",
        }
    ]
    for name, service in outside_services.items():
        if name != "filebelt-acceptance-relay":
            assert not service.get("ports"), (
                f"outside service {name} publishes a host port"
            )
    assert outside_services["filebelt-acceptance-relay"]["ports"] == [
        {
            "mode": "ingress",
            "host_ip": "127.0.0.1",
            "target": 8443,
            "published": "49152-65535",
            "protocol": "tcp",
        }
    ]

    iggy = services["filebelt-iggy"]
    assert iggy["cap_add"] == ["SYS_NICE"]
    assert "seccomp:unconfined" in iggy["security_opt"]
    for name, service in services.items():
        if name != "filebelt-iggy":
            assert "SYS_NICE" not in service.get("cap_add", []), name
            assert "seccomp:unconfined" not in service.get("security_opt", []), name
    assert services["filebelt-io-database-unavailable"]["network_mode"] == "none"

    print("Phase 5 Compose contract is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
