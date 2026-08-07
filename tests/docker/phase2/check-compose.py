#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Render and validate the Phase 4 Docker trust and mount boundaries."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "deploy/compose/compose.yaml"
PREPARE = ROOT / "deploy/compose/prepare-state.sh"
POSTGRES = (
    "docker.io/library/postgres@"
    "sha256:d129b9577d274bb96cbd44d902bdeb1b935c89247d161241e9154cba64e13df4"
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
    subprocess.run(
        ["node", "--test", str(ROOT / "tests/docker/mcp-egress/policy.test.mjs")],
        cwd=ROOT,
        check=True,
    )
    with tempfile.TemporaryDirectory(prefix="filebelt-phase2-compose-") as directory:
        state = Path(directory) / "state"
        environment = {**os.environ, "FILEBELT_STATE_DIR": str(state)}
        subprocess.run([str(PREPARE)], cwd=ROOT, env=environment, check=True)
        rendered = subprocess.run(
            [
                "docker",
                "compose",
                "--file",
                str(COMPOSE),
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
            ],
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )

    model = json.loads(rendered.stdout)
    services = model["services"]
    assert model["networks"]["control"]["internal"] is True
    assert model["networks"]["edge"]["internal"] is True
    assert model["networks"]["internet-egress"].get("internal", False) is False
    assert services["postgres"]["image"] == POSTGRES
    assert services["postgres-runtime-roles"]["image"] == POSTGRES
    assert services["postgres"]["user"] == "999:999"
    assert services["postgres-runtime-roles"]["user"] == "999:999"
    assert services["filebelt-iggy"]["image"] == IGGY

    hardened = {
        "filebelt-api",
        "filebelt-bootstrap",
        "filebelt-migrate",
        "filebelt-payload-init",
        "filebelt-web",
        "filebelt-worker-io",
        "filebelt-worker-maintenance",
        "filebelt-io-database-unavailable",
        "filebelt-mcp-broker",
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
    gateway = services["filebelt-mcp-egress"]
    web = services["filebelt-web"]
    assert not api.get("volumes"), "the API must not mount payload storage"
    assert targets(io.get("volumes"), "volume") == {"/var/lib/filebelt/payloads"}
    assert targets(maintenance.get("volumes"), "volume") == {"/var/lib/filebelt/payloads"}
    assert set(api["networks"]) == {"control", "edge"}
    assert set(io["networks"]) == {"control", "edge"}
    assert set(maintenance["networks"]) == {"control"}
    assert set(web["networks"]) == {"edge"}
    assert set(broker["networks"]) == {"control"}
    assert set(gateway["networks"]) == {"control", "internet-egress"}
    assert not broker.get("volumes"), "the MCP broker must not mount payload storage"
    assert not gateway.get("volumes"), "the egress gateway must not mount payload storage"
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
        "capability-private-key",
        "capability-public-keyset",
        "digest-key",
    }
    assert secret_sources(io) == {"io-database-url", "capability-public-keyset"}
    assert secret_sources(maintenance) == {"maintenance-database-url"}
    assert secret_sources(broker) == {
        "mcp-database-url",
        "mcp-vault-keyring",
        "capability-public-keyset",
        "mcp-egress-client-certificate",
        "mcp-egress-client-private-key",
        "mcp-egress-ca-certificate",
    }
    assert secret_sources(gateway) == {
        "mcp-egress-server-certificate",
        "mcp-egress-server-private-key",
        "mcp-egress-ca-certificate",
    }

    for name, service in services.items():
        if name != "filebelt-mcp-egress":
            assert "internet-egress" not in service.get("networks", {}), name

    for name, service in services.items():
        if name != "filebelt-web":
            assert not service.get("ports"), f"backend service {name} publishes a host port"
    assert web["ports"] == [
        {
            "mode": "ingress",
            "host_ip": "127.0.0.1",
            "target": 8443,
            "published": "8443",
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

    print("Phase 4 Compose contract is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
