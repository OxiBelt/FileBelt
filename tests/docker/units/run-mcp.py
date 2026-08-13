#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Exercise the bounded Compose MCP broker and synthetic hostile egress path."""

from __future__ import annotations

import importlib.util
import json
import sys
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
ACCEPTANCE = ROOT / "tests/docker/phase2/acceptance.py"
SPEC = importlib.util.spec_from_file_location("filebelt_phase2_acceptance", ACCEPTANCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the core acceptance helpers")
CORE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CORE
SPEC.loader.exec_module(CORE)

ORIGIN = CORE.ORIGIN
INTEGRATION_HOST = "filebelt-mcp-integration.example.test"
ATTACHMENT_POLICY = {
    "allowed_mime_patterns": ["text/plain"],
    "allowed_encodings": ["utf8"],
    "max_attachments": 0,
    "max_item_bytes": 0,
    "max_total_bytes": 0,
}


def request_json(
    browser: Any,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    expected: int = 200,
    etag: str | None = None,
) -> tuple[Any, Any]:
    headers = {"Accept": "application/json"}
    encoded = None
    if body is not None:
        encoded = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    if method not in {"GET", "HEAD"}:
        headers.update({
            "Idempotency-Key": str(uuid.uuid4()),
            "Origin": ORIGIN,
            "Sec-Fetch-Site": "same-origin",
            "X-FileBelt-Csrf": browser.csrf,
        })
    if etag is not None:
        headers["If-Match"] = etag
    result = browser.request(method, f"/api/v1{path}", body=encoded, headers=headers)
    CORE.expect(result, expected, f"{method} {path}")
    content_type = result.headers.get("Content-Type", "")
    value = None if not result.body or content_type.startswith("application/x-ndjson") else json.loads(result.body)
    return result, value


def create_registration(
    browser: Any,
    path: str,
    *,
    profile: str = "integration",
    name: str = "Integration MCP",
    provision_credential: bool = True,
) -> tuple[dict[str, Any], str]:
    result, value = request_json(
        browser,
        "POST",
        "/mcp/registrations",
        {
            "display_name": name,
            "description": "Synthetic Docker integration fixture",
            "transport": "streamable_http",
            "endpoint_uri": f"https://{INTEGRATION_HOST}{path}" if profile == "integration" else path,
            "catalog_entry_id": None,
            "trust_profile": profile,
            "attachment_policy": ATTACHMENT_POLICY,
        },
        expected=201,
    )
    assert isinstance(value, dict)
    etag = result.headers["ETag"]
    if provision_credential:
        request_json(
            browser,
            "PUT",
            f"/mcp/registrations/{value['id']}/credentials",
            {"kind": "bearer", "secret": "filebelt-mcp-integration"},
            expected=204,
            etag=etag,
        )
        refreshed_result, value = request_json(
            browser, "GET", f"/mcp/registrations/{value['id']}"
        )
        assert isinstance(value, dict)
        etag = refreshed_result.headers["ETag"]
    return value, etag


def probe_failure(
    browser: Any,
    endpoint: str,
    name: str,
    *,
    operation: str = "test",
    profile: str = "integration",
) -> None:
    registration, etag = create_registration(browser, endpoint, profile=profile, name=name)
    _, failure = request_json(
        browser,
        "POST",
        f"/mcp/registrations/{registration['id']}/{operation}",
        expected=503,
        etag=etag,
    )
    assert failure["code"] == "mcp.broker.unavailable"


def exercise() -> None:
    admin = CORE.Browser()
    member = CORE.Browser()
    CORE.wait_api(admin)
    admin.login("admin")
    member.login("member")

    registration, etag = create_registration(admin, "/mcp")
    registration_id = registration["id"]
    _, member_denied = request_json(member, "GET", f"/mcp/registrations/{registration_id}", expected=404)
    assert member_denied["code"] == "resource.not_found"

    tested_result, tested = request_json(admin, "POST", f"/mcp/registrations/{registration_id}/test", etag=etag)
    assert tested["succeeded"] is True
    assert tested["protocol_version"] == "2026-07-28"
    etag = tested_result.headers["ETag"]

    _, snapshot = request_json(
        admin, "POST", f"/mcp/registrations/{registration_id}/discover", etag=etag
    )
    assert [item["name"] for item in snapshot["capabilities"]] == ["echo"]
    capability = snapshot["capabilities"][0]
    # Discovery advances the persisted registration revision as it installs
    # the new snapshot. Refresh the registration generation before review.
    refreshed_result, _ = request_json(
        admin, "GET", f"/mcp/registrations/{registration_id}"
    )
    etag = refreshed_result.headers["ETag"]
    reviewed_result, review = request_json(
        admin,
        "PUT",
        f"/mcp/registrations/{registration_id}/capability-review",
        {
            "snapshot_id": snapshot["id"],
            "snapshot_fingerprint": snapshot["fingerprint"],
            "decisions": [{"capability_fingerprint": capability["fingerprint"], "decision": "approved"}],
        },
        etag=etag,
    )
    assert review["decisions"] == [{"capability_fingerprint": capability["fingerprint"], "decision": "approved"}]
    etag = reviewed_result.headers["ETag"]
    enabled_result, enabled = request_json(admin, "POST", f"/mcp/registrations/{registration_id}/state", {"action": "enable"}, etag=etag)
    assert enabled["lifecycle_state"] == "enabled"
    etag = enabled_result.headers["ETag"]

    invocation = {
        "application_id": "filebelt.docker.integration",
        "registration_id": registration_id,
        "capability": {"kind": "tool", "name": "echo", "fingerprint": capability["fingerprint"]},
        "arguments": {"message": "bounded"},
        "attachments": [],
    }
    request_json(member, "POST", "/mcp/invocation-intents", invocation, expected=404)
    _, intent = request_json(admin, "POST", "/mcp/invocation-intents", invocation, expected=201)
    request_json(admin, "POST", f"/mcp/invocation-intents/{intent['id']}/approval", {"scope": "once", "expires_at": None}, expected=201)
    stream, _ = request_json(admin, "POST", f"/mcp/invocation-intents/{intent['id']}/stream", invocation)
    events = [json.loads(line) for line in stream.body.splitlines()]
    assert [event["event"] for event in events] == ["started", "json", "completed"]
    assert events[1]["json"]["content"][0]["text"] == "bounded integration result"
    request_json(
        admin,
        "POST",
        f"/mcp/invocation-intents/{intent['id']}/stream",
        invocation,
        expected=404,
    )

    _, changed_intent = request_json(admin, "POST", "/mcp/invocation-intents", invocation, expected=201)
    changed = {**invocation, "arguments": {"message": "changed"}}
    request_json(
        admin,
        "POST",
        f"/mcp/invocation-intents/{changed_intent['id']}/stream",
        changed,
        expected=404,
    )

    revoked_result, revoked = request_json(admin, "POST", f"/mcp/registrations/{registration_id}/state", {"action": "revoke"}, etag=etag)
    assert revoked["lifecycle_state"] != "enabled"
    assert revoked_result.headers["ETag"] != etag
    request_json(
        admin, "POST", "/mcp/invocation-intents", invocation, expected=404
    )

    probe_failure(admin, "/redirect", "Redirect refusal")
    probe_failure(admin, "/malformed", "Malformed response")
    probe_failure(admin, "/oversized", "Oversized response")
    probe_failure(admin, "/slow", "Slow response")
    # Discovery performs another request after initialization. The fixture
    # accepts session A, injects session B on the initialized notification,
    # and proves that the subsequent request cannot complete under B.
    probe_failure(admin, "/session-confusion", "Session confusion", operation="discover")
    probe_failure(admin, "https://127.0.0.1/mcp", "Private address refusal", profile="public")
    probe_failure(admin, "https://localhost/mcp", "DNS rebinding refusal", profile="public")

    credential, credential_etag = create_registration(
        admin,
        "/credential",
        name="Credential isolation",
        provision_credential=False,
    )
    secret = f"fixture-secret-{uuid.uuid4()}"
    request_json(admin, "PUT", f"/mcp/registrations/{credential['id']}/credentials", {"kind": "bearer", "secret": secret}, expected=204, etag=credential_etag)
    credential_result, redacted = request_json(admin, "GET", f"/mcp/registrations/{credential['id']}")
    assert secret.encode() not in credential_result.body
    assert redacted["credential_present"] is True
    request_json(admin, "POST", f"/mcp/registrations/{credential['id']}/test", expected=503, etag=credential_result.headers["ETag"])

    print("MCP Docker acceptance passed: authority, intent/approval, replay, revocation, hostile synthetic egress, and credential isolation")


if __name__ == "__main__":
    exercise()
