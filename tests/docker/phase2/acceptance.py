#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Exercise the Phase 2 two-user vertical slice through the Docker TLS edge."""

from __future__ import annotations

import argparse
import concurrent.futures
import http.cookiejar
import json
import os
import re
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "deploy/compose/compose.yaml"
ORIGIN = "https://filebelt.localhost:8443"
CONNECT_HOST = os.environ.get("FILEBELT_ACCEPTANCE_CONNECT_HOST")
UUID_V4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

if CONNECT_HOST:
    _system_getaddrinfo = socket.getaddrinfo

    def _acceptance_getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> Any:
        target = CONNECT_HOST if host == "filebelt.localhost" else host
        return _system_getaddrinfo(target, port, *args, **kwargs)

    socket.getaddrinfo = _acceptance_getaddrinfo


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


@dataclass(frozen=True)
class HttpResult:
    status: int
    headers: Any
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)


class Browser:
    def __init__(self) -> None:
        self.cookies = http.cookiejar.CookieJar()
        tls = ssl.create_default_context()
        tls.check_hostname = False
        tls.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=tls),
            urllib.request.HTTPCookieProcessor(self.cookies),
            NoRedirect(),
        )
        self.csrf = ""

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResult:
        url = path_or_url if path_or_url.startswith("https://") else f"{ORIGIN}{path_or_url}"
        request = urllib.request.Request(
            url,
            data=body,
            headers=headers or {},
            method=method,
        )
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            return HttpResult(error.code, error.headers, error.read())
        with response:
            return HttpResult(response.status, response.headers, response.read())

    def login(self, fixture_user: str) -> dict[str, Any]:
        login = self.request("GET", "/api/v1/auth/login?return_path=%2F")
        expect(login, 303, "begin OIDC login")
        cookie_names = {cookie.name for cookie in self.cookies}
        if "filebelt_oidc_attempt" not in cookie_names:
            fail(
                "begin OIDC login did not store the attempt cookie; "
                f"stored cookie names: {sorted(cookie_names)}"
            )
        authorization = login.headers["Location"]
        parsed = urllib.parse.urlsplit(authorization)
        parameters = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        parameters.append(("fixture_user", fixture_user))
        authorization = urllib.parse.urlunsplit(
            (*parsed[:3], urllib.parse.urlencode(parameters), parsed.fragment)
        )
        consent = self.request("GET", authorization)
        expect(consent, 303, "complete fixture authorization")
        callback = self.request("GET", consent.headers["Location"])
        expect(callback, 303, "exchange OIDC code")
        session = self.api("GET", "/session")
        self.csrf = str(session["csrf_token"])
        return session

    def api(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        expected: int = 200,
        idempotent: bool = False,
    ) -> Any:
        headers: dict[str, str] = {"Accept": "application/json"}
        encoded = None
        if body is not None:
            encoded = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        if method not in {"GET", "HEAD"}:
            headers.update(
                {
                    "Origin": ORIGIN,
                    "Sec-Fetch-Site": "same-origin",
                    "X-FileBelt-Csrf": self.csrf,
                }
            )
        if idempotent:
            headers["Idempotency-Key"] = str(uuid.uuid4())
        result = self.request(method, f"/api/v1{path}", body=encoded, headers=headers)
        expect(result, expected, f"{method} {path}")
        if result.status == 204 or not result.body:
            return None
        return result.json()


def expect(result: HttpResult, status: int, operation: str) -> None:
    if result.status != status:
        detail = result.body.decode(errors="replace")[:1_000]
        raise AssertionError(f"{operation}: expected {status}, got {result.status}: {detail}")


def compose(*arguments: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "compose",
            "--file",
            str(COMPOSE),
            "--profile",
            "core",
            *arguments,
        ],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=capture,
    )


def wait_api(browser: Browser) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            result = browser.request("GET", "/api/v1/session")
        except urllib.error.URLError:
            time.sleep(0.5)
            continue
        if result.status in {200, 401}:
            return
        time.sleep(0.5)
    raise AssertionError("FileBelt API did not become ready")


def retry_request(
    browser: Browser,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    expected: int = 200,
) -> HttpResult:
    deadline = time.monotonic() + 60
    last: HttpResult | None = None
    while time.monotonic() < deadline:
        last = browser.request(method, path, body=body, headers=headers)
        if last.status == expected:
            return last
        if last.status not in {502, 503, 504}:
            break
        time.sleep(0.5)
    if last is None:
        raise AssertionError("request was not attempted")
    expect(last, expected, f"retry {method} {path}")
    return last


def private_drive(browser: Browser) -> dict[str, Any]:
    page = browser.api("GET", "/drives?limit=200")
    return next(item for item in page["items"] if item["kind"] == "private")


def upload(
    browser: Browser,
    drive: dict[str, Any],
    name: str,
    content: bytes,
    *,
    node_id: str | None = None,
    expected_head: str | None = None,
    restart_io: bool = False,
    restart_api: bool = False,
    competing_finalize: bool = False,
) -> dict[str, str]:
    expected_parent_generation = None
    if node_id is None:
        parent = browser.api(
            "GET", f"/drives/{drive['id']}/nodes/{drive['root_id']}"
        )
        expected_parent_generation = parent["namespace_generation"]
    allocation = browser.api(
        "POST",
        f"/drives/{drive['id']}/uploads",
        {
            "declared_size_bytes": len(content),
            "expected_head_version_id": expected_head,
            "expected_parent_generation": expected_parent_generation,
            "name": name,
            "node_id": node_id,
            "parent_id": drive["root_id"],
        },
        expected=201,
        idempotent=True,
    )
    expected_part_count = (
        1
        if len(content) <= 33_554_432
        else (len(content) + allocation["chunk_size_bytes"] - 1)
        // allocation["chunk_size_bytes"]
    )
    assert allocation["part_count"] == expected_part_count
    grants = browser.api("GET", allocation["grants_url"].removeprefix("/api/v1"))
    assert len(grants["parts"]) == expected_part_count
    for grant in grants["parts"]:
        part_number = int(grant["path"].rsplit("/", 1)[1])
        if expected_part_count == 1:
            part = content
        else:
            start = part_number * allocation["chunk_size_bytes"]
            part = content[start : start + allocation["chunk_size_bytes"]]
        receipt = retry_request(
            browser,
            "PUT",
            grant["path"],
            body=part,
            headers={
                "Authorization": f"fbcap1 {grant['authorization']}",
                "Content-Type": "application/octet-stream",
            },
        )
        assert receipt.json()["size_bytes"] == len(part)
    if restart_io:
        compose("restart", "filebelt-worker-io")
    finalize = grants["finalize"]
    if competing_finalize:
        competing = browser.api("GET", allocation["grants_url"].removeprefix("/api/v1"))["finalize"]

        def invoke(grant: dict[str, Any]) -> HttpResult:
            return browser.request(
                "POST",
                grant["path"],
                headers={"Authorization": f"fbcap1 {grant['authorization']}"},
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(invoke, [finalize, competing]))
        assert sorted(result.status for result in results) == [200, 409]
    else:
        retry_request(
            browser,
            "POST",
            finalize["path"],
            headers={"Authorization": f"fbcap1 {finalize['authorization']}"},
        )
    if restart_api:
        compose("restart", "filebelt-api")
        wait_api(browser)
    committed = browser.api(
        "POST",
        f"/uploads/{allocation['upload_id']}/commit",
        {"expected_fencing_token": allocation["fencing_token"]},
        expected=201,
        idempotent=True,
    )
    assert UUID_V4.fullmatch(committed["node_id"])
    assert UUID_V4.fullmatch(committed["version_id"])
    return committed


def download(
    browser: Browser,
    drive_id: str,
    node_id: str,
    *,
    byte_range: str | None = None,
) -> bytes:
    grant = browser.api(
        "POST",
        f"/drives/{drive_id}/nodes/{node_id}/download-grants",
        {"version_id": None},
        expected=201,
    )
    result = retry_request(
        browser,
        "GET",
        grant["path"],
        headers={"Range": byte_range} if byte_range is not None else None,
        expected=206 if byte_range is not None else 200,
    )
    assert result.headers["Accept-Ranges"] == "bytes"
    if byte_range is not None:
        assert result.headers["Content-Range"].startswith("bytes ")
    return result.body


def expire_open_upload(upload_id: str) -> None:
    if UUID_V4.fullmatch(upload_id) is None:
        raise AssertionError("refusing to interpolate a non-UUID upload identifier")
    sql = (
        "UPDATE upload_sessions SET expires_at=clock_timestamp()-interval '1 second' "
        f"WHERE id='{upload_id}'::uuid AND state='open';"
        "UPDATE quota_reservations SET expires_at=clock_timestamp()-interval '1 second' "
        f"WHERE upload_id='{upload_id}'::uuid AND state='active';"
    )
    compose(
        "exec",
        "-T",
        "postgres",
        "psql",
        "--username",
        "filebelt_owner",
        "--dbname",
        "filebelt",
        "--no-psqlrc",
        "--set",
        "ON_ERROR_STOP=1",
        "--command",
        sql,
    )


def expire_finalization_lease(upload_id: str) -> None:
    if UUID_V4.fullmatch(upload_id) is None:
        raise AssertionError("refusing to interpolate a non-UUID upload identifier")
    sql = (
        "BEGIN;"
        "UPDATE payload_objects p SET state='finalizing' FROM upload_sessions u "
        "WHERE u.tenant_id=p.tenant_id AND u.payload_id=p.id "
        f"AND u.id='{upload_id}'::uuid AND u.state='open' AND p.state='staging';"
        "UPDATE upload_sessions SET state='finalizing',"
        "finalization_owner='00000000-0000-4000-8000-000000000099'::uuid,"
        "finalization_lease_expires_at=clock_timestamp()-interval '1 second' "
        f"WHERE id='{upload_id}'::uuid AND state='open';"
        "COMMIT;"
    )
    compose(
        "exec",
        "-T",
        "postgres",
        "psql",
        "--username",
        "filebelt_owner",
        "--dbname",
        "filebelt",
        "--no-psqlrc",
        "--set",
        "ON_ERROR_STOP=1",
        "--command",
        sql,
    )


def upload_state(upload_id: str) -> str:
    if UUID_V4.fullmatch(upload_id) is None:
        raise AssertionError("refusing to query a non-UUID upload identifier")
    result = compose(
        "exec",
        "-T",
        "postgres",
        "psql",
        "--username",
        "filebelt_owner",
        "--dbname",
        "filebelt",
        "--no-psqlrc",
        "--tuples-only",
        "--no-align",
        "--command",
        (
            "SELECT u.state||':'||q.state FROM upload_sessions u JOIN quota_reservations q "
            "ON q.tenant_id=u.tenant_id AND q.upload_id=u.id "
            f"WHERE u.id='{upload_id}'::uuid"
        ),
        capture=True,
    )
    return result.stdout.strip()


def assert_runtime_role_grants() -> None:
    result = compose(
        "exec",
        "-T",
        "postgres",
        "psql",
        "--username",
        "filebelt_owner",
        "--dbname",
        "filebelt",
        "--no-psqlrc",
        "--tuples-only",
        "--no-align",
        "--command",
        (
            "SELECT has_table_privilege('filebelt_api','authorization_generations','DELETE') "
            "AND has_table_privilege('filebelt_api','acl_entries','DELETE')"
        ),
        capture=True,
    )
    assert result.stdout.strip() == "t"


def audit_count(action: str) -> int:
    if not re.fullmatch(r"[a-z_.]+", action):
        raise AssertionError("refusing to interpolate an invalid audit action")
    result = compose(
        "exec",
        "-T",
        "postgres",
        "psql",
        "--username",
        "filebelt_owner",
        "--dbname",
        "filebelt",
        "--no-psqlrc",
        "--tuples-only",
        "--no-align",
        "--command",
        f"SELECT count(*) FROM audit_events WHERE action='{action}'",
        capture=True,
    )
    return int(result.stdout.strip())


def exercise() -> None:
    admin = Browser()
    member = Browser()
    wait_api(admin)
    assert_runtime_role_grants()
    admin_session = admin.login("admin")
    member_session = member.login("member")
    assert admin_session["tenant_admin"] is True
    assert member_session["tenant_admin"] is False
    assert admin_session["verified_email"] == "admin@example.test"
    assert member_session["verified_email"] == "member@example.test"
    assert audit_count("session.create") == 2

    admin_drive = private_drive(admin)
    root = admin.api("GET", f"/drives/{admin_drive['id']}/nodes/{admin_drive['root_id']}")
    created_directory = admin.api(
        "POST",
        f"/drives/{admin_drive['id']}/nodes/{admin_drive['root_id']}/directories",
        {
            "expected_parent_generation": root["namespace_generation"],
            "name": "Acceptance directory",
        },
        expected=201,
    )
    assert UUID_V4.fullmatch(created_directory["id"])
    hidden_parent = member.api(
        "POST",
        f"/drives/{admin_drive['id']}/uploads",
        {
            "declared_size_bytes": 1,
            "expected_parent_generation": 0,
            "name": "probe.bin",
            "parent_id": admin_drive["root_id"],
        },
        expected=404,
        idempotent=True,
    )
    assert hidden_parent is not None
    first = b"phase-two-version-one\n"
    second = b"phase-two-version-two-after-worker-restart\n"
    committed = upload(
        admin,
        admin_drive,
        "acceptance.txt",
        first,
        competing_finalize=True,
    )
    node_id = committed["node_id"]
    whole_above_chunk = b"w" * 16_777_217
    boundary_commit = upload(
        admin,
        admin_drive,
        "whole-above-chunk.bin",
        whole_above_chunk,
    )
    assert (
        download(admin, admin_drive["id"], boundary_commit["node_id"])
        == whole_above_chunk
    )
    second_commit = upload(
        admin,
        admin_drive,
        "acceptance.txt",
        second,
        node_id=node_id,
        expected_head=committed["version_id"],
        restart_io=True,
        restart_api=True,
    )
    assert download(admin, admin_drive["id"], node_id) == second
    versions = admin.api(
        "GET", f"/drives/{admin_drive['id']}/nodes/{node_id}/versions?limit=200"
    )["items"]
    assert [item["ordinal"] for item in versions] == [2, 1]
    restored = admin.api(
        "POST",
        f"/drives/{admin_drive['id']}/nodes/{node_id}/versions/{committed['version_id']}/restore",
        {"expected_head_version_id": second_commit["version_id"]},
        expected=201,
        idempotent=True,
    )
    assert restored["ordinal"] == 3
    assert download(admin, admin_drive["id"], node_id) == first
    assert download(
        admin,
        admin_drive["id"],
        node_id,
        byte_range="bytes=0-4",
    ) == first[:5]

    assert member.api("GET", "/shared?limit=200")["items"] == []
    share = admin.api(
        "POST",
        f"/drives/{admin_drive['id']}/nodes/{node_id}/shares",
        {
            "inheritance": "self",
            "kind": "direct",
            "preset": "viewer",
            "verified_email": "member@example.test",
        },
        expected=201,
        idempotent=True,
    )
    assert share["principal_id"] == member_session["principal_id"]
    shared = member.api("GET", "/shared?limit=200")["items"]
    assert [item["id"] for item in shared] == [node_id]
    assert download(member, admin_drive["id"], node_id) == first
    stale_grant = member.api(
        "POST",
        f"/drives/{admin_drive['id']}/nodes/{node_id}/download-grants",
        {"version_id": None},
        expected=201,
    )
    admin.api(
        "DELETE",
        f"/drives/{admin_drive['id']}/nodes/{node_id}/shares/{member_session['principal_id']}",
        expected=204,
    )
    expect(
        member.request(
            "GET",
            stale_grant["path"],
        ),
        403,
        "rejected capability after share revoke",
    )
    denied = member.api(
        "POST",
        f"/drives/{admin_drive['id']}/nodes/{node_id}/download-grants",
        {"version_id": None},
        expected=404,
    )
    assert denied is not None
    assert member.api("GET", "/shared?limit=200")["items"] == []

    residue = admin.api(
        "POST",
        f"/drives/{admin_drive['id']}/uploads",
        {
            "declared_size_bytes": 128,
            "expected_parent_generation": admin.api(
                "GET",
                f"/drives/{admin_drive['id']}/nodes/{admin_drive['root_id']}",
            )["namespace_generation"],
            "name": "expired-crash-residue.bin",
            "parent_id": admin_drive["root_id"],
        },
        expected=201,
        idempotent=True,
    )
    foreign_commit = member.api(
        "POST",
        f"/uploads/{residue['upload_id']}/commit",
        {"expected_fencing_token": residue["fencing_token"]},
        expected=404,
        idempotent=True,
    )
    assert foreign_commit is not None
    expire_finalization_lease(residue["upload_id"])
    compose("restart", "filebelt-worker-maintenance")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and upload_state(residue["upload_id"]) != "open:active":
        time.sleep(0.5)
    assert upload_state(residue["upload_id"]) == "open:active"
    recovered = admin.api("GET", f"/uploads/{residue['upload_id']}")
    assert recovered["upload"]["fencing_token"] == residue["fencing_token"] + 1
    expire_open_upload(residue["upload_id"])
    compose("restart", "filebelt-worker-maintenance")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and upload_state(residue["upload_id"]) != "expired:released":
        time.sleep(0.5)
    assert upload_state(residue["upload_id"]) == "expired:released"

    print("Phase 2 Docker acceptance passed: two users, ACL share/revoke, versions, restarts, reconciliation")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    exercise()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
