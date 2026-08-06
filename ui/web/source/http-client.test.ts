// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { AuthenticationRequiredError } from "./client.js";
import type { components } from "./generated/openapi.js";
import { HttpFileBeltClient } from "./http-client.js";

const driveId = "00000000-0000-4000-8000-000000000001";
const rootId = "00000000-0000-4000-8000-000000000002";
const firstNodeId = "00000000-0000-4000-8000-000000000003";
const secondNodeId = "00000000-0000-4000-8000-000000000004";
const principalId = "00000000-0000-4000-8000-000000000005";
const uploadId = "00000000-0000-4000-8000-000000000006";
const payloadId = "00000000-0000-4000-8000-000000000007";
const grantId = "00000000-0000-4000-8000-000000000008";

const session = {
  csrf_token: "csrf-value-not-browser-storage",
  display_name: "Avery Morgan",
  principal_id: "00000000-0000-4000-8000-000000000009",
  reauthenticated_recently: true,
  session_id: "00000000-0000-4000-8000-000000000010",
  tenant_admin: false,
  user_id: "00000000-0000-4000-8000-000000000011",
  verified_email: "avery@example.test",
} satisfies components["schemas"]["Session"];

const drive = {
  acl_generation: 1,
  display_name: "My Drive",
  id: driveId,
  kind: "private",
  namespace_generation: 300,
  owner_display_name: "Avery Morgan",
  quota_bytes: 1_000_000,
  reserved_bytes: 0,
  root_id: rootId,
  used_physical_bytes: 64,
} satisfies components["schemas"]["Drive"];

const sessionSummary = {
  absolute_expires_at: "2026-08-07T12:00:00Z",
  created_at: "2026-08-06T10:00:00Z",
  current: true,
  id: session.session_id,
  idle_expires_at: "2026-08-06T13:00:00Z",
  last_seen_at: "2026-08-06T12:00:00Z",
  revoked: false,
  user_agent: "Firefox",
} satisfies components["schemas"]["SessionSummary"];

function node(id: string, name: string): components["schemas"]["Node"] {
  return {
    acl_generation: 1,
    display_name: name,
    drive_id: driveId,
    head_version_id: "00000000-0000-4000-8000-000000000012",
    id,
    kind: "file",
    namespace_generation: 4,
    parent_id: rootId,
    size_bytes: 4,
    trashed: false,
    updated_at: "2026-08-06T12:00:00Z",
    version_ordinal: 1,
  };
}

function directShare(): components["schemas"]["DirectShare"] {
  return {
    created_at: "2026-08-06T12:00:00Z",
    display_name: "Layla Hassan",
    inheritance: "self",
    kind: "direct",
    preset: "viewer",
    principal_id: principalId,
    verified_email: "layla@example.test",
  };
}

class ContractServer {
  readonly requests: Request[] = [];
  readonly #nodes: readonly components["schemas"]["Node"][];
  #rootReads = 0;

  constructor(nodes: readonly components["schemas"]["Node"][]) {
    this.#nodes = nodes;
  }

  readonly fetch: typeof fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    this.requests.push(request);
    const path = new URL(request.url).pathname;

    if (path === "/api/v1/session" && request.method === "GET") return json(session);
    if (path === "/api/v1/drives" && request.method === "GET") {
      return json({ items: [drive], next_cursor: null });
    }
    if (path === `/api/v1/drives/${driveId}/nodes/${rootId}` && request.method === "GET") {
      this.#rootReads += 1;
      return json({
        ...node(rootId, "My Drive"),
        head_version_id: null,
        kind: "directory",
        namespace_generation: this.#rootReads === 1 ? 17 : 19,
        parent_id: null,
        size_bytes: null,
        version_ordinal: null,
      });
    }
    if (path === `/api/v1/drives/${driveId}/nodes/${rootId}/children` && request.method === "GET") {
      return json({ items: this.#nodes, next_cursor: null });
    }
    if (path === `/api/v1/drives/${driveId}/trash` && request.method === "GET") {
      return json({ items: [], next_cursor: null });
    }
    if (path === "/api/v1/shared" && request.method === "GET") {
      return json({ items: [], next_cursor: null });
    }
    if (path === "/api/v1/sessions" && request.method === "GET") return json([sessionSummary]);
    if (path.endsWith("/versions") && request.method === "GET") {
      return json({ items: [], next_cursor: null });
    }
    if (path.endsWith("/shares") && request.method === "GET") return json([directShare()]);
    if (path === `/api/v1/drives/${driveId}/uploads` && request.method === "POST") {
      return json(uploadAllocation(), 201);
    }
    if (path === `/api/v1/uploads/${uploadId}` && request.method === "GET") {
      return json({
        finalize: byteGrant("POST", `/io/v1/uploads/${uploadId}/finalize`, "finalize-secret"),
        next_cursor: null,
        parts: [byteGrant("PUT", `/io/v1/uploads/${uploadId}/parts/0`, "part-secret")],
        upload: uploadAllocation(),
      });
    }
    if (path === `/io/v1/uploads/${uploadId}/parts/0` && request.method === "PUT") {
      return json({ blake3: "abc", part_number: 0, size_bytes: 4, upload_id: uploadId });
    }
    if (path === `/io/v1/uploads/${uploadId}/finalize` && request.method === "POST") {
      return json({ blake3: "abc", payload_id: payloadId, size_bytes: 4, state: "finalized", upload_id: uploadId });
    }
    if (path === `/api/v1/uploads/${uploadId}/commit` && request.method === "POST") {
      return json({ node_id: firstNodeId, version_id: "00000000-0000-4000-8000-000000000013" }, 201);
    }
    if (path === `/api/v1/drives/${driveId}/nodes/${firstNodeId}/download-grants` && request.method === "POST") {
      return json({
        authorization: "download-secret-must-not-be-forwarded",
        authorization_scheme: "fbcap1",
        expires_at: "2026-08-06T12:01:00Z",
        grant_id: grantId,
        method: "GET",
        path: `/io/v1/downloads/${grantId}`,
        size_bytes: 4,
      }, 201);
    }
    if (path === `/io/v1/downloads/${grantId}` && request.method === "GET") {
      return new Response("data", { status: 200 });
    }
    if (path.includes("/shares/") && request.method === "DELETE") return new Response(null, { status: 204 });
    return json({ code: "test.unhandled", status: 500, title: `Unhandled ${request.method} ${path}`, type: "about:blank" }, 500);
  };
}

describe("HttpFileBeltClient", () => {
  it("uses generated API routes, the fresh root generation, and narrow capability transports", async () => {
    const server = new ContractServer([node(firstNodeId, "File one.txt")]);
    const client = new HttpFileBeltClient(server.fetch, "https://filebelt.localhost");

    await client.getWorkspace();
    await client.upload([{ data: new Blob(["data"]), name: "upload.txt", size: 4 }]);
    expect(await (await client.download(firstNodeId)).text()).toBe("data");

    const allocation = findRequest(server.requests, "POST", `/api/v1/drives/${driveId}/uploads`);
    expect(await allocation.clone().json()).toMatchObject({
      expected_parent_generation: 19,
      name: "upload.txt",
      parent_id: rootId,
    });
    expect(allocation.headers.get("x-filebelt-csrf")).toBe(session.csrf_token);
    expect(allocation.headers.get("idempotency-key")).not.toBeNull();

    const part = findRequest(server.requests, "PUT", `/io/v1/uploads/${uploadId}/parts/0`);
    expect(part.credentials).toBe("omit");
    expect(part.headers.get("authorization")).toBe("fbcap1 part-secret");

    const download = findRequest(server.requests, "GET", `/io/v1/downloads/${grantId}`);
    expect(download.credentials).toBe("same-origin");
    expect(download.headers.has("authorization")).toBe(false);
    expect([...download.headers.values()]).not.toContain("download-secret-must-not-be-forwarded");
  });

  it("uses distinct opaque share ids to revoke the same principal from two nodes exactly", async () => {
    const server = new ContractServer([
      node(firstNodeId, "File one.txt"),
      node(secondNodeId, "File two.txt"),
    ]);
    const client = new HttpFileBeltClient(server.fetch, "https://filebelt.localhost");
    const workspace = await client.getWorkspace();
    const first = workspace.shares.find(({ resourceName }) => resourceName === "File one.txt");
    const second = workspace.shares.find(({ resourceName }) => resourceName === "File two.txt");

    expect(first).toBeDefined();
    expect(second).toBeDefined();
    expect(first?.resourceId).toBe(firstNodeId);
    expect(second?.resourceId).toBe(secondNodeId);
    expect(first?.id).not.toBe(second?.id);
    expect(first?.id).not.toBe(principalId);
    if (first === undefined || second === undefined) return;

    await client.revokeShare(first.id);
    await client.revokeShare(second.id);

    expect(requestPaths(server.requests, "DELETE")).toEqual([
      `/api/v1/drives/${driveId}/nodes/${firstNodeId}/shares/${principalId}`,
      `/api/v1/drives/${driveId}/nodes/${secondNodeId}/shares/${principalId}`,
    ]);
  });

  it("converts a session 401 into an explicit authentication-required signal", async () => {
    const fetchImplementation: typeof fetch = async () => json({
      code: "session.unauthorized",
      status: 401,
      title: "Authentication is required",
      type: "about:blank",
    }, 401);
    const client = new HttpFileBeltClient(fetchImplementation, "https://filebelt.localhost");

    await expect(client.getWorkspace()).rejects.toBeInstanceOf(AuthenticationRequiredError);
  });
});

function uploadAllocation(): components["schemas"]["UploadAllocation"] {
  return {
    chunk_size_bytes: 4,
    declared_size_bytes: 4,
    drive_id: driveId,
    fencing_token: 2,
    grants_url: `/api/v1/uploads/${uploadId}`,
    node_id: null,
    parent_id: rootId,
    part_count: 1,
    payload_id: payloadId,
    state: "open",
    upload_id: uploadId,
  };
}

function byteGrant(
  method: components["schemas"]["ByteGrant"]["method"],
  path: string,
  authorization: string,
): components["schemas"]["ByteGrant"] {
  return {
    authorization,
    authorization_scheme: "fbcap1",
    expires_at: "2026-08-06T12:01:00Z",
    method,
    path,
  };
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    headers: { "Content-Type": "application/json" },
    status,
  });
}

function findRequest(requests: readonly Request[], method: string, path: string): Request {
  const request = requests.find((candidate) => (
    candidate.method === method && new URL(candidate.url).pathname === path
  ));
  expect(request, `${method} ${path}`).toBeDefined();
  if (request === undefined) throw new Error(`Missing ${method} ${path}`);
  return request;
}

function requestPaths(requests: readonly Request[], method: string): string[] {
  return requests
    .filter((request) => request.method === method)
    .map((request) => new URL(request.url).pathname);
}
