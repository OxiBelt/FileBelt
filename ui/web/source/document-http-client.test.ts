// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { HttpDocumentSessionClient } from "./document-http-client.js";
import type { components } from "./generated/openapi.js";

const DriveId = "00000000-0000-4000-8000-000000000001";
const NodeId = "00000000-0000-4000-8000-000000000002";
const ParentId = "00000000-0000-4000-8000-000000000003";
const SessionId = "00000000-0000-4000-8000-000000000004";
const VersionId = "00000000-0000-4000-8000-000000000005";
const Cursor = "opaque-session-cursor";

const Session = {
  csrf_token: "csrf-in-memory-only",
  display_name: "Avery Morgan",
  principal_id: "00000000-0000-4000-8000-000000000006",
  reauthenticated_recently: true,
  session_id: "00000000-0000-4000-8000-000000000007",
  tenant_admin: false,
  user_id: "00000000-0000-4000-8000-000000000008",
  verified_email: "avery@example.test",
} satisfies components["schemas"]["Session"];

const Summary = {
  base_version_id: VersionId,
  closed_at: null,
  conflict_head_version_id: null,
  created_at: "2026-08-09T10:00:00Z",
  drive_id: DriveId,
  expires_at: "2026-08-09T12:00:00Z",
  id: SessionId,
  last_activity_at: "2026-08-09T10:15:00Z",
  mode: "edit",
  node_id: NodeId,
  participant_count: 1,
  state: "active",
} satisfies components["schemas"]["DocumentSessionSummary"];

const Detail = {
  participants: [{ active: true, display_name: "Avery Morgan", joined_at: "2026-08-09T10:00:00Z", last_activity_at: "2026-08-09T10:15:00Z", mode: "edit", principal_id: Session.principal_id }],
  provider_origin: "https://documentserver.example.test",
  session: Summary,
} satisfies components["schemas"]["DocumentSessionDetail"];

function Node(Id: string, Parent: string | null, Kind: "directory" | "file"): components["schemas"]["Node"] {
  return { acl_generation: 2, display_name: Kind === "directory" ? "Documents" : "Plan.docx", drive_id: DriveId, head_media_type: Kind === "directory" ? null : "application/vnd.openxmlformats-officedocument.wordprocessingml.document", head_version_id: Kind === "directory" ? null : VersionId, id: Id, kind: Kind, namespace_generation: 7, parent_id: Parent, size_bytes: Kind === "directory" ? null : 8, trashed: false, updated_at: "2026-08-09T10:00:00Z", version_ordinal: Kind === "directory" ? null : 1 };
}

describe("HttpDocumentSessionClient", () => {
  it("uses generated session routes with in-memory CSRF and idempotency headers", async () => {
    const Requests: Request[] = [];
    const Fetch: typeof fetch = async (Input, Init) => {
      const HttpRequest = Input instanceof Request ? Input : new Request(Input, Init);
      Requests.push(HttpRequest);
      const Path = new URL(HttpRequest.url).pathname;
      if (Path === "/api/v1/session") return Json(Session);
      if (Path === `/api/v1/drives/${DriveId}/nodes/${NodeId}/document-sessions` && HttpRequest.method === "POST") return Json(Detail, 201);
      if (Path === "/api/v1/document-sessions") return Json({ items: [Summary], next_cursor: null });
      if (Path === `/api/v1/document-sessions/${SessionId}` && HttpRequest.method === "GET") return Json(Detail);
      if (Path === `/api/v1/document-sessions/${SessionId}` && HttpRequest.method === "DELETE") return new Response(null, { status: 204 });
      if (Path === `/api/v1/document-sessions/${SessionId}/handoff` && HttpRequest.method === "POST") return Json({ action: "https://filebelt.localhost/onlyoffice/launch", expires_at: "2026-08-09T10:16:00Z", grant: "one-use-grant-value-long-enough-for-the-contract", session_id: SessionId }, 201);
      if (Path === `/api/v1/drives/${DriveId}/nodes/${NodeId}` && HttpRequest.method === "GET") return Json(Node(NodeId, ParentId, "file"));
      if (Path === `/api/v1/drives/${DriveId}/nodes/${ParentId}` && HttpRequest.method === "GET") return Json(Node(ParentId, null, "directory"));
      if (Path === `/api/v1/document-sessions/${SessionId}/conflict-copy` && HttpRequest.method === "POST") return Json({ node: Node("00000000-0000-4000-8000-000000000009", ParentId, "file"), version: { created_at: "2026-08-09T10:00:00Z", created_by: Session.principal_id, current: true, id: "00000000-0000-4000-8000-000000000010", media_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", node_id: NodeId, ordinal: 2, provenance: { creator_display_name: "Avery Morgan", mcp_assisted: false, origin: "external_document", source_version_id: VersionId }, restored_from_version_id: null, size_bytes: 8 } }, 201);
      if (Path === `/api/v1/drives/${DriveId}/nodes/${NodeId}/document-sessions/${SessionId}` && HttpRequest.method === "DELETE") return new Response(null, { status: 204 });
      return Json({ status: 500, title: `Unhandled ${HttpRequest.method} ${Path}` }, 500);
    };
    const Client = new HttpDocumentSessionClient(Fetch, "https://filebelt.localhost");

    await Client.createSession({ BaseVersionId: VersionId, DriveId, Mode: "edit", NodeId });
    await Client.listOwnSessions({ Cursor });
    await Client.revokeOwnSession(SessionId);
    await Client.redeemLaunch(SessionId);
    const ConflictCopy = await Client.createConflictCopy(SessionId, "Plan (conflicted copy).docx");
    await Client.forceClose(Summary);

    const Create = Find(Requests, "POST", `/api/v1/drives/${DriveId}/nodes/${NodeId}/document-sessions`);
    expect(await Create.clone().json()).toEqual({ base_version_id: VersionId, mode: "edit" });
    expect(Create.headers.get("x-filebelt-csrf")).toBe(Session.csrf_token);
    expect(Create.headers.get("idempotency-key")).not.toBeNull();
    const ListQuery = new URL(Find(Requests, "GET", "/api/v1/document-sessions").url).searchParams;
    expect(ListQuery.get("cursor")).toBe(Cursor);
    expect(ListQuery.get("limit")).toBe("200");
    const Copy = Find(Requests, "POST", `/api/v1/document-sessions/${SessionId}/conflict-copy`);
    expect(await Copy.clone().json()).toEqual({ expected_parent_generation: 7, target_name: "Plan (conflicted copy).docx", target_parent_id: ParentId });
    expect(Find(Requests, "POST", `/api/v1/document-sessions/${SessionId}/handoff`).headers.get("idempotency-key")).toBeNull();
    expect(Requests.some((Request) => Request.url.includes("csrf-in-memory-only"))).toBe(false);
    expect(ConflictCopy.node.id).toBe("00000000-0000-4000-8000-000000000009");
  });
});

function Find(Requests: readonly Request[], Method: string, Path: string): Request {
  const Request = Requests.find((Candidate) => Candidate.method === Method && new URL(Candidate.url).pathname === Path);
  if (Request === undefined) throw new Error(`Missing ${Method} ${Path}`);
  return Request;
}

function Json(Body: unknown, Status = 200): Response {
  return new Response(JSON.stringify(Body), { headers: { "content-type": "application/json" }, status: Status });
}
