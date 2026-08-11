// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { AuthenticationRequiredError } from "./client.js";
import type { components } from "./generated/openapi.js";
import { HttpFileBeltClient } from "./http-client.js";

const DriveId = "00000000-0000-4000-8000-000000000001";
const RootId = "00000000-0000-4000-8000-000000000002";
const FirstNodeId = "00000000-0000-4000-8000-000000000003";
const SecondNodeId = "00000000-0000-4000-8000-000000000004";
const PrincipalId = "00000000-0000-4000-8000-000000000005";
const UploadId = "00000000-0000-4000-8000-000000000006";
const PayloadId = "00000000-0000-4000-8000-000000000007";
const GrantId = "00000000-0000-4000-8000-000000000008";
const ImportIntentId = "00000000-0000-4000-8000-000000000014";
const SymlinkNodeId = "00000000-0000-4000-8000-000000000015";

const Session = {
  csrf_token: "csrf-value-not-browser-storage",
  display_name: "Avery Morgan",
  principal_id: "00000000-0000-4000-8000-000000000009",
  reauthenticated_recently: true,
  session_id: "00000000-0000-4000-8000-000000000010",
  tenant_admin: false,
  user_id: "00000000-0000-4000-8000-000000000011",
  verified_email: "avery@example.test",
} satisfies components["schemas"]["Session"];

const Drive = {
  acl_generation: 1,
  display_name: "My Drive",
  id: DriveId,
  kind: "private",
  namespace_generation: 300,
  owner_display_name: "Avery Morgan",
  quota_bytes: 1_000_000,
  reserved_bytes: 0,
  root_id: RootId,
  used_physical_bytes: 64,
} satisfies components["schemas"]["Drive"];

const SessionSummary = {
  absolute_expires_at: "2026-08-07T12:00:00Z",
  created_at: "2026-08-06T10:00:00Z",
  current: true,
  id: Session.session_id,
  idle_expires_at: "2026-08-06T13:00:00Z",
  last_seen_at: "2026-08-06T12:00:00Z",
  revoked: false,
  user_agent: "Firefox",
} satisfies components["schemas"]["SessionSummary"];

function Node(Id: string, Name: string): components["schemas"]["Node"] {
  return {
    acl_generation: 1,
    display_name: Name,
    drive_id: DriveId,
    head_media_type: "text/markdown",
    head_version_id: "00000000-0000-4000-8000-000000000012",
    id: Id,
    kind: "file",
    namespace_generation: 4,
    parent_id: RootId,
    size_bytes: 4,
    trashed: false,
    updated_at: "2026-08-06T12:00:00Z",
    version_ordinal: 1,
  };
}

function SymlinkNode(): components["schemas"]["Node"] {
  return {
    ...Node(SymlinkNodeId, "Current report"),
    head_media_type: null,
    head_version_id: null,
    kind: "symlink",
    size_bytes: null,
    version_ordinal: null,
  };
}

function DirectShare(): components["schemas"]["DirectShare"] {
  return {
    created_at: "2026-08-06T12:00:00Z",
    display_name: "Layla Hassan",
    inheritance: "self",
    kind: "direct",
    preset: "viewer",
    principal_id: PrincipalId,
    verified_email: "layla@example.test",
  };
}

class ContractServer {
  readonly Requests: Request[] = [];
  readonly #Nodes: readonly components["schemas"]["Node"][];
  #RootReads = 0;

  constructor(Nodes: readonly components["schemas"]["Node"][]) {
    this.#Nodes = Nodes;
  }

  readonly fetch: typeof fetch = async (Input, Init) => {
    const HttpRequest = Input instanceof Request ? Input : new Request(Input, Init);
    this.Requests.push(HttpRequest);
    const Path = new URL(HttpRequest.url).pathname;

    if (Path === "/api/v1/session" && HttpRequest.method === "GET") return Json(Session);
    if (Path === "/api/v1/drives" && HttpRequest.method === "GET") {
      return Json({ items: [Drive], next_cursor: null });
    }
    if (Path === `/api/v1/drives/${DriveId}/nodes/${RootId}` && HttpRequest.method === "GET") {
      this.#RootReads += 1;
      return Json({
        ...Node(RootId, "My Drive"),
        head_version_id: null,
        kind: "directory",
        namespace_generation: this.#RootReads === 1 ? 17 : 19,
        parent_id: null,
        size_bytes: null,
        version_ordinal: null,
      });
    }
    if (Path === `/api/v1/drives/${DriveId}/nodes/${RootId}/children` && HttpRequest.method === "GET") {
      return Json({ items: this.#Nodes, next_cursor: null });
    }
    if (Path === `/api/v1/drives/${DriveId}/trash` && HttpRequest.method === "GET") {
      return Json({ items: [], next_cursor: null });
    }
    if (Path === "/api/v1/shared" && HttpRequest.method === "GET") {
      return Json({ items: [], next_cursor: null });
    }
    if (Path === "/api/v1/sessions" && HttpRequest.method === "GET") return Json([SessionSummary]);
    if (Path.endsWith("/versions") && HttpRequest.method === "GET") {
      return Json({ items: [], next_cursor: null });
    }
    if (Path.endsWith("/shares") && HttpRequest.method === "GET") return Json([DirectShare()]);
    if (Path === `/api/v1/drives/${DriveId}/uploads` && HttpRequest.method === "POST") {
      return Json(UploadAllocation(), 201);
    }
    if (Path === `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/markdown-import-intents` && HttpRequest.method === "POST") {
      return Json({ expires_at: "2026-08-06T12:15:00Z", id: ImportIntentId, source_drive_id: DriveId, source_node_id: FirstNodeId, source_version_id: Node(FirstNodeId, "Source.docx").head_version_id as string, target_media_type: "text/markdown", target_name: "Source.md", target_parent_id: RootId }, 201);
    }
    if (Path === `/api/v1/uploads/${UploadId}` && HttpRequest.method === "GET") {
      return Json({
        finalize: ByteGrant("POST", `/io/v1/uploads/${UploadId}/finalize`, "finalize-secret"),
        next_cursor: null,
        parts: [ByteGrant("PUT", `/io/v1/uploads/${UploadId}/parts/0`, "part-secret")],
        upload: UploadAllocation(),
      });
    }
    if (Path === `/io/v1/uploads/${UploadId}/parts/0` && HttpRequest.method === "PUT") {
      return Json({ blake3: "abc", part_number: 0, size_bytes: 4, upload_id: UploadId });
    }
    if (Path === `/io/v1/uploads/${UploadId}/finalize` && HttpRequest.method === "POST") {
      return Json({ blake3: "abc", payload_id: PayloadId, size_bytes: 4, state: "finalized", upload_id: UploadId });
    }
    if (Path === `/api/v1/uploads/${UploadId}/commit` && HttpRequest.method === "POST") {
      return Json({ node_id: FirstNodeId, version_id: "00000000-0000-4000-8000-000000000013" }, 201);
    }
    if (Path === `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/download-grants` && HttpRequest.method === "POST") {
      return Json({
        authorization: "download-secret-must-not-be-forwarded",
        authorization_scheme: "fbcap1",
        expires_at: "2026-08-06T12:01:00Z",
        grant_id: GrantId,
        method: "GET",
        path: `/io/v1/downloads/${GrantId}`,
        size_bytes: 4,
      }, 201);
    }
    if (Path === `/io/v1/downloads/${GrantId}` && HttpRequest.method === "GET") {
      return new Response("data", { status: 200 });
    }
    if (Path.includes("/shares/") && HttpRequest.method === "DELETE") return new Response(null, { status: 204 });
    return Json({ code: "test.unhandled", status: 500, title: `Unhandled ${HttpRequest.method} ${Path}`, type: "about:blank" }, 500);
  };
}

describe("HttpFileBeltClient", () => {
  it("uses generated API routes, the fresh root generation, and narrow capability transports", async () => {
    const Server = new ContractServer([Node(FirstNodeId, "File one.txt")]);
    const Client = new HttpFileBeltClient(Server.fetch, "https://filebelt.localhost");

    await Client.getWorkspace();
    await Client.upload([{ Data: new Blob(["data"]), Name: "upload.txt", Size: 4 }]);
    expect(await (await Client.download(FirstNodeId)).text()).toBe("data");
    expect(await (await Client.readMarkdown(FirstNodeId, "00000000-0000-4000-8000-000000000012")).text()).toBe("data");
    await Client.saveMarkdown({
      Contents: new Blob(["# replacement"], { type: "text/markdown" }),
      EntryId: FirstNodeId,
      ExpectedHeadVersionId: "00000000-0000-4000-8000-000000000012",
      Name: "File one.txt",
    });

    const Allocation = FindRequest(Server.Requests, "POST", `/api/v1/drives/${DriveId}/uploads`);
    expect(await Allocation.clone().json()).toMatchObject({
      expected_parent_generation: 19,
      name: "upload.txt",
      parent_id: RootId,
    });
    expect(Allocation.headers.get("x-filebelt-csrf")).toBe(Session.csrf_token);
    expect(Allocation.headers.get("idempotency-key")).not.toBeNull();
    const MarkdownAllocation = Server.Requests.filter((Request) => new URL(Request.url).pathname === `/api/v1/drives/${DriveId}/uploads` && Request.method === "POST").at(-1);
    expect(MarkdownAllocation).toBeDefined();
    if (MarkdownAllocation !== undefined) expect(await MarkdownAllocation.clone().json()).toMatchObject({
      declared_media_type: "text/markdown",
      expected_head_version_id: "00000000-0000-4000-8000-000000000012",
      node_id: FirstNodeId,
    });

    const Part = FindRequest(Server.Requests, "PUT", `/io/v1/uploads/${UploadId}/parts/0`);
    expect(Part.credentials).toBe("omit");
    expect(Part.headers.get("authorization")).toBe("fbcap1 part-secret");

    const Download = FindRequest(Server.Requests, "GET", `/io/v1/downloads/${GrantId}`);
    expect(Download.credentials).toBe("same-origin");
    expect(Download.headers.has("authorization")).toBe(false);
    expect([...Download.headers.values()]).not.toContain("download-secret-must-not-be-forwarded");
  });

  it("uses distinct opaque share ids to revoke the same principal from two nodes exactly", async () => {
    const Server = new ContractServer([
      Node(FirstNodeId, "File one.txt"),
      Node(SecondNodeId, "File two.txt"),
    ]);
    const Client = new HttpFileBeltClient(Server.fetch, "https://filebelt.localhost");
    const Workspace = await Client.getWorkspace();
    const First = Workspace.Shares.find(({ ResourceName }) => ResourceName === "File one.txt");
    const Second = Workspace.Shares.find(({ ResourceName }) => ResourceName === "File two.txt");

    expect(First).toBeDefined();
    expect(Second).toBeDefined();
    expect(First?.ResourceId).toBe(FirstNodeId);
    expect(Second?.ResourceId).toBe(SecondNodeId);
    expect(First?.Id).not.toBe(Second?.Id);
    expect(First?.Id).not.toBe(PrincipalId);
    if (First === undefined || Second === undefined) return;

    await Client.revokeShare(First.Id);
    await Client.revokeShare(Second.Id);

    expect(RequestPaths(Server.Requests, "DELETE")).toEqual([
      `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/shares/${PrincipalId}`,
      `/api/v1/drives/${DriveId}/nodes/${SecondNodeId}/shares/${PrincipalId}`,
    ]);
  });

  it("converts a session 401 into an explicit authentication-required signal", async () => {
    const FetchImplementation: typeof fetch = async () => Json({
      code: "session.unauthorized",
      status: 401,
      title: "Authentication is required",
      type: "about:blank",
    }, 401);
    const Client = new HttpFileBeltClient(FetchImplementation, "https://filebelt.localhost");

    await expect(Client.getWorkspace()).rejects.toBeInstanceOf(AuthenticationRequiredError);
  });

  it("binds an Office conversion to an exact source version and one new sibling upload", async () => {
    const Source = Node(FirstNodeId, "Source.docx");
    const Server = new ContractServer([Source]);
    const Client = new HttpFileBeltClient(Server.fetch, "https://filebelt.localhost");
    await Client.getWorkspace();
    if (Source.head_version_id === null) return;

    await Client.importMarkdown({ Contents: new Blob(["# hi"], { type: "text/markdown" }), EntryId: FirstNodeId, SourceVersionId: Source.head_version_id, TargetName: "Source.md" });

    const Intent = FindRequest(Server.Requests, "POST", `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/markdown-import-intents`);
    expect(await Intent.clone().json()).toEqual({ source_version_id: Source.head_version_id, target_name: "Source.md" });
    const Allocation = Server.Requests.filter((Request) => new URL(Request.url).pathname === `/api/v1/drives/${DriveId}/uploads` && Request.method === "POST").at(-1);
    expect(Allocation).toBeDefined();
    if (Allocation !== undefined) expect(await Allocation.clone().json()).toMatchObject({ declared_media_type: "text/markdown", expected_parent_generation: 19, import_intent_id: ImportIntentId, name: "Source.md", parent_id: RootId });
  });

  it("projects symlinks without traversing them or requesting file versions and content", async () => {
    const Server = new ContractServer([SymlinkNode()]);
    const Client = new HttpFileBeltClient(Server.fetch, "https://filebelt.localhost");

    const Workspace = await Client.getWorkspace();
    expect(Workspace.Entries.find(({ Id }) => Id === SymlinkNodeId)).toMatchObject({
      HeadVersionId: null,
      Kind: "symlink",
      MarkdownEligibility: "ineligible",
      MediaType: null,
      Size: null,
      Version: 0,
    });
    expect(Server.Requests.some((Request) => new URL(Request.url).pathname === `/api/v1/drives/${DriveId}/nodes/${SymlinkNodeId}/children`)).toBe(false);
    expect(Server.Requests.some((Request) => new URL(Request.url).pathname === `/api/v1/drives/${DriveId}/nodes/${SymlinkNodeId}/versions`)).toBe(false);
    await expect(Client.download(SymlinkNodeId)).rejects.toThrow("not a file");
    expect(Server.Requests.some((Request) => new URL(Request.url).pathname === `/api/v1/drives/${DriveId}/nodes/${SymlinkNodeId}/download-grants`)).toBe(false);
  });
});

function UploadAllocation(): components["schemas"]["UploadAllocation"] {
  return {
    chunk_size_bytes: 4,
    declared_size_bytes: 4,
    drive_id: DriveId,
    fencing_token: 2,
    grants_url: `/api/v1/uploads/${UploadId}`,
    node_id: null,
    parent_id: RootId,
    part_count: 1,
    payload_id: PayloadId,
    state: "open",
    upload_id: UploadId,
  };
}

function ByteGrant(
  Method: components["schemas"]["ByteGrant"]["method"],
  Path: string,
  Authorization: string,
): components["schemas"]["ByteGrant"] {
  return {
    authorization: Authorization,
    authorization_scheme: "fbcap1",
    expires_at: "2026-08-06T12:01:00Z",
    method: Method,
    path: Path,
  };
}

function Json(Value: unknown, Status = 200): Response {
  return new Response(JSON.stringify(Value), {
    headers: { "Content-Type": "application/json" },
    status: Status,
  });
}

function FindRequest(Requests: readonly Request[], Method: string, Path: string): Request {
  const Request = Requests.find((Candidate) => (
    Candidate.method === Method && new URL(Candidate.url).pathname === Path
  ));
  expect(Request, `${Method} ${Path}`).toBeDefined();
  if (Request === undefined) throw new Error(`Missing ${Method} ${Path}`);
  return Request;
}

function RequestPaths(Requests: readonly Request[], Method: string): string[] {
  return Requests
    .filter((Request) => Request.method === Method)
    .map((Request) => new URL(Request.url).pathname);
}
