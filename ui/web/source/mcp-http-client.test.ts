// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { components } from "./generated/openapi.js";
import { HttpMcpSettingsClient } from "./mcp-http-client.js";

const RegistrationId = "00000000-0000-4000-8000-000000000041";
const SnapshotId = "00000000-0000-4000-8000-000000000042";
const InvocationId = "00000000-0000-4000-8000-000000000043";
const NodeId = "00000000-0000-4000-8000-000000000048";
const BaseVersionId = "00000000-0000-4000-8000-000000000049";

const Session = {
  csrf_token: "csrf-memory-only",
  display_name: "Avery Morgan",
  principal_id: "00000000-0000-4000-8000-000000000044",
  reauthenticated_recently: true,
  session_id: "00000000-0000-4000-8000-000000000045",
  tenant_admin: true,
  user_id: "00000000-0000-4000-8000-000000000046",
  verified_email: "avery@example.test",
} satisfies components["schemas"]["Session"];

const Registration = {
  attachment_policy: {
    allowed_encodings: ["utf8"],
    allowed_mime_patterns: ["text/*"],
    max_attachments: 4,
    max_item_bytes: 1_048_576,
    max_total_bytes: 4_194_304,
  },
  authentication_state: "ready",
  capability_snapshot_id: SnapshotId,
  capability_state: "reviewed",
  catalog_entry_id: null,
  created_at: "2026-08-07T10:00:00Z",
  credential_kind: "bearer",
  credential_present: true,
  display_name: "Read-only planning",
  endpoint_uri: "https://mcp.example.test/mcp",
  etag: '"mcp-7"',
  generation: 7,
  id: RegistrationId,
  lifecycle_state: "enabled",
  managed_locked: false,
  ownership: "personal",
  protocol_version: "2026-07-28",
  quarantine_state: "clear",
  transport: "streamable_http",
  trust_profile: "public-webpki",
  updated_at: "2026-08-07T10:00:00Z",
  validation_state: "valid",
} satisfies components["schemas"]["McpRegistration"];

class ContractServer {
  readonly Requests: Request[] = [];

  readonly fetch: typeof fetch = async (Input, Init) => {
    const RequestValue = Input instanceof Request ? Input : new Request(Input, Init);
    this.Requests.push(RequestValue);
    const Url = new URL(RequestValue.url);
    if (Url.pathname === "/api/v1/session") return Json(Session);
    if (Url.pathname === "/api/v1/mcp/registrations" && RequestValue.method === "GET") return Json({ items: [Registration], next_cursor: null });
    if (Url.pathname === "/api/v1/mcp/activity") return Json({ items: [], next_cursor: null });
    if (Url.pathname.endsWith("/credentials")) return new Response(null, { status: 204 });
    if (Url.pathname === "/api/v1/mcp/invocation-intents") return Json({ approval_required: true, expires_at: "2026-08-07T10:05:00Z", id: InvocationId, request_digest: "a".repeat(64) }, 201);
    if (Url.pathname.endsWith("/approval")) return Json({ id: "00000000-0000-4000-8000-000000000047" }, 201);
    if (Url.pathname === `/api/v1/mcp/invocations/${InvocationId}` && RequestValue.method === "DELETE") return new Response(null, { status: 204 });
    if (Url.pathname.endsWith("/stream")) {
      return new Response([
        JSON.stringify({ created_at: "2026-08-07T10:00:00Z", event: "started", invocation_id: InvocationId, sequence: 0 }),
        JSON.stringify({ created_at: "2026-08-07T10:00:01Z", event: "text", invocation_id: InvocationId, sequence: 1, text: "<script>not markup</script>" }),
        JSON.stringify({ created_at: "2026-08-07T10:00:02Z", event: "completed", invocation_id: InvocationId, sequence: 2 }),
      ].join("\n"), { headers: { "Content-Type": "application/x-ndjson" } });
    }
    return new Response(null, { status: 404 });
  };
}

function Json(Value: unknown, Status = 200): Response {
  return new Response(JSON.stringify(Value), { headers: { "Content-Type": "application/json" }, status: Status });
}

describe("HttpMcpSettingsClient", () => {
  it("sends credentials once in a protected body and never places them in a URL", async () => {
    const Server = new ContractServer();
    const Client = new HttpMcpSettingsClient(Server.fetch, "https://filebelt.example.test");
    const Snapshot = await Client.getSnapshot(false);
    const View = Snapshot.Registrations[0];
    expect(View).toBeDefined();
    if (View === undefined) return;

    await Client.putCredential(View, "bearer", "top-secret-value");
    const RequestValue = Server.Requests.at(-1);
    expect(RequestValue?.url).not.toContain("top-secret-value");
    expect(RequestValue?.headers.get("X-FileBelt-Csrf")).toBe("csrf-memory-only");
    expect(RequestValue?.headers.get("If-Match")).toBe('"mcp-7"');
    expect(await RequestValue?.clone().json()).toEqual({ kind: "bearer", secret: "top-secret-value" });
  });

  it("resubmits the exact intent request to an authenticated POST stream and parses bounded events", async () => {
    const Server = new ContractServer();
    const Client = new HttpMcpSettingsClient(Server.fetch, "https://filebelt.example.test");
    const Events: string[] = [];

    const Prepared = await Client.createInvocationIntent({
      ApplicationId: "filebelt-web",
      Arguments: { query: "quarterly plan" },
      Capability: { Fingerprint: "b".repeat(64), Kind: "tool", Name: "search" },
      RegistrationId,
      SemanticInput: { BaseVersionId, Markdown: "# Current source", NodeId },
    });
    expect(Server.Requests.some(({ url: Url }) => Url.endsWith("/stream"))).toBe(false);
    await Client.approveAndInvoke(Prepared, (Event) => Events.push(Event.Kind));

    expect(Events).toEqual(["started", "text", "completed"]);
    const Requests = Server.Requests.filter(({ url: Url }) => Url.includes("invocation"));
    expect(Requests.map(({ method: Method }) => Method)).toEqual(["POST", "POST", "POST"]);
    expect(await Requests[0]?.clone().text()).toBe(await Requests[2]?.clone().text());
    expect(await Requests[1]?.clone().json()).toEqual({ expires_at: null, scope: "once" });
    expect(await Requests[0]?.clone().json()).toMatchObject({ semantic_input: { base_version_id: BaseVersionId, format: "filebelt.markdown.semantic.v1", markdown: "# Current source", node_id: NodeId } });
    expect(Requests[2]?.headers.get("Cache-Control")).toBeNull();
    expect(Requests[2]?.headers.get("X-FileBelt-Csrf")).toBe("csrf-memory-only");
  });

  it("cancels the exact active invocation with mutation protections", async () => {
    const Server = new ContractServer();
    const Client = new HttpMcpSettingsClient(Server.fetch, "https://filebelt.example.test");

    await Client.cancelInvocation(InvocationId);

    const RequestValue = Server.Requests.at(-1);
    expect(RequestValue?.method).toBe("DELETE");
    expect(new URL(RequestValue?.url ?? "https://invalid.example").pathname).toBe(
      `/api/v1/mcp/invocations/${InvocationId}`,
    );
    expect(RequestValue?.headers.get("X-FileBelt-Csrf")).toBe("csrf-memory-only");
  });
});
