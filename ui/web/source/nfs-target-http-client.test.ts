// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { components } from "./generated/openapi.js";
import { MountReauthenticationRequiredError } from "./mount-http-client.js";
import { HttpNfsTargetClient } from "./nfs-target-http-client.js";

const ProposalId = "00000000-0000-4000-8000-000000000131";
const CredentialId = "00000000-0000-4000-8000-000000000132";
const DriveId = "00000000-0000-4000-8000-000000000133";

const Session = {
  csrf_token: "csrf-memory-only",
  display_name: "Avery Morgan",
  principal_id: "00000000-0000-4000-8000-000000000134",
  reauthenticated_recently: true,
  session_id: "00000000-0000-4000-8000-000000000135",
  tenant_admin: false,
  user_id: "00000000-0000-4000-8000-000000000136",
  verified_email: "avery@example.test",
} satisfies components["schemas"]["Session"];

const Overview = {
  mappings: [{
    allowed_drive_ids: [DriveId],
    credential_id: CredentialId,
    generation: 2,
    kerberos_principal: "avery@EXAMPLE.TEST",
    principal_id: Session.principal_id,
    projected_gid: 2001,
    projected_uid: 1001,
  }],
  proposals: [{
    allowed_drive_ids: [DriveId],
    allowed_drives: [{ display_name: "Research", id: DriveId }],
    created_at: "2026-08-11T00:00:00Z",
    decided_at: null,
    expires_at: "2026-08-12T00:00:00Z",
    generation: 1,
    id: ProposalId,
    kerberos_principal: "avery@EXAMPLE.TEST",
    principal_id: Session.principal_id,
    posix_group_id: "00000000-0000-4000-8000-000000000138",
    posix_group_name: "researchers",
    posix_name: "avery",
    projected_gid: 2001,
    projected_uid: 1001,
    proposer_principal_id: "00000000-0000-4000-8000-000000000137",
    state: "pending",
  }],
} satisfies components["schemas"]["NfsTargetOverview"];

class ContractServer {
  readonly Requests: Request[] = [];
  ReauthenticationRequired = false;

  readonly fetch: typeof fetch = async (Input, Init) => {
    const RequestValue = Input instanceof Request ? Input : new Request(Input, Init);
    this.Requests.push(RequestValue);
    const Url = new URL(RequestValue.url);
    if (Url.pathname === "/api/v1/session") return Json(Session);
    if (Url.pathname === "/api/v1/mounts/nfs" && RequestValue.method === "GET") return Json(Overview);
    if (this.ReauthenticationRequired) return Json({ code: "mount.reauthentication_required", status: 403, title: "Recent OIDC authentication is required", type: "https://filebelt.dev/problems/mount.reauthentication_required" }, 403);
    if (Url.pathname === `/api/v1/mounts/nfs/mapping-proposals/${ProposalId}/approval` && RequestValue.method === "POST") return Json(Overview.mappings[0]);
    if (Url.pathname === `/api/v1/mounts/nfs/mapping-proposals/${ProposalId}/decline` && RequestValue.method === "POST") return new Response(null, { status: 204 });
    if (Url.pathname === `/api/v1/mounts/nfs/mappings/${CredentialId}` && RequestValue.method === "DELETE") return new Response(null, { status: 204 });
    return new Response(null, { status: 404 });
  };
}

function Json(Value: unknown, Status = 200): Response {
  return new Response(JSON.stringify(Value), { headers: { "Content-Type": "application/json" }, status: Status });
}

describe("HttpNfsTargetClient", () => {
  it("loads exact consent fields and sends generation-fenced replay-safe mutations", async () => {
    const Server = new ContractServer();
    const Client = new HttpNfsTargetClient(Server.fetch, "https://filebelt.example.test");

    await expect(Client.getOverview()).resolves.toEqual(Overview);
    await Client.approveProposal(ProposalId, 1);
    await Client.declineProposal(ProposalId, 1);
    await Client.revokeMapping(CredentialId, 2);

    const Mutations = Server.Requests.filter(({ method: Method }) => Method !== "GET");
    expect(Mutations).toHaveLength(3);
    for (const RequestValue of Mutations) {
      expect(RequestValue.headers.get("X-FileBelt-Csrf")).toBe("csrf-memory-only");
      expect(RequestValue.headers.get("Idempotency-Key")).toMatch(/^[0-9a-f-]{36}$/);
      expect(RequestValue.headers.get("Origin")).toBe("https://filebelt.example.test");
      expect(RequestValue.headers.get("Sec-Fetch-Site")).toBe("same-origin");
      expect(RequestValue.url).not.toContain("csrf-memory-only");
    }
    expect(await Mutations[0]?.clone().json()).toEqual({ expected_generation: 1 });
    expect(new URL(Mutations[2]!.url).searchParams.get("expected_generation")).toBe("2");
  });

  it("surfaces recent OIDC reauthentication", async () => {
    const Server = new ContractServer();
    Server.ReauthenticationRequired = true;
    const Client = new HttpNfsTargetClient(Server.fetch, "https://filebelt.example.test");

    await expect(Client.approveProposal(ProposalId, 1)).rejects.toBeInstanceOf(MountReauthenticationRequiredError);
  });
});
