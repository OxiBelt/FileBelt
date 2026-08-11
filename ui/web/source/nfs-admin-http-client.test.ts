// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { components } from "./generated/openapi.js";
import { HttpNfsAdminClient, NfsReauthenticationRequiredError } from "./nfs-admin-http-client.js";

const DriveId = "00000000-0000-4000-8000-000000000111";
const CredentialId = "00000000-0000-4000-8000-000000000112";

const Session = {
  csrf_token: "csrf-memory-only",
  display_name: "Avery Morgan",
  principal_id: "00000000-0000-4000-8000-000000000113",
  reauthenticated_recently: true,
  session_id: "00000000-0000-4000-8000-000000000114",
  tenant_admin: true,
  user_id: "00000000-0000-4000-8000-000000000115",
  verified_email: "avery@example.test",
} satisfies components["schemas"]["Session"];

const Overview = {
  exports: [{
    applied_generation: 1,
    applied_state: "active",
    desired_generation: 2,
    desired_state: "draining",
    drive_id: DriveId,
    export_id: 7,
    export_path: `/filebelt/${DriveId}`,
    in_sync: false,
  }],
  feature: {
    applied_gateway_epoch: 4,
    applied_gateway_id: "nfs-gateway-1",
    applied_manifest_generation: 8,
    desired_manifest_generation: 9,
    generation: 3,
    manifest_applied: false,
    restore_generation: 1,
    state: "draining",
  },
  mappings: [{
    credential_id: CredentialId,
    generation: 2,
    kerberos_principal: "alice@EXAMPLE.TEST",
    principal_id: "00000000-0000-4000-8000-000000000116",
    projected_gid: 2001,
    projected_uid: 1001,
  }],
  posix_groups: [{
    group_id: "00000000-0000-4000-8000-000000000117",
    posix_name: "engineering.platform",
    projected_gid: 2001,
  }],
} satisfies components["schemas"]["NfsAdminOverview"];

class ContractServer {
  readonly Requests: Request[] = [];
  ReauthenticationRequired = false;

  readonly fetch: typeof fetch = async (Input, Init) => {
    const RequestValue = Input instanceof Request ? Input : new Request(Input, Init);
    this.Requests.push(RequestValue);
    const Url = new URL(RequestValue.url);
    if (Url.pathname === "/api/v1/session") return Json(Session);
    if (Url.pathname === "/api/v1/admin/mounts/nfs" && RequestValue.method === "GET") {
      if (this.ReauthenticationRequired) {
        return Problem({ code: "admin.reauthentication_required", status: 403, title: "Recent tenant administrator authentication is required", type: "https://filebelt.dev/problems/admin.reauthentication_required" }, 403);
      }
      return Json(Overview);
    }
    if (Url.pathname === `/api/v1/admin/mounts/nfs/exports/${DriveId}` && RequestValue.method === "PUT") {
      return Json(Overview.exports[0]);
    }
    return new Response(null, { status: 404 });
  };
}

function Json(Value: unknown, Status = 200): Response {
  return new Response(JSON.stringify(Value), { headers: { "Content-Type": "application/json" }, status: Status });
}

function Problem(Value: unknown, Status: number): Response {
  return new Response(JSON.stringify(Value), { headers: { "Content-Type": "application/problem+json" }, status: Status });
}

describe("HttpNfsAdminClient", () => {
  it("maps desired and applied state without treating pending intent as applied", async () => {
    const Server = new ContractServer();
    const Client = new HttpNfsAdminClient(Server.fetch, "https://filebelt.example.test");

    const Result = await Client.getOverview();

    expect(Result.Feature.ManifestApplied).toBe(false);
    expect(Result.Exports[0]).toMatchObject({ AppliedGeneration: 1, DesiredGeneration: 2, InSync: false });
    expect(Result.Mappings[0]?.KerberosPrincipal).toBe("alice@EXAMPLE.TEST");
  });

  it("generation-fences an export transition with memory-only CSRF and idempotency headers", async () => {
    const Server = new ContractServer();
    const Client = new HttpNfsAdminClient(Server.fetch, "https://filebelt.example.test");

    await Client.transitionExport(DriveId, 2, "draining");

    const RequestValue = Server.Requests.at(-1);
    expect(RequestValue?.headers.get("X-FileBelt-Csrf")).toBe("csrf-memory-only");
    expect(RequestValue?.headers.get("Idempotency-Key")).toMatch(/^[0-9a-f-]{36}$/);
    expect(RequestValue?.url).not.toContain("csrf-memory-only");
    expect(await RequestValue?.clone().json()).toEqual({ expected_generation: 2, target_state: "draining" });
  });

  it("maps the stable tenant-admin recent-authentication problem", async () => {
    const Server = new ContractServer();
    Server.ReauthenticationRequired = true;
    const Client = new HttpNfsAdminClient(Server.fetch, "https://filebelt.example.test");

    await expect(Client.getOverview()).rejects.toBeInstanceOf(NfsReauthenticationRequiredError);
  });
});
