// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { components } from "./generated/openapi.js";
import {
  HttpMountSettingsClient,
  MountReauthenticationRequiredError,
} from "./mount-http-client.js";

const DriveId = "00000000-0000-4000-8000-000000000071";
const CredentialId = "00000000-0000-4000-8000-000000000072";

const Session = {
  csrf_token: "csrf-memory-only",
  display_name: "Avery Morgan",
  principal_id: "00000000-0000-4000-8000-000000000073",
  reauthenticated_recently: true,
  session_id: "00000000-0000-4000-8000-000000000074",
  tenant_admin: false,
  user_id: "00000000-0000-4000-8000-000000000075",
  verified_email: "avery@example.test",
} satisfies components["schemas"]["Session"];

class ContractServer {
  readonly Requests: Request[] = [];
  ReauthenticationRequired = false;

  // oxlint-disable-next-line filebelt/pascal-case, typescript/require-await -- Fetch's platform spelling and Promise contract are required by the injected transport fake.
  readonly fetch: typeof fetch = async (Input, Init) => {
    const RequestValue = Input instanceof Request ? Input : new Request(Input, Init);
    this.Requests.push(RequestValue);
    const Url = new URL(RequestValue.url);
    if (Url.pathname === "/api/v1/session") return Json(Session);
    if (Url.pathname === "/api/v1/mounts/credentials" && RequestValue.method === "POST") {
      if (this.ReauthenticationRequired) {
        return Json(
          {
            code: "mount.reauthentication_required",
            status: 403,
            title: "Recent OIDC authentication is required",
            type: "https://filebelt.dev/problems/mount.reauthentication_required",
          },
          403,
        );
      }
      return Json(
        {
          credential_id: CredentialId,
          expires_at: "2026-08-15T10:00:00Z",
          password: "one-time-password",
          protocol: "smb",
          username: "fb-example",
        },
        201,
      );
    }
    return new Response(null, { status: 404 });
  };
}

function Json(Value: unknown, Status = 200): Response {
  return new Response(JSON.stringify(Value), {
    headers: { "Content-Type": "application/json" },
    status: Status,
  });
}

describe("HttpMountSettingsClient", () => {
  it("creates a scoped credential with CSRF protection and keeps secrets out of the URL", async () => {
    const Server = new ContractServer();
    const Client = new HttpMountSettingsClient(Server.fetch, "https://filebelt.example.test");
    const Created = await Client.createCredential({
      allowed_drive_ids: [DriveId],
      bound_device_id: null,
      expires_at: "2026-08-15T10:00:00Z",
      protocol: "smb",
      read_only: true,
    });

    expect(Created.password).toBe("one-time-password");
    const RequestValue = Server.Requests.at(-1);
    expect(RequestValue?.url).not.toContain("one-time-password");
    expect(RequestValue?.headers.get("X-FileBelt-Csrf")).toBe("csrf-memory-only");
    expect(await RequestValue?.clone().json()).toEqual({
      allowed_drive_ids: [DriveId],
      bound_device_id: null,
      expires_at: "2026-08-15T10:00:00Z",
      protocol: "smb",
      read_only: true,
    });
  });

  it("maps the stable recent-authentication problem to an actionable error", async () => {
    const Server = new ContractServer();
    Server.ReauthenticationRequired = true;
    const Client = new HttpMountSettingsClient(Server.fetch, "https://filebelt.example.test");

    await expect(
      Client.createCredential({
        allowed_drive_ids: [DriveId],
        bound_device_id: null,
        expires_at: "2026-08-15T10:00:00Z",
        protocol: "smb",
        read_only: true,
      }),
    ).rejects.toBeInstanceOf(MountReauthenticationRequiredError);
  });
});
