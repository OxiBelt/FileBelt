// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";

declare global {
  interface Window {
    FileBeltCopiedCommitOid?: string;
  }
}

const DriveId = "00000000-0000-4000-8000-000000000001";
const RootId = "00000000-0000-4000-8000-000000000002";
const NodeId = "00000000-0000-4000-8000-000000000003";
const VersionId = "00000000-0000-4000-8000-000000000004";
const GitCommitOid = "a".repeat(64);

test("keeps text history usable when the Clipboard API is unavailable", async ({ page: Page }) => {
  const PageErrors: Error[] = [];
  Page.on("pageerror", (Error) => {
    PageErrors.push(Error);
  });
  await Page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
  });
  await MockWorkspace(Page);

  await OpenTextHistory(Page);
  await Page.getByRole("button", { name: `Copy full commit identifier ${GitCommitOid}` }).click();

  await expect(Page.getByRole("heading", { name: "Text history" })).toBeVisible();
  expect(PageErrors).toEqual([]);
});

test("copies the full text-history commit identifier when Clipboard is available", async ({
  page: Page,
}) => {
  await Page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        // oxlint-disable-next-line typescript/require-await -- Clipboard is asynchronous, while this in-page test spy records synchronously.
        writeText: async (Value: string) => {
          window.FileBeltCopiedCommitOid = Value;
        },
      },
    });
  });
  await MockWorkspace(Page);

  await OpenTextHistory(Page);
  await Page.getByRole("button", { name: `Copy full commit identifier ${GitCommitOid}` }).click();

  await expect
    .poll(async () => {
      const CopiedCommitOid = await Page.evaluate(() => window.FileBeltCopiedCommitOid);
      return CopiedCommitOid;
    })
    .toBe(GitCommitOid);
});

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- Playwright owns the mutable page fixture used to register routes.
async function MockWorkspace(Page: Page): Promise<void> {
  await Page.route("**/*", async (Route) => {
    const Request = Route.request();
    if (Request.resourceType() !== "fetch") return Route.continue();
    const Path = new URL(Request.url()).pathname;
    if (Path === "/api/v1/session") return Route.fulfill({ json: Session() });
    if (Path === "/api/v1/drives")
      return Route.fulfill({
        json: {
          items: [
            {
              display_name: "My Drive",
              id: DriveId,
              kind: "private",
              quota_bytes: 1,
              root_id: RootId,
              used_physical_bytes: 0,
            },
          ],
          next_cursor: null,
        },
      });
    if (Path === `/api/v1/drives/${DriveId}/nodes/${RootId}`)
      return Route.fulfill({ json: Node(RootId, "My Drive", "directory", null, null) });
    if (Path === `/api/v1/drives/${DriveId}/nodes/${RootId}/children`)
      return Route.fulfill({
        json: { items: [Node(NodeId, "notes.txt", "file", RootId, VersionId)], next_cursor: null },
      });
    if (Path === `/api/v1/drives/${DriveId}/trash`)
      return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path.endsWith("/versions"))
      return Route.fulfill({ json: { items: [Version()], next_cursor: null } });
    if (Path.endsWith("/shares")) return Route.fulfill({ json: [] });
    if (Path === "/api/v1/shared") return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path === "/api/v1/sessions") return Route.fulfill({ json: [] });
    return Route.fulfill({
      status: 404,
      json: { code: "test.unhandled", status: 404, title: Path, type: "about:blank" },
    });
  });
}

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- Playwright owns the mutable page fixture used to drive the browser.
async function OpenTextHistory(Page: Page): Promise<void> {
  await Page.goto("/");
  await Page.getByRole("row", { name: /notes\.txt/ }).click();
  await Page.getByRole("toolbar", { name: "File commands" })
    .getByRole("button", { name: "Versions" })
    .click();
  await expect(Page.getByRole("heading", { name: "Text history" })).toBeVisible();
}

function Session(): object {
  return {
    csrf_token: "memory-only",
    display_name: "Avery Morgan",
    principal_id: "00000000-0000-4000-8000-000000000005",
    reauthenticated_recently: true,
    session_id: "00000000-0000-4000-8000-000000000006",
    tenant_admin: false,
    user_id: "00000000-0000-4000-8000-000000000007",
    verified_email: "avery@example.test",
  };
}

function Node(
  Id: string,
  Name: string,
  Kind: "directory" | "file",
  ParentId: string | null,
  HeadVersionId: string | null,
): object {
  return {
    acl_generation: 1,
    display_name: Name,
    drive_id: DriveId,
    head_media_type: Kind === "file" ? "text/plain" : null,
    head_version_id: HeadVersionId,
    id: Id,
    kind: Kind,
    namespace_generation: 1,
    parent_id: ParentId,
    size_bytes: Kind === "file" ? 42 : null,
    trashed: false,
    updated_at: "2026-08-08T00:00:00Z",
    version_ordinal: Kind === "file" ? 1 : null,
  };
}

function Version(): object {
  return {
    created_at: "2026-08-08T00:00:00Z",
    created_by: "00000000-0000-4000-8000-000000000005",
    current: true,
    git_commit_oid: GitCommitOid,
    id: VersionId,
    media_type: "text/plain",
    node_id: NodeId,
    observed_content_class: "text",
    ordinal: 1,
    provenance: {
      creator_display_name: "Avery Morgan",
      mcp_assisted: false,
      origin: "upload",
      source_version_id: null,
    },
    restored_from_version_id: null,
    revision_backend: "git_sha256",
    size_bytes: 42,
  };
}
