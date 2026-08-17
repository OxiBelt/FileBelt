// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";

declare global {
  interface Window {
    FileBeltClosedSockets?: number;
  }
}

test.describe.configure({ mode: "serial" });

const DriveId = "00000000-0000-4000-8000-000000000001";
const RootId = "00000000-0000-4000-8000-000000000002";
const NodeId = "00000000-0000-4000-8000-000000000003";
const VersionId = "00000000-0000-4000-8000-000000000004";
const NewVersionId = "00000000-0000-4000-8000-000000000015";
const MarkdownBody = "# Readme\n\n<img src=x onerror=alert(1)>\n";

test("opens an eligible Markdown file through its lazy editor route", async ({ page: Page }) => {
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
        json: { items: [Node(NodeId, "README.md", "file", RootId, VersionId)], next_cursor: null },
      });
    if (Path === `/api/v1/drives/${DriveId}/trash`)
      return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path.endsWith("/versions"))
      return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path.endsWith("/shares")) return Route.fulfill({ json: [] });
    if (Path === "/api/v1/shared") return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path === "/api/v1/sessions") return Route.fulfill({ json: [] });
    if (Path.endsWith("/download-grants"))
      return Route.fulfill({
        status: 201,
        json: {
          authorization: "unused",
          authorization_scheme: "fbcap1",
          expires_at: "2026-08-08T01:00:00Z",
          grant_id: VersionId,
          method: "GET",
          path: `/io/v1/downloads/${VersionId}`,
          size_bytes: MarkdownBody.length,
        },
      });
    if (Path === `/io/v1/downloads/${VersionId}`)
      return Route.fulfill({ body: MarkdownBody, contentType: "text/markdown" });
    return Route.fulfill({
      status: 404,
      json: { code: "test.unhandled", status: 404, title: Path, type: "about:blank" },
    });
  });

  const PreviewResponse = Page.waitForResponse(
    (Response) => new URL(Response.url()).pathname === "/markdown-preview/index.html",
  );
  await Page.goto(`/markdown/${NodeId}`);
  await expect(Page.getByRole("heading", { name: "README.md" })).toBeVisible();
  await expect(Page.getByRole("tab", { name: "Edit" })).toBeVisible();
  await expect(Page.getByRole("button", { name: "Save" })).toBeVisible();
  const Preview = Page.frameLocator('iframe[title="Markdown preview"]');
  await expect(Preview.getByText("<img src=x onerror=alert(1)>")).toBeVisible();
  await expect(Preview.locator("img")).toHaveCount(0);
  const Editor = Page.getByRole("textbox", { name: "Markdown source" });
  await Editor.click();
  await Page.keyboard.press("End");
  await Page.keyboard.type(" local edit");
  await Page.getByRole("button", { name: "Back to files" }).click();
  await expect(Page.getByRole("dialog", { name: "Leave without saving?" })).toBeVisible();
  await Page.getByRole("button", { name: "Stay" }).click();
  await expect(Page.getByRole("heading", { name: "README.md" })).toBeVisible();
  expect(new URL(Page.url()).pathname).toBe(`/markdown/${NodeId}`);
  const PreviewHeaders = (await PreviewResponse).headers();
  expect(PreviewHeaders["access-control-allow-origin"]).toBe("*");
  expect(PreviewHeaders["content-security-policy"]).toContain("connect-src 'none'");
  expect(PreviewHeaders["content-security-policy"]).toContain(
    "trusted-types filebelt-markdown-generated",
  );
});

test("reconnects after an initial collaboration failure and closes a live session after guarded navigation", async ({
  page: Page,
}) => {
  let CollaborationGrantRequests = 0;
  let ReleaseReconnect: (() => void) | undefined;
  const ReconnectGate = new Promise<void>((Resolve) => {
    ReleaseReconnect = Resolve;
  });
  await Page.addInitScript(() => {
    let Connections = 0;
    (window as Window & { FileBeltClosedSockets?: number }).FileBeltClosedSockets = 0;
    class MockWebSocket extends EventTarget {
      // oxlint-disable-next-line filebelt/pascal-case -- WebSocket platform property used by the collaboration client.
      binaryType = "arraybuffer";
      readonly CONNECTING = 0;
      readonly OPEN = 1;
      readonly CLOSING = 2;
      readonly CLOSED = 3;
      // oxlint-disable-next-line filebelt/pascal-case -- WebSocket platform property used by the collaboration client.
      readyState = 0;

      constructor(IgnoredUrl: string) {
        super();
        void IgnoredUrl;
        Connections += 1;
        const Connection = Connections;
        window.setTimeout(() => {
          if (Connection === 1) {
            this.readyState = 3;
            this.dispatchEvent(new Event("error"));
            this.dispatchEvent(new Event("close"));
            return;
          }
          this.readyState = 1;
          this.dispatchEvent(new Event("open"));
          // Collaboration frame 3: sequence 0, one empty snapshot chunk.
          this.dispatchEvent(
            new MessageEvent("message", {
              data: new Uint8Array([26, 10, 8, 0, 16, 0, 24, 1, 34, 0, 40, 1]).buffer,
            }),
          );
        }, 0);
      }

      close(IgnoredCode?: number, IgnoredReason?: string): void {
        void IgnoredCode;
        void IgnoredReason;
        if (this.readyState === 3) return;
        this.readyState = 3;
        window.FileBeltClosedSockets = (window.FileBeltClosedSockets ?? 0) + 1;
        this.dispatchEvent(new Event("close"));
      }

      send(IgnoredData: ArrayBufferLike): void {
        void IgnoredData;
      }
    }
    Object.defineProperty(window, "WebSocket", { configurable: true, value: MockWebSocket });
  });
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
    if (Path === `/api/v1/drives/${DriveId}/nodes/${NodeId}`)
      return Route.fulfill({ json: Node(NodeId, "README.md", "file", RootId, VersionId) });
    if (Path === `/api/v1/drives/${DriveId}/nodes/${RootId}/children`)
      return Route.fulfill({
        json: { items: [Node(NodeId, "README.md", "file", RootId, VersionId)], next_cursor: null },
      });
    if (Path.endsWith("/collaboration-grants")) {
      CollaborationGrantRequests += 1;
      if (CollaborationGrantRequests > 1) await ReconnectGate;
      return Route.fulfill({
        status: 201,
        json: {
          authorization: "test-grant",
          endpoints: [{ transport: "websocket", url: "ws://collaboration.test/room" }],
          presence_label: "Avery",
          room: { room_id: "00000000-0000-4000-8000-000000000009" },
        },
      });
    }
    if (Path === `/api/v1/drives/${DriveId}/trash`)
      return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path.endsWith("/versions"))
      return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path.endsWith("/shares")) return Route.fulfill({ json: [] });
    if (Path === "/api/v1/shared") return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path === "/api/v1/sessions") return Route.fulfill({ json: [] });
    if (Path.endsWith("/download-grants"))
      return Route.fulfill({
        status: 201,
        json: {
          authorization: "unused",
          authorization_scheme: "fbcap1",
          expires_at: "2026-08-08T01:00:00Z",
          grant_id: VersionId,
          method: "GET",
          path: `/io/v1/downloads/${VersionId}`,
          size_bytes: MarkdownBody.length,
        },
      });
    if (Path === `/io/v1/downloads/${VersionId}`)
      return Route.fulfill({ body: MarkdownBody, contentType: "text/markdown" });
    return Route.fulfill({
      status: 404,
      json: { code: "test.unhandled", status: 404, title: Path, type: "about:blank" },
    });
  });

  await Page.goto(`/markdown/${NodeId}`);
  await expect(Page.getByText("Live collaboration disconnected.")).toBeVisible();
  const Reconnect = Page.getByRole("button", { name: "Reconnect" });
  await expect(Reconnect).toBeVisible();
  await Reconnect.click();
  await expect(Reconnect).toBeVisible();
  await expect(Reconnect).toBeDisabled();
  await expect(Page.getByText("Connecting live collaboration…")).toBeVisible();
  ReleaseReconnect?.();
  await expect(Page.getByText("Live collaboration connected.")).toBeVisible();
  const Editor = Page.getByRole("textbox", { name: "Markdown source" });
  await Editor.click();
  await Page.keyboard.press("End");
  await Page.keyboard.type(" retained after reconnect");
  await Page.getByRole("button", { name: "Back to files" }).click();
  await expect(Page.getByRole("dialog", { name: "Leave without saving?" })).toBeVisible();
  await Page.getByRole("button", { name: "Discard changes" }).click();
  await expect(Page.getByRole("heading", { name: "My Drive" })).toBeVisible();
  await expect
    .poll(async () =>
      Page.evaluate(
        () => (window as Window & { FileBeltClosedSockets?: number }).FileBeltClosedSockets ?? 0,
      ),
    )
    .toBeGreaterThan(0);
});

test("retains the latest head when reconnect falls back after a frozen room", async ({
  page: Page,
}) => {
  let LatestHead = false;
  let GrantRequests = 0;
  await Page.addInitScript(() => {
    class MockWebSocket extends EventTarget {
      // oxlint-disable-next-line filebelt/pascal-case -- WebSocket platform property used by the collaboration client.
      binaryType = "arraybuffer";
      readonly CONNECTING = 0;
      readonly OPEN = 1;
      readonly CLOSING = 2;
      readonly CLOSED = 3;
      // oxlint-disable-next-line filebelt/pascal-case -- WebSocket platform property used by the collaboration client.
      readyState = 0;

      constructor(IgnoredUrl: string) {
        super();
        void IgnoredUrl;
        (window as Window & { FileBeltDisconnect?: () => void }).FileBeltDisconnect = () => {
          if (this.readyState === 3) return;
          this.readyState = 3;
          this.dispatchEvent(new CloseEvent("close"));
        };
        window.setTimeout(() => {
          this.readyState = 1;
          this.dispatchEvent(new Event("open"));
          this.dispatchEvent(
            new MessageEvent("message", {
              data: new Uint8Array([26, 10, 8, 0, 16, 0, 24, 1, 34, 0, 40, 1]).buffer,
            }),
          );
        }, 0);
      }

      close(): void {
        if (this.readyState === 3) return;
        this.readyState = 3;
        this.dispatchEvent(new CloseEvent("close"));
      }

      send(IgnoredData: ArrayBufferLike): void {
        void IgnoredData;
      }
    }
    Object.defineProperty(window, "WebSocket", { configurable: true, value: MockWebSocket });
  });
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
    if (Path === `/api/v1/drives/${DriveId}/nodes/${NodeId}`)
      return Route.fulfill({
        json: Node(NodeId, "README.md", "file", RootId, LatestHead ? NewVersionId : VersionId),
      });
    if (Path === `/api/v1/drives/${DriveId}/nodes/${RootId}/children`)
      return Route.fulfill({
        json: { items: [Node(NodeId, "README.md", "file", RootId, VersionId)], next_cursor: null },
      });
    if (Path.endsWith("/collaboration-grants")) {
      GrantRequests += 1;
      if (GrantRequests > 1)
        return Route.fulfill({
          status: 409,
          json: {
            code: "collaboration.room_frozen",
            status: 409,
            title: "The request conflicts with current state",
            type: "about:blank",
          },
        });
      return Route.fulfill({
        status: 201,
        json: {
          authorization: "test-grant",
          endpoints: [{ transport: "websocket", url: "ws://collaboration.test/room" }],
          presence_label: "Avery",
          room: { room_id: "00000000-0000-4000-8000-000000000009" },
        },
      });
    }
    if (Path === `/api/v1/drives/${DriveId}/trash`)
      return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path.endsWith("/versions"))
      return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path.endsWith("/shares")) return Route.fulfill({ json: [] });
    if (Path === "/api/v1/shared") return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path === "/api/v1/sessions") return Route.fulfill({ json: [] });
    if (Path.endsWith("/download-grants")) {
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- Playwright exposes decoded hostile request JSON as any at this route boundary.
      const GrantInput = Request.postDataJSON() as Record<string, unknown>;
      const RequestedVersion =
        typeof GrantInput.version_id === "string"
          ? GrantInput.version_id
          : LatestHead
            ? NewVersionId
            : VersionId;
      const Body = RequestedVersion === NewVersionId ? "# Readme\n\nexternal head\n" : MarkdownBody;
      return Route.fulfill({
        status: 201,
        json: {
          authorization: "unused",
          authorization_scheme: "fbcap1",
          expires_at: "2026-08-08T01:00:00Z",
          grant_id: RequestedVersion,
          method: "GET",
          path: `/io/v1/downloads/${RequestedVersion}`,
          size_bytes: Body.length,
        },
      });
    }
    if (Path === `/io/v1/downloads/${VersionId}`)
      return Route.fulfill({ body: MarkdownBody, contentType: "text/markdown" });
    if (Path === `/io/v1/downloads/${NewVersionId}`)
      return Route.fulfill({ body: "# Readme\n\nexternal head\n", contentType: "text/markdown" });
    return Route.fulfill({
      status: 404,
      json: { code: "test.unhandled", status: 404, title: Path, type: "about:blank" },
    });
  });

  await Page.goto(`/markdown/${NodeId}`);
  await expect(Page.getByText("Live collaboration connected.")).toBeVisible();
  const Editor = Page.getByRole("textbox", { name: "Markdown source" });
  await Editor.click();
  await Page.keyboard.press("Control+A");
  await Page.keyboard.type("local dirty");
  await expect(Editor).toContainText("local dirty");
  LatestHead = true;
  await Page.evaluate(() =>
    (window as Window & { FileBeltDisconnect?: () => void }).FileBeltDisconnect?.(),
  );
  await expect(Page.getByText("Live collaboration disconnected.")).toBeVisible();
  await Page.getByRole("button", { name: "Reconnect" }).click();
  await expect(Page.getByRole("button", { name: "Save local edits as a copy" })).toBeVisible();
  await expect(Editor).toContainText("local dirty");
  await expect(Editor).toContainText("external head");
});

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
    head_media_type: Kind === "file" ? "text/markdown" : null,
    head_version_id: HeadVersionId,
    id: Id,
    kind: Kind,
    namespace_generation: 1,
    parent_id: ParentId,
    size_bytes: Kind === "file" ? 9 : null,
    trashed: false,
    updated_at: "2026-08-08T00:00:00Z",
    version_ordinal: Kind === "file" ? 1 : null,
  };
}
