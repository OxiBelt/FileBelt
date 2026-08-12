// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";

test.describe.configure({ mode: "serial" });

const DriveId = "00000000-0000-4000-8000-000000000001";
const RootId = "00000000-0000-4000-8000-000000000002";
const NodeId = "00000000-0000-4000-8000-000000000003";
const VersionId = "00000000-0000-4000-8000-000000000004";
const MarkdownBody = "# Readme\n\n<img src=x onerror=alert(1)>\n";

test("opens an eligible Markdown file through its lazy editor route", async ({ page: Page }) => {
  await Page.route("**/*", async (Route) => {
    const Request = Route.request();
    if (Request.resourceType() !== "fetch") return Route.continue();
    const Path = new URL(Request.url()).pathname;
    if (Path === "/api/v1/session") return Route.fulfill({ json: Session() });
    if (Path === "/api/v1/drives") return Route.fulfill({ json: { items: [{ display_name: "My Drive", id: DriveId, kind: "private", quota_bytes: 1, root_id: RootId, used_physical_bytes: 0 }], next_cursor: null } });
    if (Path === `/api/v1/drives/${DriveId}/nodes/${RootId}`) return Route.fulfill({ json: Node(RootId, "My Drive", "directory", null, null) });
    if (Path === `/api/v1/drives/${DriveId}/nodes/${RootId}/children`) return Route.fulfill({ json: { items: [Node(NodeId, "README.md", "file", RootId, VersionId)], next_cursor: null } });
    if (Path === `/api/v1/drives/${DriveId}/trash`) return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path.endsWith("/versions")) return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path.endsWith("/shares")) return Route.fulfill({ json: [] });
    if (Path === "/api/v1/shared") return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path === "/api/v1/sessions") return Route.fulfill({ json: [] });
    if (Path.endsWith("/download-grants")) return Route.fulfill({ status: 201, json: { authorization: "unused", authorization_scheme: "fbcap1", expires_at: "2026-08-08T01:00:00Z", grant_id: VersionId, method: "GET", path: `/io/v1/downloads/${VersionId}`, size_bytes: MarkdownBody.length } });
    if (Path === `/io/v1/downloads/${VersionId}`) return Route.fulfill({ body: MarkdownBody, contentType: "text/markdown" });
    return Route.fulfill({ status: 404, json: { code: "test.unhandled", status: 404, title: Path, type: "about:blank" } });
  });

  const PreviewResponse = Page.waitForResponse((Response) => new URL(Response.url()).pathname === "/markdown-preview/index.html");
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
  expect(PreviewHeaders["content-security-policy"]).toContain("trusted-types filebelt-markdown-generated");
});

test("reconnects after an initial collaboration failure and closes a live session after guarded navigation", async ({ page: Page }) => {
  await Page.addInitScript(() => {
    let Connections = 0;
    (window as Window & { FileBeltClosedSockets?: number }).FileBeltClosedSockets = 0;
    class MockWebSocket extends EventTarget {
      // eslint-disable-next-line @typescript-eslint/naming-convention -- WebSocket platform property used by the collaboration client.
      binaryType = "arraybuffer";
      readonly CONNECTING = 0;
      readonly OPEN = 1;
      readonly CLOSING = 2;
      readonly CLOSED = 3;
      // eslint-disable-next-line @typescript-eslint/naming-convention -- WebSocket platform property used by the collaboration client.
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
          this.dispatchEvent(new MessageEvent("message", { data: new Uint8Array([26, 10, 8, 0, 16, 0, 24, 1, 34, 0, 40, 1]).buffer }));
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
    if (Path === "/api/v1/drives") return Route.fulfill({ json: { items: [{ display_name: "My Drive", id: DriveId, kind: "private", quota_bytes: 1, root_id: RootId, used_physical_bytes: 0 }], next_cursor: null } });
    if (Path === `/api/v1/drives/${DriveId}/nodes/${RootId}`) return Route.fulfill({ json: Node(RootId, "My Drive", "directory", null, null) });
    if (Path === `/api/v1/drives/${DriveId}/nodes/${NodeId}`) return Route.fulfill({ json: Node(NodeId, "README.md", "file", RootId, VersionId) });
    if (Path === `/api/v1/drives/${DriveId}/nodes/${RootId}/children`) return Route.fulfill({ json: { items: [Node(NodeId, "README.md", "file", RootId, VersionId)], next_cursor: null } });
    if (Path.endsWith("/collaboration-grants")) return Route.fulfill({ status: 201, json: { authorization: "test-grant", endpoints: [{ transport: "websocket", url: "ws://collaboration.test/room" }], presence_label: "Avery", room: { room_id: "00000000-0000-4000-8000-000000000009" } } });
    if (Path === `/api/v1/drives/${DriveId}/trash`) return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path.endsWith("/versions")) return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path.endsWith("/shares")) return Route.fulfill({ json: [] });
    if (Path === "/api/v1/shared") return Route.fulfill({ json: { items: [], next_cursor: null } });
    if (Path === "/api/v1/sessions") return Route.fulfill({ json: [] });
    if (Path.endsWith("/download-grants")) return Route.fulfill({ status: 201, json: { authorization: "unused", authorization_scheme: "fbcap1", expires_at: "2026-08-08T01:00:00Z", grant_id: VersionId, method: "GET", path: `/io/v1/downloads/${VersionId}`, size_bytes: MarkdownBody.length } });
    if (Path === `/io/v1/downloads/${VersionId}`) return Route.fulfill({ body: MarkdownBody, contentType: "text/markdown" });
    return Route.fulfill({ status: 404, json: { code: "test.unhandled", status: 404, title: Path, type: "about:blank" } });
  });

  await Page.goto(`/markdown/${NodeId}`);
  await expect(Page.getByText("Live collaboration disconnected.")).toBeVisible();
  await expect(Page.getByRole("button", { name: "Reconnect" })).toBeVisible();
  await Page.getByRole("button", { name: "Reconnect" }).click();
  await expect(Page.getByText("Live collaboration connected.")).toBeVisible();
  const Editor = Page.getByRole("textbox", { name: "Markdown source" });
  await Editor.click();
  await Page.keyboard.press("End");
  await Page.keyboard.type(" retained after reconnect");
  await Page.getByRole("button", { name: "Back to files" }).click();
  await expect(Page.getByRole("dialog", { name: "Leave without saving?" })).toBeVisible();
  await Page.getByRole("button", { name: "Discard changes" }).click();
  await expect(Page.getByRole("heading", { name: "My Drive" })).toBeVisible();
  await expect.poll(() => Page.evaluate(() => (window as Window & { FileBeltClosedSockets?: number }).FileBeltClosedSockets ?? 0)).toBeGreaterThan(0);
});

function Session(): object {
  return { csrf_token: "memory-only", display_name: "Avery Morgan", principal_id: "00000000-0000-4000-8000-000000000005", reauthenticated_recently: true, session_id: "00000000-0000-4000-8000-000000000006", tenant_admin: false, user_id: "00000000-0000-4000-8000-000000000007", verified_email: "avery@example.test" };
}

function Node(Id: string, Name: string, Kind: "directory" | "file", ParentId: string | null, HeadVersionId: string | null): object {
  return { acl_generation: 1, display_name: Name, drive_id: DriveId, head_media_type: Kind === "file" ? "text/markdown" : null, head_version_id: HeadVersionId, id: Id, kind: Kind, namespace_generation: 1, parent_id: ParentId, size_bytes: Kind === "file" ? 9 : null, trashed: false, updated_at: "2026-08-08T00:00:00Z", version_ordinal: Kind === "file" ? 1 : null };
}
