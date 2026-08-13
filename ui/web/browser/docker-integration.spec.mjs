// SPDX-License-Identifier: Apache-2.0
// Live Docker collaboration boundary; this suite never targets production.

import { execFileSync } from "node:child_process";
import process from "node:process";

import { expect, test } from "@playwright/test";

const NodeIds = JSON.parse(process.env.FILEBELT_COLLABORATION_NODE_IDS ?? "{}");
const DriveId = process.env.FILEBELT_COLLABORATION_DRIVE_ID;
const MemberId = process.env.FILEBELT_COLLABORATION_MEMBER_ID;
const Project = process.env.FILEBELT_ACCEPTANCE_PROJECT;
const ComposeFiles = (process.env.FILEBELT_ACCEPTANCE_COMPOSE_FILES ?? "").split(":").filter(Boolean);
const Profiles = (process.env.FILEBELT_ACCEPTANCE_PROFILES ?? "").split(":").filter(Boolean);

if (Object.keys(NodeIds).length !== 4 || !DriveId || !MemberId || !Project || ComposeFiles.length === 0 || Profiles.length === 0) {
  throw new Error("collaboration acceptance environment is incomplete");
}

function Compose(...Arguments) {
  const Prefix = ["compose", "--project-name", Project];
  for (const File of ComposeFiles) Prefix.push("--file", File);
  for (const Profile of Profiles) Prefix.push("--profile", Profile);
  execFileSync("docker", [...Prefix, ...Arguments], { stdio: "ignore" });
}

async function Login(Context, User) {
  const Page = await Context.newPage();
  await Page.goto("/api/v1/auth/login?return_path=%2F");
  await Page.getByRole("link", { name: User === "admin" ? "Administrator" : "Member" }).click();
  await expect(Page.getByRole("heading", { name: "My Drive" })).toBeVisible();
  return Page;
}

async function Session(Page) {
  return Page.evaluate(async () => {
    const Response = await fetch("/api/v1/session", { credentials: "same-origin" });
    if (!Response.ok) throw new Error(`session failed with ${Response.status}`);
    return Response.json();
  });
}

async function AppendEditorLine(Page, Editor, Value) {
  await Editor.click();
  await Page.keyboard.press("Control+End");
  await Page.keyboard.press("Enter");
  await Page.keyboard.type(Value);
  await expect(Editor).toContainText(Value);
}

async function ReplaceEditorText(Page, Editor, Value) {
  await Editor.click();
  await Page.keyboard.press("Control+A");
  const Lines = Value.split("\n");
  for (const [Index, Line] of Lines.entries()) {
    if (Line.length > 0) await Page.keyboard.type(Line);
    if (Index + 1 < Lines.length) await Page.keyboard.press("Enter");
  }
  await expect(Editor).toContainText(Lines.findLast((Line) => Line.length > 0) ?? "");
}

async function VerifyGrantIsOneUse(Page, NodeId) {
  return Page.evaluate(async ({ Drive, Node }) => {
    const SessionResponse = await fetch("/api/v1/session", { credentials: "same-origin" });
    const SessionValue = await SessionResponse.json();
    const GrantResponse = await fetch(`/api/v1/drives/${Drive}/nodes/${Node}/collaboration-grants`, {
      body: JSON.stringify({ client_id: crypto.randomUUID(), presence_mode: "display_name", transport: "websocket" }),
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID(), "Origin": location.origin, "Sec-Fetch-Site": "same-origin", "X-FileBelt-Csrf": SessionValue.csrf_token },
      method: "POST",
    });
    if (GrantResponse.status !== 201) return `grant:${GrantResponse.status}`;
    const Grant = await GrantResponse.json();
    const Endpoint = Grant.endpoints.find((Value) => Value.transport === "websocket")?.url;
    if (Endpoint === undefined || Grant.room.room_id === null) return "grant:missing";
    const Varint = (Value) => {
      const Bytes = [];
      let Remaining = Value;
      do {
        let Byte = Remaining & 0x7f;
        Remaining = Math.floor(Remaining / 128);
        if (Remaining > 0) Byte |= 0x80;
        Bytes.push(Byte);
      } while (Remaining > 0);
      return Bytes;
    };
    const Field = (NumberValue, Bytes) => [...Varint((NumberValue << 3) | 2), ...Varint(Bytes.length), ...Bytes];
    const Text = (Value) => [...new TextEncoder().encode(Value)];
    const Inner = [
      ...Field(1, Text(Grant.authorization)),
      ...Field(2, Text(Grant.room.room_id)),
      ...Varint(3 << 3), ...Varint(1),
      ...Varint(4 << 3), ...Varint(1),
    ];
    const Hello = new Uint8Array(Field(1, Inner));
    const Invoke = () => new Promise((Resolve) => {
      const Socket = new WebSocket(Endpoint);
      Socket.binaryType = "arraybuffer";
      const Timer = setTimeout(() => { Socket.close(); Resolve("timeout"); }, 10_000);
      Socket.addEventListener("open", () => Socket.send(Hello), { once: true });
      Socket.addEventListener("message", (Event) => {
        clearTimeout(Timer);
        const Bytes = new Uint8Array(Event.data);
        const Outcome = Bytes[0] === 0x1a ? "sync" : Bytes[0] === 0x4a ? "rejected" : `frame:${Bytes[0]}`;
        Socket.close();
        Resolve(Outcome);
      }, { once: true });
      Socket.addEventListener("close", () => { clearTimeout(Timer); Resolve("closed"); }, { once: true });
      Socket.addEventListener("error", () => { clearTimeout(Timer); Resolve("error"); }, { once: true });
    });
    const First = await Invoke();
    const Second = await Invoke();
    return `${First}:${Second}`;
  }, { Drive: DriveId, Node: NodeId });
}

async function CommitExternalHead(Page, NodeId) {
  return Page.evaluate(async ({ Drive, Node }) => {
    const Json = async (Response, Operation) => {
      if (!Response.ok) throw new Error(`${Operation} failed with ${Response.status}`);
      return Response.json();
    };
    const SessionValue = await Json(
      await fetch("/api/v1/session", { credentials: "same-origin" }),
      "session",
    );
    const NodeValue = await Json(
      await fetch(`/api/v1/drives/${Drive}/nodes/${Node}`, { credentials: "same-origin" }),
      "node",
    );
    const MutationHeaders = () => ({
      "Content-Type": "application/json",
      "Idempotency-Key": crypto.randomUUID(),
      "Origin": location.origin,
      "Sec-Fetch-Site": "same-origin",
      "X-FileBelt-Csrf": SessionValue.csrf_token,
    });
    const Bytes = new TextEncoder().encode("# Collaboration\n\nexternal head\n");
    const Allocation = await Json(await fetch(`/api/v1/drives/${Drive}/uploads`, {
      body: JSON.stringify({
        declared_size_bytes: Bytes.byteLength,
        expected_head_version_id: NodeValue.head_version_id,
        expected_parent_generation: null,
        name: NodeValue.display_name,
        node_id: Node,
        parent_id: NodeValue.parent_id,
      }),
      credentials: "same-origin",
      headers: MutationHeaders(),
      method: "POST",
    }), "allocate external head");
    const Grants = await Json(
      await fetch(Allocation.grants_url, { credentials: "same-origin" }),
      "external grants",
    );
    if (Grants.parts.length !== 1) throw new Error("external fixture expected one upload part");
    const Part = Grants.parts[0];
    const Receipt = await fetch(Part.path, {
      body: Bytes,
      headers: {
        "Authorization": `fbcap1 ${Part.authorization}`,
        "Content-Type": "application/octet-stream",
      },
      method: "PUT",
    });
    if (!Receipt.ok) throw new Error(`external part failed with ${Receipt.status}`);
    const Finalized = await fetch(Grants.finalize.path, {
      headers: { "Authorization": `fbcap1 ${Grants.finalize.authorization}` },
      method: "POST",
    });
    if (!Finalized.ok) throw new Error(`external finalize failed with ${Finalized.status}`);
    const Committed = await Json(await fetch(`/api/v1/uploads/${Allocation.upload_id}/commit`, {
      body: JSON.stringify({ expected_fencing_token: Allocation.fencing_token }),
      credentials: "same-origin",
      headers: MutationHeaders(),
      method: "POST",
    }), "commit external head");
    return Committed.version_id;
  }, { Drive: DriveId, Node: NodeId });
}

test("converges, checkpoints, reconnects, and revokes a two-user room", async ({ browser: BrowserValue, browserName: BrowserName }) => {
  const NodeId = NodeIds[`${BrowserName}:convergence`];
  const AdminContext = await BrowserValue.newContext({ ignoreHTTPSErrors: true });
  const MemberContext = await BrowserValue.newContext({ ignoreHTTPSErrors: true });
  const Admin = await Login(AdminContext, "admin");
  const Member = await Login(MemberContext, "member");
  const AdminSession = await Session(Admin);
  const ShareStatus = await Admin.evaluate(async ({ Drive, Node, Csrf }) => {
    const Response = await fetch(`/api/v1/drives/${Drive}/nodes/${Node}/shares`, {
      body: JSON.stringify({ inheritance: "self", kind: "direct", preset: "contributor", verified_email: "member@example.test" }),
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID(), "Origin": location.origin, "Sec-Fetch-Site": "same-origin", "X-FileBelt-Csrf": Csrf },
      method: "POST",
    });
    return Response.status;
  }, { Drive: DriveId, Node: NodeId, Csrf: AdminSession.csrf_token });
  expect([201, 409]).toContain(ShareStatus);
  // This wire-level contract is independent of the browser engine. Exercise
  // it once so the shared room does not retain a redundant participant while
  // both engines still cover the complete two-user application flow.
  if (BrowserName === "chromium") {
    expect(await VerifyGrantIsOneUse(Admin, NodeId)).toMatch(/^sync:(?:rejected|closed|error)$/);
  }
  await Admin.goto(`/markdown/${NodeId}`);
  await Member.goto(`/markdown/${NodeId}`);
  await expect(Admin.getByText("Live collaboration connected.")).toBeVisible();
  await expect(Member.getByText("Live collaboration connected.")).toBeVisible();

  const AdminEditor = Admin.getByRole("textbox", { name: "Markdown source" });
  const MemberEditor = Member.getByRole("textbox", { name: "Markdown source" });
  await AppendEditorLine(Admin, AdminEditor, "admin-edit");
  await expect(Admin.getByText("Live collaboration connected.")).toBeVisible();
  await expect(MemberEditor).toContainText("admin-edit");
  await AppendEditorLine(Member, MemberEditor, "member-edit");
  await expect(Member.getByText("Live collaboration connected.")).toBeVisible();
  await expect(AdminEditor).toContainText("member-edit");
  await Admin.getByRole("button", { name: "Save" }).click();
  await expect(Admin.getByRole("button", { name: "Save" })).toBeDisabled();

  Compose("restart", "filebelt-collaboration");
  await expect(Admin.getByText("Live collaboration disconnected.")).toBeVisible({ timeout: 30_000 });
  await Admin.getByRole("button", { name: "Reconnect" }).click();
  await expect(Admin.getByText("Live collaboration connected.")).toBeVisible({ timeout: 60_000 });

  const Revoked = await Admin.evaluate(async ({ Drive, Node, Principal, Csrf }) => {
    const Response = await fetch(`/api/v1/drives/${Drive}/nodes/${Node}/shares/${Principal}`, {
      credentials: "same-origin",
      headers: { "Origin": location.origin, "Sec-Fetch-Site": "same-origin", "X-FileBelt-Csrf": Csrf },
      method: "DELETE",
    });
    return Response.status;
  }, { Drive: DriveId, Node: NodeId, Principal: MemberId, Csrf: AdminSession.csrf_token });
  expect(Revoked).toBe(204);
  await expect(Member.getByText("Live collaboration disconnected.")).toBeVisible({ timeout: 60_000 });
  await AdminContext.close();
  await MemberContext.close();
});

test("freezes dirty collaboration on an external head and surfaces a conflict copy", async ({ browser: BrowserValue, browserName: BrowserName }) => {
  const NodeId = NodeIds[`${BrowserName}:conflict`];
  const AdminContext = await BrowserValue.newContext({ ignoreHTTPSErrors: true });
  const MemberContext = await BrowserValue.newContext({ ignoreHTTPSErrors: true });
  const Admin = await Login(AdminContext, "admin");
  const Member = await Login(MemberContext, "member");
  const AdminSession = await Session(Admin);
  const ShareStatus = await Admin.evaluate(async ({ Drive, Node, Csrf }) => {
    const Response = await fetch(`/api/v1/drives/${Drive}/nodes/${Node}/shares`, {
      body: JSON.stringify({ inheritance: "self", kind: "direct", preset: "contributor", verified_email: "member@example.test" }),
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID(), "Origin": location.origin, "Sec-Fetch-Site": "same-origin", "X-FileBelt-Csrf": Csrf },
      method: "POST",
    });
    return Response.status;
  }, { Drive: DriveId, Node: NodeId, Csrf: AdminSession.csrf_token });
  expect([201, 409]).toContain(ShareStatus);

  await Admin.goto(`/markdown/${NodeId}`);
  await Member.goto(`/markdown/${NodeId}`);
  await expect(Admin.getByText("Live collaboration connected.")).toBeVisible();
  await expect(Member.getByText("Live collaboration connected.")).toBeVisible();
  const AdminEditor = Admin.getByRole("textbox", { name: "Markdown source" });
  await ReplaceEditorText(Admin, AdminEditor, "# Collaboration\n\nlocal dirty\n");
  await expect(Admin.getByText("Live collaboration connected.")).toBeVisible();
  await expect(Member.getByRole("textbox", { name: "Markdown source" })).toContainText("local dirty");

  await CommitExternalHead(Admin, NodeId);
  await expect(Admin.getByText("Live collaboration disconnected.")).toBeVisible({ timeout: 60_000 });
  await expect(Member.getByText("Live collaboration disconnected.")).toBeVisible({ timeout: 60_000 });
  await Admin.getByRole("button", { name: "Reconnect" }).click();
  await expect(Admin.getByRole("button", { name: "Save local edits as a copy" })).toBeVisible();
  await AdminContext.close();
  await MemberContext.close();
});
