// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { MockFileBeltClient } from "./client.js";

describe("MockFileBeltClient", () => {
  it("exercises trash, restore, upload, and share workflows through the API boundary", async () => {
    const client = new MockFileBeltClient();
    const initial = await client.getWorkspace();
    const file = initial.entries.find(({ kind, trashed }) => kind === "file" && !trashed);
    expect(file).toBeDefined();
    if (file === undefined) return;

    await client.trashEntries([file.id]);
    expect((await client.getWorkspace()).entries.find(({ id }) => id === file.id)?.trashed).toBe(true);
    await client.restoreEntries([file.id]);
    expect((await client.getWorkspace()).entries.find(({ id }) => id === file.id)?.trashed).toBe(false);

    await client.upload([{ name: "New file.txt", size: 128 }]);
    expect((await client.getWorkspace()).entries.some(({ name }) => name === "New file.txt")).toBe(true);

    await client.createShare({ fileId: file.id, kind: "direct", permission: "Viewer", target: "layla@example.test" });
    const share = (await client.getWorkspace()).shares.find(({ target }) => target === "layla@example.test");
    expect(share).toBeDefined();
    expect(share?.resourceId).toBe(file.id);
    if (share !== undefined) await client.revokeShare(share.id);
    expect((await client.getWorkspace()).shares.some(({ id }) => id === share?.id)).toBe(false);
  });

  it("restores immutable content as a new head and protects the current session", async () => {
    const client = new MockFileBeltClient();
    const initial = await client.getWorkspace();
    const oldVersion = initial.versions.at(-1);
    expect(oldVersion).toBeDefined();
    if (oldVersion === undefined) return;

    const previousHead = Math.max(...initial.versions.filter(({ fileId }) => fileId === oldVersion.fileId).map(({ version }) => version));
    await client.restoreVersion(oldVersion.id);
    const restored = await client.getWorkspace();
    expect(Math.max(...restored.versions.filter(({ fileId }) => fileId === oldVersion.fileId).map(({ version }) => version))).toBe(previousHead + 1);

    const currentSession = restored.sessions.find(({ current }) => current);
    expect(currentSession).toBeDefined();
    if (currentSession !== undefined) await client.revokeSession(currentSession.id);
    expect((await client.getWorkspace()).sessions.some(({ id }) => id === currentSession?.id)).toBe(true);
  });
});
