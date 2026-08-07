// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { MockFileBeltClient } from "./client.js";

describe("MockFileBeltClient", () => {
  it("exercises trash, restore, upload, and share workflows through the API boundary", async () => {
    const Client = new MockFileBeltClient();
    const Initial = await Client.getWorkspace();
    const File = Initial.Entries.find(({ Kind, Trashed }) => Kind === "file" && !Trashed);
    expect(File).toBeDefined();
    if (File === undefined) return;

    await Client.trashEntries([File.Id]);
    expect((await Client.getWorkspace()).Entries.find(({ Id }) => Id === File.Id)?.Trashed).toBe(true);
    await Client.restoreEntries([File.Id]);
    expect((await Client.getWorkspace()).Entries.find(({ Id }) => Id === File.Id)?.Trashed).toBe(false);

    await Client.upload([{ Name: "New file.txt", Size: 128 }]);
    expect((await Client.getWorkspace()).Entries.some(({ Name }) => Name === "New file.txt")).toBe(true);

    await Client.createShare({ FileId: File.Id, Kind: "direct", Permission: "Viewer", Target: "layla@example.test" });
    const Share = (await Client.getWorkspace()).Shares.find(({ Target }) => Target === "layla@example.test");
    expect(Share).toBeDefined();
    expect(Share?.ResourceId).toBe(File.Id);
    if (Share !== undefined) await Client.revokeShare(Share.Id);
    expect((await Client.getWorkspace()).Shares.some(({ Id }) => Id === Share?.Id)).toBe(false);
  });

  it("restores immutable content as a new head and protects the current session", async () => {
    const Client = new MockFileBeltClient();
    const Initial = await Client.getWorkspace();
    const OldVersion = Initial.Versions.at(-1);
    expect(OldVersion).toBeDefined();
    if (OldVersion === undefined) return;

    const PreviousHead = Math.max(...Initial.Versions.filter(({ FileId }) => FileId === OldVersion.FileId).map(({ Version }) => Version));
    await Client.restoreVersion(OldVersion.Id);
    const Restored = await Client.getWorkspace();
    expect(Math.max(...Restored.Versions.filter(({ FileId }) => FileId === OldVersion.FileId).map(({ Version }) => Version))).toBe(PreviousHead + 1);

    const CurrentSession = Restored.Sessions.find(({ Current }) => Current);
    expect(CurrentSession).toBeDefined();
    if (CurrentSession !== undefined) await Client.revokeSession(CurrentSession.Id);
    expect((await Client.getWorkspace()).Sessions.some(({ Id }) => Id === CurrentSession?.Id)).toBe(true);
  });
});
