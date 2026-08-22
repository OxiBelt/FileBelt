// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { MockFileBeltClient, VersionConflictError } from "./client.js";

describe("MockFileBeltClient", () => {
  it("returns one ordered outcome per trash and restore target after a mixed failure", async () => {
    const Client = new MockFileBeltClient();
    const Initial = await Client.getWorkspace();
    const First = Initial.Entries[0];
    const Second = Initial.Entries[1];
    const MissingId = "00000000-0000-4000-8000-000000009999";
    expect(First).toBeDefined();
    expect(Second).toBeDefined();
    if (First === undefined || Second === undefined) return;

    const Trash = await Client.trashEntries([First.Id, MissingId, Second.Id]);
    expect(Trash).toEqual([
      { EntryId: First.Id, Kind: "success" },
      {
        EntryId: MissingId,
        Error: {
          Code: "node.unavailable",
          Detail: null,
          Message: "The selected resource is unavailable.",
          Status: 404,
        },
        Kind: "failure",
      },
      { EntryId: Second.Id, Kind: "success" },
    ]);
    let Current = await Client.getWorkspace();
    expect(Current.Entries.find(({ Id }) => Id === First.Id)?.Trashed).toBe(true);
    expect(Current.Entries.find(({ Id }) => Id === Second.Id)?.Trashed).toBe(true);

    const Restore = await Client.restoreEntries([First.Id, MissingId, Second.Id]);
    expect(Restore.map(({ EntryId, Kind }) => ({ EntryId, Kind }))).toEqual([
      { EntryId: First.Id, Kind: "success" },
      { EntryId: MissingId, Kind: "failure" },
      { EntryId: Second.Id, Kind: "success" },
    ]);
    Current = await Client.getWorkspace();
    expect(Current.Entries.find(({ Id }) => Id === First.Id)?.Trashed).toBe(false);
    expect(Current.Entries.find(({ Id }) => Id === Second.Id)?.Trashed).toBe(false);
  });

  it("exercises trash, restore, upload, and share workflows through the API boundary", async () => {
    const Client = new MockFileBeltClient();
    const Initial = await Client.getWorkspace();
    const File = Initial.Entries.find(({ Kind, Trashed }) => Kind === "file" && !Trashed);
    expect(File).toBeDefined();
    if (File === undefined) return;

    await Client.trashEntries([File.Id]);
    expect((await Client.getWorkspace()).Entries.find(({ Id }) => Id === File.Id)?.Trashed).toBe(
      true,
    );
    await Client.restoreEntries([File.Id]);
    expect((await Client.getWorkspace()).Entries.find(({ Id }) => Id === File.Id)?.Trashed).toBe(
      false,
    );

    await Client.upload([{ Name: "New file.txt", Size: 128 }]);
    expect((await Client.getWorkspace()).Entries.some(({ Name }) => Name === "New file.txt")).toBe(
      true,
    );

    await Client.createShare({
      FileId: File.Id,
      Kind: "direct",
      Permission: "Viewer",
      Target: "layla@example.test",
    });
    const Share = (await Client.getWorkspace()).Shares.find(
      ({ Target }) => Target === "layla@example.test",
    );
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

    const PreviousHead = Math.max(
      ...Initial.Versions.filter(({ FileId }) => FileId === OldVersion.FileId).map(
        ({ Version }) => Version,
      ),
    );
    await Client.restoreVersion(OldVersion.Id);
    const Restored = await Client.getWorkspace();
    expect(
      Math.max(
        ...Restored.Versions.filter(({ FileId }) => FileId === OldVersion.FileId).map(
          ({ Version }) => Version,
        ),
      ),
    ).toBe(PreviousHead + 1);

    const CurrentSession = Restored.Sessions.find(({ Current }) => Current);
    expect(CurrentSession).toBeDefined();
    if (CurrentSession !== undefined) await Client.revokeSession(CurrentSession.Id);
    expect((await Client.getWorkspace()).Sessions.some(({ Id }) => Id === CurrentSession?.Id)).toBe(
      true,
    );
  });

  it("reads an exact Markdown version and rejects stale replacement saves", async () => {
    const Client = new MockFileBeltClient();
    const Snapshot = await Client.getWorkspace();
    const Markdown = Snapshot.Entries.find(({ TextEligibility }) => TextEligibility === "editable");
    expect(Markdown?.HeadVersionId).not.toBeNull();
    if (Markdown?.HeadVersionId === null || Markdown === undefined) return;

    expect(await (await Client.readMarkdown(Markdown.Id, Markdown.HeadVersionId)).text()).toContain(
      "FileBelt Markdown content",
    );
    const NewVersion = await Client.saveMarkdown({
      Contents: new Blob(["# changed"], { type: "text/markdown" }),
      EntryId: Markdown.Id,
      ExpectedHeadVersionId: Markdown.HeadVersionId,
      Name: Markdown.Name,
    });
    expect(NewVersion).not.toBe(Markdown.HeadVersionId);
    await expect(
      Client.saveMarkdown({
        Contents: new Blob(["# stale"], { type: "text/markdown" }),
        EntryId: Markdown.Id,
        ExpectedHeadVersionId: Markdown.HeadVersionId,
        Name: Markdown.Name,
      }),
    ).rejects.toBeInstanceOf(VersionConflictError);
  });

  it("imports an exact Office source version as a new Markdown sibling", async () => {
    const Client = new MockFileBeltClient();
    const Snapshot = await Client.getWorkspace();
    const Office = Snapshot.Entries.find(({ Name }) => Name.endsWith(".xlsx"));
    expect(Office?.HeadVersionId).not.toBeNull();
    if (Office?.HeadVersionId === null || Office === undefined) return;
    await Client.importMarkdown({
      Contents: new Blob(["# Imported"], { type: "text/markdown" }),
      EntryId: Office.Id,
      SourceVersionId: Office.HeadVersionId,
      TargetName: "Q3 forecast.md",
    });
    const Imported = (await Client.getWorkspace()).Entries.find(
      ({ Name }) => Name === "Q3 forecast.md",
    );
    expect(Imported).toMatchObject({
      TextEligibility: "editable",
      MediaType: "text/markdown",
      Version: 1,
    });
  });

  it("uses an ETag to preserve personal text-limit updates and exposes text history seams", async () => {
    const Client = new MockFileBeltClient();
    const Initial = await Client.getTextPreferences();
    expect(Initial.Value).toEqual({ EditLimitBytes: 2_097_152, InlineLimitBytes: 8_388_608 });
    const Updated = await Client.updateTextPreferences(
      { EditLimitBytes: 4_194_304, InlineLimitBytes: 8_388_608 },
      Initial.Etag,
    );
    expect(Updated.Etag).not.toBe(Initial.Etag);
    await expect(Client.updateTextPreferences(Initial.Value, Initial.Etag)).rejects.toThrow(
      "Text preferences changed elsewhere",
    );
    const Entry = (await Client.getWorkspace()).Entries.find(({ Kind }) => Kind === "file");
    if (Entry === undefined) return;
    if (Entry.HeadVersionId === null) return;
    const Page = await Client.listTextVersions(Entry.Id, null);
    expect(Page.NextCursor).toBeNull();
  });
});
