// SPDX-License-Identifier: Apache-2.0

import type {
  AdminDrive,
  AdminGroup,
  FileEntry,
  ShareRecord,
  UploadCandidate,
  VersionRecord,
  WorkspaceSnapshot,
} from "./model.js";

/** Transitional browser shape until the generated OpenAPI contract lands. */
export type EditTextLimitBytes = 1_048_576 | 2_097_152 | 4_194_304 | 8_388_608 | 16_777_216;
export type InlineTextLimitBytes = 8_388_608 | 16_777_216 | 33_554_432 | 67_108_864 | 104_857_600;

export interface TextPreferences {
  EditLimitBytes: EditTextLimitBytes;
  InlineLimitBytes: InlineTextLimitBytes;
}

export interface VersionPage {
  Items: readonly VersionRecord[];
  NextCursor: string | null;
}

export interface TextDiffHunk {
  BaseLines: number;
  BaseStart: number;
  Lines: readonly TextDiffLine[];
  TargetLines: number;
  TargetStart: number;
}

export interface TextDiffLine {
  Kind: "add" | "context" | "remove";
  Text: string;
}

export interface TextComparison {
  Hunks: readonly TextDiffHunk[];
}

export interface CreateShareInput {
  FileId: string;
  Kind: ShareRecord["Kind"];
  Permission: ShareRecord["Permission"];
  Target: string;
}

export interface PublicShareGrant {
  ExpiresAt: string;
  ExchangeId: string;
  Name: string;
  Size: number;
}

export interface PublicShareClient {
  downloadPublic(ExchangeId: string): Promise<Blob>;
  exchangePublicShare(FragmentToken: string): Promise<PublicShareGrant>;
}

export interface MarkdownSaveInput {
  CheckpointId?: string;
  Contents: Blob;
  EntryId: string;
  ExpectedHeadVersionId: string;
  Name: string;
}

export interface MarkdownImportInput {
  Contents: Blob;
  EntryId: string;
  SourceVersionId: string;
  TargetName: string;
}

export interface MarkdownCollaborationGrant {
  Authorization: string;
  ClientId: string;
  EndpointUrl: string;
  PresenceLabel: string;
  RoomId: string;
}

export interface MarkdownHead {
  Contents: Blob;
  VersionId: string;
}

export class VersionConflictError extends Error {
  constructor() {
    super("This file changed on the server. Your local edits are still available.");
    this.name = "VersionConflictError";
  }
}

/** Signals that the browser must start a fresh OIDC login flow. */
export class AuthenticationRequiredError extends Error {
  constructor() {
    super("Sign in to continue.");
    this.name = "AuthenticationRequiredError";
  }
}

/**
 * API-shaped boundary for the SPA. A generated OpenAPI adapter can implement
 * this interface without exposing transport details to React components.
 */
export interface FileBeltClient {
  beginMarkdownCollaboration(
    EntryId: string,
    ClientId: string,
  ): Promise<MarkdownCollaborationGrant | null>;
  createGroup(Name: string): Promise<void>;
  createShare(Input: CreateShareInput): Promise<void>;
  createSharedDrive(Name: string): Promise<void>;
  download(EntryId: string): Promise<Blob>;
  importMarkdown(Input: MarkdownImportInput): Promise<string>;
  readMarkdown(EntryId: string, VersionId: string): Promise<Blob>;
  readMarkdownHead(EntryId: string): Promise<MarkdownHead>;
  saveMarkdown(Input: MarkdownSaveInput): Promise<string>;
  saveMarkdownCopy(
    Input: Omit<MarkdownSaveInput, "CheckpointId" | "ExpectedHeadVersionId">,
  ): Promise<string>;
  getWorkspace(Signal?: AbortSignal): Promise<WorkspaceSnapshot>;
  markPrivacyRead(): Promise<void>;
  restoreEntries(EntryIds: readonly string[]): Promise<void>;
  restoreVersion(VersionId: string): Promise<void>;
  revokeSession(SessionId: string): Promise<void>;
  revokeShare(ShareId: string): Promise<void>;
  suspendUser(UserId: string): Promise<void>;
  trashEntries(EntryIds: readonly string[]): Promise<void>;
  upload(Files: readonly UploadCandidate[]): Promise<void>;
  compareTextVersions(
    EntryId: string,
    BaseVersionId: string,
    TargetVersionId: string,
  ): Promise<TextComparison>;
  getTextPreferences(): Promise<{ Etag: string; Value: TextPreferences }>;
  listTextVersions(EntryId: string, Cursor: string | null): Promise<VersionPage>;
  setNodeContentClass(EntryId: string, ContentClass: "auto" | "binary"): Promise<void>;
  updateTextPreferences(
    Patch: TextPreferences,
    ExpectedEtag: string,
  ): Promise<{ Etag: string; Value: TextPreferences }>;
}

const Now = "2026-08-06T12:00:00Z";

function Uuid(Suffix: string): string {
  return `00000000-0000-4000-8000-${Suffix.padStart(12, "0")}`;
}

const InitialSnapshot: WorkspaceSnapshot = {
  CurrentUser: {
    DisplayName: "Avery Morgan",
    Email: "avery@example.test",
    IsTenantAdmin: true,
  },
  Entries: [
    {
      Id: Uuid("101"),
      HeadVersionId: null,
      Kind: "folder",
      TextEligibility: "ineligible",
      MediaType: null,
      ModifiedAt: "2026-08-06T09:24:00Z",
      Name: "Launch documents",
      Owner: "Avery Morgan",
      Shared: true,
      Size: null,
      Status: "ready",
      Trashed: false,
      Version: 1,
    },
    {
      Id: Uuid("102"),
      HeadVersionId: Uuid("301"),
      Kind: "file",
      TextEligibility: "ineligible",
      MediaType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      ModifiedAt: "2026-08-06T10:48:00Z",
      Name: "Q3 forecast.xlsx",
      Owner: "Avery Morgan",
      Shared: true,
      Size: 4_782_080,
      Status: "ready",
      Trashed: false,
      Version: 7,
    },
    {
      Id: Uuid("103"),
      HeadVersionId: Uuid("302"),
      Kind: "file",
      TextEligibility: "ineligible",
      MediaType: "application/pdf",
      ModifiedAt: "2026-08-05T16:12:00Z",
      Name: "Product brief.pdf",
      Owner: "Samir Haddad",
      Shared: false,
      Size: 1_843_200,
      Status: "ready",
      Trashed: false,
      Version: 3,
    },
    {
      Id: Uuid("104"),
      HeadVersionId: Uuid("303"),
      Kind: "file",
      TextEligibility: "editable",
      MediaType: "text/markdown",
      ModifiedAt: "2026-08-02T11:30:00Z",
      Name: "Archive notes.txt",
      Owner: "Avery Morgan",
      Shared: false,
      Size: 16_384,
      Status: "ready",
      Trashed: true,
      Version: 2,
    },
    {
      Id: Uuid("105"),
      HeadVersionId: Uuid("304"),
      Kind: "file",
      TextEligibility: "viewable",
      MediaType: "text/markdown",
      ModifiedAt: "2026-08-06T08:05:00Z",
      Name: "‫خطة المشروع‬.pdf",
      Owner: "Layla Hassan",
      Shared: true,
      Size: 942_080,
      Status: "ready",
      Trashed: false,
      Version: 4,
    },
  ],
  Uploads: [
    {
      Id: Uuid("201"),
      Name: "Team photography.zip",
      Progress: 0.68,
      Size: 85_899_345,
      State: "uploading",
    },
    {
      Id: Uuid("202"),
      Name: "Roadmap.pdf",
      Progress: 1,
      Size: 2_048_000,
      State: "complete",
    },
  ],
  Versions: [
    {
      Author: "Avery Morgan",
      CreatedAt: Now,
      FileId: Uuid("102"),
      Id: Uuid("301"),
      Size: 4_782_080,
      Version: 7,
    },
    {
      Author: "Samir Haddad",
      CreatedAt: "2026-08-04T15:20:00Z",
      FileId: Uuid("102"),
      Id: Uuid("302"),
      Size: 4_701_184,
      Version: 6,
    },
    {
      Author: "Avery Morgan",
      CreatedAt: "2026-08-01T08:00:00Z",
      FileId: Uuid("102"),
      Id: Uuid("303"),
      Size: 4_501_504,
      Version: 5,
    },
  ],
  Shares: [
    {
      Id: Uuid("401"),
      Kind: "direct",
      Permission: "Contributor",
      ResourceId: Uuid("102"),
      ResourceName: "Q3 forecast.xlsx",
      Target: "samir@example.test",
    },
    {
      Id: Uuid("402"),
      Kind: "group",
      Permission: "Viewer",
      ResourceId: Uuid("101"),
      ResourceName: "Launch documents",
      Target: "Product group",
    },
    {
      ExpiresAt: "2026-08-13T12:00:00Z",
      Id: Uuid("403"),
      Kind: "link",
      Permission: "Viewer",
      ResourceId: Uuid("103"),
      ResourceName: "Product brief.pdf",
      Target: "Anonymous link",
    },
  ],
  Sessions: [
    {
      Current: true,
      Device: "Firefox on Linux",
      Id: Uuid("501"),
      LastActiveAt: Now,
      Location: "Current device",
    },
    {
      Current: false,
      Device: "Firefox on Android",
      Id: Uuid("502"),
      LastActiveAt: "2026-08-05T19:11:00Z",
      Location: "Berlin, DE",
    },
  ],
  Privacy: [
    {
      Action: "Your quota was changed to 1 TB",
      Actor: "Tenant administrator",
      CreatedAt: "2026-08-05T14:02:00Z",
      Id: Uuid("601"),
      Unread: true,
    },
    {
      Action: "A session was revoked",
      Actor: "You",
      CreatedAt: "2026-07-29T10:40:00Z",
      Id: Uuid("602"),
      Unread: false,
    },
  ],
  Admin: {
    Users: [
      { Email: "avery@example.test", Id: Uuid("701"), Name: "Avery Morgan", Status: "active" },
      { Email: "samir@example.test", Id: Uuid("702"), Name: "Samir Haddad", Status: "active" },
      { Email: "layla@example.test", Id: Uuid("703"), Name: "Layla Hassan", Status: "active" },
    ],
    Groups: [
      { Id: Uuid("801"), ManagerCount: 2, MemberCount: 8, Name: "Product group" },
      { Id: Uuid("802"), ManagerCount: 1, MemberCount: 4, Name: "Finance group" },
    ],
    Drives: [
      {
        Id: Uuid("901"),
        Name: "Product shared drive",
        QuotaBytes: 10_995_116_277_760,
        UsedBytes: 2_748_779_069_440,
      },
      {
        Id: Uuid("902"),
        Name: "Finance shared drive",
        QuotaBytes: 5_497_558_138_880,
        UsedBytes: 1_099_511_627_776,
      },
    ],
  },
};

function CloneSnapshot(Snapshot: WorkspaceSnapshot): WorkspaceSnapshot {
  return structuredClone(Snapshot);
}

export class MockFileBeltClient implements FileBeltClient, PublicShareClient {
  readonly #Snapshot = CloneSnapshot(InitialSnapshot);
  #Sequence = 1_000;
  #TextPreferences: TextPreferences = { EditLimitBytes: 2_097_152, InlineLimitBytes: 8_388_608 };
  #TextPreferencesEtag = '"text-preferences-1"';

  async getTextPreferences(): Promise<{ Etag: string; Value: TextPreferences }> {
    return { Etag: this.#TextPreferencesEtag, Value: { ...this.#TextPreferences } };
  }

  async updateTextPreferences(
    Patch: TextPreferences,
    ExpectedEtag: string,
  ): Promise<{ Etag: string; Value: TextPreferences }> {
    if (ExpectedEtag !== this.#TextPreferencesEtag)
      throw new Error("Text preferences changed elsewhere. Refresh and try again.");
    if (Patch.InlineLimitBytes < Patch.EditLimitBytes)
      throw new Error("The inline limit must be at least the edit limit.");
    this.#TextPreferences = { ...Patch };
    this.#TextPreferencesEtag = `"text-preferences-${++this.#Sequence}"`;
    return this.getTextPreferences();
  }

  async listTextVersions(EntryId: string, Cursor: string | null): Promise<VersionPage> {
    if (Cursor !== null) return { Items: [], NextCursor: null };
    return {
      Items: this.#Snapshot.Versions.filter(({ FileId }) => FileId === EntryId),
      NextCursor: null,
    };
  }

  async compareTextVersions(
    EntryId: string,
    BaseVersionId: string,
    TargetVersionId: string,
  ): Promise<TextComparison> {
    const Versions = this.#Snapshot.Versions.filter(({ FileId }) => FileId === EntryId);
    if (
      !Versions.some(({ Id }) => Id === BaseVersionId) ||
      !Versions.some(({ Id }) => Id === TargetVersionId)
    )
      throw new Error("The selected versions are unavailable.");
    return {
      Hunks: [
        {
          BaseLines: 1,
          BaseStart: 1,
          Lines: [
            {
              Kind: "context",
              Text: "Mock comparison is available after the generated API client is connected.",
            },
          ],
          TargetLines: 1,
          TargetStart: 1,
        },
      ],
    };
  }

  async setNodeContentClass(EntryId: string, ContentClass: "auto" | "binary"): Promise<void> {
    const Entry = this.#Snapshot.Entries.find(({ Id }) => Id === EntryId);
    if (Entry === undefined) throw new Error("The selected file is unavailable.");
    Entry.TextEligibility =
      ContentClass === "binary"
        ? "history-only"
        : TextEligibility(Entry.Name, Entry.Size ?? 0, Entry.MediaType);
  }

  async getWorkspace(Signal?: AbortSignal): Promise<WorkspaceSnapshot> {
    if (Signal?.aborted === true) {
      throw new DOMException("Request was aborted", "AbortError");
    }
    return CloneSnapshot(this.#Snapshot);
  }

  async upload(Files: readonly UploadCandidate[]): Promise<void> {
    for (const File of Files) {
      const Id = Uuid(String(++this.#Sequence));
      this.#Snapshot.Entries.unshift({
        Id,
        HeadVersionId: Uuid(String(++this.#Sequence)),
        Kind: "file",
        TextEligibility: TextEligibility(File.Name, File.Size, File.MediaType ?? null),
        MediaType: File.MediaType ?? null,
        ModifiedAt: new Date().toISOString(),
        Name: File.Name,
        Owner: this.#Snapshot.CurrentUser.DisplayName,
        Shared: false,
        Size: File.Size,
        Status: "ready",
        Trashed: false,
        Version: 1,
      });
      this.#Snapshot.Uploads.unshift({
        Id,
        Name: File.Name,
        Progress: 1,
        Size: File.Size,
        State: "complete",
      });
    }
  }

  async download(EntryId: string): Promise<Blob> {
    const Entry = this.#Snapshot.Entries.find(({ Id }) => Id === EntryId);
    if (Entry === undefined || Entry.Kind !== "file") throw new Error("The file is unavailable.");
    return new Blob([`FileBelt mock download for ${Entry.Name}\n`], { type: "text/plain" });
  }

  async readMarkdown(EntryId: string, VersionId: string): Promise<Blob> {
    const Entry = this.#Snapshot.Entries.find(({ Id }) => Id === EntryId);
    if (Entry?.HeadVersionId !== VersionId || Entry.Kind !== "file")
      throw new Error("The requested file version is unavailable.");
    return new Blob([`# ${Entry.Name}\n\nFileBelt Markdown content.\n`], { type: "text/markdown" });
  }

  async importMarkdown(Input: MarkdownImportInput): Promise<string> {
    const Original = this.#Snapshot.Entries.find(({ Id }) => Id === Input.EntryId);
    if (Original?.HeadVersionId !== Input.SourceVersionId)
      throw new Error("The Office source version is unavailable.");
    const Id = Uuid(String(++this.#Sequence));
    const VersionId = Uuid(String(++this.#Sequence));
    this.#Snapshot.Entries.unshift({
      ...Original,
      HeadVersionId: VersionId,
      Id,
      TextEligibility: "editable",
      MediaType: "text/markdown",
      ModifiedAt: new Date().toISOString(),
      Name: Input.TargetName,
      Shared: false,
      Size: Input.Contents.size,
      Version: 1,
    });
    return VersionId;
  }

  async beginMarkdownCollaboration(IgnoredEntryId: string, IgnoredClientId: string): Promise<null> {
    void IgnoredEntryId;
    void IgnoredClientId;
    return null;
  }

  async readMarkdownHead(EntryId: string): Promise<MarkdownHead> {
    const Entry = this.#Snapshot.Entries.find(({ Id }) => Id === EntryId);
    if (Entry?.HeadVersionId === null || Entry?.HeadVersionId === undefined)
      throw new Error("The Markdown file has no current version.");
    return {
      Contents: await this.readMarkdown(EntryId, Entry.HeadVersionId),
      VersionId: Entry.HeadVersionId,
    };
  }

  async saveMarkdown(Input: MarkdownSaveInput): Promise<string> {
    const Entry = this.#Snapshot.Entries.find(({ Id }) => Id === Input.EntryId);
    if (Entry === undefined || Entry.HeadVersionId !== Input.ExpectedHeadVersionId)
      throw new VersionConflictError();
    if (Entry.TextEligibility !== "editable") throw new Error("This text file is view-only.");
    Entry.HeadVersionId = Uuid(String(++this.#Sequence));
    Entry.ModifiedAt = new Date().toISOString();
    Entry.Size = Input.Contents.size;
    Entry.Version += 1;
    return Entry.HeadVersionId;
  }

  async saveMarkdownCopy(
    Input: Omit<MarkdownSaveInput, "CheckpointId" | "ExpectedHeadVersionId">,
  ): Promise<string> {
    const Original = this.#Snapshot.Entries.find(({ Id }) => Id === Input.EntryId);
    if (Original === undefined) throw new Error("The source Markdown file is unavailable.");
    const Id = Uuid(String(++this.#Sequence));
    const VersionId = Uuid(String(++this.#Sequence));
    this.#Snapshot.Entries.unshift({
      ...Original,
      HeadVersionId: VersionId,
      Id,
      ModifiedAt: new Date().toISOString(),
      Name: Input.Name,
      Shared: false,
      Size: Input.Contents.size,
      Version: 1,
    });
    return VersionId;
  }

  async exchangePublicShare(FragmentToken: string): Promise<PublicShareGrant> {
    if (FragmentToken.trim().length < 8)
      throw new Error("This share link is invalid or has expired.");
    return {
      ExchangeId: Uuid(String(++this.#Sequence)),
      ExpiresAt: "2026-08-13T12:00:00Z",
      Name: "Product brief.pdf",
      Size: 1_843_200,
    };
  }

  async downloadPublic(ExchangeId: string): Promise<Blob> {
    if (ExchangeId.length === 0) throw new Error("This share link is unavailable.");
    return new Blob(["FileBelt mock public-share download\n"], { type: "text/plain" });
  }

  async trashEntries(EntryIds: readonly string[]): Promise<void> {
    this.#updateEntries(EntryIds, (Entry) => ({ ...Entry, Trashed: true }));
  }

  async restoreEntries(EntryIds: readonly string[]): Promise<void> {
    this.#updateEntries(EntryIds, (Entry) => ({ ...Entry, Trashed: false }));
  }

  async createShare(Input: CreateShareInput): Promise<void> {
    const Entry = this.#Snapshot.Entries.find(({ Id }) => Id === Input.FileId);
    if (Entry === undefined) {
      throw new Error("The selected resource is unavailable.");
    }
    this.#Snapshot.Shares.unshift({
      Id: Uuid(String(++this.#Sequence)),
      Kind: Input.Kind,
      Permission: Input.Kind === "link" ? "Viewer" : Input.Permission,
      ResourceId: Entry.Id,
      ResourceName: Entry.Name,
      Target: Input.Kind === "link" ? "Anonymous link" : Input.Target,
      ...(Input.Kind === "link" ? { ExpiresAt: "2026-08-13T12:00:00Z" } : {}),
    });
    Entry.Shared = true;
  }

  async revokeShare(ShareId: string): Promise<void> {
    const Index = this.#Snapshot.Shares.findIndex(({ Id }) => Id === ShareId);
    if (Index !== -1) this.#Snapshot.Shares.splice(Index, 1);
  }

  async restoreVersion(VersionId: string): Promise<void> {
    const Version = this.#Snapshot.Versions.find(({ Id }) => Id === VersionId);
    const Entry = this.#Snapshot.Entries.find(({ Id }) => Id === Version?.FileId);
    if (Version === undefined || Entry === undefined) return;
    const NextVersion =
      Math.max(
        ...this.#Snapshot.Versions.filter(({ FileId }) => FileId === Entry.Id).map(
          ({ Version: Value }) => Value,
        ),
      ) + 1;
    Entry.Version = NextVersion;
    Entry.ModifiedAt = new Date().toISOString();
    this.#Snapshot.Versions.unshift({
      Author: this.#Snapshot.CurrentUser.DisplayName,
      CreatedAt: Entry.ModifiedAt,
      FileId: Entry.Id,
      Id: Uuid(String(++this.#Sequence)),
      Size: Version.Size,
      Version: NextVersion,
    });
  }

  async revokeSession(SessionId: string): Promise<void> {
    const Index = this.#Snapshot.Sessions.findIndex(({ Id }) => Id === SessionId);
    if (this.#Snapshot.Sessions[Index]?.Current === true) return;
    if (Index !== -1) this.#Snapshot.Sessions.splice(Index, 1);
  }

  async markPrivacyRead(): Promise<void> {
    for (const Event of this.#Snapshot.Privacy) Event.Unread = false;
  }

  async suspendUser(UserId: string): Promise<void> {
    const User = this.#Snapshot.Admin.Users.find(({ Id }) => Id === UserId);
    if (User !== undefined) User.Status = User.Status === "active" ? "suspended" : "active";
  }

  async createGroup(Name: string): Promise<void> {
    const Group: AdminGroup = {
      Id: Uuid(String(++this.#Sequence)),
      ManagerCount: 1,
      MemberCount: 1,
      Name,
    };
    this.#Snapshot.Admin.Groups.push(Group);
  }

  async createSharedDrive(Name: string): Promise<void> {
    const Drive: AdminDrive = {
      Id: Uuid(String(++this.#Sequence)),
      Name,
      QuotaBytes: 10_995_116_277_760,
      UsedBytes: 0,
    };
    this.#Snapshot.Admin.Drives.push(Drive);
  }

  #updateEntries(EntryIds: readonly string[], Update: (Entry: FileEntry) => FileEntry): void {
    const Wanted = new Set(EntryIds);
    this.#Snapshot.Entries = this.#Snapshot.Entries.map((Entry) =>
      Wanted.has(Entry.Id) ? Update(Entry) : Entry,
    );
  }
}

function TextEligibility(
  Name: string,
  Size: number,
  MediaType: string | null,
): FileEntry["TextEligibility"] {
  const IsText =
    MediaType?.startsWith("text/") === true ||
    /\.(?:asc|conf|csv|ini|json|log|md|markdown|mdown|mkdn|rst|sh|text|toml|ts|tsx|txt|xml|yaml|yml)$/i.test(
      Name,
    );
  if (!IsText) return "ineligible";
  if (Size > 100 * 1024 * 1024) return "history-only";
  return Size <= 16 * 1024 * 1024 ? "editable" : "viewable";
}
