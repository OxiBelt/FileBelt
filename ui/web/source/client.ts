// SPDX-License-Identifier: Apache-2.0

import type {
  AdminDrive,
  AdminGroup,
  FileEntry,
  ShareRecord,
  UploadCandidate,
  WorkspaceSnapshot,
} from "./model.js";

export interface CreateShareInput {
  fileId: string;
  kind: ShareRecord["kind"];
  permission: ShareRecord["permission"];
  target: string;
}

export interface PublicShareGrant {
  expiresAt: string;
  exchangeId: string;
  name: string;
  size: number;
}

export interface PublicShareClient {
  downloadPublic(exchangeId: string): Promise<Blob>;
  exchangePublicShare(fragmentToken: string): Promise<PublicShareGrant>;
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
  createGroup(name: string): Promise<void>;
  createShare(input: CreateShareInput): Promise<void>;
  createSharedDrive(name: string): Promise<void>;
  download(entryId: string): Promise<Blob>;
  getWorkspace(signal?: AbortSignal): Promise<WorkspaceSnapshot>;
  markPrivacyRead(): Promise<void>;
  restoreEntries(entryIds: readonly string[]): Promise<void>;
  restoreVersion(versionId: string): Promise<void>;
  revokeSession(sessionId: string): Promise<void>;
  revokeShare(shareId: string): Promise<void>;
  suspendUser(userId: string): Promise<void>;
  trashEntries(entryIds: readonly string[]): Promise<void>;
  upload(files: readonly UploadCandidate[]): Promise<void>;
}

const now = "2026-08-06T12:00:00Z";

function uuid(suffix: string): string {
  return `00000000-0000-4000-8000-${suffix.padStart(12, "0")}`;
}

const initialSnapshot: WorkspaceSnapshot = {
  currentUser: {
    displayName: "Avery Morgan",
    email: "avery@example.test",
    isTenantAdmin: true,
  },
  entries: [
    {
      id: uuid("101"),
      kind: "folder",
      modifiedAt: "2026-08-06T09:24:00Z",
      name: "Launch documents",
      owner: "Avery Morgan",
      shared: true,
      size: null,
      status: "ready",
      trashed: false,
      version: 1,
    },
    {
      id: uuid("102"),
      kind: "file",
      modifiedAt: "2026-08-06T10:48:00Z",
      name: "Q3 forecast.xlsx",
      owner: "Avery Morgan",
      shared: true,
      size: 4_782_080,
      status: "ready",
      trashed: false,
      version: 7,
    },
    {
      id: uuid("103"),
      kind: "file",
      modifiedAt: "2026-08-05T16:12:00Z",
      name: "Product brief.pdf",
      owner: "Samir Haddad",
      shared: false,
      size: 1_843_200,
      status: "ready",
      trashed: false,
      version: 3,
    },
    {
      id: uuid("104"),
      kind: "file",
      modifiedAt: "2026-08-02T11:30:00Z",
      name: "Archive notes.txt",
      owner: "Avery Morgan",
      shared: false,
      size: 16_384,
      status: "ready",
      trashed: true,
      version: 2,
    },
    {
      id: uuid("105"),
      kind: "file",
      modifiedAt: "2026-08-06T08:05:00Z",
      name: "‫خطة المشروع‬.pdf",
      owner: "Layla Hassan",
      shared: true,
      size: 942_080,
      status: "ready",
      trashed: false,
      version: 4,
    },
  ],
  uploads: [
    {
      id: uuid("201"),
      name: "Team photography.zip",
      progress: 0.68,
      size: 85_899_345,
      state: "uploading",
    },
    {
      id: uuid("202"),
      name: "Roadmap.pdf",
      progress: 1,
      size: 2_048_000,
      state: "complete",
    },
  ],
  versions: [
    { author: "Avery Morgan", createdAt: now, fileId: uuid("102"), id: uuid("301"), size: 4_782_080, version: 7 },
    { author: "Samir Haddad", createdAt: "2026-08-04T15:20:00Z", fileId: uuid("102"), id: uuid("302"), size: 4_701_184, version: 6 },
    { author: "Avery Morgan", createdAt: "2026-08-01T08:00:00Z", fileId: uuid("102"), id: uuid("303"), size: 4_501_504, version: 5 },
  ],
  shares: [
    { id: uuid("401"), kind: "direct", permission: "Contributor", resourceId: uuid("102"), resourceName: "Q3 forecast.xlsx", target: "samir@example.test" },
    { id: uuid("402"), kind: "group", permission: "Viewer", resourceId: uuid("101"), resourceName: "Launch documents", target: "Product group" },
    { expiresAt: "2026-08-13T12:00:00Z", id: uuid("403"), kind: "link", permission: "Viewer", resourceId: uuid("103"), resourceName: "Product brief.pdf", target: "Anonymous link" },
  ],
  sessions: [
    { current: true, device: "Firefox on Linux", id: uuid("501"), lastActiveAt: now, location: "Current device" },
    { current: false, device: "Firefox on Android", id: uuid("502"), lastActiveAt: "2026-08-05T19:11:00Z", location: "Berlin, DE" },
  ],
  privacy: [
    { action: "Your quota was changed to 1 TB", actor: "Tenant administrator", createdAt: "2026-08-05T14:02:00Z", id: uuid("601"), unread: true },
    { action: "A session was revoked", actor: "You", createdAt: "2026-07-29T10:40:00Z", id: uuid("602"), unread: false },
  ],
  admin: {
    users: [
      { email: "avery@example.test", id: uuid("701"), name: "Avery Morgan", status: "active" },
      { email: "samir@example.test", id: uuid("702"), name: "Samir Haddad", status: "active" },
      { email: "layla@example.test", id: uuid("703"), name: "Layla Hassan", status: "active" },
    ],
    groups: [
      { id: uuid("801"), managerCount: 2, memberCount: 8, name: "Product group" },
      { id: uuid("802"), managerCount: 1, memberCount: 4, name: "Finance group" },
    ],
    drives: [
      { id: uuid("901"), name: "Product shared drive", quotaBytes: 10_995_116_277_760, usedBytes: 2_748_779_069_440 },
      { id: uuid("902"), name: "Finance shared drive", quotaBytes: 5_497_558_138_880, usedBytes: 1_099_511_627_776 },
    ],
  },
};

function cloneSnapshot(snapshot: WorkspaceSnapshot): WorkspaceSnapshot {
  return structuredClone(snapshot);
}

export class MockFileBeltClient implements FileBeltClient, PublicShareClient {
  readonly #snapshot = cloneSnapshot(initialSnapshot);
  #sequence = 1_000;

  async getWorkspace(signal?: AbortSignal): Promise<WorkspaceSnapshot> {
    if (signal?.aborted === true) {
      throw new DOMException("Request was aborted", "AbortError");
    }
    return cloneSnapshot(this.#snapshot);
  }

  async upload(files: readonly UploadCandidate[]): Promise<void> {
    for (const file of files) {
      const id = uuid(String(++this.#sequence));
      this.#snapshot.entries.unshift({
        id,
        kind: "file",
        modifiedAt: new Date().toISOString(),
        name: file.name,
        owner: this.#snapshot.currentUser.displayName,
        shared: false,
        size: file.size,
        status: "ready",
        trashed: false,
        version: 1,
      });
      this.#snapshot.uploads.unshift({ id, name: file.name, progress: 1, size: file.size, state: "complete" });
    }
  }

  async download(entryId: string): Promise<Blob> {
    const entry = this.#snapshot.entries.find(({ id }) => id === entryId);
    if (entry === undefined || entry.kind !== "file") throw new Error("The file is unavailable.");
    return new Blob([`FileBelt mock download for ${entry.name}\n`], { type: "text/plain" });
  }

  async exchangePublicShare(fragmentToken: string): Promise<PublicShareGrant> {
    if (fragmentToken.trim().length < 8) throw new Error("This share link is invalid or has expired.");
    return {
      exchangeId: uuid(String(++this.#sequence)),
      expiresAt: "2026-08-13T12:00:00Z",
      name: "Product brief.pdf",
      size: 1_843_200,
    };
  }

  async downloadPublic(exchangeId: string): Promise<Blob> {
    if (exchangeId.length === 0) throw new Error("This share link is unavailable.");
    return new Blob(["FileBelt mock public-share download\n"], { type: "text/plain" });
  }

  async trashEntries(entryIds: readonly string[]): Promise<void> {
    this.#updateEntries(entryIds, (entry) => ({ ...entry, trashed: true }));
  }

  async restoreEntries(entryIds: readonly string[]): Promise<void> {
    this.#updateEntries(entryIds, (entry) => ({ ...entry, trashed: false }));
  }

  async createShare(input: CreateShareInput): Promise<void> {
    const entry = this.#snapshot.entries.find(({ id }) => id === input.fileId);
    if (entry === undefined) {
      throw new Error("The selected resource is unavailable.");
    }
    this.#snapshot.shares.unshift({
      id: uuid(String(++this.#sequence)),
      kind: input.kind,
      permission: input.kind === "link" ? "Viewer" : input.permission,
      resourceId: entry.id,
      resourceName: entry.name,
      target: input.kind === "link" ? "Anonymous link" : input.target,
      ...(input.kind === "link" ? { expiresAt: "2026-08-13T12:00:00Z" } : {}),
    });
    entry.shared = true;
  }

  async revokeShare(shareId: string): Promise<void> {
    const index = this.#snapshot.shares.findIndex(({ id }) => id === shareId);
    if (index !== -1) this.#snapshot.shares.splice(index, 1);
  }

  async restoreVersion(versionId: string): Promise<void> {
    const version = this.#snapshot.versions.find(({ id }) => id === versionId);
    const entry = this.#snapshot.entries.find(({ id }) => id === version?.fileId);
    if (version === undefined || entry === undefined) return;
    const nextVersion = Math.max(...this.#snapshot.versions.filter(({ fileId }) => fileId === entry.id).map(({ version: value }) => value)) + 1;
    entry.version = nextVersion;
    entry.modifiedAt = new Date().toISOString();
    this.#snapshot.versions.unshift({
      author: this.#snapshot.currentUser.displayName,
      createdAt: entry.modifiedAt,
      fileId: entry.id,
      id: uuid(String(++this.#sequence)),
      size: version.size,
      version: nextVersion,
    });
  }

  async revokeSession(sessionId: string): Promise<void> {
    const index = this.#snapshot.sessions.findIndex(({ id }) => id === sessionId);
    if (this.#snapshot.sessions[index]?.current === true) return;
    if (index !== -1) this.#snapshot.sessions.splice(index, 1);
  }

  async markPrivacyRead(): Promise<void> {
    for (const event of this.#snapshot.privacy) event.unread = false;
  }

  async suspendUser(userId: string): Promise<void> {
    const user = this.#snapshot.admin.users.find(({ id }) => id === userId);
    if (user !== undefined) user.status = user.status === "active" ? "suspended" : "active";
  }

  async createGroup(name: string): Promise<void> {
    const group: AdminGroup = { id: uuid(String(++this.#sequence)), managerCount: 1, memberCount: 1, name };
    this.#snapshot.admin.groups.push(group);
  }

  async createSharedDrive(name: string): Promise<void> {
    const drive: AdminDrive = {
      id: uuid(String(++this.#sequence)),
      name,
      quotaBytes: 10_995_116_277_760,
      usedBytes: 0,
    };
    this.#snapshot.admin.drives.push(drive);
  }

  #updateEntries(entryIds: readonly string[], update: (entry: FileEntry) => FileEntry): void {
    const wanted = new Set(entryIds);
    this.#snapshot.entries = this.#snapshot.entries.map((entry) => wanted.has(entry.id) ? update(entry) : entry);
  }
}
