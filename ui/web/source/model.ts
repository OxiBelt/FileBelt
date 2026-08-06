// SPDX-License-Identifier: Apache-2.0

export type RouteId =
  | "drive"
  | "shared-drives"
  | "shared"
  | "recent"
  | "trash"
  | "uploads"
  | "versions"
  | "shares"
  | "sessions"
  | "privacy";

export type EntryKind = "file" | "folder";
export type EntryStatus = "ready" | "uploading" | "conflict" | "quarantined";

export interface FileEntry {
  id: string;
  kind: EntryKind;
  modifiedAt: string;
  name: string;
  owner: string;
  shared: boolean;
  size: number | null;
  status: EntryStatus;
  trashed: boolean;
  version: number;
}

export interface UploadRecord {
  id: string;
  name: string;
  progress: number;
  size: number;
  state: "complete" | "failed" | "uploading";
}

export interface VersionRecord {
  author: string;
  createdAt: string;
  fileId: string;
  id: string;
  size: number;
  version: number;
}

export interface ShareRecord {
  expiresAt?: string;
  id: string;
  kind: "direct" | "group" | "link";
  permission: "Contributor" | "Manager" | "Viewer";
  resourceId: string;
  resourceName: string;
  target: string;
}

export interface SessionRecord {
  current: boolean;
  device: string;
  id: string;
  lastActiveAt: string;
  location: string;
}

export interface PrivacyEvent {
  action: string;
  actor: string;
  createdAt: string;
  id: string;
  unread: boolean;
}

export interface AdminUser {
  email: string;
  id: string;
  name: string;
  status: "active" | "suspended";
}

export interface AdminGroup {
  id: string;
  managerCount: number;
  memberCount: number;
  name: string;
}

export interface AdminDrive {
  id: string;
  name: string;
  quotaBytes: number;
  usedBytes: number;
}

export interface WorkspaceSnapshot {
  admin: {
    drives: AdminDrive[];
    groups: AdminGroup[];
    users: AdminUser[];
  };
  currentUser: {
    displayName: string;
    email: string;
    isTenantAdmin: boolean;
  };
  entries: FileEntry[];
  privacy: PrivacyEvent[];
  sessions: SessionRecord[];
  shares: ShareRecord[];
  uploads: UploadRecord[];
  versions: VersionRecord[];
}

export interface UploadCandidate {
  data?: Blob;
  name: string;
  size: number;
}
