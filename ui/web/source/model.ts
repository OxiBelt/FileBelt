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
  | "privacy"
  | "mcp"
  | "mounts"
  | "markdown";

export type EntryKind = "file" | "folder";
export type EntryStatus = "ready" | "uploading" | "conflict" | "quarantined";
export type MarkdownEligibility = "editable" | "ineligible" | "viewable";

export interface FileEntry {
  HeadVersionId: string | null;
  Id: string;
  Kind: EntryKind;
  ModifiedAt: string;
  MarkdownEligibility: MarkdownEligibility;
  MediaType: string | null;
  Name: string;
  Owner: string;
  Shared: boolean;
  Size: number | null;
  Status: EntryStatus;
  Trashed: boolean;
  Version: number;
}

export interface UploadRecord {
  Id: string;
  Name: string;
  Progress: number;
  Size: number;
  State: "complete" | "failed" | "uploading";
}

export interface VersionRecord {
  Author: string;
  CreatedAt: string;
  FileId: string;
  Id: string;
  Size: number;
  Version: number;
}

export interface ShareRecord {
  ExpiresAt?: string;
  Id: string;
  Kind: "direct" | "group" | "link";
  Permission: "Contributor" | "Manager" | "Viewer";
  ResourceId: string;
  ResourceName: string;
  Target: string;
}

export interface SessionRecord {
  Current: boolean;
  Device: string;
  Id: string;
  LastActiveAt: string;
  Location: string;
}

export interface PrivacyEvent {
  Action: string;
  Actor: string;
  CreatedAt: string;
  Id: string;
  Unread: boolean;
}

export interface AdminUser {
  Email: string;
  Id: string;
  Name: string;
  Status: "active" | "suspended";
}

export interface AdminGroup {
  Id: string;
  ManagerCount: number;
  MemberCount: number;
  Name: string;
}

export interface AdminDrive {
  Id: string;
  Name: string;
  QuotaBytes: number;
  UsedBytes: number;
}

export interface WorkspaceSnapshot {
  Admin: {
    Drives: AdminDrive[];
    Groups: AdminGroup[];
    Users: AdminUser[];
  };
  CurrentUser: {
    DisplayName: string;
    Email: string;
    IsTenantAdmin: boolean;
  };
  Entries: FileEntry[];
  Privacy: PrivacyEvent[];
  Sessions: SessionRecord[];
  Shares: ShareRecord[];
  Uploads: UploadRecord[];
  Versions: VersionRecord[];
}

export interface UploadCandidate {
  Data?: Blob;
  MediaType?: string;
  Name: string;
  Size: number;
}
