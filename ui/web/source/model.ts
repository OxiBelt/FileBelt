// SPDX-License-Identifier: Apache-2.0

export type RouteId =
  | 'drive'
  | 'shared-drives'
  | 'shared'
  | 'recent'
  | 'trash'
  | 'uploads'
  | 'versions'
  | 'shares'
  | 'sessions'
  | 'documents'
  | 'privacy'
  | 'mcp'
  | 'mounts'
  | 'text'
  | 'markdown'

export type EntryKind = 'file' | 'folder' | 'symlink'
export type EntryStatus = 'ready' | 'uploading' | 'conflict' | 'quarantined'
export type TextEligibility = 'editable' | 'history-only' | 'ineligible' | 'viewable'

export interface FileEntry {
  /** Available only from the generated node projection; never treated as authorization. */
  DriveId?: string
  HeadVersionId: string | null
  Id: string
  Kind: EntryKind
  ModifiedAt: string
  /** Server-validated text admission; this remains a presentation hint only. */
  TextEligibility: TextEligibility
  MediaType: string | null
  Name: string
  Owner: string
  /** Parent node used for navigation only; authorization remains server-side. */
  ParentId?: string | null
  Shared: boolean
  Size: number | null
  Status: EntryStatus
  Trashed: boolean
  Version: number
}

export interface WorkspaceDrive {
  Id: string
  Kind: 'private' | 'shared'
  Name: string
  RootId: string
}

export interface UploadRecord {
  Id: string
  Name: string
  Progress: number
  Size: number
  State: 'complete' | 'failed' | 'uploading'
}

export interface VersionRecord {
  Author: string
  CreatedAt: string
  FileId: string
  Id: string
  Size: number
  Version: number
  GitCommitOid?: string | null
  ObservedContentClass?: 'binary' | 'office' | 'text' | 'unclassified' | null
  RevisionBackend?: 'git_sha256' | 'legacy_payload' | 'shared_chunks' | null
}

export interface ShareRecord {
  ExpiresAt?: string
  Id: string
  Kind: 'direct' | 'group' | 'link'
  Permission: 'Contributor' | 'Manager' | 'Viewer'
  ResourceId: string
  ResourceName: string
  Target: string
}

export interface SessionRecord {
  Current: boolean
  Device: string
  Id: string
  LastActiveAt: string
  Location: string
}

export interface PrivacyEvent {
  Action: string
  Actor: string
  CreatedAt: string
  Id: string
  Unread: boolean
}

export interface AdminUser {
  Email: string
  Id: string
  Name: string
  Status: 'active' | 'suspended'
}

export interface AdminGroup {
  Id: string
  ManagerCount: number
  MemberCount: number
  Name: string
}

export interface AdminDrive {
  Id: string
  Name: string
  QuotaBytes: number
  UsedBytes: number
}

export interface WorkspaceSnapshot {
  Admin: {
    Drives: AdminDrive[]
    Groups: AdminGroup[]
    Users: AdminUser[]
  }
  CurrentUser: {
    DisplayName: string
    Email: string
    IsTenantAdmin: boolean
  }
  Drives: WorkspaceDrive[]
  Entries: FileEntry[]
  Privacy: PrivacyEvent[]
  Sessions: SessionRecord[]
  Shares: ShareRecord[]
  Uploads: UploadRecord[]
  Versions: VersionRecord[]
}

export interface UploadCandidate {
  Data?: Blob
  MediaType?: string
  Name: string
  Size: number
}

export interface UploadTarget {
  DriveId: string
  ParentId: string
}
