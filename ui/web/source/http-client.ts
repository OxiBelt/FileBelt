// SPDX-License-Identifier: Apache-2.0

import createClient from 'openapi-fetch'
import type { Client } from 'openapi-fetch'

import { AclConflictError, AuthenticationRequiredError, VersionConflictError } from './client.js'
import type {
  AclCollection,
  AclEntryMutation,
  AclPrincipalSelector,
  CreateShareInput,
  EntryMutationOutcome,
  FileBeltClient,
  PublicShareClient,
  PublicShareGrant,
  MarkdownSaveInput,
  MarkdownImportInput,
  MarkdownCollaborationGrant,
  MarkdownHead,
  TextComparison,
  TextPreferences,
  VersionPage as TextVersionPage,
  WorkspaceLoadScope,
} from './client.js'
import type { components, operations, paths } from './generated/openapi.js'
import type {
  FileEntry,
  SessionRecord,
  ShareRecord,
  UploadCandidate,
  UploadTarget,
  VersionRecord,
  WorkspaceSnapshot,
} from './model.js'

type SessionResponse = components['schemas']['Session']
type SessionSummaryResponse = components['schemas']['SessionSummary']
type DriveResponse = components['schemas']['Drive']
type NodeResponse = components['schemas']['Node']
type VersionResponse = components['schemas']['FileVersion']
type ShareResponse = components['schemas']['DirectShare']
type UploadAllocation = components['schemas']['UploadAllocation']
type ByteGrant = components['schemas']['ByteGrant']
type UploadGrants = components['schemas']['UploadGrants']
type DownloadGrant = components['schemas']['DownloadGrant']
type CollaborationGrant = components['schemas']['CollaborationGrant']
type MarkdownImportIntent = components['schemas']['MarkdownImportIntent']
type DrivePage = components['schemas']['DrivePage']
type NodePage = components['schemas']['NodePage']
type VersionPage = components['schemas']['VersionPage']
type TextComparisonResponse = components['schemas']['TextVersionComparison']
type TextPreferencesResponse = components['schemas']['TextPreferences']
type AclCollectionResponse = components['schemas']['AclCollection']
type UploadCommit = operations['commitUpload']['responses'][201]['content']['application/json']

interface NodeLocation {
  DriveId: string
  HeadVersionId: string | null
  Kind: NodeResponse['kind']
  NamespaceGeneration: number
  ParentId: string | null
}

interface DirectShareLocation {
  DriveId: string
  NodeId: string
  PrincipalId: string
}

interface WorkspaceRoutingState {
  Locations: Map<string, NodeLocation>
  Session: SessionResponse | null
  Shares: Map<string, DirectShareLocation>
  UploadTarget: { DriveId: string; NamespaceGeneration: number; RootId: string } | null
  Versions: Map<string, { DriveId: string; NodeId: string }>
}

interface Page<T> {
  // oxlint-disable-next-line filebelt/pascal-case -- Generated OpenAPI page responses expose this exact key.
  readonly items: readonly T[]
  // oxlint-disable-next-line filebelt/pascal-case -- Generated OpenAPI page responses expose this exact key.
  readonly next_cursor: string | null
}

interface ApiResult<T> {
  // oxlint-disable-next-line filebelt/pascal-case -- `openapi-fetch` returns this exact result key.
  readonly data?: T
  // oxlint-disable-next-line filebelt/pascal-case -- `openapi-fetch` returns this exact result key.
  readonly error?: unknown
  // oxlint-disable-next-line filebelt/pascal-case -- `openapi-fetch` returns this exact result key.
  readonly response: Response
}

interface MutationHeaders {
  Origin: string
  'Sec-Fetch-Site': 'same-origin'
  'X-FileBelt-Csrf': string
}

interface IdempotencyHeaders {
  'Idempotency-Key': string
}

interface PageQueryShape {
  // oxlint-disable-next-line filebelt/pascal-case -- Generated OpenAPI query parameters expose this exact key.
  cursor?: string
  // oxlint-disable-next-line filebelt/pascal-case -- Generated OpenAPI query parameters expose this exact key.
  limit: number
}

type SignalInitShape = {
  // oxlint-disable-next-line filebelt/pascal-case -- Fetch `RequestInit` exposes this exact abort-signal key.
  signal?: AbortSignal
}

export class ApiRequestError extends Error {
  readonly Code: string | null
  readonly Detail: string | null
  readonly Status: number

  constructor(Status: number, Message: string, Code: string | null, Detail: string | null) {
    super(Message)
    this.name = 'ApiRequestError'
    this.Code = Code
    this.Detail = Detail
    this.Status = Status
  }
}

const PageLimit = 200

/** Same-origin production adapter for the generated FileBelt HTTP contract. */
export class HttpFileBeltClient implements FileBeltClient, PublicShareClient {
  readonly #Api: Client<paths>
  readonly #BaseUrl: string
  readonly #Fetch: typeof fetch
  #Routing: WorkspaceRoutingState = {
    Locations: new Map(),
    Session: null,
    Shares: new Map(),
    UploadTarget: null,
    Versions: new Map(),
  }
  #WorkspaceRefreshGeneration = 0

  constructor(
    FetchImplementation: typeof fetch = globalThis.fetch.bind(globalThis),
    BaseUrl: string = DefaultBaseUrl(),
  ) {
    this.#BaseUrl = BaseUrl
    this.#Fetch = FetchImplementation
    this.#Api = createClient<paths>({
      baseUrl: BaseUrl,
      credentials: 'same-origin',
      fetch: async (Request) => this.#Fetch(Request),
    })
  }

  async GetWorkspace(
    Signal?: Readonly<AbortSignal>,
    Scope: WorkspaceLoadScope = { Kind: 'global' },
  ): Promise<WorkspaceSnapshot> {
    const RefreshGeneration = ++this.#WorkspaceRefreshGeneration
    const Session = RequireData<SessionResponse>(
      await this.#Api.GET('/api/v1/session', SignalInit(Signal)),
    )
    const Drives = await this.#CollectPages<DriveResponse>(async (Cursor) =>
      RequireData<DrivePage>(
        await this.#Api.GET('/api/v1/drives', {
          params: { query: PageQuery(Cursor) },
          ...SignalInit(Signal),
        }),
      ),
    )
    const PrivateDrive = Drives.find(({ kind: Kind }) => Kind === 'private') ?? null
    let UploadTarget: WorkspaceRoutingState['UploadTarget']
    if (PrivateDrive === null) {
      UploadTarget = null
    } else {
      const Root = await this.#GetNode(PrivateDrive.id, PrivateDrive.root_id, Signal)
      if (Root.kind !== 'directory') throw new Error('The private drive root is unavailable.')
      UploadTarget = {
        DriveId: PrivateDrive.id,
        NamespaceGeneration: Root.namespace_generation,
        RootId: PrivateDrive.root_id,
      }
    }

    const Entries: FileEntry[] = []
    const Versions: VersionRecord[] = []
    const Shares: ShareRecord[] = []
    const Locations = new Map<string, NodeLocation>()
    const ShareLocations = new Map<string, DirectShareLocation>()
    const VersionLocations = new Map<string, { DriveId: string; NodeId: string }>()
    const FolderDriveId =
      Scope.Kind === 'folder' ? (Scope.DriveId ?? PrivateDrive?.id ?? null) : null
    for (const Drive of Drives) {
      if (Scope.Kind === 'folder' && Drive.id !== FolderDriveId) continue
      const Nodes: NodeResponse[] = []
      if (Scope.Kind === 'folder') {
        const CurrentNodeId = Scope.NodeId ?? Drive.root_id
        if (Scope.NodeId !== null) {
          const Current = await this.#GetNode(Drive.id, CurrentNodeId, Signal)
          if (Current.kind !== 'directory') throw new Error('The selected folder is unavailable.')
          Nodes.push(Current)
        }
        Nodes.push(...(await this.#ListChildren(Drive.id, CurrentNodeId, Signal)))
      } else {
        const Directories = [Drive.root_id]
        while (Directories.length > 0) {
          const ParentId = Directories.shift()
          if (ParentId === undefined) break
          const Children = await this.#ListChildren(Drive.id, ParentId, Signal)
          Nodes.push(...Children)
          Directories.push(
            ...Children.filter(({ kind: Kind }) => Kind === 'directory').map(({ id: Id }) => Id),
          )
        }
        Nodes.push(...(await this.#ListTrash(Drive.id, Signal)))
      }
      for (const Node of Nodes) {
        Locations.set(Node.id, {
          DriveId: Drive.id,
          HeadVersionId: Node.kind === 'file' ? Node.head_version_id : null,
          Kind: Node.kind,
          NamespaceGeneration: Node.namespace_generation,
          ParentId: Node.parent_id,
        })
        const NodeVersions =
          Scope.Kind === 'global' && Node.kind === 'file'
            ? await this.#ListVersions(Drive.id, Node.id, Signal)
            : []
        for (const Version of NodeVersions) {
          VersionLocations.set(Version.id, { DriveId: Drive.id, NodeId: Node.id })
          Versions.push(VersionRecord(Version))
        }
        const NodeShares = await this.#OptionalShares(Drive.id, Node.id, Signal)
        for (const Share of NodeShares) {
          const ShareId = crypto.randomUUID()
          ShareLocations.set(ShareId, {
            DriveId: Drive.id,
            NodeId: Node.id,
            PrincipalId: Share.principal_id,
          })
          Shares.push({
            Id: ShareId,
            Kind: Share.kind,
            Permission: SharePermission(Share.preset),
            ResourceId: Node.id,
            ResourceName: Node.display_name,
            Target: Share.verified_email,
          })
        }
        Entries.push(
          FileEntry(
            Node,
            Drive.owner_display_name,
            Drive.kind === 'shared' || NodeShares.length > 0,
          ),
        )
      }
    }

    const KnownEntries = new Set(Entries.map(({ Id }) => Id))
    const SharedNodes =
      Scope.Kind === 'global'
        ? await this.#CollectPages<NodeResponse>(async (Cursor) =>
            RequireData<NodePage>(
              await this.#Api.GET('/api/v1/shared', {
                params: { query: PageQuery(Cursor) },
                ...SignalInit(Signal),
              }),
            ),
          )
        : []
    for (const Node of SharedNodes) {
      if (KnownEntries.has(Node.id)) continue
      Locations.set(Node.id, {
        DriveId: Node.drive_id,
        HeadVersionId: Node.kind === 'file' ? Node.head_version_id : null,
        Kind: Node.kind,
        NamespaceGeneration: Node.namespace_generation,
        ParentId: Node.parent_id,
      })
      if (Node.kind === 'file') {
        const NodeVersions = await this.#ListVersions(Node.drive_id, Node.id, Signal)
        for (const Version of NodeVersions) {
          VersionLocations.set(Version.id, { DriveId: Node.drive_id, NodeId: Node.id })
          Versions.push(VersionRecord(Version))
        }
      }
      Entries.push(FileEntry(Node, 'Owner unavailable', true))
    }

    const SessionResponse = RequireData<readonly SessionSummaryResponse[]>(
      await this.#Api.GET('/api/v1/sessions', SignalInit(Signal)),
    )
    const Sessions = SessionResponse.map<SessionRecord>((Item: SessionSummaryResponse) => ({
      Current: Item.current,
      Device: Item.user_agent ?? 'Unknown client',
      Id: Item.id,
      LastActiveAt: Item.last_seen_at,
      Location: Item.current ? 'Current device' : 'Location unavailable',
    }))

    const Snapshot: WorkspaceSnapshot = {
      Admin: {
        Drives: Drives.filter(({ kind: Kind }) => Kind === 'shared').map((Drive) => ({
          Id: Drive.id,
          Name: Drive.display_name,
          QuotaBytes: Drive.quota_bytes,
          UsedBytes: Drive.used_physical_bytes,
        })),
        Groups: [],
        Users: [],
      },
      CurrentUser: {
        DisplayName: Session.display_name,
        Email: Session.verified_email ?? '',
        IsTenantAdmin: Session.tenant_admin,
      },
      Drives: Drives.map((Drive) => ({
        Id: Drive.id,
        Kind: Drive.kind,
        Name: Drive.display_name,
        RootId: Drive.root_id,
      })),
      Entries,
      Privacy: [],
      Sessions,
      Shares,
      Uploads: [],
      Versions,
    }
    if (RefreshGeneration !== this.#WorkspaceRefreshGeneration) {
      throw new DOMException('Workspace refresh was superseded.', 'AbortError')
    }
    this.#Routing = {
      Locations,
      Session,
      Shares: ShareLocations,
      UploadTarget,
      Versions: VersionLocations,
    }
    return Snapshot
  }

  async Upload(
    Files: readonly Readonly<UploadCandidate>[],
    RequestedTarget?: Readonly<UploadTarget>,
  ): Promise<void> {
    const DefaultTarget = this.#Routing.UploadTarget
    if (RequestedTarget === undefined && DefaultTarget === null)
      throw new Error('No writable private drive is available.')
    const Target =
      RequestedTarget === undefined
        ? DefaultTarget
        : {
            DriveId: RequestedTarget.DriveId,
            NamespaceGeneration: 0,
            RootId: RequestedTarget.ParentId,
          }
    if (Target === null) throw new Error('No writable upload folder is available.')
    if (RequestedTarget !== undefined) {
      const Location = this.#Location(RequestedTarget.ParentId)
      if (Location.DriveId !== RequestedTarget.DriveId || Location.Kind !== 'directory')
        throw new Error('The upload folder is unavailable.')
    }
    await this.#EnsureSession()
    for (const Candidate of Files) {
      if (Candidate.Data === undefined || Candidate.Data.size !== Candidate.Size) {
        throw new Error('The selected file bytes are unavailable.')
      }
      const Root = await this.#GetNode(Target.DriveId, Target.RootId)
      if (Root.kind !== 'directory') throw new Error('The private drive root is unavailable.')
      Target.NamespaceGeneration = Root.namespace_generation
      const Allocation = RequireData<UploadAllocation>(
        await this.#Api.POST('/api/v1/drives/{drive_id}/uploads', {
          body: {
            declared_size_bytes: Candidate.Size,
            expected_parent_generation: Target.NamespaceGeneration,
            name: Candidate.Name,
            parent_id: Target.RootId,
          },
          params: {
            header: this.#IdempotentMutationHeaders(),
            path: { drive_id: Target.DriveId },
          },
        }),
      )

      let Cursor: string | null = null
      let Finalize: ByteGrant | null
      do {
        const Grants: UploadGrants = RequireData<UploadGrants>(
          await this.#Api.GET('/api/v1/uploads/{upload_id}', {
            params: {
              path: { upload_id: Allocation.upload_id },
              query: PageQuery(Cursor),
            },
          }),
        )
        for (let Index = 0; Index < Grants.parts.length; Index += 1) {
          const Grant = Grants.parts[Index]
          if (Grant === undefined) continue
          const PartNumber = UploadPartNumber(Grant.path) ?? Index
          const Start = PartNumber * Allocation.chunk_size_bytes
          const End = Math.min(Start + Allocation.chunk_size_bytes, Candidate.Size)
          await this.#IoRequest(
            Grant.path,
            {
              body: Candidate.Data.slice(Start, End),
              headers: { Authorization: `fbcap1 ${Grant.authorization}` },
              method: 'PUT',
            },
            'omit',
          )
        }
        Finalize = Grants.finalize
        Cursor = Grants.next_cursor
      } while (Cursor !== null)
      // oxlint-disable-next-line typescript/no-unnecessary-condition -- The pagination callback assigns this required final grant across awaited iterations.
      if (Finalize === null) throw new Error('The upload finalize grant is unavailable.')
      await this.#IoRequest(
        Finalize.path,
        {
          headers: { Authorization: `fbcap1 ${Finalize.authorization}` },
          method: 'POST',
        },
        'omit',
      )
      RequireSuccess(
        await this.#Api.POST('/api/v1/uploads/{upload_id}/commit', {
          body: { expected_fencing_token: Allocation.fencing_token },
          params: {
            header: this.#IdempotentMutationHeaders(),
            path: { upload_id: Allocation.upload_id },
          },
        }),
      )
    }
  }

  async Download(EntryId: string): Promise<Blob> {
    const Location = this.#FileLocation(EntryId)
    await this.#EnsureSession()
    const Grant = RequireData<DownloadGrant>(
      await this.#Api.POST('/api/v1/drives/{drive_id}/nodes/{node_id}/download-grants', {
        body: { version_id: null },
        params: {
          header: this.#MutationHeaders(),
          path: { drive_id: Location.DriveId, node_id: EntryId },
        },
      }),
    )
    const Response = await this.#IoRequest(Grant.path, { method: 'GET' }, 'same-origin')
    return Response.blob()
  }

  async ReadMarkdown(EntryId: string, VersionId: string): Promise<Blob> {
    const Location = this.#FileLocation(EntryId)
    await this.#EnsureSession()
    const Grant = RequireData<DownloadGrant>(
      await this.#Api.POST('/api/v1/drives/{drive_id}/nodes/{node_id}/download-grants', {
        body: { version_id: VersionId },
        params: {
          header: this.#MutationHeaders(),
          path: { drive_id: Location.DriveId, node_id: EntryId },
        },
      }),
    )
    return (await this.#IoRequest(Grant.path, { method: 'GET' }, 'same-origin')).blob()
  }

  async GetTextPreferences(): Promise<{ Etag: string; Value: TextPreferences }> {
    const Result = await this.#Api.GET('/api/v1/preferences/text')
    const Value = RequireData<TextPreferencesResponse>(Result)
    return {
      Etag: RequireEtag(Result.response),
      Value: { EditLimitBytes: Value.edit_limit_bytes, InlineLimitBytes: Value.inline_limit_bytes },
    }
  }

  async GetAcl(
    EntryId: string,
    Signal?: Readonly<AbortSignal>,
  ): Promise<{ Etag: string; Value: AclCollection }> {
    const Location = this.#Location(EntryId)
    const Result = await this.#Api.GET('/api/v1/drives/{drive_id}/nodes/{node_id}/acl', {
      params: { path: { drive_id: Location.DriveId, node_id: EntryId } },
      ...SignalInit(Signal),
    })
    const Value = RequireData<AclCollectionResponse>(Result)
    return {
      Etag: RequireEtag(Result.response),
      Value: AclCollectionValue(Value),
    }
  }

  async ReplaceAcl(
    EntryId: string,
    ExpectedEtag: string,
    Principal: Readonly<AclPrincipalSelector>,
    Entries: readonly Readonly<AclEntryMutation>[],
  ): Promise<{ Etag: string; Value: AclCollection }> {
    const Location = this.#Location(EntryId)
    await this.#EnsureSession()
    try {
      const Result = await this.#Api.PUT('/api/v1/drives/{drive_id}/nodes/{node_id}/acl', {
        body: {
          entries: Entries.map((Entry) => ({
            action: Entry.Action,
            effect: Entry.Effect,
            inheritance: Entry.Inheritance,
          })),
          principal: {
            group_id: Principal.GroupId,
            kind: Principal.Kind,
            verified_email: Principal.VerifiedEmail,
          },
        },
        params: {
          header: { ...this.#MutationHeaders(), 'If-Match': ExpectedEtag },
          path: { drive_id: Location.DriveId, node_id: EntryId },
        },
      })
      const Value = RequireData<AclCollectionResponse>(Result)
      return {
        Etag: RequireEtag(Result.response),
        Value: AclCollectionValue(Value),
      }
    } catch (Cause) {
      if (Cause instanceof ApiRequestError && Cause.Status === 409) throw new AclConflictError()
      throw Cause
    }
  }

  async UpdateTextPreferences(
    Patch: Readonly<TextPreferences>,
    ExpectedEtag: string,
  ): Promise<{ Etag: string; Value: TextPreferences }> {
    await this.#EnsureSession()
    const Result = await this.#Api.PATCH('/api/v1/preferences/text', {
      body: { edit_limit_bytes: Patch.EditLimitBytes, inline_limit_bytes: Patch.InlineLimitBytes },
      params: { header: { ...this.#MutationHeaders(), 'If-Match': ExpectedEtag } },
    })
    const Value = RequireData<TextPreferencesResponse>(Result)
    return {
      Etag: RequireEtag(Result.response),
      Value: { EditLimitBytes: Value.edit_limit_bytes, InlineLimitBytes: Value.inline_limit_bytes },
    }
  }

  async ListTextVersions(EntryId: string, Cursor: string | null): Promise<TextVersionPage> {
    const Location = this.#FileLocation(EntryId)
    const Page = RequireData<VersionPage>(
      await this.#Api.GET('/api/v1/drives/{drive_id}/nodes/{node_id}/versions', {
        params: {
          path: { drive_id: Location.DriveId, node_id: EntryId },
          query: PageQuery(Cursor),
        },
      }),
    )
    for (const Version of Page.items)
      this.#Routing.Versions.set(Version.id, { DriveId: Location.DriveId, NodeId: EntryId })
    return { Items: Page.items.map(VersionRecord), NextCursor: Page.next_cursor }
  }

  async CompareTextVersions(
    EntryId: string,
    BaseVersionId: string,
    TargetVersionId: string,
  ): Promise<TextComparison> {
    const Location = this.#FileLocation(EntryId)
    const Comparison = RequireData<TextComparisonResponse>(
      await this.#Api.GET(
        '/api/v1/drives/{drive_id}/nodes/{node_id}/versions/{base_version_id}/compare/{target_version_id}',
        {
          params: {
            path: {
              base_version_id: BaseVersionId,
              drive_id: Location.DriveId,
              node_id: EntryId,
              target_version_id: TargetVersionId,
            },
          },
        },
      ),
    )
    return {
      Hunks: Comparison.hunks.map((Hunk) => ({
        BaseLines: Hunk.base_lines,
        BaseStart: Hunk.base_start,
        Lines: Hunk.lines.map((Line) => ({
          Kind: Line.kind === 'delete' ? 'remove' : Line.kind,
          Text: Line.text,
        })),
        TargetLines: Hunk.target_lines,
        TargetStart: Hunk.target_start,
      })),
    }
  }

  async SetNodeContentClass(EntryId: string, ContentClass: 'auto' | 'binary'): Promise<void> {
    const Location = this.#FileLocation(EntryId)
    await this.#EnsureSession()
    const Current = await this.#Api.GET('/api/v1/drives/{drive_id}/nodes/{node_id}', {
      params: { path: { drive_id: Location.DriveId, node_id: EntryId } },
    })
    RequireData<NodeResponse>(Current)
    RequireSuccess(
      await this.#Api.PATCH('/api/v1/drives/{drive_id}/nodes/{node_id}/content-class-policy', {
        body: { policy: ContentClass },
        params: {
          header: {
            ...this.#IdempotentMutationHeaders(),
            'If-Match': RequireEtag(Current.response),
          },
          path: { drive_id: Location.DriveId, node_id: EntryId },
        },
      }),
    )
  }

  async ImportMarkdown(Input: Readonly<MarkdownImportInput>): Promise<string> {
    const Location = this.#FileLocation(Input.EntryId)
    await this.#EnsureSession()
    const Intent = RequireData<MarkdownImportIntent>(
      await this.#Api.POST('/api/v1/drives/{drive_id}/nodes/{node_id}/markdown-import-intents', {
        body: { source_version_id: Input.SourceVersionId, target_name: Input.TargetName },
        params: {
          header: this.#IdempotentMutationHeaders(),
          path: { drive_id: Location.DriveId, node_id: Input.EntryId },
        },
      }),
    )
    const Parent = await this.#GetNode(Location.DriveId, Intent.target_parent_id)
    if (Parent.kind !== 'directory') throw new Error('The Office source parent is unavailable.')
    const Allocation = RequireData<UploadAllocation>(
      await this.#Api.POST('/api/v1/drives/{drive_id}/uploads', {
        body: {
          declared_media_type: 'text/markdown',
          declared_size_bytes: Input.Contents.size,
          expected_parent_generation: Parent.namespace_generation,
          import_intent_id: Intent.id,
          name: Intent.target_name,
          parent_id: Intent.target_parent_id,
        },
        params: { header: this.#IdempotentMutationHeaders(), path: { drive_id: Location.DriveId } },
      }),
    )
    return this.#PutUploadContents(Allocation, Input.Contents)
  }

  async BeginMarkdownCollaboration(
    EntryId: string,
    ClientId: string,
  ): Promise<MarkdownCollaborationGrant | null> {
    const Location = this.#FileLocation(EntryId)
    await this.#EnsureSession()
    let Grant: CollaborationGrant
    try {
      Grant = RequireData<CollaborationGrant>(
        await this.#Api.POST('/api/v1/drives/{drive_id}/nodes/{node_id}/collaboration-grants', {
          body: { client_id: ClientId, presence_mode: 'display_name', transport: 'websocket' },
          params: {
            header: this.#IdempotentMutationHeaders(),
            path: { drive_id: Location.DriveId, node_id: EntryId },
          },
        }),
      )
    } catch (Cause) {
      if (Cause instanceof ApiRequestError && Cause.Status === 404) return null
      throw Cause
    }
    const Endpoint = Grant.endpoints.find(({ transport: Transport }) => Transport === 'websocket')
    if (Endpoint === undefined || Grant.room.room_id === null)
      throw new Error('The collaboration endpoint is unavailable.')
    return {
      Authorization: Grant.authorization,
      ClientId,
      EndpointUrl: Endpoint.url,
      PresenceLabel: Grant.presence_label,
      RoomId: Grant.room.room_id,
    }
  }

  async ReadMarkdownHead(EntryId: string): Promise<MarkdownHead> {
    const Location = this.#FileLocation(EntryId)
    await this.#EnsureSession()
    const Node = await this.#GetNode(Location.DriveId, EntryId)
    if (Node.head_version_id === null) throw new Error('The Markdown file has no current version.')
    return {
      Contents: await this.ReadMarkdown(EntryId, Node.head_version_id),
      VersionId: Node.head_version_id,
    }
  }

  async SaveMarkdown(Input: Readonly<MarkdownSaveInput>): Promise<string> {
    const Location = this.#FileLocation(Input.EntryId)
    if (Location.ParentId === null) throw new Error('The Markdown file has no writable parent.')
    await this.#EnsureSession()
    try {
      const Allocation = RequireData<UploadAllocation>(
        await this.#Api.POST('/api/v1/drives/{drive_id}/uploads', {
          body: {
            ...(Input.CheckpointId === undefined
              ? {}
              : { collaboration_checkpoint_id: Input.CheckpointId }),
            declared_media_type: Input.Contents.type || 'text/plain',
            declared_size_bytes: Input.Contents.size,
            expected_head_version_id: Input.ExpectedHeadVersionId,
            name: Input.Name,
            node_id: Input.EntryId,
            parent_id: Location.ParentId,
          },
          params: {
            header: this.#IdempotentMutationHeaders(),
            path: { drive_id: Location.DriveId },
          },
        }),
      )
      return await this.#PutUploadContents(Allocation, Input.Contents)
    } catch (Cause) {
      if (Cause instanceof ApiRequestError && Cause.Status === 409) throw new VersionConflictError()
      throw Cause
    }
  }

  async SaveMarkdownCopy(
    Input: Omit<MarkdownSaveInput, 'CheckpointId' | 'ExpectedHeadVersionId'>,
  ): Promise<string> {
    const Location = this.#FileLocation(Input.EntryId)
    if (Location.ParentId === null) throw new Error('The Markdown file has no writable parent.')
    await this.#EnsureSession()
    const Parent = await this.#GetNode(Location.DriveId, Location.ParentId)
    if (Parent.kind !== 'directory') throw new Error('The Markdown file parent is unavailable.')
    const Allocation = RequireData<UploadAllocation>(
      await this.#Api.POST('/api/v1/drives/{drive_id}/uploads', {
        body: {
          declared_media_type: Input.Contents.type || 'text/plain',
          declared_size_bytes: Input.Contents.size,
          expected_parent_generation: Parent.namespace_generation,
          name: Input.Name,
          parent_id: Location.ParentId,
        },
        params: { header: this.#IdempotentMutationHeaders(), path: { drive_id: Location.DriveId } },
      }),
    )
    return this.#PutUploadContents(Allocation, Input.Contents)
  }

  async TrashEntries(EntryIds: readonly string[]): Promise<readonly EntryMutationOutcome[]> {
    return this.#BatchEntryMutation(EntryIds, async (EntryId, Location) => {
      RequireSuccess(
        await this.#Api.POST('/api/v1/drives/{drive_id}/nodes/{node_id}/trash', {
          body: { expected_namespace_generation: Location.NamespaceGeneration },
          params: {
            header: this.#MutationHeaders(),
            path: { drive_id: Location.DriveId, node_id: EntryId },
          },
        }),
      )
    })
  }

  async RestoreEntries(EntryIds: readonly string[]): Promise<readonly EntryMutationOutcome[]> {
    return this.#BatchEntryMutation(EntryIds, async (EntryId, Location) => {
      RequireSuccess(
        await this.#Api.POST('/api/v1/drives/{drive_id}/nodes/{node_id}/restore', {
          body: { expected_namespace_generation: Location.NamespaceGeneration },
          params: {
            header: this.#MutationHeaders(),
            path: { drive_id: Location.DriveId, node_id: EntryId },
          },
        }),
      )
    })
  }

  async CreateShare(Input: Readonly<CreateShareInput>): Promise<void> {
    if (Input.Kind !== 'direct') {
      throw new Error('This FileBelt version supports direct verified-email shares only.')
    }
    await this.#EnsureSession()
    const Location = this.#Location(Input.FileId)
    RequireSuccess(
      await this.#Api.POST('/api/v1/drives/{drive_id}/nodes/{node_id}/shares', {
        body: {
          inheritance: 'self',
          kind: Input.Kind,
          preset: SharePreset(Input.Permission),
          verified_email: Input.Target,
        },
        params: {
          header: this.#IdempotentMutationHeaders(),
          path: { drive_id: Location.DriveId, node_id: Input.FileId },
        },
      }),
    )
  }

  async RevokeShare(ShareId: string): Promise<void> {
    const Location = this.#Routing.Shares.get(ShareId)
    if (Location === undefined) throw new Error('The selected share is unavailable.')
    await this.#EnsureSession()
    RequireSuccess(
      await this.#Api.DELETE('/api/v1/drives/{drive_id}/nodes/{node_id}/shares/{principal_id}', {
        params: {
          header: this.#MutationHeaders(),
          path: {
            drive_id: Location.DriveId,
            node_id: Location.NodeId,
            principal_id: Location.PrincipalId,
          },
        },
      }),
    )
  }

  async RestoreVersion(VersionId: string): Promise<void> {
    const Location = this.#Routing.Versions.get(VersionId)
    if (Location === undefined) throw new Error('The selected version is unavailable.')
    const Node = this.#Location(Location.NodeId)
    if (Node.HeadVersionId === null) throw new Error('The selected file head is unavailable.')
    await this.#EnsureSession()
    RequireSuccess(
      await this.#Api.POST(
        '/api/v1/drives/{drive_id}/nodes/{node_id}/versions/{version_id}/restore',
        {
          body: { expected_head_version_id: Node.HeadVersionId },
          params: {
            header: this.#IdempotentMutationHeaders(),
            path: {
              drive_id: Location.DriveId,
              node_id: Location.NodeId,
              version_id: VersionId,
            },
          },
        },
      ),
    )
  }

  async RevokeSession(SessionId: string): Promise<void> {
    await this.#EnsureSession()
    RequireSuccess(
      await this.#Api.DELETE('/api/v1/sessions/{session_id}', {
        params: {
          header: this.#MutationHeaders(),
          path: { session_id: SessionId },
        },
      }),
    )
  }

  // oxlint-disable typescript/require-await -- Unsupported operations must retain the asynchronous client interface while rejecting immediately.
  async MarkPrivacyRead(): Promise<void> {
    throw new Error('Privacy notification updates are not available in this release.')
  }

  async SuspendUser(): Promise<void> {
    throw new Error('Tenant user administration is not available in this release.')
  }

  async CreateGroup(): Promise<void> {
    throw new Error('Group administration is not available in this release.')
  }

  async CreateSharedDrive(): Promise<void> {
    throw new Error('Shared-drive administration is not available in this release.')
  }

  async ExchangePublicShare(): Promise<PublicShareGrant> {
    throw new Error('Anonymous share links are not available in this release.')
  }

  async DownloadPublic(): Promise<Blob> {
    throw new Error('Anonymous share links are not available in this release.')
  }
  // oxlint-enable typescript/require-await

  #Location(EntryId: string): NodeLocation {
    const Location = this.#Routing.Locations.get(EntryId)
    if (Location === undefined) throw new Error('The selected resource is unavailable.')
    return Location
  }

  #FileLocation(EntryId: string): NodeLocation {
    const Location = this.#Location(EntryId)
    if (Location.Kind !== 'file') throw new Error('The selected resource is not a file.')
    return Location
  }

  async #PutUploadContents(Allocation: UploadAllocation, Contents: Blob): Promise<string> {
    let Cursor: string | null = null
    let Finalize: ByteGrant | null
    do {
      const Grants: UploadGrants = RequireData<UploadGrants>(
        await this.#Api.GET('/api/v1/uploads/{upload_id}', {
          params: { path: { upload_id: Allocation.upload_id }, query: PageQuery(Cursor) },
        }),
      )
      for (let Index = 0; Index < Grants.parts.length; Index += 1) {
        const Grant = Grants.parts[Index]
        if (Grant === undefined) continue
        const PartNumber = UploadPartNumber(Grant.path) ?? Index
        const Start = PartNumber * Allocation.chunk_size_bytes
        const End = Math.min(Start + Allocation.chunk_size_bytes, Contents.size)
        await this.#IoRequest(
          Grant.path,
          {
            body: Contents.slice(Start, End),
            headers: { Authorization: `fbcap1 ${Grant.authorization}` },
            method: 'PUT',
          },
          'omit',
        )
      }
      Finalize = Grants.finalize
      Cursor = Grants.next_cursor
    } while (Cursor !== null)
    // oxlint-disable-next-line typescript/no-unnecessary-condition -- The pagination callback assigns this required final grant across awaited iterations.
    if (Finalize === null) throw new Error('The upload finalize grant is unavailable.')
    await this.#IoRequest(
      Finalize.path,
      { headers: { Authorization: `fbcap1 ${Finalize.authorization}` }, method: 'POST' },
      'omit',
    )
    const Committed = RequireData<UploadCommit>(
      await this.#Api.POST('/api/v1/uploads/{upload_id}/commit', {
        body: { expected_fencing_token: Allocation.fencing_token },
        params: {
          header: this.#IdempotentMutationHeaders(),
          path: { upload_id: Allocation.upload_id },
        },
      }),
    )
    return Committed.version_id
  }

  async #CollectPages<T>(LoadPage: (Cursor: string | null) => Promise<Page<T>>): Promise<T[]> {
    const Items: T[] = []
    let Cursor: string | null = null
    do {
      const Page = await LoadPage(Cursor)
      Items.push(...Page.items)
      Cursor = Page.next_cursor
    } while (Cursor !== null)
    return Items
  }

  async #BatchEntryMutation(
    EntryIds: readonly string[],
    Operation: (EntryId: string, Location: Readonly<NodeLocation>) => Promise<void>,
  ): Promise<readonly EntryMutationOutcome[]> {
    if (EntryIds.length === 0) return []
    try {
      await this.#EnsureSession()
    } catch (Cause) {
      return EntryIds.map((EntryId) => FailedEntryMutation(EntryId, Cause))
    }
    const Outcomes: EntryMutationOutcome[] = []
    for (const EntryId of EntryIds) {
      try {
        await Operation(EntryId, this.#Location(EntryId))
        Outcomes.push({ EntryId, Kind: 'success' })
      } catch (Cause) {
        Outcomes.push(FailedEntryMutation(EntryId, Cause))
      }
    }
    return Outcomes
  }

  async #GetNode(
    DriveId: string,
    NodeId: string,
    Signal?: Readonly<AbortSignal>,
  ): Promise<NodeResponse> {
    return RequireData<NodeResponse>(
      await this.#Api.GET('/api/v1/drives/{drive_id}/nodes/{node_id}', {
        params: { path: { drive_id: DriveId, node_id: NodeId } },
        ...SignalInit(Signal),
      }),
    )
  }

  async #ListChildren(
    DriveId: string,
    NodeId: string,
    Signal?: Readonly<AbortSignal>,
  ): Promise<NodeResponse[]> {
    return this.#CollectPages(async (Cursor) =>
      RequireData<NodePage>(
        await this.#Api.GET('/api/v1/drives/{drive_id}/nodes/{node_id}/children', {
          params: {
            path: { drive_id: DriveId, node_id: NodeId },
            query: PageQuery(Cursor),
          },
          ...SignalInit(Signal),
        }),
      ),
    )
  }

  async #ListTrash(DriveId: string, Signal?: Readonly<AbortSignal>): Promise<NodeResponse[]> {
    return this.#CollectPages(async (Cursor) =>
      RequireData<NodePage>(
        await this.#Api.GET('/api/v1/drives/{drive_id}/trash', {
          params: {
            path: { drive_id: DriveId },
            query: PageQuery(Cursor),
          },
          ...SignalInit(Signal),
        }),
      ),
    )
  }

  async #ListVersions(
    DriveId: string,
    NodeId: string,
    Signal?: Readonly<AbortSignal>,
  ): Promise<VersionResponse[]> {
    return this.#CollectPages(async (Cursor) =>
      RequireData<VersionPage>(
        await this.#Api.GET('/api/v1/drives/{drive_id}/nodes/{node_id}/versions', {
          params: {
            path: { drive_id: DriveId, node_id: NodeId },
            query: PageQuery(Cursor),
          },
          ...SignalInit(Signal),
        }),
      ),
    )
  }

  async #OptionalShares(
    DriveId: string,
    NodeId: string,
    Signal?: Readonly<AbortSignal>,
  ): Promise<readonly ShareResponse[]> {
    const Result = await this.#Api.GET('/api/v1/drives/{drive_id}/nodes/{node_id}/shares', {
      params: { path: { drive_id: DriveId, node_id: NodeId } },
      ...SignalInit(Signal),
    })
    if (Result.response.status === 404) return []
    return RequireData<readonly ShareResponse[]>(Result)
  }

  async #EnsureSession(): Promise<SessionResponse> {
    if (this.#Routing.Session !== null) return this.#Routing.Session
    const Session = RequireData<SessionResponse>(await this.#Api.GET('/api/v1/session'))
    this.#Routing = { ...this.#Routing, Session }
    return Session
  }

  #MutationHeaders(): MutationHeaders {
    if (this.#Routing.Session === null) throw new Error('The session is unavailable.')
    return {
      Origin: new URL(this.#BaseUrl).origin,
      'Sec-Fetch-Site': 'same-origin',
      'X-FileBelt-Csrf': this.#Routing.Session.csrf_token,
    }
  }

  #IdempotentMutationHeaders(): MutationHeaders & IdempotencyHeaders {
    return { ...this.#MutationHeaders(), 'Idempotency-Key': crypto.randomUUID() }
  }

  async #IoRequest(
    Path: string,
    // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- RequestInit is a mutable platform union that is copied into a new Request.
    Init: Readonly<RequestInit>,
    Credentials: RequestCredentials,
  ): Promise<Response> {
    const HttpRequest = new Request(new URL(Path, this.#BaseUrl), {
      ...Init,
      credentials: Credentials,
    })
    const Response = await this.#Fetch(HttpRequest)
    if (Response.ok) return Response
    let Problem: unknown
    try {
      Problem = await Response.json()
    } catch {
      Problem = undefined
    }
    throw RequestError(Response, Problem)
  }
}

function DefaultBaseUrl(): string {
  return typeof window === 'undefined' ? 'https://filebelt.localhost' : window.location.origin
}

function FileEntry(Node: NodeResponse, Owner: string, Shared: boolean): FileEntry {
  const IsFile = Node.kind === 'file'
  return {
    DriveId: Node.drive_id,
    Id: Node.id,
    HeadVersionId: IsFile ? Node.head_version_id : null,
    Kind: Node.kind === 'directory' ? 'folder' : Node.kind,
    ModifiedAt: Node.updated_at,
    TextEligibility: IsFile
      ? TextEligibility(
          Node.content_class_policy,
          Node.display_name,
          Node.head_media_type,
          Node.size_bytes,
        )
      : 'ineligible',
    MediaType: IsFile ? Node.head_media_type : null,
    Name: Node.display_name,
    Owner,
    ParentId: Node.parent_id,
    Shared,
    Size: IsFile ? Node.size_bytes : null,
    Status: 'ready',
    Trashed: Node.trashed,
    Version: IsFile ? (Node.version_ordinal ?? 0) : 0,
  }
}

function TextEligibility(
  Policy: NodeResponse['content_class_policy'],
  Name: string,
  MediaType: string | null,
  Size: number | null,
): FileEntry['TextEligibility'] {
  const IsText =
    MediaType?.startsWith('text/') === true ||
    /\.(?:asc|conf|csv|ini|json|log|md|markdown|mdown|mkdn|rst|sh|text|toml|ts|tsx|txt|xml|yaml|yml)$/i.test(
      Name,
    )
  if (Policy === 'binary') return 'history-only'
  if (!IsText || Size === null) return 'ineligible'
  if (Size > 100 * 1024 * 1024) return 'history-only'
  return Size <= 16 * 1024 * 1024 ? 'editable' : 'viewable'
}

function AclCollectionValue(Value: Readonly<AclCollectionResponse>): AclCollection {
  return {
    Entries: Value.entries.map((Entry) => ({
      Action: Entry.action,
      DisplayName: Entry.display_name,
      Effect: Entry.effect,
      GroupId: Entry.group_id,
      Inheritance: Entry.inheritance,
      PrincipalId: Entry.principal_id,
      PrincipalKind: Entry.principal_kind,
      ReadOnly: Entry.read_only,
      Source: Entry.source,
      VerifiedEmail: Entry.verified_email,
    })),
    SupportedActions: Value.supported_actions,
  }
}

function PageQuery(Cursor: string | null): PageQueryShape {
  return Cursor === null ? { limit: PageLimit } : { cursor: Cursor, limit: PageLimit }
}

// oxlint-disable-next-line typescript/no-unnecessary-type-parameters -- The generated operation at each call site supplies the expected response schema.
function RequireData<T>(Result: ApiResult<unknown>): T {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- openapi-fetch has already selected the generated schema for the successful operation.
  if (Result.response.ok && Result.data !== undefined) return Result.data as T
  throw RequestError(Result.response, Result.error)
}

function RequireSuccess(Result: ApiResult<unknown>): void {
  if (!Result.response.ok) throw RequestError(Result.response, Result.error)
}

function RequireEtag(Response: Response): string {
  const Etag = Response.headers.get('ETag')
  if (Etag === null || Etag.length === 0)
    throw new Error('The server did not return the required generation ETag.')
  return Etag
}

function RequestError(Response: Response, Error: unknown): Error {
  if (Response.status === 401) return new AuthenticationRequiredError()
  return new ApiRequestError(
    Response.status,
    ProblemTitle(Error) ?? `FileBelt request failed (${Response.status}).`,
    ProblemString(Error, 'code'),
    ProblemString(Error, 'detail'),
  )
}

function FailedEntryMutation(EntryId: string, Cause: unknown): EntryMutationOutcome {
  if (Cause instanceof ApiRequestError) {
    return {
      EntryId,
      Error: {
        Code: Cause.Code,
        Detail: Cause.Detail,
        Message: Cause.message,
        Status: Cause.Status,
      },
      Kind: 'failure',
    }
  }
  if (Cause instanceof AuthenticationRequiredError) {
    return {
      EntryId,
      Error: { Code: null, Detail: null, Message: Cause.message, Status: 401 },
      Kind: 'failure',
    }
  }
  return {
    EntryId,
    Error: {
      Code: null,
      Detail: null,
      Message:
        Cause instanceof Error ? Cause.message : 'The selected resource could not be changed.',
      Status: null,
    },
    Kind: 'failure',
  }
}

function ProblemTitle(Value: unknown): string | null {
  return ProblemString(Value, 'title')
}

function ProblemString(Value: unknown, Key: 'code' | 'detail' | 'title'): string | null {
  if (!IsProblemObject(Value)) return null
  const Candidate = Value[Key]
  return typeof Candidate === 'string' ? Candidate : null
}

function IsProblemObject(
  Value: unknown,
): Value is Partial<Record<'code' | 'detail' | 'title', unknown>> {
  return typeof Value === 'object' && Value !== null
}

function UploadPartNumber(Path: string): number | null {
  const Match = /\/parts\/(\d+)$/.exec(Path)
  if (Match?.[1] === undefined) return null
  const Value = Number.parseInt(Match[1], 10)
  return Number.isSafeInteger(Value) ? Value : null
}

function SignalInit(Signal: Readonly<AbortSignal> | undefined): SignalInitShape {
  return Signal === undefined ? {} : { signal: Signal }
}

// oxlint-disable-next-line typescript/consistent-return -- The generated preset union is exhaustive and has no fallback wire value.
function SharePermission(Preset: ShareResponse['preset']): ShareRecord['Permission'] {
  switch (Preset) {
    case 'contributor':
      return 'Contributor'
    case 'manager':
      return 'Manager'
    case 'viewer':
      return 'Viewer'
  }
}

// oxlint-disable-next-line typescript/consistent-return -- The local permission union is exhaustive and has no fallback wire value.
function SharePreset(Permission: ShareRecord['Permission']): ShareResponse['preset'] {
  switch (Permission) {
    case 'Contributor':
      return 'contributor'
    case 'Manager':
      return 'manager'
    case 'Viewer':
      return 'viewer'
  }
}

function VersionRecord(Version: VersionResponse): VersionRecord {
  return {
    Author: Version.created_by,
    CreatedAt: Version.created_at,
    FileId: Version.node_id,
    Id: Version.id,
    GitCommitOid: Version.git_commit_oid,
    ObservedContentClass: Version.observed_content_class,
    RevisionBackend: Version.revision_backend,
    Size: Version.size_bytes,
    Version: Version.ordinal,
  }
}
