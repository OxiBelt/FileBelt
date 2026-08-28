// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest'

import { AclConflictError, AuthenticationRequiredError } from './client.js'
import type { components } from './generated/openapi.js'
import { HttpFileBeltClient } from './http-client.js'

const DriveId = '00000000-0000-4000-8000-000000000001'
const RootId = '00000000-0000-4000-8000-000000000002'
const FirstNodeId = '00000000-0000-4000-8000-000000000003'
const SecondNodeId = '00000000-0000-4000-8000-000000000004'
const PrincipalId = '00000000-0000-4000-8000-000000000005'
const GroupId = '00000000-0000-4000-8000-000000000016'
const UploadId = '00000000-0000-4000-8000-000000000006'
const PayloadId = '00000000-0000-4000-8000-000000000007'
const GrantId = '00000000-0000-4000-8000-000000000008'
const ImportIntentId = '00000000-0000-4000-8000-000000000014'
const SymlinkNodeId = '00000000-0000-4000-8000-000000000015'
const FirstVersionId = '00000000-0000-4000-8000-000000000012'
const SecondVersionId = '00000000-0000-4000-8000-000000000013'

const Session = {
  csrf_token: 'csrf-value-not-browser-storage',
  display_name: 'Avery Morgan',
  principal_id: '00000000-0000-4000-8000-000000000009',
  reauthenticated_recently: true,
  session_id: '00000000-0000-4000-8000-000000000010',
  tenant_admin: false,
  user_id: '00000000-0000-4000-8000-000000000011',
  verified_email: 'avery@example.test',
} satisfies components['schemas']['Session']

const Drive = {
  acl_generation: 1,
  display_name: 'My Drive',
  id: DriveId,
  kind: 'private',
  namespace_generation: 300,
  owner_display_name: 'Avery Morgan',
  quota_bytes: 1_000_000,
  reserved_bytes: 0,
  root_id: RootId,
  used_physical_bytes: 64,
} satisfies components['schemas']['Drive']

const SessionSummary = {
  absolute_expires_at: '2026-08-07T12:00:00Z',
  created_at: '2026-08-06T10:00:00Z',
  current: true,
  id: Session.session_id,
  idle_expires_at: '2026-08-06T13:00:00Z',
  last_seen_at: '2026-08-06T12:00:00Z',
  revoked: false,
  user_agent: 'Firefox',
} satisfies components['schemas']['SessionSummary']

function Node(Id: string, Name: string): components['schemas']['Node'] {
  return {
    acl_generation: 1,
    attribute_generation: 2,
    content_class_policy: 'auto',
    display_name: Name,
    drive_id: DriveId,
    head_media_type: 'text/markdown',
    head_version_id: '00000000-0000-4000-8000-000000000012',
    id: Id,
    kind: 'file',
    namespace_generation: 4,
    parent_id: RootId,
    size_bytes: 4,
    trashed: false,
    updated_at: '2026-08-06T12:00:00Z',
    version_ordinal: 1,
  }
}

function SymlinkNode(): components['schemas']['Node'] {
  return {
    ...Node(SymlinkNodeId, 'Current report'),
    head_media_type: null,
    head_version_id: null,
    kind: 'symlink',
    size_bytes: null,
    version_ordinal: null,
  }
}

function DirectoryNode(Id: string, Name: string): components['schemas']['Node'] {
  return {
    ...Node(Id, Name),
    head_media_type: null,
    head_version_id: null,
    kind: 'directory',
    size_bytes: null,
    version_ordinal: null,
  }
}

function DirectShare(): components['schemas']['DirectShare'] {
  return {
    created_at: '2026-08-06T12:00:00Z',
    display_name: 'Layla Hassan',
    inheritance: 'self',
    kind: 'direct',
    preset: 'viewer',
    principal_id: PrincipalId,
    verified_email: 'layla@example.test',
  }
}

class ContractServer {
  readonly Requests: Request[] = []
  readonly #Nodes: readonly components['schemas']['Node'][]
  #RootReads = 0

  constructor(Nodes: readonly components['schemas']['Node'][]) {
    this.#Nodes = Nodes
  }

  // oxlint-disable-next-line filebelt/pascal-case, typescript/require-await -- Fetch's platform spelling and Promise contract are required by the injected transport fake.
  readonly fetch: typeof fetch = async (Input, Init) => {
    const HttpRequest = Input instanceof Request ? Input : new Request(Input, Init)
    this.Requests.push(HttpRequest)
    const Path = new URL(HttpRequest.url).pathname

    if (Path === '/api/v1/session' && HttpRequest.method === 'GET') return Json(Session)
    if (Path === '/api/v1/drives' && HttpRequest.method === 'GET') {
      return Json({ items: [Drive], next_cursor: null })
    }
    if (Path === `/api/v1/drives/${DriveId}/nodes/${RootId}` && HttpRequest.method === 'GET') {
      this.#RootReads += 1
      return Json({
        ...Node(RootId, 'My Drive'),
        head_version_id: null,
        kind: 'directory',
        namespace_generation: this.#RootReads === 1 ? 17 : 19,
        parent_id: null,
        size_bytes: null,
        version_ordinal: null,
      })
    }
    if (Path === `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}` && HttpRequest.method === 'GET')
      return Json(
        this.#Nodes.find(({ id: Id }) => Id === FirstNodeId) ?? Node(FirstNodeId, 'File one.txt'),
        200,
        { ETag: '"node-attribute-2"' },
      )
    if (
      Path === `/api/v1/drives/${DriveId}/nodes/${RootId}/children` &&
      HttpRequest.method === 'GET'
    ) {
      return Json({ items: this.#Nodes, next_cursor: null })
    }
    if (Path === `/api/v1/drives/${DriveId}/trash` && HttpRequest.method === 'GET') {
      return Json({ items: [], next_cursor: null })
    }
    if (Path === '/api/v1/shared' && HttpRequest.method === 'GET') {
      return Json({ items: [], next_cursor: null })
    }
    if (Path === '/api/v1/sessions' && HttpRequest.method === 'GET') return Json([SessionSummary])
    if (Path === '/api/v1/preferences/text' && HttpRequest.method === 'GET')
      return Json(
        { edit_limit_bytes: 2_097_152, generation: 5, inline_limit_bytes: 8_388_608 },
        200,
        { ETag: '"preferences-5"' },
      )
    if (Path === '/api/v1/preferences/text' && HttpRequest.method === 'PATCH')
      return Json(
        { edit_limit_bytes: 4_194_304, generation: 6, inline_limit_bytes: 8_388_608 },
        200,
        { ETag: '"preferences-6"' },
      )
    if (
      Path === `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/acl` &&
      HttpRequest.method === 'GET'
    )
      return Json(AclCollection(), 200, { ETag: '"acl-7"' })
    if (
      Path === `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/acl` &&
      HttpRequest.method === 'PUT'
    )
      return Json(AclCollection(), 200, { ETag: '"acl-8"' })
    if (
      Path ===
        `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/versions/${FirstVersionId}/compare/${SecondVersionId}` &&
      HttpRequest.method === 'GET'
    )
      return Json({
        algorithm: 'git-histogram-v1',
        base_final_newline: true,
        base_version_id: FirstVersionId,
        context_lines: 3,
        hunks: [
          {
            base_lines: 1,
            base_start: 1,
            lines: [{ base_line: 1, kind: 'context', target_line: 1, text: 'same' }],
            target_lines: 1,
            target_start: 1,
          },
        ],
        target_final_newline: true,
        target_version_id: SecondVersionId,
      })
    if (
      Path === `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/content-class-policy` &&
      HttpRequest.method === 'PATCH'
    )
      return Json(Node(FirstNodeId, 'File one.txt'), 200, { ETag: '"node-attribute-3"' })
    if (Path.endsWith('/versions') && HttpRequest.method === 'GET') {
      return Json({
        items: [
          FileVersion(FirstNodeId, FirstVersionId),
          FileVersion(FirstNodeId, SecondVersionId),
        ],
        next_cursor: null,
      })
    }
    if (Path.endsWith('/shares') && HttpRequest.method === 'GET') return Json([DirectShare()])
    if (Path === `/api/v1/drives/${DriveId}/uploads` && HttpRequest.method === 'POST') {
      return Json(UploadAllocation(), 201)
    }
    if (
      Path === `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/markdown-import-intents` &&
      HttpRequest.method === 'POST'
    ) {
      const SourceVersionId = Node(FirstNodeId, 'Source.docx').head_version_id
      if (SourceVersionId === null) throw new Error('The source fixture requires a head version.')
      return Json(
        {
          expires_at: '2026-08-06T12:15:00Z',
          id: ImportIntentId,
          source_drive_id: DriveId,
          source_node_id: FirstNodeId,
          source_version_id: SourceVersionId,
          target_media_type: 'text/markdown',
          target_name: 'Source.md',
          target_parent_id: RootId,
        },
        201,
      )
    }
    if (Path === `/api/v1/uploads/${UploadId}` && HttpRequest.method === 'GET') {
      return Json({
        finalize: ByteGrant('POST', `/io/v1/uploads/${UploadId}/finalize`, 'finalize-secret'),
        next_cursor: null,
        parts: [ByteGrant('PUT', `/io/v1/uploads/${UploadId}/parts/0`, 'part-secret')],
        upload: UploadAllocation(),
      })
    }
    if (Path === `/io/v1/uploads/${UploadId}/parts/0` && HttpRequest.method === 'PUT') {
      return Json({ blake3: 'abc', part_number: 0, size_bytes: 4, upload_id: UploadId })
    }
    if (Path === `/io/v1/uploads/${UploadId}/finalize` && HttpRequest.method === 'POST') {
      return Json({
        blake3: 'abc',
        payload_id: PayloadId,
        size_bytes: 4,
        state: 'finalized',
        upload_id: UploadId,
      })
    }
    if (Path === `/api/v1/uploads/${UploadId}/commit` && HttpRequest.method === 'POST') {
      return Json({ node_id: FirstNodeId, version_id: '00000000-0000-4000-8000-000000000013' }, 201)
    }
    if (
      Path === `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/download-grants` &&
      HttpRequest.method === 'POST'
    ) {
      return Json(
        {
          authorization: 'download-secret-must-not-be-forwarded',
          authorization_scheme: 'fbcap1',
          expires_at: '2026-08-06T12:01:00Z',
          grant_id: GrantId,
          method: 'GET',
          path: `/io/v1/downloads/${GrantId}`,
          size_bytes: 4,
        },
        201,
      )
    }
    if (Path === `/io/v1/downloads/${GrantId}` && HttpRequest.method === 'GET') {
      return new Response('data', { status: 200 })
    }
    if (Path.includes('/shares/') && HttpRequest.method === 'DELETE')
      return new Response(null, { status: 204 })
    return Json(
      {
        code: 'test.unhandled',
        status: 500,
        title: `Unhandled ${HttpRequest.method} ${Path}`,
        type: 'about:blank',
      },
      500,
    )
  }
}

describe('HttpFileBeltClient', () => {
  it('uploads to a selected nested directory using its immutable routing record', async () => {
    const NestedDirectory = DirectoryNode(FirstNodeId, 'Nested')
    const Server = new ContractServer([NestedDirectory])
    const Client = new HttpFileBeltClient(Server.fetch, 'https://filebelt.localhost')
    await Client.getWorkspace(undefined, { DriveId, Kind: 'folder', NodeId: null })

    await Client.upload([{ Data: new Blob(['data']), Name: 'nested.txt', Size: 4 }], {
      DriveId,
      ParentId: FirstNodeId,
    })

    const Allocation = FindRequest(Server.Requests, 'POST', `/api/v1/drives/${DriveId}/uploads`)
    expect(await Allocation.clone().json()).toMatchObject({
      expected_parent_generation: NestedDirectory.namespace_generation,
      parent_id: FirstNodeId,
    })
  })

  it('loads only root children for ordinary drive browsing and never walks nested directories', async () => {
    const NestedDirectory = DirectoryNode(FirstNodeId, 'Nested')
    const Server = new ContractServer([NestedDirectory])
    const Client = new HttpFileBeltClient(Server.fetch, 'https://filebelt.localhost')

    const Workspace = await Client.getWorkspace(undefined, {
      DriveId,
      Kind: 'folder',
      NodeId: null,
    })

    expect(Workspace.Entries.map(({ Id }) => Id)).toEqual([FirstNodeId])
    expect(
      Server.Requests.some(
        (Request) =>
          new URL(Request.url).pathname ===
          `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/children`,
      ),
    ).toBe(false)
    expect(RequestPaths(Server.Requests, 'GET')).not.toContain(`/api/v1/drives/${DriveId}/trash`)
    expect(RequestPaths(Server.Requests, 'GET')).not.toContain('/api/v1/shared')
    expect(RequestPaths(Server.Requests, 'GET').some((Path) => Path.endsWith('/versions'))).toBe(
      false,
    )
  })

  it('uses generated API routes, the fresh root generation, and narrow capability transports', async () => {
    const Server = new ContractServer([Node(FirstNodeId, 'File one.txt')])
    const Client = new HttpFileBeltClient(Server.fetch, 'https://filebelt.localhost')

    await Client.getWorkspace()
    await Client.upload([{ Data: new Blob(['data']), Name: 'upload.txt', Size: 4 }])
    expect(await (await Client.download(FirstNodeId)).text()).toBe('data')
    expect(
      await (await Client.readMarkdown(FirstNodeId, '00000000-0000-4000-8000-000000000012')).text(),
    ).toBe('data')
    await Client.saveMarkdown({
      Contents: new Blob(['# replacement'], { type: 'text/markdown' }),
      EntryId: FirstNodeId,
      ExpectedHeadVersionId: '00000000-0000-4000-8000-000000000012',
      Name: 'File one.txt',
    })

    const Allocation = FindRequest(Server.Requests, 'POST', `/api/v1/drives/${DriveId}/uploads`)
    expect(await Allocation.clone().json()).toMatchObject({
      expected_parent_generation: 19,
      name: 'upload.txt',
      parent_id: RootId,
    })
    expect(Allocation.headers.get('x-filebelt-csrf')).toBe(Session.csrf_token)
    expect(Allocation.headers.get('idempotency-key')).not.toBeNull()
    const MarkdownAllocation = Server.Requests.filter(
      (Request) =>
        new URL(Request.url).pathname === `/api/v1/drives/${DriveId}/uploads` &&
        Request.method === 'POST',
    ).at(-1)
    expect(MarkdownAllocation).toBeDefined()
    if (MarkdownAllocation !== undefined)
      expect(await MarkdownAllocation.clone().json()).toMatchObject({
        declared_media_type: 'text/markdown',
        expected_head_version_id: '00000000-0000-4000-8000-000000000012',
        node_id: FirstNodeId,
      })

    const Part = FindRequest(Server.Requests, 'PUT', `/io/v1/uploads/${UploadId}/parts/0`)
    expect(Part.credentials).toBe('omit')
    expect(Part.headers.get('authorization')).toBe('fbcap1 part-secret')

    const Download = FindRequest(Server.Requests, 'GET', `/io/v1/downloads/${GrantId}`)
    expect(Download.credentials).toBe('same-origin')
    expect(Download.headers.has('authorization')).toBe(false)
    expect([...Download.headers.values()]).not.toContain('download-secret-must-not-be-forwarded')
  })

  it('uses distinct opaque share ids to revoke the same principal from two nodes exactly', async () => {
    const Server = new ContractServer([
      Node(FirstNodeId, 'File one.txt'),
      Node(SecondNodeId, 'File two.txt'),
    ])
    const Client = new HttpFileBeltClient(Server.fetch, 'https://filebelt.localhost')
    const Workspace = await Client.getWorkspace()
    const First = Workspace.Shares.find(({ ResourceName }) => ResourceName === 'File one.txt')
    const Second = Workspace.Shares.find(({ ResourceName }) => ResourceName === 'File two.txt')

    expect(First).toBeDefined()
    expect(Second).toBeDefined()
    expect(First?.ResourceId).toBe(FirstNodeId)
    expect(Second?.ResourceId).toBe(SecondNodeId)
    expect(First?.Id).not.toBe(Second?.Id)
    expect(First?.Id).not.toBe(PrincipalId)
    if (First === undefined || Second === undefined) return

    await Client.revokeShare(First.Id)
    await Client.revokeShare(Second.Id)

    expect(RequestPaths(Server.Requests, 'DELETE')).toEqual([
      `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/shares/${PrincipalId}`,
      `/api/v1/drives/${DriveId}/nodes/${SecondNodeId}/shares/${PrincipalId}`,
    ])
  })

  it('continues trash and restore batches after a failure and preserves problem detail per ID', async () => {
    const Server = new ContractServer([
      Node(FirstNodeId, 'File one.txt'),
      Node(SecondNodeId, 'File two.txt'),
    ])
    const Fetch: typeof fetch = async (Input, Init) => {
      const HttpRequest = Input instanceof Request ? Input : new Request(Input, Init)
      const Path = new URL(HttpRequest.url).pathname
      const IsEntryMutation = Path.endsWith('/trash') || Path.endsWith('/restore')
      if (HttpRequest.method === 'POST' && IsEntryMutation) {
        if (Path.includes(FirstNodeId))
          return Json(
            {
              code: 'node.generation_conflict',
              detail: 'Expected namespace generation 4, but found 5.',
              status: 409,
              title: 'The item changed',
            },
            409,
          )
        return new Response(null, { status: 204 })
      }
      return Server.fetch(HttpRequest)
    }
    const Client = new HttpFileBeltClient(Fetch, 'https://filebelt.localhost')
    await Client.getWorkspace()

    for (const Mutate of [
      async (EntryIds: readonly string[]) => Client.trashEntries(EntryIds),
      async (EntryIds: readonly string[]) => Client.restoreEntries(EntryIds),
    ]) {
      const Outcomes = await Mutate([FirstNodeId, SecondNodeId])
      expect(Outcomes).toEqual([
        {
          EntryId: FirstNodeId,
          Error: {
            Code: 'node.generation_conflict',
            Detail: 'Expected namespace generation 4, but found 5.',
            Message: 'The item changed',
            Status: 409,
          },
          Kind: 'failure',
        },
        { EntryId: SecondNodeId, Kind: 'success' },
      ])
    }
  })

  it('converts a session 401 into an explicit authentication-required signal', async () => {
    // oxlint-disable-next-line typescript/require-await -- Fetch's Promise contract is required by this synchronous in-memory response fake.
    const FetchImplementation: typeof fetch = async () =>
      Json(
        {
          code: 'session.unauthorized',
          status: 401,
          title: 'Authentication is required',
          type: 'about:blank',
        },
        401,
      )
    const Client = new HttpFileBeltClient(FetchImplementation, 'https://filebelt.localhost')

    await expect(Client.getWorkspace()).rejects.toBeInstanceOf(AuthenticationRequiredError)
  })

  it('keeps the last complete routing state when a refresh fails late', async () => {
    const Server = new ContractServer([Node(FirstNodeId, 'File one.txt')])
    const Requests: Request[] = []
    let FailRefresh = false
    let SessionReads = 0
    const Fetch: typeof fetch = async (Input, Init) => {
      const HttpRequest = Input instanceof Request ? Input : new Request(Input, Init)
      Requests.push(HttpRequest)
      const Path = new URL(HttpRequest.url).pathname
      if (Path === '/api/v1/session' && HttpRequest.method === 'GET') {
        SessionReads += 1
        return Json({ ...Session, csrf_token: `csrf-${SessionReads}` })
      }
      if (FailRefresh && Path === '/api/v1/drives' && HttpRequest.method === 'GET') {
        return Json({ items: [], next_cursor: null })
      }
      if (FailRefresh && Path === '/api/v1/sessions' && HttpRequest.method === 'GET') {
        return Json(
          {
            code: 'test.refresh_failed',
            status: 503,
            title: 'Refresh failed',
            type: 'about:blank',
          },
          503,
        )
      }
      if (Path.endsWith(`/versions/${FirstVersionId}/restore`) && HttpRequest.method === 'POST') {
        return new Response(null, { status: 204 })
      }
      return Server.fetch(HttpRequest)
    }
    const Client = new HttpFileBeltClient(Fetch, 'https://filebelt.localhost')
    const Initial = await Client.getWorkspace()
    const InitialShare = Initial.Shares[0]
    expect(InitialShare).toBeDefined()
    if (InitialShare === undefined) return

    FailRefresh = true
    await expect(Client.getWorkspace()).rejects.toThrow('Refresh failed')
    expect(await (await Client.download(FirstNodeId)).text()).toBe('data')
    await Client.revokeShare(InitialShare.Id)
    await Client.restoreVersion(FirstVersionId)
    await Client.upload([{ Data: new Blob(['data']), Name: 'after-failure.txt', Size: 4 }])

    const Revocation = FindRequest(
      Requests,
      'DELETE',
      `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/shares/${PrincipalId}`,
    )
    const Restore = FindRequest(
      Requests,
      'POST',
      `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/versions/${FirstVersionId}/restore`,
    )
    const Allocation = Requests.filter(
      (Request) =>
        new URL(Request.url).pathname === `/api/v1/drives/${DriveId}/uploads` &&
        Request.method === 'POST',
    ).at(-1)
    expect(Restore.headers.get('x-filebelt-csrf')).toBe('csrf-1')
    expect(Revocation.headers.get('x-filebelt-csrf')).toBe('csrf-1')
    expect(Allocation).toBeDefined()
    if (Allocation !== undefined) expect(Allocation.headers.get('x-filebelt-csrf')).toBe('csrf-1')
  })

  it('keeps the last complete routing state when a refresh is aborted', async () => {
    const Server = new ContractServer([Node(FirstNodeId, 'File one.txt')])
    let AbortRefresh = false
    let MarkAbortRequestReached = (): void => undefined
    const AbortRequestReached = new Promise<void>((Resolve) => {
      MarkAbortRequestReached = Resolve
    })
    const Fetch: typeof fetch = async (Input, Init) => {
      const HttpRequest = Input instanceof Request ? Input : new Request(Input, Init)
      const Path = new URL(HttpRequest.url).pathname
      if (AbortRefresh && Path === '/api/v1/sessions' && HttpRequest.method === 'GET') {
        MarkAbortRequestReached()
        return new Promise<Response>((IgnoredResolve, Reject) => {
          void IgnoredResolve
          const RejectAbort = (): void => {
            Reject(new DOMException('The operation was aborted.', 'AbortError'))
          }
          if (HttpRequest.signal.aborted) RejectAbort()
          else HttpRequest.signal.addEventListener('abort', RejectAbort, { once: true })
        })
      }
      return Server.fetch(HttpRequest)
    }
    const Client = new HttpFileBeltClient(Fetch, 'https://filebelt.localhost')
    const Initial = await Client.getWorkspace()
    const InitialShare = Initial.Shares[0]
    expect(InitialShare).toBeDefined()
    if (InitialShare === undefined) return

    AbortRefresh = true
    const Controller = new AbortController()
    const Refresh = Client.getWorkspace(Controller.signal)
    await AbortRequestReached
    Controller.abort()
    await expect(Refresh).rejects.toMatchObject({ name: 'AbortError' })
    await Client.revokeShare(InitialShare.Id)
  })

  it('prevents a superseded refresh from replacing newer routing state', async () => {
    const Server = new ContractServer([Node(FirstNodeId, 'File one.txt')])
    let SessionListReads = 0
    let MarkFirstRefreshReached = (): void => undefined
    let ReleaseFirstRefresh = (): void => undefined
    const FirstRefreshReached = new Promise<void>((Resolve) => {
      MarkFirstRefreshReached = Resolve
    })
    const FirstRefreshGate = new Promise<void>((Resolve) => {
      ReleaseFirstRefresh = Resolve
    })
    const Fetch: typeof fetch = async (Input, Init) => {
      const HttpRequest = Input instanceof Request ? Input : new Request(Input, Init)
      const Path = new URL(HttpRequest.url).pathname
      if (Path === '/api/v1/sessions' && HttpRequest.method === 'GET') {
        SessionListReads += 1
        if (SessionListReads === 1) {
          MarkFirstRefreshReached()
          await FirstRefreshGate
        }
      }
      return Server.fetch(HttpRequest)
    }
    const Client = new HttpFileBeltClient(Fetch, 'https://filebelt.localhost')
    const FirstRefresh = Client.getWorkspace()
    await FirstRefreshReached
    const Newer = await Client.getWorkspace()
    const NewerShare = Newer.Shares[0]
    ReleaseFirstRefresh()
    expect(NewerShare).toBeDefined()
    await expect(FirstRefresh).rejects.toMatchObject({ name: 'AbortError' })
    if (NewerShare === undefined) return
    await Client.revokeShare(NewerShare.Id)
  })

  it('binds an Office conversion to an exact source version and one new sibling upload', async () => {
    const Source = Node(FirstNodeId, 'Source.docx')
    const Server = new ContractServer([Source])
    const Client = new HttpFileBeltClient(Server.fetch, 'https://filebelt.localhost')
    await Client.getWorkspace()
    if (Source.head_version_id === null) return

    await Client.importMarkdown({
      Contents: new Blob(['# hi'], { type: 'text/markdown' }),
      EntryId: FirstNodeId,
      SourceVersionId: Source.head_version_id,
      TargetName: 'Source.md',
    })

    const Intent = FindRequest(
      Server.Requests,
      'POST',
      `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/markdown-import-intents`,
    )
    expect(await Intent.clone().json()).toEqual({
      source_version_id: Source.head_version_id,
      target_name: 'Source.md',
    })
    const Allocation = Server.Requests.filter(
      (Request) =>
        new URL(Request.url).pathname === `/api/v1/drives/${DriveId}/uploads` &&
        Request.method === 'POST',
    ).at(-1)
    expect(Allocation).toBeDefined()
    if (Allocation !== undefined)
      expect(await Allocation.clone().json()).toMatchObject({
        declared_media_type: 'text/markdown',
        expected_parent_generation: 19,
        import_intent_id: ImportIntentId,
        name: 'Source.md',
        parent_id: RootId,
      })
  })

  it('uses generated text preferences, history, comparison, and content-class routes', async () => {
    const Server = new ContractServer([Node(FirstNodeId, 'File one.txt')])
    const Client = new HttpFileBeltClient(Server.fetch, 'https://filebelt.localhost')
    await Client.getWorkspace()
    const Preferences = await Client.getTextPreferences()
    expect(Preferences).toMatchObject({
      Etag: '"preferences-5"',
      Value: { EditLimitBytes: 2_097_152, InlineLimitBytes: 8_388_608 },
    })
    await Client.updateTextPreferences(
      { EditLimitBytes: 4_194_304, InlineLimitBytes: 8_388_608 },
      Preferences.Etag,
    )
    const History = await Client.listTextVersions(FirstNodeId, null)
    expect(History.Items).toHaveLength(2)
    expect(History.Items[0]).toMatchObject({
      GitCommitOid: 'a'.repeat(64),
      ObservedContentClass: 'text',
      RevisionBackend: 'git_sha256',
    })
    const Comparison = await Client.compareTextVersions(
      FirstNodeId,
      FirstVersionId,
      SecondVersionId,
    )
    expect(Comparison.Hunks[0]?.Lines[0]).toEqual({ Kind: 'context', Text: 'same' })
    await Client.setNodeContentClass(FirstNodeId, 'binary')
    const PreferencePatch = FindRequest(Server.Requests, 'PATCH', '/api/v1/preferences/text')
    expect(PreferencePatch.headers.get('if-match')).toBe('"preferences-5"')
    const PolicyPatch = FindRequest(
      Server.Requests,
      'PATCH',
      `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/content-class-policy`,
    )
    expect(PolicyPatch.headers.get('if-match')).toBe('"node-attribute-2"')
    expect(await PolicyPatch.clone().json()).toEqual({ policy: 'binary' })
  })

  it('round-trips ACL provenance and fences exact replacement with the GET ETag', async () => {
    const Server = new ContractServer([Node(FirstNodeId, 'File one.txt')])
    const Client = new HttpFileBeltClient(Server.fetch, 'https://filebelt.localhost')
    await Client.getWorkspace()

    const Current = await Client.getAcl(FirstNodeId)
    expect(Current).toMatchObject({
      Etag: '"acl-7"',
      Value: {
        Entries: [
          {
            GroupId,
            PrincipalKind: 'group',
            ReadOnly: true,
            Source: 'share',
            VerifiedEmail: null,
          },
        ],
      },
    })
    await Client.replaceAcl(
      FirstNodeId,
      Current.Etag,
      { GroupId, Kind: 'group', VerifiedEmail: null },
      [{ Action: 'TRAVERSE', Effect: 'deny', Inheritance: 'children' }],
    )

    const Request = FindRequest(
      Server.Requests,
      'PUT',
      `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/acl`,
    )
    expect(Request.headers.get('if-match')).toBe('"acl-7"')
    expect(Request.headers.get('x-filebelt-csrf')).toBe(Session.csrf_token)
    expect(await Request.clone().json()).toEqual({
      entries: [{ action: 'TRAVERSE', effect: 'deny', inheritance: 'children' }],
      principal: { group_id: GroupId, kind: 'group', verified_email: null },
    })
  })

  it('maps a stale ACL replacement to a draft-preserving conflict signal', async () => {
    const Server = new ContractServer([Node(FirstNodeId, 'File one.txt')])
    const Fetch: typeof fetch = async (Input, Init) => {
      const HttpRequest = Input instanceof Request ? Input : new Request(Input, Init)
      if (
        HttpRequest.method === 'PUT' &&
        new URL(HttpRequest.url).pathname === `/api/v1/drives/${DriveId}/nodes/${FirstNodeId}/acl`
      )
        return Json({ code: 'acl.stale', status: 409, title: 'ACL changed' }, 409)
      return Server.fetch(HttpRequest)
    }
    const Client = new HttpFileBeltClient(Fetch, 'https://filebelt.localhost')
    await Client.getWorkspace()

    await expect(
      Client.replaceAcl(
        FirstNodeId,
        '"acl-6"',
        { GroupId: null, Kind: 'user', VerifiedEmail: 'avery@example.test' },
        [],
      ),
    ).rejects.toBeInstanceOf(AclConflictError)
  })

  it('preserves the revision admission problem for retry guidance', async () => {
    const Server = new ContractServer([Node(FirstNodeId, 'File one.txt')])
    const Fetch: typeof fetch = async (Input, Init) => {
      const RequestValue = Input instanceof Request ? Input : new Request(Input, Init)
      if (
        new URL(RequestValue.url).pathname.endsWith(
          `/versions/${FirstVersionId}/compare/${SecondVersionId}`,
        )
      ) {
        return Json(
          {
            code: 'revision.admission_limited',
            status: 429,
            title: 'Text revision comparison is temporarily at capacity',
            type: 'https://filebelt.dev/problems/revision.admission_limited',
          },
          429,
          { 'Retry-After': '5' },
        )
      }
      return Server.fetch(RequestValue)
    }
    const Client = new HttpFileBeltClient(Fetch, 'https://filebelt.localhost')
    await Client.getWorkspace()
    await expect(
      Client.compareTextVersions(FirstNodeId, FirstVersionId, SecondVersionId),
    ).rejects.toThrow('Text revision comparison is temporarily at capacity')
  })

  it('projects symlinks without traversing them or requesting file versions and content', async () => {
    const Server = new ContractServer([SymlinkNode()])
    const Client = new HttpFileBeltClient(Server.fetch, 'https://filebelt.localhost')

    const Workspace = await Client.getWorkspace()
    expect(Workspace.Entries.find(({ Id }) => Id === SymlinkNodeId)).toMatchObject({
      HeadVersionId: null,
      Kind: 'symlink',
      TextEligibility: 'ineligible',
      MediaType: null,
      Size: null,
      Version: 0,
    })
    expect(
      Server.Requests.some(
        (Request) =>
          new URL(Request.url).pathname ===
          `/api/v1/drives/${DriveId}/nodes/${SymlinkNodeId}/children`,
      ),
    ).toBe(false)
    expect(
      Server.Requests.some(
        (Request) =>
          new URL(Request.url).pathname ===
          `/api/v1/drives/${DriveId}/nodes/${SymlinkNodeId}/versions`,
      ),
    ).toBe(false)
    await expect(Client.download(SymlinkNodeId)).rejects.toThrow('not a file')
    expect(
      Server.Requests.some(
        (Request) =>
          new URL(Request.url).pathname ===
          `/api/v1/drives/${DriveId}/nodes/${SymlinkNodeId}/download-grants`,
      ),
    ).toBe(false)
  })
})

function UploadAllocation(): components['schemas']['UploadAllocation'] {
  return {
    chunk_size_bytes: 4,
    declared_size_bytes: 4,
    drive_id: DriveId,
    fencing_token: 2,
    grants_url: `/api/v1/uploads/${UploadId}`,
    node_id: null,
    parent_id: RootId,
    part_count: 1,
    payload_id: PayloadId,
    state: 'open',
    upload_id: UploadId,
  }
}

function FileVersion(NodeId: string, Id: string): components['schemas']['FileVersion'] {
  return {
    created_at: '2026-08-06T12:00:00Z',
    created_by: Session.principal_id,
    current: Id === FirstVersionId,
    git_commit_oid: 'a'.repeat(64),
    id: Id,
    media_type: 'text/plain',
    node_id: NodeId,
    observed_content_class: 'text',
    ordinal: Id === FirstVersionId ? 2 : 1,
    provenance: {
      creator_display_name: 'Avery Morgan',
      mcp_assisted: false,
      origin: 'upload',
      source_version_id: null,
    },
    restored_from_version_id: null,
    revision_backend: 'git_sha256',
    size_bytes: 4,
  }
}

function AclCollection(): components['schemas']['AclCollection'] {
  return {
    entries: [
      {
        action: 'TRAVERSE',
        display_name: 'Research',
        effect: 'allow',
        group_id: GroupId,
        inheritance: 'self_and_descendants',
        principal_id: PrincipalId,
        principal_kind: 'group',
        read_only: true,
        source: 'share',
        verified_email: null,
      },
    ],
    supported_actions: [
      'READ_METADATA',
      'LIST_CHILDREN',
      'READ_CONTENT',
      'CREATE_CHILD',
      'WRITE_CONTENT',
      'CREATE_VERSION',
      'RENAME',
      'MOVE',
      'DELETE',
      'RESTORE',
      'SET_ATTRIBUTES',
      'SHARE',
      'MANAGE_ACL',
      'MANAGE_DRIVE',
      'TRANSCODE',
      'USE_EXTERNAL_EDITOR',
      'COMMENT',
      'REVIEW',
      'USE_MCP',
      'MOUNT',
      'EXPORT',
      'TRAVERSE',
      'READ_REPOSITORY',
      'WRITE_REPOSITORY',
      'MANAGE_REPOSITORY',
      'BYPASS_REPOSITORY_RULES',
    ],
  }
}

function ByteGrant(
  Method: components['schemas']['ByteGrant']['method'],
  Path: string,
  Authorization: string,
): components['schemas']['ByteGrant'] {
  return {
    authorization: Authorization,
    authorization_scheme: 'fbcap1',
    expires_at: '2026-08-06T12:01:00Z',
    method: Method,
    path: Path,
  }
}

function Json(
  Value: unknown,
  Status = 200,
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- HeadersInit is the platform input contract and is copied before use.
  HeaderValues: HeadersInit = {},
): Response {
  const ResponseHeaders = new Headers(HeaderValues)
  ResponseHeaders.set('Content-Type', 'application/json')
  return new Response(JSON.stringify(Value), {
    headers: ResponseHeaders,
    status: Status,
  })
}

function FindRequest(
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- Request is a mutable platform type, but this lookup helper only observes it.
  Requests: readonly Readonly<Request>[],
  Method: string,
  Path: string,
): Request {
  const Request = Requests.find(
    (Candidate) => Candidate.method === Method && new URL(Candidate.url).pathname === Path,
  )
  expect(Request, `${Method} ${Path}`).toBeDefined()
  if (Request === undefined) throw new Error(`Missing ${Method} ${Path}`)
  return Request
}

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- Request is a mutable platform type, but this projection helper only observes it.
function RequestPaths(Requests: readonly Readonly<Request>[], Method: string): string[] {
  return Requests.filter((Request) => Request.method === Method).map(
    (Request) => new URL(Request.url).pathname,
  )
}
