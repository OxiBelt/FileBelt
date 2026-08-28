// SPDX-License-Identifier: Apache-2.0

import createClient from 'openapi-fetch'
import type { Client } from 'openapi-fetch'

import { AuthenticationRequiredError } from './client.js'
import type { components, paths } from './generated/openapi.js'

export type DocumentSessionDetail = components['schemas']['DocumentSessionDetail']
export type DocumentSessionConflictCopy = components['schemas']['DocumentSessionConflictCopy']
export type DocumentSessionLaunchHandoff = components['schemas']['DocumentSessionLaunchHandoff']
export type DocumentSessionPage = components['schemas']['DocumentSessionPage']
export type DocumentSessionMode = components['schemas']['CreateDocumentSession']['mode']

export interface CreateDocumentSessionInput {
  BaseVersionId: string
  DriveId: string
  Mode: DocumentSessionMode
  NodeId: string
}

export interface ListDocumentSessionsOptions {
  Cursor?: string
  Signal?: Readonly<AbortSignal>
}

/** Provider-neutral browser boundary for document-session controls. */
export interface DocumentSessionClient {
  CreateSession(Input: Readonly<CreateDocumentSessionInput>): Promise<DocumentSessionDetail>
  CreateConflictCopy(SessionId: string, TargetName: string): Promise<DocumentSessionConflictCopy>
  ForceClose(Session: Readonly<components['schemas']['DocumentSessionSummary']>): Promise<void>
  GetOwnSession(SessionId: string): Promise<DocumentSessionDetail>
  ListNodeSessions(
    DriveId: string,
    NodeId: string,
    Options?: Readonly<ListDocumentSessionsOptions>,
  ): Promise<DocumentSessionPage>
  ListOwnSessions(Options?: Readonly<ListDocumentSessionsOptions>): Promise<DocumentSessionPage>
  RedeemLaunch(SessionId: string): Promise<DocumentSessionLaunchHandoff>
  RevokeOwnSession(SessionId: string): Promise<void>
}

interface SessionResponse {
  // oxlint-disable-next-line filebelt/pascal-case -- Generated OpenAPI response uses this exact key.
  readonly csrf_token: string
}

interface CsrfHeaders {
  Origin: string
  'Sec-Fetch-Site': 'same-origin'
  'X-FileBelt-Csrf': string
}

interface MutationHeaders extends CsrfHeaders {
  'Idempotency-Key': string
}

interface ApiResult<T> {
  // oxlint-disable-next-line filebelt/pascal-case -- `openapi-fetch` returns this exact result key.
  readonly data?: T
  // oxlint-disable-next-line filebelt/pascal-case -- `openapi-fetch` returns this exact result key.
  readonly error?: unknown
  // oxlint-disable-next-line filebelt/pascal-case -- `openapi-fetch` returns this exact result key.
  readonly response: Response
}

const PageLimit = 200

/** Same-origin adapter for generated document-session operations. */
export class HttpDocumentSessionClient implements DocumentSessionClient {
  readonly #Api: Client<paths>
  readonly #BaseUrl: string
  #Session: SessionResponse | null = null

  constructor(
    FetchImplementation: typeof fetch = globalThis.fetch.bind(globalThis),
    BaseUrl: string = DefaultBaseUrl(),
  ) {
    this.#BaseUrl = BaseUrl
    this.#Api = createClient<paths>({
      baseUrl: BaseUrl,
      credentials: 'same-origin',
      fetch: async (Request) => FetchImplementation(Request),
    })
  }

  async CreateSession(Input: Readonly<CreateDocumentSessionInput>): Promise<DocumentSessionDetail> {
    await this.#EnsureSession()
    return RequireData<DocumentSessionDetail>(
      await this.#Api.POST('/api/v1/drives/{drive_id}/nodes/{node_id}/document-sessions', {
        body: { base_version_id: Input.BaseVersionId, mode: Input.Mode },
        params: {
          header: this.#Headers(),
          path: { drive_id: Input.DriveId, node_id: Input.NodeId },
        },
      }),
    )
  }

  async ListOwnSessions(
    Options: Readonly<ListDocumentSessionsOptions> = {},
  ): Promise<DocumentSessionPage> {
    return RequireData<DocumentSessionPage>(
      await this.#Api.GET('/api/v1/document-sessions', {
        params: {
          query: {
            limit: PageLimit,
            ...(Options.Cursor === undefined ? {} : { cursor: Options.Cursor }),
          },
        },
        ...(Options.Signal === undefined ? {} : { signal: Options.Signal }),
      }),
    )
  }

  async GetOwnSession(SessionId: string): Promise<DocumentSessionDetail> {
    return RequireData<DocumentSessionDetail>(
      await this.#Api.GET('/api/v1/document-sessions/{document_session_id}', {
        params: { path: { document_session_id: SessionId } },
      }),
    )
  }

  async RevokeOwnSession(SessionId: string): Promise<void> {
    await this.#EnsureSession()
    RequireSuccess(
      await this.#Api.DELETE('/api/v1/document-sessions/{document_session_id}', {
        params: { header: this.#Headers(), path: { document_session_id: SessionId } },
      }),
    )
  }

  async RedeemLaunch(SessionId: string): Promise<DocumentSessionLaunchHandoff> {
    await this.#EnsureSession()
    return RequireData<DocumentSessionLaunchHandoff>(
      await this.#Api.POST('/api/v1/document-sessions/{document_session_id}/handoff', {
        params: { header: this.#CsrfHeaders(), path: { document_session_id: SessionId } },
      }),
    )
  }

  async ListNodeSessions(
    DriveId: string,
    NodeId: string,
    Options: Readonly<ListDocumentSessionsOptions> = {},
  ): Promise<DocumentSessionPage> {
    return RequireData<DocumentSessionPage>(
      await this.#Api.GET('/api/v1/drives/{drive_id}/nodes/{node_id}/document-sessions', {
        params: {
          path: { drive_id: DriveId, node_id: NodeId },
          query: {
            limit: PageLimit,
            ...(Options.Cursor === undefined ? {} : { cursor: Options.Cursor }),
          },
        },
        ...(Options.Signal === undefined ? {} : { signal: Options.Signal }),
      }),
    )
  }

  async ForceClose(
    Session: Readonly<components['schemas']['DocumentSessionSummary']>,
  ): Promise<void> {
    await this.#EnsureSession()
    RequireSuccess(
      await this.#Api.DELETE(
        '/api/v1/drives/{drive_id}/nodes/{node_id}/document-sessions/{document_session_id}',
        {
          params: {
            header: this.#Headers(),
            path: {
              document_session_id: Session.id,
              drive_id: Session.drive_id,
              node_id: Session.node_id,
            },
          },
        },
      ),
    )
  }

  async CreateConflictCopy(
    SessionId: string,
    TargetName: string,
  ): Promise<DocumentSessionConflictCopy> {
    await this.#EnsureSession()
    const Detail = await this.GetOwnSession(SessionId)
    const Source = RequireData<components['schemas']['Node']>(
      await this.#Api.GET('/api/v1/drives/{drive_id}/nodes/{node_id}', {
        params: { path: { drive_id: Detail.session.drive_id, node_id: Detail.session.node_id } },
      }),
    )
    if (Source.parent_id === null) throw new Error('The conflicted file has no writable parent.')
    const Parent = RequireData<components['schemas']['Node']>(
      await this.#Api.GET('/api/v1/drives/{drive_id}/nodes/{node_id}', {
        params: { path: { drive_id: Detail.session.drive_id, node_id: Source.parent_id } },
      }),
    )
    if (Parent.kind !== 'directory') throw new Error('The conflicted file parent is unavailable.')
    return RequireData<DocumentSessionConflictCopy>(
      await this.#Api.POST('/api/v1/document-sessions/{document_session_id}/conflict-copy', {
        body: {
          expected_parent_generation: Parent.namespace_generation,
          target_name: TargetName,
          target_parent_id: Parent.id,
        },
        params: { header: this.#Headers(), path: { document_session_id: SessionId } },
      }),
    )
  }

  async #EnsureSession(): Promise<void> {
    if (this.#Session !== null) return
    this.#Session = RequireData<SessionResponse>(await this.#Api.GET('/api/v1/session'))
  }

  #Headers(): MutationHeaders {
    return { ...this.#CsrfHeaders(), 'Idempotency-Key': crypto.randomUUID() }
  }

  #CsrfHeaders(): CsrfHeaders {
    if (this.#Session === null) throw new Error('The session is unavailable.')
    return {
      Origin: new URL(this.#BaseUrl).origin,
      'Sec-Fetch-Site': 'same-origin',
      'X-FileBelt-Csrf': this.#Session.csrf_token,
    }
  }
}

function DefaultBaseUrl(): string {
  return typeof window === 'undefined' ? 'https://filebelt.localhost' : window.location.origin
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

function RequestError(Response: Response, ErrorValue: unknown): Error {
  if (Response.status === 401) return new AuthenticationRequiredError()
  const Title =
    typeof ErrorValue === 'object' &&
    ErrorValue !== null &&
    'title' in ErrorValue &&
    typeof ErrorValue.title === 'string'
      ? ErrorValue.title
      : null
  return new Error(Title ?? `FileBelt request failed (${Response.status}).`)
}
