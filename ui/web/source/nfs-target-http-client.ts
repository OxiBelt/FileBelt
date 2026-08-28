// SPDX-License-Identifier: Apache-2.0

import createClient from 'openapi-fetch'
import type { Client } from 'openapi-fetch'

import { AuthenticationRequiredError } from './client.js'
import type { components, paths } from './generated/openapi.js'
import { MountReauthenticationRequiredError } from './mount-http-client.js'

export type NfsMappingProposal = components['schemas']['NfsMappingProposal']
export type NfsPrincipalMapping = components['schemas']['NfsPrincipalMapping']
export type NfsTargetOverview = components['schemas']['NfsTargetOverview']

interface ApiResult<T> {
  // oxlint-disable-next-line filebelt/pascal-case -- `openapi-fetch` returns this exact result key.
  readonly data?: T
  // oxlint-disable-next-line filebelt/pascal-case -- `openapi-fetch` returns this exact result key.
  readonly error?: unknown
  // oxlint-disable-next-line filebelt/pascal-case -- `openapi-fetch` returns this exact result key.
  readonly response: Response
}

interface MutationHeaders {
  'Idempotency-Key': string
  Origin: string
  'Sec-Fetch-Site': 'same-origin'
  'X-FileBelt-Csrf': string
}

type SessionResponse = components['schemas']['Session']

export interface NfsTargetClient {
  approveProposal(ProposalId: string, ExpectedGeneration: number): Promise<void>
  declineProposal(ProposalId: string, ExpectedGeneration: number): Promise<void>
  getOverview(Signal?: Readonly<AbortSignal>): Promise<NfsTargetOverview>
  revokeMapping(CredentialId: string, ExpectedGeneration: number): Promise<void>
}

/** Same-origin client for the target user's exact NFS mapping consent. */
export class HttpNfsTargetClient implements NfsTargetClient {
  readonly #Api: Client<paths>
  readonly #Origin: string
  #CsrfToken: string | null = null

  constructor(
    FetchImplementation: typeof fetch = globalThis.fetch.bind(globalThis),
    BaseUrl: string = DefaultBaseUrl(),
  ) {
    this.#Origin = new URL(BaseUrl).origin
    this.#Api = createClient<paths>({
      baseUrl: BaseUrl,
      credentials: 'same-origin',
      fetch: async (Request) => FetchImplementation(Request),
    })
  }

  async getOverview(Signal?: Readonly<AbortSignal>): Promise<NfsTargetOverview> {
    const Result = await this.#Api.GET(
      '/api/v1/mounts/nfs',
      Signal === undefined ? {} : { signal: Signal },
    )
    return RequireData<NfsTargetOverview>(Result)
  }

  async approveProposal(ProposalId: string, ExpectedGeneration: number): Promise<void> {
    RequireData(
      await this.#Api.POST('/api/v1/mounts/nfs/mapping-proposals/{proposal_id}/approval', {
        body: { expected_generation: ExpectedGeneration },
        params: { header: await this.#mutationHeaders(), path: { proposal_id: ProposalId } },
      }),
    )
  }

  async declineProposal(ProposalId: string, ExpectedGeneration: number): Promise<void> {
    RequireSuccess(
      await this.#Api.POST('/api/v1/mounts/nfs/mapping-proposals/{proposal_id}/decline', {
        body: { expected_generation: ExpectedGeneration },
        params: { header: await this.#mutationHeaders(), path: { proposal_id: ProposalId } },
      }),
    )
  }

  async revokeMapping(CredentialId: string, ExpectedGeneration: number): Promise<void> {
    RequireSuccess(
      await this.#Api.DELETE('/api/v1/mounts/nfs/mappings/{credential_id}', {
        params: {
          header: await this.#mutationHeaders(),
          path: { credential_id: CredentialId },
          query: { expected_generation: ExpectedGeneration },
        },
      }),
    )
  }

  async #mutationHeaders(): Promise<MutationHeaders> {
    if (this.#CsrfToken === null) {
      const Session = RequireData<SessionResponse>(await this.#Api.GET('/api/v1/session'))
      this.#CsrfToken = Session.csrf_token
    }
    return {
      'Idempotency-Key': crypto.randomUUID(),
      Origin: this.#Origin,
      'Sec-Fetch-Site': 'same-origin',
      'X-FileBelt-Csrf': this.#CsrfToken,
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
  throw RequestError(Result)
}

function RequireSuccess(Result: ApiResult<unknown>): void {
  if (!Result.response.ok) throw RequestError(Result)
}

function RequestError(Result: ApiResult<unknown>): Error {
  if (Result.response.status === 401) return new AuthenticationRequiredError()
  if (ProblemCode(Result.error) === 'mount.reauthentication_required')
    return new MountReauthenticationRequiredError()
  const Title = ProblemTitle(Result.error)
  return new Error(Title ?? `FileBelt NFS consent request failed (${Result.response.status}).`)
}

function ProblemCode(Value: unknown): string | null {
  if (typeof Value !== 'object' || Value === null || !('code' in Value)) return null
  return typeof Value.code === 'string' ? Value.code : null
}

function ProblemTitle(Value: unknown): string | null {
  if (typeof Value !== 'object' || Value === null || !('title' in Value)) return null
  return typeof Value.title === 'string' ? Value.title : null
}
