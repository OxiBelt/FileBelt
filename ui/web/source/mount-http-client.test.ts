// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest'

import type { components } from './generated/openapi.js'
import {
  HttpMountSettingsClient,
  MountCredentialOutcomeUnknownError,
  MountReauthenticationRequiredError,
} from './mount-http-client.js'

const DriveId = '00000000-0000-4000-8000-000000000071'
const CredentialId = '00000000-0000-4000-8000-000000000072'
const OperationGeneration = 7

const Session = {
  csrf_token: 'csrf-memory-only',
  display_name: 'Avery Morgan',
  principal_id: '00000000-0000-4000-8000-000000000073',
  reauthenticated_recently: true,
  session_id: '00000000-0000-4000-8000-000000000074',
  tenant_admin: false,
  user_id: '00000000-0000-4000-8000-000000000075',
  verified_email: 'avery@example.test',
} satisfies components['schemas']['Session']

class ContractServer {
  readonly Requests: Request[] = []
  MalformedSuccess = false
  Rejected = false
  ReauthenticationRequired = false
  ReusedOperation = false
  TransportFailure = false
  Unavailable = false

  // oxlint-disable-next-line filebelt/pascal-case, typescript/require-await -- Fetch's platform spelling and Promise contract are required by the injected transport fake.
  readonly fetch: typeof fetch = async (Input, Init) => {
    const RequestValue = Input instanceof Request ? Input : new Request(Input, Init)
    this.Requests.push(RequestValue)
    const Url = new URL(RequestValue.url)
    if (Url.pathname === '/api/v1/session') return Json(Session)
    if (Url.pathname === '/api/v1/mounts/credential-operations' && RequestValue.method === 'POST')
      return Json(
        {
          expires_at: '2026-08-08T10:02:00Z',
          operation_generation: OperationGeneration,
          operation_id: CredentialId,
        },
        this.ReusedOperation ? 200 : 201,
      )
    if (
      Url.pathname === `/api/v1/mounts/credential-operations/${CredentialId}` &&
      RequestValue.method === 'DELETE'
    )
      return new Response(null, { status: 204 })
    if (Url.pathname === '/api/v1/mounts/credentials' && RequestValue.method === 'POST') {
      if (this.TransportFailure) throw new TypeError('Connection interrupted')
      if (this.Unavailable) return new Response(null, { status: 503 })
      if (this.MalformedSuccess) return new Response(null, { status: 201 })
      if (this.Rejected)
        return Json(
          {
            code: 'mount.credential_invalid',
            detail: 'The requested expiry exceeds the permitted lifetime.',
            status: 400,
            title: 'Invalid mount credential request',
          },
          400,
        )
      if (this.ReauthenticationRequired) {
        return Json(
          {
            code: 'mount.reauthentication_required',
            status: 403,
            title: 'Recent OIDC authentication is required',
            type: 'https://filebelt.dev/problems/mount.reauthentication_required',
          },
          403,
        )
      }
      return Json(
        {
          credential_id: CredentialId,
          expires_at: '2026-08-15T10:00:00Z',
          password: 'one-time-password',
          protocol: 'smb',
          username: 'fb-example',
        },
        201,
      )
    }
    return new Response(null, { status: 404 })
  }
}

function Json(Value: unknown, Status = 200): Response {
  return new Response(JSON.stringify(Value), {
    headers: { 'Content-Type': 'application/json' },
    status: Status,
  })
}

describe('HttpMountSettingsClient', () => {
  it('creates a scoped credential with CSRF protection and keeps secrets out of the URL', async () => {
    const Server = new ContractServer()
    const Client = new HttpMountSettingsClient(Server.fetch, 'https://filebelt.example.test')
    const Created = await Client.createCredential({
      allowed_drive_ids: [DriveId],
      bound_device_id: null,
      expires_at: '2026-08-15T10:00:00Z',
      operation_generation: OperationGeneration,
      operation_id: CredentialId,
      protocol: 'smb',
      read_only: true,
    })

    expect(Created.password).toBe('one-time-password')
    const RequestValue = Server.Requests.at(-1)
    expect(RequestValue?.url).not.toContain('one-time-password')
    expect(RequestValue?.headers.get('X-FileBelt-Csrf')).toBe('csrf-memory-only')
    expect(await RequestValue?.clone().json()).toEqual({
      allowed_drive_ids: [DriveId],
      bound_device_id: null,
      expires_at: '2026-08-15T10:00:00Z',
      operation_generation: OperationGeneration,
      operation_id: CredentialId,
      protocol: 'smb',
      read_only: true,
    })
  })

  it('maps the stable recent-authentication problem to an actionable error', async () => {
    const Server = new ContractServer()
    Server.ReauthenticationRequired = true
    const Client = new HttpMountSettingsClient(Server.fetch, 'https://filebelt.example.test')

    await expect(
      Client.createCredential({
        allowed_drive_ids: [DriveId],
        bound_device_id: null,
        expires_at: '2026-08-15T10:00:00Z',
        operation_generation: OperationGeneration,
        operation_id: CredentialId,
        protocol: 'smb',
        read_only: true,
      }),
    ).rejects.toBeInstanceOf(MountReauthenticationRequiredError)
  })

  it('exposes the caller-known credential id instead of retrying an unknown creation', async () => {
    const Server = new ContractServer()
    Server.Unavailable = true
    const Client = new HttpMountSettingsClient(Server.fetch, 'https://filebelt.example.test')

    await expect(
      Client.createCredential({
        allowed_drive_ids: [DriveId],
        bound_device_id: null,
        expires_at: '2026-08-15T10:00:00Z',
        operation_generation: OperationGeneration,
        operation_id: CredentialId,
        protocol: 'smb',
        read_only: true,
      }),
    ).rejects.toMatchObject({ OperationGeneration, OperationId: CredentialId })
    expect(Server.Requests.filter(({ method: Method }) => Method === 'POST')).toHaveLength(1)
  })

  it('treats a transport interruption as unknown without retrying credential creation', async () => {
    const Server = new ContractServer()
    Server.TransportFailure = true
    const Client = new HttpMountSettingsClient(Server.fetch, 'https://filebelt.example.test')

    await expect(
      Client.createCredential({
        allowed_drive_ids: [DriveId],
        bound_device_id: null,
        expires_at: '2026-08-15T10:00:00Z',
        operation_generation: OperationGeneration,
        operation_id: CredentialId,
        protocol: 'smb',
        read_only: true,
      }),
    ).rejects.toMatchObject({ OperationGeneration, OperationId: CredentialId })
    expect(Server.Requests.filter(({ method: Method }) => Method === 'POST')).toHaveLength(1)
  })

  it('treats a success without recoverable one-time material as an unknown outcome', async () => {
    const Server = new ContractServer()
    Server.MalformedSuccess = true
    const Client = new HttpMountSettingsClient(Server.fetch, 'https://filebelt.example.test')

    await expect(
      Client.createCredential({
        allowed_drive_ids: [DriveId],
        bound_device_id: null,
        expires_at: '2026-08-15T10:00:00Z',
        operation_generation: OperationGeneration,
        operation_id: CredentialId,
        protocol: 'smb',
        read_only: true,
      }),
    ).rejects.toMatchObject({ OperationGeneration, OperationId: CredentialId })
  })

  it('keeps a definite client rejection distinct from an unknown creation outcome', async () => {
    const Server = new ContractServer()
    Server.Rejected = true
    const Client = new HttpMountSettingsClient(Server.fetch, 'https://filebelt.example.test')

    await expect(
      Client.createCredential({
        allowed_drive_ids: [DriveId],
        bound_device_id: null,
        expires_at: '2026-08-15T10:00:00Z',
        operation_generation: OperationGeneration,
        operation_id: CredentialId,
        protocol: 'smb',
        read_only: true,
      }),
    ).rejects.not.toBeInstanceOf(MountCredentialOutcomeUnknownError)
    expect(Server.Requests.filter(({ method: Method }) => Method === 'POST')).toHaveLength(1)
  })

  it('treats a definite missing credential as an already-complete revocation', async () => {
    const Server = new ContractServer()
    const Client = new HttpMountSettingsClient(Server.fetch, 'https://filebelt.example.test')

    await expect(Client.revokeCredential(CredentialId)).resolves.toBeUndefined()
    const RequestValue = Server.Requests.at(-1)
    expect(RequestValue?.method).toBe('DELETE')
    expect(RequestValue?.url).toBe(
      `https://filebelt.example.test/api/v1/mounts/credentials/${CredentialId}`,
    )
  })

  it('prepares a server-owned operation tuple with the mutation protections', async () => {
    const Server = new ContractServer()
    const Client = new HttpMountSettingsClient(Server.fetch, 'https://filebelt.example.test')

    await expect(Client.prepareCredentialOperation()).resolves.toEqual({
      Created: true,
      Operation: {
        expires_at: '2026-08-08T10:02:00Z',
        operation_generation: OperationGeneration,
        operation_id: CredentialId,
      },
    })
    const RequestValue = Server.Requests.at(-1)
    expect(RequestValue?.method).toBe('POST')
    expect(RequestValue?.headers.get('X-FileBelt-Csrf')).toBe('csrf-memory-only')
  })

  it('preserves whether prepare replayed an existing operation', async () => {
    const Server = new ContractServer()
    Server.ReusedOperation = true
    const Client = new HttpMountSettingsClient(Server.fetch, 'https://filebelt.example.test')

    await expect(Client.prepareCredentialOperation()).resolves.toMatchObject({ Created: false })
  })

  it('recovers the exact operation tuple through the dedicated route', async () => {
    const Server = new ContractServer()
    const Client = new HttpMountSettingsClient(Server.fetch, 'https://filebelt.example.test')

    await expect(
      Client.cancelCredentialOperation(CredentialId, OperationGeneration),
    ).resolves.toBeUndefined()
    const RequestValue = Server.Requests.at(-1)
    expect(RequestValue?.method).toBe('DELETE')
    expect(RequestValue?.url).toBe(
      `https://filebelt.example.test/api/v1/mounts/credential-operations/${CredentialId}?expected_generation=${OperationGeneration}`,
    )
  })
})
