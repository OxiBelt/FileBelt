// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest'

import type { components } from './generated/openapi.js'
import { HttpNfsAdminClient, NfsReauthenticationRequiredError } from './nfs-admin-http-client.js'

const DriveId = '00000000-0000-4000-8000-000000000111'
const CredentialId = '00000000-0000-4000-8000-000000000112'
const ConflictId = '00000000-0000-4000-8000-000000000118'
const ProposalId = '00000000-0000-4000-8000-000000000124'

const Session = {
  csrf_token: 'csrf-memory-only',
  display_name: 'Avery Morgan',
  principal_id: '00000000-0000-4000-8000-000000000113',
  reauthenticated_recently: true,
  session_id: '00000000-0000-4000-8000-000000000114',
  tenant_admin: true,
  user_id: '00000000-0000-4000-8000-000000000115',
  verified_email: 'avery@example.test',
} satisfies components['schemas']['Session']

const Overview = {
  exports: [
    {
      applied_generation: 1,
      applied_state: 'active',
      desired_generation: 2,
      desired_state: 'draining',
      drive_id: DriveId,
      export_id: 7,
      export_path: `/filebelt/${DriveId}`,
      in_sync: false,
    },
  ],
  feature: {
    applied_gateway_epoch: 4,
    applied_gateway_id: 'nfs-gateway-1',
    applied_manifest_generation: 8,
    desired_manifest_generation: 9,
    generation: 3,
    manifest_applied: false,
    restore_generation: 1,
    state: 'draining',
  },
  mappings: [
    {
      allowed_drive_ids: [DriveId],
      credential_id: CredentialId,
      generation: 2,
      kerberos_principal: 'alice@EXAMPLE.TEST',
      principal_id: '00000000-0000-4000-8000-000000000116',
      projected_gid: 2001,
      projected_uid: 1001,
    },
  ],
  posix_groups: [
    {
      group_id: '00000000-0000-4000-8000-000000000117',
      posix_name: 'engineering.platform',
      projected_gid: 2001,
    },
  ],
  realm: 'EXAMPLE.TEST',
  tenant_slug: 'acme',
} satisfies components['schemas']['NfsAdminOverview']

const Conflicts = [
  {
    base_version_id: null,
    conflict_copy_node_id: null,
    conflict_copy_version_id: null,
    created_at: '2026-08-11T00:00:00Z',
    drive_id: DriveId,
    expected_head_version_id: null,
    expires_at: '2026-08-18T00:00:00Z',
    id: ConflictId,
    logical_size_bytes: 17,
    observed_head_version_id: null,
    source_node_id: '00000000-0000-4000-8000-000000000119',
    state: 'retained',
    write_session_id: '00000000-0000-4000-8000-000000000120',
  },
] satisfies components['schemas']['NfsWriteConflict'][]

const Proposals = [
  {
    allowed_drive_ids: [DriveId],
    allowed_drives: [{ display_name: 'Research', id: DriveId }],
    created_at: '2026-08-11T00:00:00Z',
    decided_at: null,
    expires_at: '2026-08-12T00:00:00Z',
    generation: 1,
    id: ProposalId,
    kerberos_principal: 'bob@EXAMPLE.TEST',
    principal_id: '00000000-0000-4000-8000-000000000125',
    posix_group_id: '00000000-0000-4000-8000-000000000126',
    posix_group_name: 'researchers',
    posix_name: 'bob',
    projected_gid: 2002,
    projected_uid: 1002,
    proposer_principal_id: Session.principal_id,
    state: 'pending',
  },
] satisfies components['schemas']['NfsMappingProposal'][]

const QuarantinedMappings = [
  {
    allowed_drive_ids: [DriveId],
    credential_id: CredentialId,
    generation: 2,
    kerberos_principal: 'alice@EXAMPLE.TEST',
    principal_id: '00000000-0000-4000-8000-000000000116',
    projected_gid: 2001,
    projected_uid: 1001,
    quarantined_at: '2026-08-11T00:00:00Z',
    quarantine_reason: 'target_approval_cutover',
  },
] satisfies components['schemas']['NfsQuarantinedMapping'][]

class ContractServer {
  readonly Requests: Request[] = []
  ReauthenticationRequired = false
  OverviewResponse: components['schemas']['NfsAdminOverview'] = Overview

  // oxlint-disable-next-line filebelt/pascal-case, typescript/require-await -- Fetch's platform spelling and Promise contract are required by the injected transport fake.
  readonly fetch: typeof fetch = async (Input, Init) => {
    const RequestValue = Input instanceof Request ? Input : new Request(Input, Init)
    this.Requests.push(RequestValue)
    const Url = new URL(RequestValue.url)
    if (Url.pathname === '/api/v1/session') return Json(Session)
    if (Url.pathname === '/api/v1/admin/mounts/nfs' && RequestValue.method === 'GET') {
      if (this.ReauthenticationRequired) {
        return Problem(
          {
            code: 'admin.reauthentication_required',
            status: 403,
            title: 'Recent tenant administrator authentication is required',
            type: 'https://filebelt.dev/problems/admin.reauthentication_required',
          },
          403,
        )
      }
      return Json(this.OverviewResponse)
    }
    if (Url.pathname === '/api/v1/admin/mounts/nfs/conflicts' && RequestValue.method === 'GET')
      return Json(Conflicts)
    if (
      Url.pathname === '/api/v1/admin/mounts/nfs/mapping-proposals' &&
      RequestValue.method === 'GET'
    )
      return Json(Proposals)
    if (
      Url.pathname === '/api/v1/admin/mounts/nfs/mapping-proposals' &&
      RequestValue.method === 'POST'
    )
      return Json(Proposals[0], 201)
    if (
      Url.pathname === `/api/v1/admin/mounts/nfs/mapping-proposals/${ProposalId}` &&
      RequestValue.method === 'DELETE'
    )
      return new Response(null, { status: 204 })
    if (
      Url.pathname === '/api/v1/admin/mounts/nfs/quarantined-mappings' &&
      RequestValue.method === 'GET'
    )
      return Json(QuarantinedMappings)
    if (
      Url.pathname === `/api/v1/admin/mounts/nfs/exports/${DriveId}` &&
      RequestValue.method === 'PUT'
    ) {
      return Json(Overview.exports[0])
    }
    if (Url.pathname === '/api/v1/admin/mounts/nfs/feature' && RequestValue.method === 'PUT')
      return Json(Overview.feature)
    if (Url.pathname === '/api/v1/admin/mounts/nfs/exports' && RequestValue.method === 'POST')
      return Json(Overview.exports[0], 201)
    if (Url.pathname === '/api/v1/admin/mounts/nfs/posix-groups' && RequestValue.method === 'POST')
      return Json(Overview.posix_groups[0], 201)
    if (
      Url.pathname === `/api/v1/admin/mounts/nfs/mappings/${CredentialId}` &&
      RequestValue.method === 'DELETE'
    )
      return new Response(null, { status: 204 })
    if (
      Url.pathname === `/api/v1/admin/mounts/nfs/mappings/${CredentialId}/scope` &&
      RequestValue.method === 'PUT'
    )
      return Json(Overview.mappings[0])
    if (
      Url.pathname === `/api/v1/admin/mounts/nfs/conflicts/${ConflictId}/copy` &&
      RequestValue.method === 'POST'
    ) {
      return Json(
        {
          blake3: '00'.repeat(32),
          conflict_id: ConflictId,
          display_name: 'recovered.txt',
          drive_id: DriveId,
          node_id: '00000000-0000-4000-8000-000000000121',
          size_bytes: 17,
          version_id: '00000000-0000-4000-8000-000000000122',
        },
        201,
      )
    }
    if (
      Url.pathname === `/api/v1/admin/mounts/nfs/conflicts/${ConflictId}` &&
      RequestValue.method === 'DELETE'
    )
      return new Response(null, { status: 204 })
    return new Response(null, { status: 404 })
  }
}

function Json(Value: unknown, Status = 200): Response {
  return new Response(JSON.stringify(Value), {
    headers: { 'Content-Type': 'application/json' },
    status: Status,
  })
}

function Problem(Value: unknown, Status: number): Response {
  return new Response(JSON.stringify(Value), {
    headers: { 'Content-Type': 'application/problem+json' },
    status: Status,
  })
}

describe('HttpNfsAdminClient', () => {
  it('maps desired and applied state without treating pending intent as applied', async () => {
    const Server = new ContractServer()
    const Client = new HttpNfsAdminClient(Server.fetch, 'https://filebelt.example.test')

    const Result = await Client.getOverview()

    expect(Result.Feature.ManifestApplied).toBe(false)
    expect(Result.Exports[0]).toMatchObject({
      AppliedGeneration: 1,
      DesiredGeneration: 2,
      InSync: false,
    })
    expect(Result.Mappings[0]?.KerberosPrincipal).toBe('alice@EXAMPLE.TEST')
    expect(Result.Mappings[0]?.AllowedDriveIds).toEqual([DriveId])
    expect(Result.PendingProposals[0]).toMatchObject({ Id: ProposalId, State: 'pending' })
    expect(Result.QuarantinedMappings[0]).toMatchObject({
      CredentialId,
      QuarantineReason: 'target_approval_cutover',
    })
    expect(Result.Conflicts[0]).toMatchObject({
      Id: ConflictId,
      LogicalSizeBytes: 17,
      State: 'retained',
    })
    expect(Result.Realm).toBe('EXAMPLE.TEST')
    expect(Result.TenantSlug).toBe('acme')
  })

  it('preserves an absent legacy mapping drive projection as unknown', async () => {
    const Server = new ContractServer()
    Server.OverviewResponse = {
      ...Overview,
      mappings: [
        {
          credential_id: CredentialId,
          generation: 2,
          kerberos_principal: 'legacy@EXAMPLE.TEST',
          principal_id: '00000000-0000-4000-8000-000000000116',
          projected_gid: 2001,
          projected_uid: 1001,
        },
      ],
    }
    const Client = new HttpNfsAdminClient(Server.fetch, 'https://filebelt.example.test')

    const Result = await Client.getOverview()

    expect(Result.Mappings[0]?.AllowedDriveIds).toBeUndefined()
  })

  it('generation-fences an export transition with memory-only CSRF and idempotency headers', async () => {
    const Server = new ContractServer()
    const Client = new HttpNfsAdminClient(Server.fetch, 'https://filebelt.example.test')

    await Client.transitionExport(DriveId, 2, 'draining', 'acme')

    const RequestValue = Server.Requests.at(-1)
    expect(RequestValue?.headers.get('X-FileBelt-Csrf')).toBe('csrf-memory-only')
    expect(RequestValue?.headers.get('Idempotency-Key')).toMatch(/^[0-9a-f-]{36}$/)
    expect(RequestValue?.url).not.toContain('csrf-memory-only')
    expect(await RequestValue?.clone().json()).toEqual({
      confirm_tenant: 'acme',
      expected_generation: 2,
      target_state: 'draining',
    })
  })

  it('carries the exact tenant confirmation on every NFS mutation', async () => {
    const Server = new ContractServer()
    const Client = new HttpNfsAdminClient(Server.fetch, 'https://filebelt.example.test')

    await Client.transitionFeature(3, 'draining', 'Acme')
    await Client.registerExport({ DriveId, ExportId: 7 }, 'Acme')
    await Client.registerPosixGroup(
      {
        GroupId: '00000000-0000-4000-8000-000000000117',
        PosixName: 'engineering.platform',
        ProjectedGid: 2001,
      },
      'Acme',
    )
    await Client.proposeMapping(
      {
        AllowedDriveIds: [DriveId],
        KerberosPrincipal: 'alice@EXAMPLE.TEST',
        PrincipalId: '00000000-0000-4000-8000-000000000116',
        ProjectedGid: 2001,
        ProjectedUid: 1001,
      },
      'Acme',
    )
    await Client.cancelProposal(ProposalId, 1, 'Acme')
    await Client.attenuateMappingScope(CredentialId, [DriveId], 2, 'Acme')
    await Client.revokeMapping(CredentialId, 2, 'Acme')
    await Client.copyConflict(
      ConflictId,
      {
        DisplayName: 'recovered.txt',
        DriveId,
        ExpectedParentGeneration: 9,
        ParentId: '00000000-0000-4000-8000-000000000123',
      },
      'Acme',
    )
    await Client.discardConflict(ConflictId, 'Acme')

    const Mutations = Server.Requests.filter(
      (RequestValue) => !['GET'].includes(RequestValue.method),
    )
    expect(
      Mutations.some(
        (RequestValue) =>
          new URL(RequestValue.url).pathname === '/api/v1/admin/mounts/nfs/mappings' &&
          RequestValue.method === 'POST',
      ),
    ).toBe(false)
    expect(
      Mutations.some(
        (RequestValue) =>
          new URL(RequestValue.url).pathname === '/api/v1/admin/mounts/nfs/mapping-proposals' &&
          RequestValue.method === 'POST',
      ),
    ).toBe(true)
    const JsonBodies = await Promise.all(
      Mutations.filter((RequestValue) => RequestValue.method !== 'DELETE').map(
        // oxlint-disable-next-line typescript/no-unsafe-return -- Response.json is typed as any at this hostile-payload test boundary.
        async (RequestValue) => RequestValue.clone().json(),
      ),
    )
    expect(
      JsonBodies.every((Body: unknown) => ExternalValue(Body, 'confirm_tenant') === 'Acme'),
    ).toBe(true)
    const DeleteUrls = Mutations.filter((RequestValue) => RequestValue.method === 'DELETE').map(
      (RequestValue) => new URL(RequestValue.url),
    )
    expect(DeleteUrls.every((Url) => Url.searchParams.get('confirm_tenant') === 'Acme')).toBe(true)
  })

  it('maps the stable tenant-admin recent-authentication problem', async () => {
    const Server = new ContractServer()
    Server.ReauthenticationRequired = true
    const Client = new HttpNfsAdminClient(Server.fetch, 'https://filebelt.example.test')

    await expect(Client.getOverview()).rejects.toBeInstanceOf(NfsReauthenticationRequiredError)
  })
})

function ExternalValue(Value: unknown, Key: string): unknown {
  if (typeof Value !== 'object' || Value === null) return undefined
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- This helper deliberately inspects an untrusted JSON object in a transport-boundary test.
  return (Value as Record<string, unknown>)[Key]
}
