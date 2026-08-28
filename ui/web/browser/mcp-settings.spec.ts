// SPDX-License-Identifier: Apache-2.0

import { expect, test } from '@playwright/test'

const RegistrationId = '00000000-0000-4000-8000-000000000071'
const SecondaryRegistrationId = '00000000-0000-4000-8000-000000000078'
const SnapshotId = '00000000-0000-4000-8000-000000000072'
const InvocationId = '00000000-0000-4000-8000-000000000073'
const ToolFingerprint = 'b'.repeat(64)
const ResourceFingerprint = 'c'.repeat(64)

test('keeps credentials out of browser persistence and renders MCP output as text', async ({
  page: Page,
}) => {
  const Credential = 'browser-test-secret'
  const CredentialRequests: { Body: string; Url: string }[] = []
  const IntentRequests: string[] = []
  let StreamRequests = 0

  await Page.route('**/*', async (Route) => {
    const Request = Route.request()
    const Url = new URL(Request.url())
    if (Request.resourceType() !== 'fetch') return Route.continue()
    if (Url.pathname === '/api/v1/session') return Route.fulfill({ json: Session() })
    if (Url.pathname === '/api/v1/drives')
      return Route.fulfill({ json: { items: [], next_cursor: null } })
    if (Url.pathname === '/api/v1/shared')
      return Route.fulfill({ json: { items: [], next_cursor: null } })
    if (Url.pathname === '/api/v1/sessions') return Route.fulfill({ json: [] })
    if (Url.pathname === '/api/v1/mcp/registrations')
      return Route.fulfill({
        json: {
          items: [
            Registration(RegistrationId, 'Planning server'),
            Registration(SecondaryRegistrationId, 'Backup server'),
          ],
          next_cursor: null,
        },
      })
    if (Url.pathname === '/api/v1/mcp/activity')
      return Route.fulfill({ json: { items: [], next_cursor: null } })
    if (Url.pathname.endsWith('/capability-review'))
      return Route.fulfill({
        json: Review(
          Url.pathname.includes(SecondaryRegistrationId) ? SecondaryRegistrationId : RegistrationId,
        ),
      })
    if (Url.pathname.endsWith('/credentials')) {
      CredentialRequests.push({ Body: Request.postData() ?? '', Url: Request.url() })
      return Route.fulfill({ status: 204 })
    }
    if (Url.pathname === '/api/v1/mcp/invocation-intents') {
      IntentRequests.push(Request.postData() ?? '')
      return Route.fulfill({
        json: {
          approval_required: true,
          expires_at: '2026-08-07T10:05:00Z',
          id: InvocationId,
          request_digest: 'd'.repeat(64),
        },
        status: 201,
      })
    }
    if (Url.pathname.endsWith('/approval')) {
      return Route.fulfill({ json: { id: '00000000-0000-4000-8000-000000000077' }, status: 201 })
    }
    if (Url.pathname.endsWith('/stream')) {
      StreamRequests += 1
      return Route.fulfill({
        body: [
          JSON.stringify({
            created_at: '2026-08-07T10:00:00Z',
            event: 'started',
            invocation_id: InvocationId,
            sequence: 0,
          }),
          JSON.stringify({
            created_at: '2026-08-07T10:00:01Z',
            event: 'text',
            invocation_id: InvocationId,
            sequence: 1,
            text: '<script>window.pwned=true</script>',
          }),
          JSON.stringify({
            created_at: '2026-08-07T10:00:02Z',
            event: 'completed',
            invocation_id: InvocationId,
            sequence: 2,
          }),
        ].join('\n'),
        contentType: 'application/x-ndjson',
      })
    }
    return Route.fulfill({
      json: {
        code: 'test.unhandled',
        status: 404,
        title: `Unhandled ${Request.method()} ${Url.pathname}`,
        type: 'about:blank',
      },
      status: 404,
    })
  })

  await Page.goto('/settings/mcp')
  await expect(Page.getByRole('heading', { name: 'MCP servers' })).toBeVisible()
  await Page.getByLabel('Credential value').fill(Credential)
  await Page.getByText('Backup server', { exact: true }).click()
  await expect(Page.getByRole('heading', { exact: true, name: 'Backup server' })).toBeVisible()
  await expect(Page.getByLabel('Credential value')).toHaveValue('')
  await Page.getByText('Planning server', { exact: true }).click()
  await expect(Page.getByRole('heading', { exact: true, name: 'Planning server' })).toBeVisible()
  await expect(Page.getByLabel('Credential value')).toHaveValue('')
  await Page.getByLabel('Credential value').fill(Credential)
  await Page.getByRole('button', { name: 'Save credential' }).click()
  await expect.poll(() => CredentialRequests.length).toBe(1)
  expect(CredentialRequests[0]?.Url).not.toContain(Credential)
  expect(CredentialRequests[0]?.Url).toContain(RegistrationId)
  expect(CredentialRequests[0]?.Body).toContain(Credential)

  const StoredValues = await Page.evaluate(async () => ({
    Local: Object.values(localStorage),
    Session: Object.values(sessionStorage),
    Databases:
      typeof indexedDB.databases === 'function'
        ? (await indexedDB.databases()).map(({ name: Name }) => Name ?? '')
        : [],
  }))
  expect(JSON.stringify(StoredValues)).not.toContain(Credential)

  const InvocationForm = Page.getByRole('heading', {
    exact: true,
    name: 'Run test invocation',
  }).locator('..')
  await InvocationForm.getByRole('combobox').selectOption(ResourceFingerprint)
  await Page.getByLabel('JSON arguments').fill('{"query":"roadmap"}')
  await Page.getByRole('button', { exact: true, name: 'Run test invocation' }).click()
  const Confirmation = Page.getByRole('heading', { name: 'Confirm exact invocation' }).locator('..')
  await expect(Confirmation).toBeVisible()
  await expect(Confirmation.getByText('resource', { exact: true })).toBeVisible()
  await expect(Confirmation.getByText('shared', { exact: true })).toBeVisible()
  await expect(Confirmation.getByText(ResourceFingerprint, { exact: true })).toBeVisible()
  await expect.poll(() => IntentRequests.length).toBe(1)
  expect(JSON.parse(IntentRequests[0] ?? 'null')).toMatchObject({
    capability: { fingerprint: ResourceFingerprint, kind: 'resource', name: 'shared' },
  })
  expect(StreamRequests).toBe(0)
  await Page.getByRole('button', { name: 'Approve once and run' }).click()
  await expect(Page.getByText('<script>window.pwned=true</script>', { exact: true })).toBeVisible()
  expect(StreamRequests).toBe(1)
  expect(await Page.evaluate(() => 'pwned' in window)).toBe(false)
})

function Session(): object {
  return {
    csrf_token: 'csrf-browser-memory-only',
    display_name: 'Avery Morgan',
    principal_id: '00000000-0000-4000-8000-000000000074',
    reauthenticated_recently: true,
    session_id: '00000000-0000-4000-8000-000000000075',
    tenant_admin: false,
    user_id: '00000000-0000-4000-8000-000000000076',
    verified_email: 'avery@example.test',
  }
}

function Registration(Id: string, DisplayName: string): object {
  return {
    attachment_policy: {
      allowed_encodings: ['utf8'],
      allowed_mime_patterns: ['text/*'],
      max_attachments: 4,
      max_item_bytes: 1048576,
      max_total_bytes: 4194304,
    },
    authentication_state: 'ready',
    capability_snapshot_id: SnapshotId,
    capability_state: 'reviewed',
    catalog_entry_id: null,
    created_at: '2026-08-07T10:00:00Z',
    credential_kind: 'bearer',
    credential_present: true,
    display_name: DisplayName,
    endpoint_uri: 'https://mcp.example.test/mcp',
    etag: '"mcp-1"',
    generation: 1,
    id: Id,
    lifecycle_state: 'enabled',
    managed_locked: false,
    ownership: 'personal',
    protocol_version: '2026-07-28',
    quarantine_state: 'clear',
    transport: 'streamable_http',
    trust_profile: 'public-webpki',
    updated_at: '2026-08-07T10:00:00Z',
    validation_state: 'valid',
  }
}

function Review(Registration: string): object {
  return {
    decisions: [
      { capability_fingerprint: ToolFingerprint, decision: 'approved' },
      { capability_fingerprint: ResourceFingerprint, decision: 'approved' },
    ],
    reviewed_at: '2026-08-07T10:00:00Z',
    snapshot: {
      capabilities: [
        {
          description: 'Runs a shared action',
          fingerprint: ToolFingerprint,
          input_schema: { type: 'object' },
          kind: 'tool',
          name: 'shared',
          read_only_hint: true,
          risk: 'low',
          state: 'unchanged',
          title: 'Run shared action',
        },
        {
          description: 'Reads shared data',
          fingerprint: ResourceFingerprint,
          input_schema: { type: 'object' },
          kind: 'resource',
          name: 'shared',
          read_only_hint: null,
          risk: 'low',
          state: 'unchanged',
          title: 'Read shared data',
        },
      ],
      created_at: '2026-08-07T10:00:00Z',
      fingerprint: 'e'.repeat(64),
      id: SnapshotId,
      protocol_version: '2026-07-28',
      registration_id: Registration,
    },
  }
}
