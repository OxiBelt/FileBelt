// SPDX-License-Identifier: Apache-2.0

import { expect, test } from '@playwright/test'

const DriveId = '00000000-0000-4000-8000-000000000181'
const RootId = '00000000-0000-4000-8000-000000000182'

test.use({ viewport: { height: 720, width: 375 } })

test('exposes mobile navigation state and restores focus after Escape and selection', async ({
  page: Page,
}) => {
  await Page.route('**/*', async (Route) => {
    const Request = Route.request()
    if (Request.resourceType() !== 'fetch') return Route.continue()
    const Path = new URL(Request.url()).pathname
    if (Path === '/api/v1/session') return Route.fulfill({ json: Session() })
    if (Path === '/api/v1/drives')
      return Route.fulfill({
        json: {
          items: [
            {
              acl_generation: 1,
              display_name: 'My Drive',
              id: DriveId,
              kind: 'private',
              namespace_generation: 1,
              owner_display_name: 'Avery Morgan',
              quota_bytes: 1,
              reserved_bytes: 0,
              root_id: RootId,
              used_physical_bytes: 0,
            },
          ],
          next_cursor: null,
        },
      })
    if (Path === `/api/v1/drives/${DriveId}/nodes/${RootId}`)
      return Route.fulfill({ json: RootNode() })
    if (Path === `/api/v1/drives/${DriveId}/nodes/${RootId}/children`)
      return Route.fulfill({ json: { items: [], next_cursor: null } })
    if (Path === `/api/v1/drives/${DriveId}/trash`)
      return Route.fulfill({ json: { items: [], next_cursor: null } })
    if (Path === '/api/v1/shared') return Route.fulfill({ json: { items: [], next_cursor: null } })
    if (Path === '/api/v1/sessions') return Route.fulfill({ json: [] })
    return Route.fulfill({
      json: { code: 'test.unhandled', status: 404, title: Path, type: 'about:blank' },
      status: 404,
    })
  })
  await Page.goto('/drive')

  const Trigger = Page.getByRole('button', { name: 'FileBelt navigation' })
  await expect(Trigger).toHaveAttribute('aria-controls', 'main-navigation')
  await expect(Trigger).toHaveAttribute('aria-expanded', 'false')

  await Trigger.click()
  await expect(Trigger).toHaveAttribute('aria-expanded', 'true')
  await expect(Page.getByRole('button', { name: 'My Drive', exact: true })).toBeFocused()

  await Page.keyboard.press('Escape')
  await expect(Trigger).toHaveAttribute('aria-expanded', 'false')
  await expect(Trigger).toBeFocused()

  await Trigger.click()
  await Page.getByRole('button', { name: 'Shared with me', exact: true }).click()
  await expect(Page).toHaveURL(/\/shared$/)
  await expect(Trigger).toHaveAttribute('aria-expanded', 'false')
  await expect(Page.locator('#main-content')).toBeFocused()
})

function Session(): Record<string, unknown> {
  return {
    csrf_token: 'csrf-test',
    display_name: 'Avery Morgan',
    principal_id: '00000000-0000-4000-8000-000000000183',
    reauthenticated_recently: true,
    session_id: '00000000-0000-4000-8000-000000000184',
    tenant_admin: false,
    user_id: '00000000-0000-4000-8000-000000000185',
    verified_email: 'avery@example.test',
  }
}

function RootNode(): Record<string, unknown> {
  return {
    acl_generation: 1,
    attribute_generation: 1,
    content_class_policy: 'auto',
    display_name: 'My Drive',
    drive_id: DriveId,
    head_media_type: null,
    head_version_id: null,
    id: RootId,
    kind: 'directory',
    namespace_generation: 1,
    parent_id: null,
    size_bytes: null,
    trashed: false,
    updated_at: '2026-08-22T00:00:00Z',
    version_ordinal: null,
  }
}
