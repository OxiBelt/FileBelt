// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'

import { SharesView } from './ActivityViews.js'
import type { FileEntry, ShareRecord } from './model.js'
import { En } from './strings.js'

describe('SharesView', () => {
  it('filters same-named shares by immutable resource identity', () => {
    const Selected: FileEntry = {
      HeadVersionId: '00000000-0000-4000-8000-000000000012',
      Id: '00000000-0000-4000-8000-000000000101',
      Kind: 'file',
      ModifiedAt: '2026-08-06T12:00:00Z',
      TextEligibility: 'ineligible',
      MediaType: null,
      Name: 'same-name.txt',
      Owner: 'Owner',
      Shared: true,
      Size: 1,
      Status: 'ready',
      Trashed: false,
      Version: 1,
    }
    const Shares: ShareRecord[] = [
      {
        Id: 'share-selected',
        Kind: 'direct',
        Permission: 'Viewer',
        ResourceId: Selected.Id,
        ResourceName: Selected.Name,
        Target: 'selected@example.test',
      },
      {
        Id: 'share-other',
        Kind: 'direct',
        Permission: 'Viewer',
        ResourceId: '00000000-0000-4000-8000-000000000102',
        ResourceName: Selected.Name,
        Target: 'other@example.test',
      },
    ]

    const Markup = renderToStaticMarkup(
      <SharesView
        File={Selected}
        // oxlint-disable-next-line typescript/require-await -- Static rendering requires the asynchronous prop shape but performs no mutation.
        onCreate={async () => undefined}
        // oxlint-disable-next-line typescript/require-await -- Static rendering requires the asynchronous prop shape but performs no mutation.
        onRevoke={async () => undefined}
        Shares={Shares}
        Strings={En}
      />,
    )

    expect(Markup).toContain('selected@example.test')
    expect(Markup).not.toContain('other@example.test')
    expect(Markup).not.toContain(En.anonymousLink)
    expect(Markup).not.toContain(En.groupShare)
    expect(Markup).toContain('aria-haspopup="dialog"')
    expect(Markup).not.toContain(En.shareRevokeHeading)
  })
})
