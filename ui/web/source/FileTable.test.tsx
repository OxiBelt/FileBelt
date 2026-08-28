// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'

import { FileTable } from './FileTable.js'
import { En } from './strings.js'

describe('FileTable', () => {
  it('renders a multiselect grid with selected state and bidi-isolated names', () => {
    const Markup = renderToStaticMarkup(
      <FileTable
        DispatchSelection={() => undefined}
        Entries={[
          {
            HeadVersionId: '00000000-0000-4000-8000-000000000012',
            Id: 'file-1',
            Kind: 'file',
            ModifiedAt: '2026-08-06T12:00:00Z',
            TextEligibility: 'ineligible',
            MediaType: null,
            Name: '‫خطة المشروع‬.pdf',
            Owner: 'Layla Hassan',
            Shared: true,
            Size: 512,
            Status: 'ready',
            Trashed: false,
            Version: 4,
          },
        ]}
        OnOpenActions={() => undefined}
        OnOpenEntry={() => undefined}
        Selection={{ AnchorId: 'file-1', FocusedId: 'file-1', SelectedIds: new Set(['file-1']) }}
        Strings={En}
      />,
    )

    expect(Markup).toContain('role="grid"')
    expect(Markup).toContain('aria-multiselectable="true"')
    expect(Markup).toContain('aria-selected="true"')
    expect(Markup).toContain('<bdi dir="auto"')
    expect(Markup).toContain('aria-label="Shared"')
    expect(Markup).toMatch(/aria-label="Deselect [^"]+"[^>]*tabindex="-1"/)
  })

  it('labels logical symlinks without making them file-open candidates', () => {
    const Markup = renderToStaticMarkup(
      <FileTable
        DispatchSelection={() => undefined}
        Entries={[
          {
            HeadVersionId: null,
            Id: 'symlink-1',
            Kind: 'symlink',
            ModifiedAt: '2026-08-11T12:00:00Z',
            TextEligibility: 'ineligible',
            MediaType: null,
            Name: 'Current report',
            Owner: 'Avery Morgan',
            Shared: false,
            Size: null,
            Status: 'ready',
            Trashed: false,
            Version: 0,
          },
        ]}
        OnOpenActions={() => undefined}
        OnOpenEntry={() => undefined}
        Selection={{ AnchorId: null, FocusedId: 'symlink-1', SelectedIds: new Set() }}
        Strings={En}
      />,
    )

    expect(Markup).toContain(`aria-label="${En.symlink}"`)
    expect(Markup).toContain('Current report')
  })
})
