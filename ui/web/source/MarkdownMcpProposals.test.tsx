// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import {
  IsPreparedRequestStale,
  MarkdownMcpProposals,
  type PreparedRequestIdentity,
} from './MarkdownMcpProposals.js'

const Prepared: PreparedRequestIdentity = {
  BaseVersionId: '00000000-0000-4000-8000-000000000002',
  Fingerprint: 'sha256:capability',
  NodeId: '00000000-0000-4000-8000-000000000001',
  RegistrationId: '00000000-0000-4000-8000-000000000003',
  SelectionEnd: 4,
  SelectionStart: 0,
  Source: '# draft',
}

describe('Markdown MCP proposals', () => {
  it('renders proposal-only controls without a save action', () => {
    const Client = {
      // oxlint-disable typescript/require-await -- This object is a synchronous fake for an asynchronous MCP client contract.
      ApproveAndInvoke: async () => undefined,
      CreateInvocationIntent: async () => {
        throw new Error('not reached')
      },
      GetCapabilityReview: async () => null,
      GetSnapshot: async () => ({
        Activity: [],
        BlockRules: [],
        Registrations: [],
        ServiceIdentities: [],
        Templates: [],
      }),
      // oxlint-enable typescript/require-await
    }
    const Markup = renderToStaticMarkup(
      <MarkdownMcpProposals
        BaseVersionId='00000000-0000-4000-8000-000000000002'
        // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- This deliberately partial fake exercises only the server-rendered proposal shell.
        Client={Client as never}
        NodeId='00000000-0000-4000-8000-000000000001'
        OnApply={() => true}
        Selection={{ End: 4, Start: 0 }}
        Source='# draft'
      />,
    )
    expect(Markup).toContain('MCP proposal')
    expect(Markup).toContain('Request proposal')
    expect(Markup).not.toContain('Save')
  })

  it('invalidates confirmation when any reviewed input changes', () => {
    expect(IsPreparedRequestStale(Prepared, Prepared)).toBe(false)
    expect(IsPreparedRequestStale(Prepared, { ...Prepared, Source: '# changed' })).toBe(true)
    expect(IsPreparedRequestStale(Prepared, { ...Prepared, SelectionEnd: 3 })).toBe(true)
    expect(
      IsPreparedRequestStale(Prepared, {
        ...Prepared,
        BaseVersionId: '00000000-0000-4000-8000-000000000004',
      }),
    ).toBe(true)
    expect(IsPreparedRequestStale(Prepared, { ...Prepared, Fingerprint: 'sha256:other' })).toBe(
      true,
    )
  })
})
