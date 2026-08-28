// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'

import AdminPanel from './index.js'

// oxlint-disable-next-line typescript/promise-function-async -- This static UI test double intentionally fulfills the asynchronous admin callback contract.
const Resolve = (): Promise<void> => Promise.resolve()

describe('AdminPanel', () => {
  it('exposes tenant controls with labelled tabs and bidi-isolated user content', () => {
    const Markup = renderToStaticMarkup(
      <AdminPanel
        Drives={[]}
        Groups={[]}
        onCreateGroup={Resolve}
        onCreateSharedDrive={Resolve}
        onToggleUserSuspension={Resolve}
        Users={[{ Email: 'layla@example.test', Id: 'user-1', Name: 'ليلى', Status: 'active' }]}
      />,
    )

    expect(Markup).toContain('aria-label="Tenant administration"')
    expect(Markup).toContain('<bdi dir="auto">ليلى</bdi>')
    expect(Markup).toContain('Sensitive changes require recent sign-in')
  })
})
