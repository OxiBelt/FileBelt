// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'

import { MockFileBeltClient } from './client.js'
import { TextSettings } from './TextSettings.js'

describe('TextSettings', () => {
  it('keeps the server-enforced personal text limits on labeled controls', () => {
    const Markup = renderToStaticMarkup(<TextSettings Client={new MockFileBeltClient()} />)
    expect(Markup).toContain('Text editing')
    expect(Markup).toContain('Loading text preferences')
  })
})
