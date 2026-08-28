// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest'

import { ResolveTheme } from './index.js'

describe('resolveTheme', () => {
  it('uses an explicit theme regardless of the system preference', () => {
    expect(ResolveTheme('light', true)).toBe('light')
    expect(ResolveTheme('dark', false)).toBe('dark')
  })

  it('follows the system when requested', () => {
    expect(ResolveTheme('system', true)).toBe('dark')
    expect(ResolveTheme('system', false)).toBe('light')
  })
})
