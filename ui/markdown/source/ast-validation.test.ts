// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest'
import { IsFileBeltOfficeAstV1 } from './ast-validation.js'
import { ParseFileBeltGfmV1 } from './parser.js'

describe('preview AST validation', () => {
  it('accepts the normalized FileBelt profile', () => {
    const Parsed = ParseFileBeltGfmV1({
      HasByteOrderMark: false,
      LineEnding: 'lf',
      Text: '# Heading\n\nText **strong**.\n',
    })
    expect(IsFileBeltOfficeAstV1(Parsed.Ast)).toBe(true)
  })

  it('rejects unbounded or executable-shaped message fields', () => {
    expect(
      IsFileBeltOfficeAstV1({
        Children: [
          { Children: [], Kind: 'paragraph', OnClick: 'run()', Range: { End: 0, Start: 0 } },
        ],
        Profile: 'filebelt-gfm-v1',
        Range: { End: 0, Start: 0 },
      }),
    ).toBe(false)
    expect(
      IsFileBeltOfficeAstV1({
        Children: [
          { Kind: 'mermaid', Range: { End: 1, Start: 0 }, Source: 'x'.repeat(65 * 1_024) },
        ],
        Profile: 'filebelt-gfm-v1',
        Range: { End: 1, Start: 0 },
      }),
    ).toBe(false)
  })
})
