// SPDX-License-Identifier: Apache-2.0

declare const SanitizedMarkupBrand: unique symbol

export type SanitizedGeneratedMarkup = string & { readonly [SanitizedMarkupBrand]: true }

export interface GeneratedMarkupSanitizer {
  SanitizeHtml(GeneratedMarkup: string): SanitizedGeneratedMarkup
  SanitizeSvg(GeneratedMarkup: string): SanitizedGeneratedMarkup
}

export interface DomPurifyLike {
  // oxlint-disable-next-line filebelt/pascal-case -- DOMPurify exposes this exact sanitizer method.
  sanitize(DirtyMarkup: string, Options: Readonly<Record<string, unknown>>): string
}

export function CreateGeneratedMarkupSanitizer(
  Purify: Readonly<DomPurifyLike>,
): GeneratedMarkupSanitizer {
  return {
    SanitizeHtml(GeneratedMarkup: string): SanitizedGeneratedMarkup {
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- This branded value is created only after the fixed HTML sanitizer profile completes.
      return Purify.sanitize(GeneratedMarkup, {
        FORBID_TAGS: ['audio', 'form', 'iframe', 'img', 'object', 'script', 'style', 'video'],
        USE_PROFILES: { html: true },
      }) as SanitizedGeneratedMarkup
    },
    SanitizeSvg(GeneratedMarkup: string): SanitizedGeneratedMarkup {
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- This branded value is created only after the fixed SVG sanitizer profile completes.
      return Purify.sanitize(GeneratedMarkup, {
        FORBID_ATTR: ['href', 'xlink:href'],
        FORBID_TAGS: ['a', 'foreignObject', 'script'],
        USE_PROFILES: { svg: true, svgFilters: false },
      }) as SanitizedGeneratedMarkup
    },
  }
}
