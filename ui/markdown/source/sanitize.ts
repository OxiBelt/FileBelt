// SPDX-License-Identifier: Apache-2.0

declare const SanitizedMarkupBrand: unique symbol;

export type SanitizedGeneratedMarkup = string & { readonly [SanitizedMarkupBrand]: true };

export interface GeneratedMarkupSanitizer {
  SanitizeHtml(GeneratedMarkup: string): SanitizedGeneratedMarkup;
  SanitizeSvg(GeneratedMarkup: string): SanitizedGeneratedMarkup;
}

export interface DomPurifyLike {
  sanitize(DirtyMarkup: string, Options: Record<string, unknown>): string;
}

export function CreateGeneratedMarkupSanitizer(Purify: DomPurifyLike): GeneratedMarkupSanitizer {
  return {
    SanitizeHtml(GeneratedMarkup: string): SanitizedGeneratedMarkup {
      return Purify.sanitize(GeneratedMarkup, {
        FORBID_TAGS: ["audio", "form", "iframe", "img", "object", "script", "style", "video"],
        USE_PROFILES: { html: true },
      }) as SanitizedGeneratedMarkup;
    },
    SanitizeSvg(GeneratedMarkup: string): SanitizedGeneratedMarkup {
      return Purify.sanitize(GeneratedMarkup, {
        FORBID_ATTR: ["href", "xlink:href"],
        FORBID_TAGS: ["a", "foreignObject", "script"],
        USE_PROFILES: { svg: true, svgFilters: false },
      }) as SanitizedGeneratedMarkup;
    },
  };
}
