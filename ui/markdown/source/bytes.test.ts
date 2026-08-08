// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { DecodeMarkdown, EncodeMarkdown, MarkdownInputError } from "./bytes.js";

describe("Markdown byte boundaries", () => {
  it("preserves a BOM and CRLF save format while editing normalized text", () => {
    const Source = DecodeMarkdown(new Uint8Array([0xef, 0xbb, 0xbf, 97, 13, 10, 98]), 32);
    expect(Source).toEqual({ HasByteOrderMark: true, LineEnding: "crlf", Text: "a\nb" });
    expect(EncodeMarkdown(Source, 32)).toEqual(new Uint8Array([0xef, 0xbb, 0xbf, 97, 13, 10, 98]));
  });

  it("rejects malformed UTF-8, NUL, mixed endings, and oversize input", () => {
    expect(() => DecodeMarkdown(new Uint8Array([0xc3, 0x28]), 32)).toThrow(MarkdownInputError);
    expect(() => DecodeMarkdown(new Uint8Array([0]), 32)).toThrow(MarkdownInputError);
    expect(() => DecodeMarkdown(new TextEncoder().encode("a\nb\r\nc"), 32)).toThrow(MarkdownInputError);
    expect(() => DecodeMarkdown(new TextEncoder().encode("four"), 3)).toThrow(MarkdownInputError);
  });
});
