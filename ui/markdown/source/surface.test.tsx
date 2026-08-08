// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { MarkdownPreview } from "./renderer.js";
import { MarkdownSurface } from "./surface.js";
import { EnglishMarkdownStrings } from "./strings.js";
import type { FileBeltOfficeAstV1, MarkdownSource } from "./types.js";

const Source: MarkdownSource = { HasByteOrderMark: false, LineEnding: "lf", Text: "# title" };
const Ast: FileBeltOfficeAstV1 = { Children: [], Profile: "filebelt-gfm-v1", Range: { End: 0, Start: 0 } };

describe("Markdown isolation and accessibility", () => {
  it("uses an opaque script-only preview frame and labels keyboard tabs", () => {
    const Preview = renderToStaticMarkup(<MarkdownPreview Ast={Ast} />);
    expect(Preview).toContain('sandbox="allow-scripts"');
    expect(Preview).toContain('title="Markdown preview"');
    const Surface = renderToStaticMarkup(<MarkdownSurface Mode="split" OnModeChange={() => undefined} Source={Source} Strings={EnglishMarkdownStrings} />);
    expect(Surface).toContain('role="tablist"');
    expect(Surface).toContain("aria-controls=");
    expect(Surface).toContain('role="tabpanel"');
  });
});
