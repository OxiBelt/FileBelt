// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { CreateMermaidRenderBudget, ImportOfficeMarkdown, OfficeImportType, RenderKaTeX, RenderMermaid } from "./lazy.js";

// officeparser reports these documented lower-camel result keys.
type OfficeParserMessage = Record<"code", string> & Record<"message", string> & Record<"type", string>;

describe("lazy rich render adapters", () => {
  it("applies strict Mermaid and KaTeX options before generated markup crosses the sanitizer boundary", async () => {
    let MermaidOptions: unknown;
    const Svg = await RenderMermaid(async () => ({ default: { initialize: (Options) => { MermaidOptions = Options; }, render: async () => ({ svg: "<svg />" }) } }), { DiagramId: "diagram-1", Source: "flowchart TD\nA-->B" });
    expect(Svg).toBe("<svg />");
    expect(MermaidOptions).toEqual({ flowchart: { htmlLabels: false }, securityLevel: "strict", startOnLoad: false });
    await expect(RenderKaTeX(async () => ({ default: { renderToString: (Expression: string, Options: unknown) => { void Expression; return JSON.stringify(Options); } } }), "x")).resolves.toBe('{"macros":{},"throwOnError":false,"trust":false}');
  });

  it("rejects diagrams beyond the resource ceilings", async () => {
    await expect(RenderMermaid(async () => ({ default: { initialize: () => undefined, render: async () => ({ svg: "" }) } }), { DiagramId: "oversize", Source: "a".repeat(64 * 1024 + 1) })).rejects.toThrow(RangeError);
    await expect(RenderMermaid(async () => ({ default: { initialize: () => undefined, render: async () => ({ svg: "" }) } }), { DiagramId: "edges", Source: Array.from({ length: 501 }, () => "A-->B").join("\n") })).rejects.toThrow(RangeError);
    await expect(RenderMermaid(async () => ({ default: { initialize: () => undefined, render: async () => ({ svg: "" }) } }), { DiagramId: "click", Source: "click A href" })).rejects.toThrow(RangeError);
    const Budget = CreateMermaidRenderBudget(1);
    await RenderMermaid(async () => ({ default: { initialize: () => undefined, render: async () => ({ svg: "" }) } }), { DiagramId: "first", Source: "A-->B" }, Budget);
    await expect(RenderMermaid(async () => ({ default: { initialize: () => undefined, render: async () => ({ svg: "" }) } }), { DiagramId: "second", Source: "A-->B" }, Budget)).rejects.toThrow(RangeError);
  });

  it("converts only admitted Office formats with OCR, attachments, and remote assets disabled", async () => {
    let ConversionOptions: unknown;
    const Markdown = await ImportOfficeMarkdown({ Contents: new Uint8Array([1, 2, 3]), SourceType: "docx" }, async () => ({
      convert: async (IgnoredContents, IgnoredDestination, Options) => {
        void IgnoredContents;
        void IgnoredDestination;
        ConversionOptions = Options;
        return { messages: [], value: "# Imported\n" };
      },
    }));
    expect(Markdown).toBe("# Imported\n");
    expect(ConversionOptions).toMatchObject({
      generatorConfig: { ignoreInternalLinks: true, includeCharts: false, includeImages: false },
      parseConfig: { extractAttachments: false, fileType: "docx", ignoreInternalLinks: true, includeRawContent: false, ocr: false },
    });
    expect(OfficeImportType("REPORT.DOCX")).toBe("docx");
    expect(OfficeImportType("scan.pdf")).toBeNull();
  });

  it("rejects unsafe, lossy, or oversized Office conversion results", async () => {
    const Load = (Value: string, Messages: readonly OfficeParserMessage[] = []) => async () => ({ convert: async () => ({ messages: Messages, value: Value }) });
    await expect(ImportOfficeMarkdown({ Contents: new Uint8Array(9), MaximumInputBytes: 8, SourceType: "xlsx" }, Load("ok"))).rejects.toThrow(RangeError);
    await expect(ImportOfficeMarkdown({ Contents: new Uint8Array(), MaximumOutputBytes: 4, SourceType: "xlsx" }, Load("12345"))).rejects.toThrow(RangeError);
    await expect(ImportOfficeMarkdown({ Contents: new Uint8Array(), SourceType: "xlsx" }, Load("bad\0value"))).rejects.toThrow("NUL");
    await expect(ImportOfficeMarkdown({ Contents: new Uint8Array(), SourceType: "xlsx" }, Load("partial", [{ code: "TABLE_CELL_LIMIT_EXCEEDED", message: "truncated", type: "warning" }]))).rejects.toThrow("truncated");
  });
});
