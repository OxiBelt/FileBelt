// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  CreateMermaidRenderBudget,
  ImportOfficeMarkdown,
  OfficeImportType,
  RenderKaTeX,
  RenderMermaid,
} from "./lazy.js";
import type { OfficeImportModule } from "./lazy.js";

// officeparser reports these documented lower-camel result keys.
type OfficeParserMessage = Record<"code", string> &
  Record<"message", string> &
  Record<"type", string>;

function Load<Value>(Value: Value): () => Promise<Value> {
  // oxlint-disable-next-line typescript/promise-function-async -- Test module loaders must retain the production promise contract.
  return () => Promise.resolve(Value);
}

function CaptureOfficeImport(
  Capture: (Options: unknown) => void,
): () => Promise<OfficeImportModule> {
  return Load({
    // oxlint-disable-next-line typescript/promise-function-async -- This test double must observe conversion options while retaining the production promise contract.
    convert: (IgnoredContents, IgnoredDestination, Options) => {
      void IgnoredContents;
      void IgnoredDestination;
      Capture(Options);
      return Promise.resolve({ messages: [], value: "# Imported\n" });
    },
  });
}

describe("lazy rich render adapters", () => {
  it("applies strict Mermaid and KaTeX options before generated markup crosses the sanitizer boundary", async () => {
    let MermaidOptions: unknown;
    const Svg = await RenderMermaid(
      Load({
        default: {
          initialize: (Options) => {
            MermaidOptions = Options;
          },
          render: Load({ svg: "<svg />" }),
        },
      }),
      { DiagramId: "diagram-1", Source: "flowchart TD\nA-->B" },
    );
    expect(Svg).toBe("<svg />");
    expect(MermaidOptions).toEqual({
      flowchart: { htmlLabels: false },
      securityLevel: "strict",
      startOnLoad: false,
    });
    await expect(
      RenderKaTeX(
        Load({
          default: {
            renderToString: (Expression: string, Options: unknown) => {
              void Expression;
              return JSON.stringify(Options);
            },
          },
        }),
        "x",
      ),
    ).resolves.toBe('{"macros":{},"throwOnError":false,"trust":false}');
  });

  it("rejects diagrams beyond the resource ceilings", async () => {
    await expect(
      RenderMermaid(Load({ default: { initialize: () => undefined, render: Load({ svg: "" }) } }), {
        DiagramId: "oversize",
        Source: "a".repeat(64 * 1024 + 1),
      }),
    ).rejects.toThrow(RangeError);
    await expect(
      RenderMermaid(Load({ default: { initialize: () => undefined, render: Load({ svg: "" }) } }), {
        DiagramId: "edges",
        Source: Array.from({ length: 501 }, () => "A-->B").join("\n"),
      }),
    ).rejects.toThrow(RangeError);
    await expect(
      RenderMermaid(Load({ default: { initialize: () => undefined, render: Load({ svg: "" }) } }), {
        DiagramId: "click",
        Source: "click A href",
      }),
    ).rejects.toThrow(RangeError);
    const Budget = CreateMermaidRenderBudget(1);
    await RenderMermaid(
      Load({ default: { initialize: () => undefined, render: Load({ svg: "" }) } }),
      { DiagramId: "first", Source: "A-->B" },
      Budget,
    );
    await expect(
      RenderMermaid(
        Load({ default: { initialize: () => undefined, render: Load({ svg: "" }) } }),
        { DiagramId: "second", Source: "A-->B" },
        Budget,
      ),
    ).rejects.toThrow(RangeError);
  });

  it("converts only admitted Office formats with OCR, attachments, and remote assets disabled", async () => {
    let ConversionOptions: unknown;
    const Markdown = await ImportOfficeMarkdown(
      { Contents: new Uint8Array([1, 2, 3]), SourceType: "docx" },
      CaptureOfficeImport((Options) => {
        ConversionOptions = Options;
      }),
    );
    expect(Markdown).toBe("# Imported\n");
    expect(ConversionOptions).toMatchObject({
      generatorConfig: { ignoreInternalLinks: true, includeCharts: false, includeImages: false },
      parseConfig: {
        extractAttachments: false,
        fileType: "docx",
        ignoreInternalLinks: true,
        includeRawContent: false,
        ocr: false,
      },
    });
    expect(OfficeImportType("REPORT.DOCX")).toBe("docx");
    expect(OfficeImportType("scan.pdf")).toBeNull();
  });

  it("rejects unsafe, lossy, or oversized Office conversion results", async () => {
    const CreateOfficeLoad = (Value: string, Messages: readonly OfficeParserMessage[] = []) =>
      Load({ convert: Load({ messages: Messages, value: Value }) });
    await expect(
      ImportOfficeMarkdown(
        { Contents: new Uint8Array(9), MaximumInputBytes: 8, SourceType: "xlsx" },
        CreateOfficeLoad("ok"),
      ),
    ).rejects.toThrow(RangeError);
    await expect(
      ImportOfficeMarkdown(
        { Contents: new Uint8Array(), MaximumOutputBytes: 4, SourceType: "xlsx" },
        CreateOfficeLoad("12345"),
      ),
    ).rejects.toThrow(RangeError);
    await expect(
      ImportOfficeMarkdown(
        { Contents: new Uint8Array(), SourceType: "xlsx" },
        CreateOfficeLoad("bad\0value"),
      ),
    ).rejects.toThrow("NUL");
    await expect(
      ImportOfficeMarkdown(
        { Contents: new Uint8Array(), SourceType: "xlsx" },
        CreateOfficeLoad("partial", [
          { code: "TABLE_CELL_LIMIT_EXCEEDED", message: "truncated", type: "warning" },
        ]),
      ),
    ).rejects.toThrow("truncated");
  });
});
