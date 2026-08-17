// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { NormalizeMdast, ParseFileBeltGfmV1 } from "./parser.js";
import type { MarkdownSource } from "./types.js";

const Source: MarkdownSource = {
  HasByteOrderMark: false,
  LineEnding: "lf",
  Text: "# Title\n\n> [!NOTE]\n> Keep <b>literal</b>.\n\n```mermaid\nflowchart TD\nA-->B\n```\n\n$$\nx^2\n$$\n\n[^one]: Footnote",
};

describe("filebelt-gfm-v1 normalization", () => {
  it("keeps source ranges and converts permitted extensions to Office AST", () => {
    const Result = ParseFileBeltGfmV1(Source);
    expect(Result.Ast.Profile).toBe("filebelt-gfm-v1");
    expect(Result.Ast.Range).toEqual({ End: Source.Text.length, Start: 0 });
    expect(Result.Ast.Children.map((Block) => Block.Kind)).toEqual([
      "heading",
      "alert",
      "mermaid",
      "math",
      "footnoteDefinition",
    ]);
    expect(Result.Ast.Children[1]).toMatchObject({ Kind: "alert", Severity: "note" });
    expect(JSON.stringify(Result.Ast.Children[1])).toContain("Keep ");
    expect(JSON.stringify(Result.Ast.Children[1])).not.toContain("[!NOTE]");
    expect(Result.Diagnostics.some((Diagnostic) => Diagnostic.Code === "markdown.raw-html")).toBe(
      true,
    );
  });

  it("fails closed before recursively normalizing an excessive AST", () => {
    // eslint-disable-next-line @typescript-eslint/naming-convention -- mdast fixtures retain external node keys.
    let Root: { children?: unknown[]; type: string } = { type: "paragraph" };
    for (let Index = 0; Index < 66; Index += 1) Root = { children: [Root], type: "blockquote" };
    const Result = NormalizeMdast(Root as never, {
      HasByteOrderMark: false,
      LineEnding: "none",
      Text: "deep",
    });
    expect(Result.Ast.Children).toEqual([]);
    expect(Result.Diagnostics[0]?.Code).toBe("markdown.complexity");
  });
});
