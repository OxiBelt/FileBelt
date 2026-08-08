// SPDX-License-Identifier: Apache-2.0

/* eslint-disable @typescript-eslint/naming-convention -- mdast is an external AST contract with exact lowercase field names. */

import { fromMarkdown } from "mdast-util-from-markdown";
import { gfmFromMarkdown } from "mdast-util-gfm";
import { mathFromMarkdown } from "mdast-util-math";
import { gfm } from "micromark-extension-gfm";
import { math } from "micromark-extension-math";
import { ParseFileBeltReference } from "./links.js";
import { CreateLineStarts, RangeFromPosition } from "./ranges.js";
import type { MarkdownPosition } from "./ranges.js";
import type {
  FileBeltOfficeAstV1,
  MarkdownDiagnostic,
  MarkdownSource,
  OfficeBlock,
  OfficeInline,
  ParseResult,
  SourceRange,
} from "./types.js";
import { FileBeltGfmProfile } from "./types.js";

interface MdastNode {
  align?: readonly ("center" | "left" | "right" | null)[];
  checked?: boolean | null;
  children?: readonly MdastNode[];
  depth?: number;
  identifier?: string;
  lang?: string | null;
  position?: MarkdownPosition;
  start?: number;
  title?: string | null;
  type: string;
  url?: string;
  value?: string;
}

interface NormalizationContext {
  Diagnostics: MarkdownDiagnostic[];
  LineStarts: readonly number[];
}

export function ParseFileBeltGfmV1(Source: MarkdownSource): ParseResult {
  const Root = fromMarkdown(Source.Text, {
    extensions: [gfm(), math()],
    mdastExtensions: [gfmFromMarkdown(), mathFromMarkdown()],
  } as never) as unknown as MdastNode;
  return NormalizeMdast(Root, Source);
}

export function NormalizeMdast(Root: MdastNode, Source: MarkdownSource): ParseResult {
  const Context: NormalizationContext = {
    Diagnostics: [],
    LineStarts: CreateLineStarts(Source.Text),
  };
  if (!MdastWithinBudget(Root)) {
    return {
      Ast: { Children: [], Profile: FileBeltGfmProfile, Range: { End: Source.Text.length, Start: 0 } },
      Diagnostics: [{ Code: "markdown.complexity", Message: "Markdown structure exceeds the preview complexity limit.", Range: { End: Source.Text.length, Start: 0 }, Severity: "error" }],
    };
  }
  const Ast: FileBeltOfficeAstV1 = {
    Children: (Root.children ?? []).flatMap((Node) => NormalizeBlock(Node, Context)),
    Profile: FileBeltGfmProfile,
    Range: { End: Source.Text.length, Start: 0 },
  };
  return { Ast, Diagnostics: Context.Diagnostics };
}

function MdastWithinBudget(Root: MdastNode): boolean {
  const Pending: Array<{ Depth: number; Node: MdastNode }> = [{ Depth: 0, Node: Root }];
  let Nodes = 0;
  while (Pending.length > 0) {
    const Current = Pending.pop();
    if (Current === undefined || Current.Depth > 64) return false;
    Nodes += 1;
    if (Nodes > 100_000) return false;
    for (const Child of Current.Node.children ?? []) Pending.push({ Depth: Current.Depth + 1, Node: Child });
  }
  return true;
}

function NormalizeBlock(Node: MdastNode, Context: NormalizationContext): readonly OfficeBlock[] {
  const Range = NodeRange(Node, Context);
  switch (Node.type) {
    case "heading":
      return [{ Children: NormalizeInlines(Node.children ?? [], Context), Depth: ClampHeadingDepth(Node.depth), Kind: "heading", Range }];
    case "paragraph":
      return [{ Children: NormalizeInlines(Node.children ?? [], Context), Kind: "paragraph", Range }];
    case "code":
      return NormalizeCode(Node, Range);
    case "math":
      return [{ Expression: Node.value ?? "", Kind: "math", Range }];
    case "thematicBreak":
      return [{ Kind: "thematicBreak", Range }];
    case "blockquote":
      return [NormalizeQuote(Node, Context, Range)];
    case "list":
      return [{
        Items: (Node.children ?? []).map((Item) => ({
          Checked: Item.checked ?? null,
          Children: (Item.children ?? []).flatMap((Child) => NormalizeBlock(Child, Context)),
          Range: NodeRange(Item, Context),
        })),
        Kind: "list",
        Ordered: Node.start !== undefined,
        Range,
      }];
    case "table":
      return [{
        Align: Node.align ?? [],
        Kind: "table",
        Range,
        Rows: (Node.children ?? []).map((Row) => ({
          Cells: (Row.children ?? []).map((Cell) => NormalizeInlines(Cell.children ?? [], Context)),
          Range: NodeRange(Row, Context),
        })),
      }];
    case "footnoteDefinition":
      return [{
        Children: (Node.children ?? []).flatMap((Child) => NormalizeBlock(Child, Context)),
        Identifier: Node.identifier ?? "",
        Kind: "footnoteDefinition",
        Range,
      }];
    case "html":
      Context.Diagnostics.push({ Code: "markdown.raw-html", Message: "Raw HTML is rendered as literal text.", Range, Severity: "warning" });
      return [{ Children: [{ Kind: "text", Range, Text: Node.value ?? "" }], Kind: "paragraph", Range }];
    default:
      Context.Diagnostics.push({ Code: "markdown.unsupported", Message: `Unsupported Markdown node: ${Node.type}.`, Range, Severity: "warning" });
      return [];
  }
}

function NormalizeQuote(Node: MdastNode, Context: NormalizationContext, Range: SourceRange): OfficeBlock {
  const First = Node.children?.[0];
  const FirstText = First?.children?.[0];
  const Alert = First?.type === "paragraph" && FirstText?.type === "text"
    ? /^\[!(CAUTION|IMPORTANT|NOTE|TIP|WARNING)\]\s*/.exec(FirstText.value ?? "")
    : null;
  if (Alert === null) return { Children: (Node.children ?? []).flatMap((Child) => NormalizeBlock(Child, Context)), Kind: "quote", Range };
  const Severity = (Alert[1] ?? "note").toLowerCase() as "caution" | "important" | "note" | "tip" | "warning";
  const AlertChildren = (Node.children ?? []).map((Child, Index) => {
    if (Index !== 0 || Child !== First) return Child;
    return {
      ...Child,
      children: (Child.children ?? []).map((Inline, InlineIndex) => InlineIndex === 0 && Inline === FirstText
        ? { ...Inline, value: (Inline.value ?? "").slice(Alert[0].length) }
        : Inline),
    };
  });
  return { Children: AlertChildren.flatMap((Child) => NormalizeBlock(Child, Context)), Kind: "alert", Range, Severity };
}

function NormalizeCode(Node: MdastNode, Range: SourceRange): readonly OfficeBlock[] {
  if (Node.lang === "mermaid") return [{ Kind: "mermaid", Range, Source: Node.value ?? "" }];
  if (Node.lang === "math") return [{ Expression: Node.value ?? "", Kind: "math", Range }];
  return [{ Code: Node.value ?? "", Kind: "code", Language: Node.lang ?? null, Range }];
}

function NormalizeInlines(Nodes: readonly MdastNode[], Context: NormalizationContext): readonly OfficeInline[] {
  return Nodes.flatMap((Node) => {
    const Range = NodeRange(Node, Context);
    switch (Node.type) {
      case "text": return [{ Kind: "text", Range, Text: Node.value ?? "" }];
      case "inlineCode": return [{ Kind: "code", Range, Text: Node.value ?? "" }];
      case "emphasis": return [{ Children: NormalizeInlines(Node.children ?? [], Context), Kind: "emphasis", Range }];
      case "strong": return [{ Children: NormalizeInlines(Node.children ?? [], Context), Kind: "strong", Range }];
      case "link": return NormalizeLink(Node, Context, Range);
      case "footnoteReference": return [{ Identifier: Node.identifier ?? "", Kind: "footnoteReference", Range }];
      case "break": return [{ Kind: "text", Range, Text: "\n" }];
      case "html":
        Context.Diagnostics.push({ Code: "markdown.raw-html", Message: "Raw HTML is rendered as literal text.", Range, Severity: "warning" });
        return [{ Kind: "text", Range, Text: Node.value ?? "" }];
      default:
        Context.Diagnostics.push({ Code: "markdown.unsupported", Message: `Unsupported Markdown inline: ${Node.type}.`, Range, Severity: "warning" });
        return [];
    }
  });
}

function NormalizeLink(Node: MdastNode, Context: NormalizationContext, Range: SourceRange): readonly OfficeInline[] {
  const Target = ParseFileBeltReference(Node.url ?? "");
  if (Target !== undefined) return [{ Kind: "filebeltLink", Range, Target, Title: Node.title ?? null }];
  if ((Node.url ?? "").startsWith("filebelt:")) {
    Context.Diagnostics.push({ Code: "markdown.filebelt-link", Message: "The FileBelt link is not valid.", Range, Severity: "error" });
  }
  return [{ Children: NormalizeInlines(Node.children ?? [], Context), Destination: Node.url ?? "", Kind: "link", Range, Title: Node.title ?? null }];
}

function NodeRange(Node: MdastNode, Context: NormalizationContext): SourceRange {
  return RangeFromPosition(Node.position, Context.LineStarts);
}

function ClampHeadingDepth(Depth: number | undefined): 1 | 2 | 3 | 4 | 5 | 6 {
  if (Depth === 2 || Depth === 3 || Depth === 4 || Depth === 5 || Depth === 6) return Depth;
  return 1;
}
