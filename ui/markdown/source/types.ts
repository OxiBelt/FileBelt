// SPDX-License-Identifier: Apache-2.0

export const FileBeltGfmProfile = "filebelt-gfm-v1" as const;
/** The largest server-authorized text source the browser can edit. */
export const MaximumEditableBytes = 16 * 1024 * 1024;
/** The largest server-authorized text source the browser can render as source. */
export const MaximumViewableBytes = 100 * 1024 * 1024;

export type MarkdownMode = "source" | "split" | "preview";
export type LineEnding = "crlf" | "lf" | "none";

export interface SourceRange {
  End: number;
  Start: number;
}

export interface MarkdownSource {
  HasByteOrderMark: boolean;
  LineEnding: LineEnding;
  Text: string;
}

/**
 * Language-neutral source representation. `MarkdownSource` remains exported
 * for downstream Phase 5 callers while all text source consumers converge on
 * this shape.
 */
export type TextSource = MarkdownSource;

export interface MarkdownDocument {
  Ast: FileBeltOfficeAstV1;
  Source: MarkdownSource;
}

export interface FileBeltOfficeAstV1 {
  Children: readonly OfficeBlock[];
  Profile: typeof FileBeltGfmProfile;
  Range: SourceRange;
}

export type OfficeBlock = AlertBlock | CodeBlock | FootnoteDefinitionBlock | HeadingBlock | ListBlock | MathBlock | MermaidBlock | ParagraphBlock | QuoteBlock | TableBlock | ThematicBreakBlock;

export interface AlertBlock {
  Children: readonly OfficeBlock[];
  Kind: "alert";
  Range: SourceRange;
  Severity: "caution" | "important" | "note" | "tip" | "warning";
}

export interface CodeBlock {
  Code: string;
  Kind: "code";
  Language: string | null;
  Range: SourceRange;
}

export interface FootnoteDefinitionBlock {
  Children: readonly OfficeBlock[];
  Identifier: string;
  Kind: "footnoteDefinition";
  Range: SourceRange;
}

export interface HeadingBlock {
  Children: readonly OfficeInline[];
  Depth: 1 | 2 | 3 | 4 | 5 | 6;
  Kind: "heading";
  Range: SourceRange;
}

export interface ListBlock {
  Items: readonly ListItem[];
  Kind: "list";
  Ordered: boolean;
  Range: SourceRange;
}

export interface ListItem {
  Checked: boolean | null;
  Children: readonly OfficeBlock[];
  Range: SourceRange;
}

export interface MathBlock {
  Expression: string;
  Kind: "math";
  Range: SourceRange;
}

export interface MermaidBlock {
  Kind: "mermaid";
  Range: SourceRange;
  Source: string;
}

export interface ParagraphBlock {
  Children: readonly OfficeInline[];
  Kind: "paragraph";
  Range: SourceRange;
}

export interface QuoteBlock {
  Children: readonly OfficeBlock[];
  Kind: "quote";
  Range: SourceRange;
}

export interface TableBlock {
  Align: readonly ("center" | "left" | "right" | null)[];
  Kind: "table";
  Range: SourceRange;
  Rows: readonly TableRow[];
}

export interface TableRow {
  Cells: readonly (readonly OfficeInline[])[];
  Range: SourceRange;
}

export interface ThematicBreakBlock {
  Kind: "thematicBreak";
  Range: SourceRange;
}

export type OfficeInline = CodeInline | EmphasisInline | FileBeltLinkInline | FootnoteReferenceInline | LinkInline | StrongInline | TextInline;

export interface CodeInline {
  Kind: "code";
  Range: SourceRange;
  Text: string;
}

export interface EmphasisInline {
  Children: readonly OfficeInline[];
  Kind: "emphasis";
  Range: SourceRange;
}

export interface FileBeltLinkInline {
  Kind: "filebeltLink";
  Range: SourceRange;
  Target: FileBeltReference;
  Title: string | null;
}

export interface FootnoteReferenceInline {
  Identifier: string;
  Kind: "footnoteReference";
  Range: SourceRange;
}

export interface LinkInline {
  Children: readonly OfficeInline[];
  Destination: string;
  Kind: "link";
  Range: SourceRange;
  Title: string | null;
}

export interface StrongInline {
  Children: readonly OfficeInline[];
  Kind: "strong";
  Range: SourceRange;
}

export interface TextInline {
  Kind: "text";
  Range: SourceRange;
  Text: string;
}

export interface FileBeltReference {
  DriveId: string;
  NodeId: string;
  VersionId?: string;
}

export interface MarkdownDiagnostic {
  Code: "markdown.complexity" | "markdown.filebelt-link" | "markdown.raw-html" | "markdown.unsupported";
  Message: string;
  Range: SourceRange;
  Severity: "error" | "warning";
}

export interface ParseResult {
  Ast: FileBeltOfficeAstV1;
  Diagnostics: readonly MarkdownDiagnostic[];
}

export interface CollaborationIdentity {
  Color: string;
  DisplayName: string;
  SessionId: string;
}

export interface MarkdownStrings {
  Edit: string;
  Preview: string;
  Split: string;
  SourceEditor: string;
  UnsupportedFeature: string;
}

export interface TextStrings {
  Edit: string;
  SourceEditor: string;
  View: string;
}
