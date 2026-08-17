// SPDX-License-Identifier: Apache-2.0

import { Fragment, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import {
  CreateMermaidRenderBudget,
  RenderKaTeX,
  RenderMermaid,
  type MermaidRenderBudget,
} from "./lazy.js";
import { CreateGeneratedMarkupSanitizer, type SanitizedGeneratedMarkup } from "./sanitize.js";
import type { FileBeltOfficeAstV1, OfficeBlock, OfficeInline } from "./types.js";

export interface MarkdownPreviewProps {
  Ast: FileBeltOfficeAstV1;
  OnFileBeltLink?: (
    Target: Readonly<Extract<OfficeInline, { Kind: "filebeltLink" }>["Target"]>,
  ) => void;
}

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- React owns and may clone component props.
export function MarkdownPreview({ Ast, OnFileBeltLink }: MarkdownPreviewProps): ReactNode {
  const Frame = useRef<HTMLIFrameElement>(null);
  const AstValue = useRef(Ast);
  const LinkHandler = useRef(OnFileBeltLink);
  const Port = useRef<MessagePort | undefined>(undefined);
  useEffect(() => {
    AstValue.current = Ast;
    Port.current?.postMessage({ Ast, Type: "filebelt-markdown-preview-v1" });
  }, [Ast]);
  useEffect(() => {
    LinkHandler.current = OnFileBeltLink;
  }, [OnFileBeltLink]);
  useEffect(() => {
    const Current = Frame.current;
    if (Current === null) return undefined;
    const Connect = (): void => {
      Port.current?.close();
      const Channel = new MessageChannel();
      Port.current = Channel.port1;
      // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- DOM dispatch owns the mutable event object.
      Channel.port1.addEventListener("message", (Event: Readonly<MessageEvent<unknown>>) => {
        if (IsLinkMessage(Event.data)) LinkHandler.current?.(Event.data.Target);
      });
      Channel.port1.start();
      Current.contentWindow?.postMessage({ Type: "filebelt-markdown-connect-v1" }, "*", [
        Channel.port2,
      ]);
      Channel.port1.postMessage({ Ast: AstValue.current, Type: "filebelt-markdown-preview-v1" });
    };
    Current.addEventListener("load", Connect);
    return () => {
      Current.removeEventListener("load", Connect);
      Port.current?.close();
      Port.current = undefined;
    };
  }, []);
  return (
    <iframe
      className="filebelt-markdown-preview"
      ref={Frame}
      sandbox="allow-scripts"
      src="/markdown-preview/index.html"
      title="Markdown preview"
    />
  );
}

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- React owns and may clone component props.
export function MarkdownPreviewDocument({ Ast, OnFileBeltLink }: MarkdownPreviewProps): ReactNode {
  const Budget = useMemo(() => CreateMermaidRenderBudget(), [Ast]);
  return (
    <article data-filebelt-markdown-profile={Ast.Profile}>
      {Ast.Children.map((Block, Index) => (
        <Fragment key={`${Block.Range.Start}-${Index}`}>
          {RenderBlock(Block, OnFileBeltLink, Budget)}
        </Fragment>
      ))}
    </article>
  );
}

interface LinkMessage {
  Target: Extract<OfficeInline, { Kind: "filebeltLink" }>["Target"];
  Type: "filebelt-markdown-link-v1";
}

function IsLinkMessage(Value: unknown): Value is LinkMessage {
  if (typeof Value !== "object" || Value === null) return false;
  const Candidate = Value as { Target?: unknown; Type?: unknown };
  if (
    Candidate.Type !== "filebelt-markdown-link-v1" ||
    typeof Candidate.Target !== "object" ||
    Candidate.Target === null
  )
    return false;
  const Target = Candidate.Target as { DriveId?: unknown; NodeId?: unknown; VersionId?: unknown };
  return (
    IsUuid(Target.DriveId) &&
    IsUuid(Target.NodeId) &&
    (Target.VersionId === undefined || IsUuid(Target.VersionId))
  );
}

function IsUuid(Value: unknown): Value is string {
  return (
    typeof Value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(Value)
  );
}

function RenderBlock(
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- The public AST contains mutable nested fields for schema compatibility.
  Block: OfficeBlock,
  OnFileBeltLink: MarkdownPreviewProps["OnFileBeltLink"],
  Budget: MermaidRenderBudget,
): ReactNode {
  switch (Block.Kind) {
    case "heading":
      return (
        <Heading Children={RenderInlines(Block.Children, OnFileBeltLink)} Depth={Block.Depth} />
      );
    case "paragraph":
      return <p>{RenderInlines(Block.Children, OnFileBeltLink)}</p>;
    case "code":
      return (
        <pre>
          <code data-language={Block.Language ?? undefined}>{Block.Code}</code>
        </pre>
      );
    case "math":
      return <GeneratedMarkup Kind="math" Source={Block.Expression} />;
    case "mermaid":
      return <GeneratedMarkup Budget={Budget} Kind="mermaid" Source={Block.Source} />;
    case "thematicBreak":
      return <hr />;
    case "quote":
      return (
        <blockquote>
          {Block.Children.map((Child, Index) => (
            <Fragment key={`${Child.Range.Start}-${Index}`}>
              {RenderBlock(Child, OnFileBeltLink, Budget)}
            </Fragment>
          ))}
        </blockquote>
      );
    case "alert":
      return (
        <aside aria-label={Block.Severity} data-filebelt-alert={Block.Severity}>
          {Block.Children.map((Child, Index) => (
            <Fragment key={`${Child.Range.Start}-${Index}`}>
              {RenderBlock(Child, OnFileBeltLink, Budget)}
            </Fragment>
          ))}
        </aside>
      );
    case "list": {
      const List = Block.Ordered ? "ol" : "ul";
      return (
        <List>
          {Block.Items.map((Item, Index) => (
            <li key={`${Item.Range.Start}-${Index}`} data-checked={Item.Checked ?? undefined}>
              {Item.Children.map((Child, ChildIndex) => (
                <Fragment key={`${Child.Range.Start}-${ChildIndex}`}>
                  {RenderBlock(Child, OnFileBeltLink, Budget)}
                </Fragment>
              ))}
            </li>
          ))}
        </List>
      );
    }
    case "table": {
      const [HeadingRow, ...BodyRows] = Block.Rows;
      return (
        <table>
          {HeadingRow === undefined ? null : (
            <thead>
              <tr>
                {HeadingRow.Cells.map((Cell, CellIndex) => (
                  <th key={CellIndex} scope="col">
                    {RenderInlines(Cell, OnFileBeltLink)}
                  </th>
                ))}
              </tr>
            </thead>
          )}
          <tbody>
            {BodyRows.map((Row, RowIndex) => (
              <tr key={`${Row.Range.Start}-${RowIndex}`}>
                {Row.Cells.map((Cell, CellIndex) => (
                  <td key={CellIndex}>{RenderInlines(Cell, OnFileBeltLink)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      );
    }
    case "footnoteDefinition":
      return (
        <section data-filebelt-footnote={Block.Identifier}>
          {Block.Children.map((Child, Index) => (
            <Fragment key={`${Child.Range.Start}-${Index}`}>
              {RenderBlock(Child, OnFileBeltLink, Budget)}
            </Fragment>
          ))}
        </section>
      );
  }
  return null;
}

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- React owns and may clone component props.
function GeneratedMarkup({
  Budget,
  Kind,
  Source,
}: {
  Budget?: MermaidRenderBudget;
  Kind: "math" | "mermaid";
  Source: string;
}): ReactNode {
  const Element = useRef<HTMLDivElement>(null);
  const GeneratedId = useId().replaceAll(":", "-");
  const [ErrorMessage, SetError] = useState<string | null>(null);
  useEffect(() => {
    let Active = true;
    void (async () => {
      const Purify = (await import("dompurify")).default;
      const Sanitizer = CreateGeneratedMarkupSanitizer(Purify);
      const Markup =
        Kind === "mermaid"
          ? Sanitizer.SanitizeSvg(
              await RenderMermaid(
                async () => import("mermaid"),
                { DiagramId: `filebelt-${GeneratedId}`, Source },
                Budget,
              ),
            )
          : Sanitizer.SanitizeHtml(await RenderKaTeX(async () => import("katex"), Source));
      // oxlint-disable-next-line typescript/no-unnecessary-condition -- The cleanup changes this effect's captured lifecycle flag.
      if (Active && Element.current !== null) SetTrustedMarkup(Element.current, Markup);
    })().catch((Cause: unknown) => {
      if (Active)
        SetError(
          Cause instanceof Error ? Cause.message : "Generated Markdown content is unavailable.",
        );
    });
    return () => {
      Active = false;
    };
  }, [Budget, GeneratedId, Kind, Source]);
  if (ErrorMessage !== null) return <pre data-filebelt-generated-error={Kind}>{ErrorMessage}</pre>;
  return (
    <div
      aria-label={Kind === "math" ? "Mathematical expression" : "Mermaid diagram"}
      data-filebelt-generated={Kind}
      ref={Element}
      role="img"
    />
  );
}

interface TrustedTypesFactoryLike {
  createPolicy(
    Name: string,
    Rules: { createHTML(Value: string): string },
  ): { createHTML(Value: string): unknown };
}

let GeneratedMarkupPolicy: { createHTML(Value: string): unknown } | undefined;

function SetTrustedMarkup(
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- This is the reviewed DOM mutation sink for sanitized markup.
  Element: HTMLDivElement,
  Markup: SanitizedGeneratedMarkup,
): void {
  const Factory = (
    globalThis as typeof globalThis & Partial<Record<"trustedTypes", TrustedTypesFactoryLike>>
  ).trustedTypes;
  GeneratedMarkupPolicy ??= Factory?.createPolicy("filebelt-markdown-generated", {
    createHTML: (Value) => Value,
  });
  const TrustedMarkup: unknown = GeneratedMarkupPolicy?.createHTML(Markup) ?? Markup;
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- The sole markup sink receives only sanitizer output or its Trusted Types wrapper.
  Element.innerHTML = TrustedMarkup as string;
}

function RenderInlines(
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- The public AST contains mutable nested fields for schema compatibility.
  Nodes: readonly OfficeInline[],
  OnFileBeltLink: MarkdownPreviewProps["OnFileBeltLink"],
): ReactNode {
  // oxlint-disable-next-line typescript/promise-function-async -- React node mapping deliberately remains a synchronous render operation.
  return Nodes.map((Node, Index) => {
    const Key = `${Node.Range.Start}-${Index}`;
    switch (Node.Kind) {
      case "text":
        return <Fragment key={Key}>{Node.Text}</Fragment>;
      case "code":
        return <code key={Key}>{Node.Text}</code>;
      case "emphasis":
        return <em key={Key}>{RenderInlines(Node.Children, OnFileBeltLink)}</em>;
      case "strong":
        return <strong key={Key}>{RenderInlines(Node.Children, OnFileBeltLink)}</strong>;
      case "footnoteReference":
        return <sup key={Key}>[{Node.Identifier}]</sup>;
      case "filebeltLink": {
        const OpenFileBeltLink = (): void => {
          OnFileBeltLink?.(Node.Target);
        };
        return (
          <button key={Key} onClick={OpenFileBeltLink} type="button">
            Open FileBelt item
          </button>
        );
      }
      case "link":
        return SafeLink(Node.Destination, Key, RenderInlines(Node.Children, OnFileBeltLink));
    }
    return null;
  });
}

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- React owns and may clone component props.
function Heading({
  Children,
  Depth,
}: {
  Children: ReactNode;
  Depth: 1 | 2 | 3 | 4 | 5 | 6;
}): ReactNode {
  if (Depth === 1) return <h1>{Children}</h1>;
  if (Depth === 2) return <h2>{Children}</h2>;
  if (Depth === 3) return <h3>{Children}</h3>;
  if (Depth === 4) return <h4>{Children}</h4>;
  if (Depth === 5) return <h5>{Children}</h5>;
  return <h6>{Children}</h6>;
}

function SafeLink(
  Destination: string,
  Key: string,
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- ReactNode is framework-owned and may contain mutable elements.
  Children: Readonly<ReactNode>,
): ReactNode {
  try {
    const Url = new URL(Destination, "https://filebelt.invalid");
    if (Url.protocol === "https:" || Url.protocol === "mailto:")
      return (
        <a href={Destination} key={Key} rel="noreferrer noopener" target="_blank">
          {Children}
        </a>
      );
  } catch {
    // Invalid destinations deliberately render as text.
  }
  return <span key={Key}>{Children}</span>;
}
