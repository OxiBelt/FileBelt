// SPDX-License-Identifier: Apache-2.0

import { MaximumEditableBytes, MaximumViewableBytes } from "./types.js";
import type { LineEnding, MarkdownSource } from "./types.js";

const Encoder = new TextEncoder();
const FatalDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export class MarkdownInputError extends Error {
  constructor(public readonly Code: "bom" | "line-ending" | "nul" | "size" | "utf8") {
    super(Code);
    this.name = "MarkdownInputError";
  }
}

export function DecodeMarkdown(Bytes: Uint8Array, MaximumBytes: number): MarkdownSource {
  if (Bytes.byteLength > MaximumBytes) throw new MarkdownInputError("size");
  let Text: string;
  try {
    Text = FatalDecoder.decode(Bytes);
  } catch {
    throw new MarkdownInputError("utf8");
  }
  if (Text.includes("\0")) throw new MarkdownInputError("nul");
  const HasByteOrderMark = Bytes.length >= 3 && Bytes[0] === 0xef && Bytes[1] === 0xbb && Bytes[2] === 0xbf;
  const Content = HasByteOrderMark && Text.startsWith("\ufeff") ? Text.slice(1) : Text;
  const LineEnding = DetectLineEnding(Content);
  return { HasByteOrderMark, LineEnding, Text: LineEnding === "crlf" ? Content.replaceAll("\r\n", "\n") : Content };
}

export function EncodeMarkdown(Source: MarkdownSource, MaximumBytes: number): Uint8Array {
  if (Source.Text.includes("\0")) throw new MarkdownInputError("nul");
  if (Source.Text.includes("\r")) throw new MarkdownInputError("line-ending");
  const Content = Source.LineEnding === "crlf" ? Source.Text.replaceAll("\n", "\r\n") : Source.Text;
  const Bytes = Encoder.encode(`${Source.HasByteOrderMark ? "\ufeff" : ""}${Content}`);
  if (Bytes.byteLength > MaximumBytes) throw new MarkdownInputError("size");
  return Bytes;
}

export function DecodeEditableMarkdown(Bytes: Uint8Array): MarkdownSource {
  return DecodeEditableText(Bytes);
}

export function DecodeViewableMarkdown(Bytes: Uint8Array): MarkdownSource {
  return DecodeViewableText(Bytes);
}

/** Decode a server-validated text source for an editable CodeMirror surface. */
export function DecodeEditableText(Bytes: Uint8Array): MarkdownSource {
  return DecodeMarkdown(Bytes, MaximumEditableBytes);
}

/** Decode a server-validated text source for a source-only viewer. */
export function DecodeViewableText(Bytes: Uint8Array): MarkdownSource {
  return DecodeMarkdown(Bytes, MaximumViewableBytes);
}

/** Encode a language-neutral source while preserving its reviewed byte format. */
export function EncodeText(Source: MarkdownSource, MaximumBytes: number): Uint8Array {
  return EncodeMarkdown(Source, MaximumBytes);
}

export function DetectLineEnding(Text: string): LineEnding {
  const HasCrLf = Text.includes("\r\n");
  const WithoutCrLf = Text.replaceAll("\r\n", "");
  if (WithoutCrLf.includes("\r")) throw new MarkdownInputError("line-ending");
  if (HasCrLf && WithoutCrLf.includes("\n")) throw new MarkdownInputError("line-ending");
  if (HasCrLf) return "crlf";
  return Text.includes("\n") ? "lf" : "none";
}
