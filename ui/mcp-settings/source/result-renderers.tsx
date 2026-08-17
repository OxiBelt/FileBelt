// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from "react";
import type { ReactNode } from "react";

import { McpEn } from "./strings.js";

const MaximumMediaBytes = 4 * 1024 * 1024;
const MaximumJsonDepth = 16;
export const MaximumJsonRenderNodes = 2_000;
const SafeMediaTypes = new Set([
  "audio/mpeg",
  "audio/ogg",
  "audio/wav",
  "image/jpeg",
  "image/png",
  "image/webp",
]);

export interface SafeMediaValue {
  Base64: string;
  MimeType: "audio/mpeg" | "audio/ogg" | "audio/wav" | "image/jpeg" | "image/png" | "image/webp";
  SizeBytes: number;
}

function DecodeBase64(Value: string): Uint8Array | null {
  if (
    Value.length > Math.ceil(MaximumMediaBytes / 3) * 4 + 8 ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(Value)
  )
    return null;
  try {
    const Decoded = globalThis.atob(Value);
    const Bytes = new Uint8Array(Decoded.length);
    for (let Index = 0; Index < Decoded.length; Index += 1)
      Bytes[Index] = Decoded.charCodeAt(Index);
    return Bytes;
  } catch {
    return null;
  }
}

function HasPrefix(Bytes: Uint8Array, Prefix: readonly number[], Offset = 0): boolean {
  return Prefix.every((Value, Index) => Bytes[Offset + Index] === Value);
}

function MatchesMagic(Bytes: Uint8Array, MimeType: string): boolean {
  if (MimeType === "image/png")
    return HasPrefix(Bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (MimeType === "image/jpeg") return HasPrefix(Bytes, [0xff, 0xd8, 0xff]);
  if (MimeType === "image/webp")
    return (
      HasPrefix(Bytes, [0x52, 0x49, 0x46, 0x46]) && HasPrefix(Bytes, [0x57, 0x45, 0x42, 0x50], 8)
    );
  if (MimeType === "audio/ogg") return HasPrefix(Bytes, [0x4f, 0x67, 0x67, 0x53]);
  if (MimeType === "audio/wav")
    return (
      HasPrefix(Bytes, [0x52, 0x49, 0x46, 0x46]) && HasPrefix(Bytes, [0x57, 0x41, 0x56, 0x45], 8)
    );
  if (MimeType === "audio/mpeg")
    return (
      HasPrefix(Bytes, [0x49, 0x44, 0x33]) ||
      (Bytes[0] === 0xff && ((Bytes[1] ?? 0) & 0xe0) === 0xe0)
    );
  return false;
}

interface JsonRenderBudget {
  Remaining: number;
  TruncationRendered: boolean;
}

function JsonChildren(
  Depth: number,
  Entries: readonly (readonly [string, unknown])[],
  Budget: JsonRenderBudget,
): ReactNode[] {
  const Children: ReactNode[] = [];
  for (const [Name, Value] of Entries) {
    if (Budget.Remaining === 0) {
      if (!Budget.TruncationRendered) {
        Children.push(
          <li key="filebelt-json-truncated">
            <span>{McpEn.resultTruncated}</span>
          </li>,
        );
        Budget.TruncationRendered = true;
      }
      break;
    }
    Children.push(JsonNode(Depth, Name, Value, Budget));
  }
  return Children;
}

function JsonNode(
  Depth: number,
  Name: string | undefined,
  Value: unknown,
  Budget: JsonRenderBudget,
): ReactNode {
  Budget.Remaining -= 1;
  const Label =
    Name === undefined ? null : (
      <span className="fb-mcp-json-key">
        <bdi dir="auto">{Name}</bdi>:{" "}
      </span>
    );
  if (Depth >= MaximumJsonDepth)
    return (
      <li>
        {Label}
        <span>…</span>
      </li>
    );
  if (Value === null)
    return (
      <li>
        {Label}
        <span>null</span>
      </li>
    );
  if (typeof Value === "string")
    return (
      <li>
        {Label}
        <span>
          <bdi dir="auto">{JSON.stringify(Value)}</bdi>
        </span>
      </li>
    );
  if (typeof Value === "number" || typeof Value === "boolean")
    return (
      <li>
        {Label}
        <span>{String(Value)}</span>
      </li>
    );
  if (Array.isArray(Value)) {
    const Entries = Value.slice(0, 200).map((Item, Index) => [String(Index), Item] as const);
    return (
      <li>
        {Label}
        <span>[</span>
        <ol>{JsonChildren(Depth + 1, Entries, Budget)}</ol>
        <span>]</span>
      </li>
    );
  }
  if (typeof Value === "object") {
    const Entries = Object.entries(Value).slice(0, 200);
    return (
      <li>
        {Label}
        <span>{"{"}</span>
        <ul>{JsonChildren(Depth + 1, Entries, Budget)}</ul>
        <span>{"}"}</span>
      </li>
    );
  }
  return (
    <li>
      {Label}
      <span>{McpEn.resultUnsupported}</span>
    </li>
  );
}

export function SafeJsonResult({ Value }: { Value: unknown }): ReactNode {
  const Budget: JsonRenderBudget = { Remaining: MaximumJsonRenderNodes, TruncationRendered: false };
  return (
    <div aria-label={McpEn.jsonResult} className="fb-mcp-json" role="tree">
      <ul>{JsonNode(0, undefined, Value, Budget)}</ul>
    </div>
  );
}

export function SafeTextResult({ Value }: { Value: string }): ReactNode {
  return (
    <pre className="fb-mcp-text" dir="auto">
      <bdi>{Value}</bdi>
    </pre>
  );
}

export function SafeMediaResult({ Value }: { Value: SafeMediaValue }): ReactNode {
  const [ObjectUrl, SetObjectUrl] = useState<string | null>(null);
  const [Rejected, SetRejected] = useState(false);

  useEffect(() => {
    const Bytes = DecodeBase64(Value.Base64);
    if (
      Bytes === null ||
      Bytes.byteLength !== Value.SizeBytes ||
      Bytes.byteLength > MaximumMediaBytes ||
      !SafeMediaTypes.has(Value.MimeType) ||
      !MatchesMagic(Bytes, Value.MimeType)
    ) {
      SetRejected(true);
      return;
    }
    const Buffer = new ArrayBuffer(Bytes.byteLength);
    new Uint8Array(Buffer).set(Bytes);
    const Url = URL.createObjectURL(new Blob([Buffer], { type: Value.MimeType }));
    SetObjectUrl(Url);
    return () => URL.revokeObjectURL(Url);
  }, [Value.Base64, Value.MimeType, Value.SizeBytes]);

  const Reject = (): void => {
    if (ObjectUrl !== null) URL.revokeObjectURL(ObjectUrl);
    SetObjectUrl(null);
    SetRejected(true);
  };

  if (Rejected)
    return (
      <p className="fb-error" role="alert">
        {McpEn.unsafeMedia}
      </p>
    );
  if (ObjectUrl === null) return <p aria-live="polite">{McpEn.working}</p>;
  if (Value.MimeType.startsWith("image/")) {
    return (
      <img
        alt={McpEn.resultImageAlt}
        className="fb-mcp-result-image"
        onError={Reject}
        onLoad={(Event) => {
          const Image = Event.currentTarget;
          if (
            Image.naturalWidth > 4096 ||
            Image.naturalHeight > 4096 ||
            Image.naturalWidth * Image.naturalHeight > 16_000_000
          )
            Reject();
        }}
        src={ObjectUrl}
      />
    );
  }
  return (
    <audio
      controls
      onDurationChange={(Event) => {
        const Duration = Event.currentTarget.duration;
        if (!Number.isFinite(Duration) || Duration > 300) Reject();
      }}
      onError={Reject}
      preload="metadata"
      src={ObjectUrl}
    >
      {McpEn.resultAudioUnavailable}
    </audio>
  );
}
