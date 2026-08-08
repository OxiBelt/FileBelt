// SPDX-License-Identifier: Apache-2.0

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { IsFileBeltOfficeAstV1 } from "./ast-validation.js";
import { MarkdownPreviewDocument } from "./renderer.js";
import type { FileBeltOfficeAstV1, FileBeltReference } from "./types.js";
import "katex/dist/katex.min.css";
import "./preview.css";

const Host = document.querySelector("#filebelt-markdown-preview");
if (!(Host instanceof HTMLElement)) throw new Error("The Markdown preview root is unavailable.");
let ParentOrigin: string | undefined;
let ParentPort: MessagePort | undefined;
const Root = createRoot(Host);

window.addEventListener("message", (Event: MessageEvent<unknown>) => {
  if (ParentPort !== undefined || Event.source !== parent || !IsAllowedParentOrigin(Event.origin) || !IsConnectMessage(Event.data) || Event.ports.length !== 1) return;
  ParentOrigin ??= Event.origin;
  if (Event.origin !== ParentOrigin) return;
  const Port = Event.ports[0];
  if (Port === undefined) return;
  ParentPort = Port;
  Port.addEventListener("message", (PortEvent: MessageEvent<unknown>) => {
    if (IsPreviewMessage(PortEvent.data)) Root.render(<StrictMode><MarkdownPreviewDocument Ast={PortEvent.data.Ast} OnFileBeltLink={OpenFileBeltLink} /></StrictMode>);
  });
  Port.start();
});

function OpenFileBeltLink(Target: FileBeltReference): void {
  ParentPort?.postMessage({ Target, Type: "filebelt-markdown-link-v1" });
}

function IsConnectMessage(Value: unknown): Value is { Type: "filebelt-markdown-connect-v1" } {
  return typeof Value === "object" && Value !== null && (Value as { Type?: unknown }).Type === "filebelt-markdown-connect-v1";
}

function IsAllowedParentOrigin(Origin: string): boolean {
  try {
    const Value = new URL(Origin);
    return Value.origin === Origin && (Value.protocol === "https:" || IsLoopbackHost(Value.hostname));
  } catch {
    return false;
  }
}

function IsLoopbackHost(Hostname: string): boolean {
  return Hostname === "localhost" || Hostname === "127.0.0.1" || Hostname === "[::1]";
}

function IsPreviewMessage(Value: unknown): Value is { Ast: FileBeltOfficeAstV1; Type: "filebelt-markdown-preview-v1" } {
  if (typeof Value !== "object" || Value === null) return false;
  const Candidate = Value as { Ast?: unknown; Type?: unknown };
  return Candidate.Type === "filebelt-markdown-preview-v1" && IsFileBeltOfficeAstV1(Candidate.Ast);
}
