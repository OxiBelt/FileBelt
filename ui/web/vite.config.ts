// SPDX-License-Identifier: Apache-2.0

import { fileURLToPath } from "node:url";
import { cp, readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, isAbsolute, posix, relative, resolve, sep, win32 } from "node:path";
import { defineConfig } from "vitest/config";
import type { Connect, Plugin } from "vite";
import { ResolveFluentIconsContext } from "../vitest-fluent-icons-resolver.js";

export function ParentContentSecurityPolicy(
  DocumentLaunchAction = process.env.FILEBELT_DOCUMENT_LAUNCH_ACTION,
): string {
  const EditorOrigin =
    DocumentLaunchAction === undefined ? "" : ` ${DocumentLaunchOrigin(DocumentLaunchAction)}`;
  return `default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self' data:; form-action 'self'${EditorOrigin}; frame-src 'self'; frame-ancestors 'none'; img-src 'self' data: blob:; media-src 'self' blob:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; require-trusted-types-for 'script'; trusted-types 'none'`;
}

function DocumentLaunchOrigin(Action: string): string {
  const Url = new URL(Action);
  if (
    Url.protocol !== "https:" ||
    Url.hostname.endsWith(".") ||
    Url.pathname !== "/onlyoffice/launch" ||
    Url.username !== "" ||
    Url.password !== "" ||
    Url.port !== "" ||
    Url.search !== "" ||
    Url.hash !== ""
  ) {
    throw new Error(
      "FILEBELT_DOCUMENT_LAUNCH_ACTION must be an exact HTTPS /onlyoffice/launch URL",
    );
  }
  return Url.origin;
}

const ParentCsp = ParentContentSecurityPolicy();
export const MarkdownPreviewContentSecurityPolicy =
  "default-src 'none'; base-uri 'none'; connect-src 'none'; font-src 'self' data:; form-action 'none'; frame-src 'none'; frame-ancestors 'self'; img-src 'self' blob:; media-src 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; worker-src 'self' blob:; require-trusted-types-for 'script'; trusted-types filebelt-markdown-generated";
const MarkdownPreviewPrefix = "/markdown-preview/";
const MarkdownPreviewDevelopmentRoot = fileURLToPath(
  new URL("../markdown/dist/preview", import.meta.url),
);
const MarkdownPreviewBuiltRoot = fileURLToPath(new URL("dist/markdown-preview", import.meta.url));
const MarkdownPreviewContentTypes: Readonly<Record<string, string>> = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".ttf": "font/ttf",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};

type MarkdownPreviewDevelopmentReader = (Path: string) => Promise<Uint8Array>;

type MarkdownPreviewResponse =
  | { Kind: "asset"; ContentType: string; Contents: Uint8Array }
  | { Kind: "not-found" }
  | { Kind: "pass" };

function RequestPathname(RequestUrl: string | undefined): string | undefined {
  if (RequestUrl === undefined) return undefined;
  const QueryOrFragment = RequestUrl.search(/[?#]/u);
  return QueryOrFragment === -1 ? RequestUrl : RequestUrl.slice(0, QueryOrFragment);
}

function DecodeNestedAsciiPathOctets(Pathname: string): string {
  const Decoded: string[] = [];
  for (const Character of Pathname) {
    Decoded.push(Character);
    while (Decoded.length >= 3) {
      const EncodedOctet = Decoded.slice(-3).join("");
      if (!/^%[0-7][0-9a-f]$/iu.test(EncodedOctet)) break;
      Decoded.splice(-3, 3, String.fromCodePoint(Number.parseInt(EncodedOctet.slice(-2), 16)));
    }
  }
  return Decoded.join("");
}

function NormalizedRequestPathname(Pathname: string, ProtectEncodedDelimiters: boolean): string {
  const UrlPathname = ProtectEncodedDelimiters
    ? Pathname.replaceAll("?", "%3F").replaceAll("#", "%23")
    : Pathname;
  return new URL(`/.${UrlPathname}`, "http://filebelt.invalid").pathname;
}

function HasMarkdownPreviewPrefix(Pathname: string): boolean {
  const Match = /^\/+([^/]+)\//u.exec(Pathname);
  if (Match === null) return false;
  const Segment = (Match[1] ?? "").replace(/^[ .]+|[ .]+$/gu, "").toLowerCase();
  const Name = Segment.split(":", 1)[0] ?? "";
  return Name === "markdown-preview" || /^[^.:]{1,6}~[0-9]+(?:\.[^.:]{0,3})?$/u.test(Name);
}

function Win32NormalizedRequestPathname(Pathname: string): string {
  const TrimmedSegments = Pathname.split(/[/\\]/u).map((Segment) => {
    const SpaceTrimmed = Segment.replace(/^ +| +$/gu, "");
    return SpaceTrimmed === "." || SpaceTrimmed === ".."
      ? SpaceTrimmed
      : SpaceTrimmed.replace(/[ .]+$/u, "");
  });
  return win32.normalize(TrimmedSegments.join("\\")).replaceAll("\\", "/");
}

function HasNormalizedMarkdownPreviewPrefix(Pathname: string): boolean {
  return (
    HasMarkdownPreviewPrefix(Pathname) ||
    HasMarkdownPreviewPrefix(posix.normalize(Pathname)) ||
    HasMarkdownPreviewPrefix(Win32NormalizedRequestPathname(Pathname))
  );
}

function IsMarkdownPreviewRequest(RequestUrl: string | undefined): boolean {
  const Pathname = RequestPathname(RequestUrl);
  if (Pathname === undefined) return false;
  if (HasNormalizedMarkdownPreviewPrefix(Pathname)) return true;
  try {
    if (HasMarkdownPreviewPrefix(NormalizedRequestPathname(Pathname, false))) return true;
    const Decoded = DecodeNestedAsciiPathOctets(Pathname);
    if (HasNormalizedMarkdownPreviewPrefix(Decoded)) return true;
    return HasNormalizedMarkdownPreviewPrefix(NormalizedRequestPathname(Decoded, true));
  } catch {
    return false;
  }
}

function SetBrowserSecurityHeaders(
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- Vite supplies Node request objects whose public contract is mutable.
  Request: IncomingMessage,
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- This middleware must mutate the Vite-provided response headers.
  Response: ServerResponse,
): void {
  const IsMarkdownPreview = IsMarkdownPreviewRequest(Request.url);
  Response.setHeader(
    "Content-Security-Policy",
    IsMarkdownPreview ? MarkdownPreviewContentSecurityPolicy : ParentCsp,
  );
  Response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  Response.setHeader(
    "Cross-Origin-Resource-Policy",
    IsMarkdownPreview ? "cross-origin" : "same-origin",
  );
  if (IsMarkdownPreview) Response.setHeader("Access-Control-Allow-Origin", "*");
  Response.setHeader("Strict-Transport-Security", "max-age=31536000");
  Response.setHeader(
    "Permissions-Policy",
    "camera=(), display-capture=(), geolocation=(), microphone=(), payment=(), usb=()",
  );
  Response.setHeader("Referrer-Policy", "no-referrer");
  Response.setHeader("X-Content-Type-Options", "nosniff");
}

function BrowserSecurityHeaders(): Plugin {
  return {
    name: "filebelt-browser-security-headers",
    configurePreviewServer(Server) {
      Server.middlewares.use((Request, Response, Next) => {
        SetBrowserSecurityHeaders(Request, Response);
        Next();
      });
    },
    configureServer(Server) {
      Server.middlewares.use((Request, Response, Next) => {
        SetBrowserSecurityHeaders(Request, Response);
        Next();
      });
    },
  };
}

function CopyMarkdownPreview(): Plugin {
  return {
    name: "filebelt-copy-markdown-preview",
    configurePreviewServer(Server) {
      Server.middlewares.use(MarkdownPreviewMiddleware(MarkdownPreviewBuiltRoot));
    },
    configureServer(Server) {
      Server.middlewares.use(MarkdownPreviewMiddleware(MarkdownPreviewDevelopmentRoot));
    },
    async closeBundle() {
      await cp(
        fileURLToPath(new URL("../markdown/dist/preview", import.meta.url)),
        fileURLToPath(new URL("dist/markdown-preview", import.meta.url)),
        { recursive: true },
      );
    },
  };
}

function MarkdownPreviewMiddleware(Root: string): Connect.NextHandleFunction {
  return (Request, Response, Next) => {
    void ReadMarkdownPreviewResponse(Request.url, Root)
      .then((Result) => {
        if (Result.Kind === "pass") {
          Next();
          return;
        }
        if (Result.Kind === "not-found") {
          Response.statusCode = 404;
          Response.end();
          return;
        }
        Response.setHeader("Content-Type", Result.ContentType);
        Response.end(Result.Contents);
      })
      .catch((Cause: unknown) => {
        Next(Cause);
      });
  };
}

const WindowsReservedName =
  /^(?:aux|clock\$|con|conin\$|conout\$|nul|prn|com[1-9¹²³]|lpt[1-9¹²³])(?:\.|$)/iu;

function IsCanonicalMarkdownPreviewSegment(Segment: string): boolean {
  return (
    Segment !== "" &&
    Segment !== "." &&
    Segment !== ".." &&
    !/[ .]$/u.test(Segment) &&
    // oxlint-disable-next-line eslint/no-control-regex -- Decoded URL path segments must reject C0 and DEL controls before filesystem access.
    !/[\u0000-\u001f\u007f<>:"|?*]/u.test(Segment) &&
    !WindowsReservedName.test(Segment)
  );
}

function MarkdownPreviewAsset(
  RequestUrl: string | undefined,
  Root: string,
): { ContentType: string; Path: string } | null {
  const Pathname = RequestPathname(RequestUrl);
  if (Pathname === undefined || !Pathname.startsWith(MarkdownPreviewPrefix)) return null;
  const EncodedRelative = Pathname.slice(MarkdownPreviewPrefix.length);
  if (/%(?:2f|5c)/iu.test(EncodedRelative)) return null;
  let Relative: string;
  try {
    Relative = decodeURIComponent(EncodedRelative);
  } catch {
    return null;
  }
  if (
    Relative.startsWith("/") ||
    Relative.includes("\\") ||
    /%[0-9a-f]{2}/iu.test(Relative) ||
    !Relative.split("/").every(IsCanonicalMarkdownPreviewSegment)
  )
    return null;
  const Path = resolve(Root, Relative);
  const RootRelative = relative(Root, Path);
  if (
    RootRelative.length === 0 ||
    RootRelative === ".." ||
    RootRelative.startsWith(`..${sep}`) ||
    isAbsolute(RootRelative)
  )
    return null;
  const ContentType = MarkdownPreviewContentTypes[extname(Path).toLowerCase()];
  if (ContentType === undefined) return null;
  return { ContentType, Path };
}

export function MarkdownPreviewDevelopmentAsset(
  RequestUrl: string | undefined,
): { ContentType: string; Path: string } | null {
  return MarkdownPreviewAsset(RequestUrl, MarkdownPreviewDevelopmentRoot);
}

export async function MarkdownPreviewDevelopmentResponse(
  RequestUrl: string | undefined,
  ReadAsset: MarkdownPreviewDevelopmentReader = readFile,
): Promise<MarkdownPreviewResponse> {
  return ReadMarkdownPreviewResponse(RequestUrl, MarkdownPreviewDevelopmentRoot, ReadAsset);
}

async function ReadMarkdownPreviewResponse(
  RequestUrl: string | undefined,
  Root: string,
  ReadAsset: MarkdownPreviewDevelopmentReader = readFile,
): Promise<MarkdownPreviewResponse> {
  if (!IsMarkdownPreviewRequest(RequestUrl)) return { Kind: "pass" };
  const Asset = MarkdownPreviewAsset(RequestUrl, Root);
  if (Asset === null) return { Kind: "not-found" };
  try {
    return {
      Kind: "asset",
      ContentType: Asset.ContentType,
      Contents: await ReadAsset(Asset.Path),
    };
  } catch (Cause: unknown) {
    const Code =
      typeof Cause === "object" && Cause !== null && "code" in Cause ? Cause.code : undefined;
    if (Code === "ENOENT" || Code === "ENOTDIR") return { Kind: "not-found" };
    throw Cause;
  }
}

export default defineConfig({
  build: {
    assetsDir: "assets",
    emptyOutDir: true,
    manifest: true,
    // oxlint-disable-next-line typescript/no-deprecated -- Vite 8 retains Rollup options while FileBelt validates Rolldown migration separately.
    rollupOptions: {
      // oxlint-disable-next-line typescript/no-deprecated -- The warning filter remains on Rollup's onwarn contract until Rolldown parity is validated.
      onwarn(Warning, Warn) {
        if (Warning.code === "MODULE_LEVEL_DIRECTIVE" && Warning.message.includes('"use client"'))
          return;
        Warn(Warning);
      },
      output: {
        manualChunks(Id) {
          if (Id.includes("/node_modules/@fluentui/")) return "fluent";
          if (Id.includes("/node_modules/lucide-react/")) return "icons";
          if (Id.includes("/node_modules/react/") || Id.includes("/node_modules/react-dom/")) {
            return "react";
          }
          return undefined;
        },
      },
    },
    sourcemap: false,
    target: "es2022",
  },
  resolve: {
    alias: {
      "@filebelt/admin": fileURLToPath(new URL("../admin/source/index.tsx", import.meta.url)),
      "@filebelt/design-system": fileURLToPath(
        new URL("../design-system/source/index.tsx", import.meta.url),
      ),
      "@filebelt/markdown": fileURLToPath(new URL("../markdown/source/index.ts", import.meta.url)),
      "@filebelt/mcp-settings": fileURLToPath(
        new URL("../mcp-settings/source/index.tsx", import.meta.url),
      ),
    },
  },
  plugins: [BrowserSecurityHeaders(), CopyMarkdownPreview(), ResolveFluentIconsContext()],
  test: {
    environment: "node",
    exclude: ["browser/**", "dist/**", "node_modules/**"],
    server: {
      deps: { inline: [/@fluentui/] },
    },
  },
});
