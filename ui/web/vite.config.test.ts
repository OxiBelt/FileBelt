// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";

import {
  MarkdownPreviewDevelopmentAsset,
  MarkdownPreviewDevelopmentResponse,
  MarkdownPreviewContentSecurityPolicy,
  ParentContentSecurityPolicy,
} from "./vite.config.js";
import { ResolveFluentIconsContextId } from "../vitest-fluent-icons-resolver.js";

describe("ParentContentSecurityPolicy", () => {
  it("admits only the configured isolated editor origin for form posts", () => {
    const Csp = ParentContentSecurityPolicy("https://editor.example.test/onlyoffice/launch");
    expect(Csp).toContain("form-action 'self' https://editor.example.test");
    expect(Csp).toContain("connect-src 'self'");
    expect(Csp).toContain("script-src 'self'");
  });

  it("rejects a non-HTTPS or non-launch configuration", () => {
    expect(() =>
      ParentContentSecurityPolicy("http://editor.example.test/onlyoffice/launch"),
    ).toThrow();
    expect(() =>
      ParentContentSecurityPolicy("https://editor.example.test/integrations/launch"),
    ).toThrow();
    expect(() =>
      ParentContentSecurityPolicy("https://editor.example.test:8443/onlyoffice/launch"),
    ).toThrow();
    expect(() =>
      ParentContentSecurityPolicy("https://editor.example.test./onlyoffice/launch"),
    ).toThrow();
  });
});

describe("ResolveFluentIconsContextId", () => {
  it("resolves only Fluent Icons' extensionless context import", () => {
    expect(
      ResolveFluentIconsContextId(
        "./contexts/index",
        "/workspace/node_modules/@fluentui/react-icons/lib/providers.js",
      ),
    ).toBe("/workspace/node_modules/@fluentui/react-icons/lib/contexts/index.js");
    expect(
      ResolveFluentIconsContextId(
        "./contexts/other",
        "/workspace/node_modules/@fluentui/react-icons/lib/providers.js",
      ),
    ).toBeNull();
    expect(
      ResolveFluentIconsContextId(
        "./contexts/index",
        "/workspace/node_modules/example/lib/providers.js",
      ),
    ).toBeNull();
  });
});

describe("MarkdownPreviewDevelopmentAsset", () => {
  it("serves canonical preview artifacts below the built preview root", () => {
    expect(MarkdownPreviewDevelopmentAsset("/markdown-preview/index.html")?.ContentType).toBe(
      "text/html; charset=utf-8",
    );
    expect(
      MarkdownPreviewDevelopmentAsset("/markdown-preview/assets/index-example.js")?.Path,
    ).toMatch(/\/markdown\/dist\/preview\/assets\/index-example\.js$/);
    expect(
      MarkdownPreviewDevelopmentAsset("/markdown-preview/assets/index%20example.js?cache=1")?.Path,
    ).toMatch(/\/markdown\/dist\/preview\/assets\/index example\.js$/);
  });

  it.each([
    ["index.css", "text/css; charset=utf-8"],
    ["index.html", "text/html; charset=utf-8"],
    ["index.js", "text/javascript; charset=utf-8"],
    ["index.ttf", "font/ttf"],
    ["index.woff", "font/woff"],
    ["index.woff2", "font/woff2"],
  ])("maps the resolved .%s asset to its content type", (Name, ContentType) => {
    expect(MarkdownPreviewDevelopmentAsset(`/markdown-preview/${Name}`)?.ContentType).toBe(
      ContentType,
    );
  });

  it.each([
    "/markdown-preview/",
    "/markdown-preview//index.html",
    "/markdown-preview/./index.html",
    "/markdown-preview/assets/../index.html",
    "/markdown-preview/../package.json",
    "/markdown-preview/%2e%2e/package.json",
    "/markdown-preview/%252e%252e/%252e%252e/%252e%252e/web/index.html",
    "/markdown-preview/%252E%252E/index.html",
    "/markdown-preview/%252e./index.html",
    "/markdown-preview/.%252e/index.html",
    "/markdown-preview/%25252e%25252e/index.html",
    "/markdown-preview/assets%2findex.js",
    "/markdown-preview/%2e%2e%5cindex.js",
    "/markdown-preview/assets%00index.js",
    "/markdown-preview/assets/%0aindex.js",
    "/markdown-preview/..%20/..%20/..%20/web/index.html",
    "/markdown-preview/assets/index.%20",
    "/markdown-preview/assets/index%3Astream.js",
    "/markdown-preview/CON.js",
    "/markdown-preview/nul.JS",
    "/markdown-preview/COM1.woff",
    "/markdown-preview/lpt9.ttf",
    "/markdown-preview/assets/%zz.js",
    "/markdown-preview/package.json",
  ])("rejects the non-canonical or unsupported path %s", (Path) => {
    expect(MarkdownPreviewDevelopmentAsset(Path)).toBeNull();
  });

  it("passes only requests outside the preview namespace", async () => {
    expect(MarkdownPreviewDevelopmentAsset("/source/main.tsx")).toBeNull();
    expect(await MarkdownPreviewDevelopmentResponse("/source/main.tsx")).toEqual({ Kind: "pass" });
  });

  it.each([
    "/markdown-preview/%2e%2e/package.json",
    "/%6darkdown-preview/missing.html",
    "/%6Darkdown-preview/missing.html",
    "/%6darkdown-preview/%zz",
    "/%6darkdown-preview/%FF",
    "/%256darkdown-preview/missing.html",
    "/%25256darkdown-preview/missing.html",
    "/%25%36%64arkdown-preview/missing.html",
    "/markdown-preview%2fmissing.html",
    "/markdown-preview%25%32%66missing.html",
    "/markdown-preview%2f%zz",
    "/%2e/markdown-preview/missing.html",
    "/%3f/../markdown-preview/missing.html",
    "/%23/../markdown-preview/missing.html",
    "/x%3fy/../markdown-preview/missing.html",
    "/%2f%5b/../%6darkdown-preview/missing.html",
    "/x//../markdown-preview/missing.html",
    "/x///../../markdown-preview/missing.html",
    "/x/..%20/markdown-preview/missing.html",
    "/.%20/markdown-preview/missing.html",
    "/MARKDOWN-PREVIEW/missing.html",
    "/%20markdown-preview/missing.html",
    "/  MARKDOWN-PREVIEW/missing.html",
    "/markdown-preview./missing.html",
    "/markdown-preview%20/missing.html",
    "/markdown-preview::$INDEX_ALLOCATION/missing.html",
    "/MARKDO~1/missing.html",
  ])("owns the rejected preview namespace alias %s without reading an asset", async (Path) => {
    const Reader = vi
      .fn<(Path: string) => Promise<Uint8Array>>()
      .mockResolvedValue(new Uint8Array());
    const Result = await MarkdownPreviewDevelopmentResponse(Path, Reader);
    expect(Result).toEqual({ Kind: "not-found" });
    expect(Reader).not.toHaveBeenCalled();
  });

  it.each(["ENOENT", "ENOTDIR"])("turns %s into a preview-local not found", async (Code) => {
    const Cause = Object.assign(new Error("missing preview asset"), { code: Code });
    const Reader = vi.fn<(Path: string) => Promise<Uint8Array>>().mockRejectedValue(Cause);
    const Result = await MarkdownPreviewDevelopmentResponse(
      "/markdown-preview/missing.html",
      Reader,
    );
    expect(Result).toEqual({ Kind: "not-found" });
  });

  it("returns a resolved preview asset and propagates unexpected read failures", async () => {
    const Contents = new TextEncoder().encode("preview");
    const Reader = vi.fn<(Path: string) => Promise<Uint8Array>>().mockResolvedValue(Contents);
    const Result = await MarkdownPreviewDevelopmentResponse("/markdown-preview/index.html", Reader);
    expect(Reader).toHaveBeenCalledWith(
      expect.stringMatching(/\/markdown\/dist\/preview\/index\.html$/),
    );
    expect(Result).toEqual({
      Kind: "asset",
      ContentType: "text/html; charset=utf-8",
      Contents,
    });

    const Cause = Object.assign(new Error("preview read failed"), { code: "EACCES" });
    const FailingReader = vi.fn<(Path: string) => Promise<Uint8Array>>().mockRejectedValue(Cause);
    await expect(
      MarkdownPreviewDevelopmentResponse("/markdown-preview/index.html", FailingReader),
    ).rejects.toBe(Cause);
  });
});

describe("MarkdownPreviewContentSecurityPolicy", () => {
  it("admits packaged KaTeX data fonts without admitting network access", () => {
    expect(MarkdownPreviewContentSecurityPolicy).toContain("font-src 'self' data:");
    expect(MarkdownPreviewContentSecurityPolicy).toContain("connect-src 'none'");
  });
});
