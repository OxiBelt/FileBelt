// SPDX-License-Identifier: Apache-2.0

import { fileURLToPath } from "node:url";
import { cp } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { defineConfig } from "vitest/config";
import type { Plugin } from "vite";

const ParentContentSecurityPolicy = "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self' data:; form-action 'self'; frame-src 'self'; frame-ancestors 'none'; img-src 'self' data: blob:; media-src 'self' blob:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; require-trusted-types-for 'script'; trusted-types 'none'";
const MarkdownPreviewContentSecurityPolicy = "default-src 'none'; base-uri 'none'; connect-src 'none'; font-src 'self'; form-action 'none'; frame-src 'none'; frame-ancestors 'self'; img-src 'self' blob:; media-src 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; worker-src 'self' blob:; require-trusted-types-for 'script'; trusted-types filebelt-markdown-generated";

function SetBrowserSecurityHeaders(Request: IncomingMessage, Response: ServerResponse): void {
  const IsMarkdownPreview = Request.url?.startsWith("/markdown-preview/") ?? false;
  Response.setHeader(
    "Content-Security-Policy",
    IsMarkdownPreview ? MarkdownPreviewContentSecurityPolicy : ParentContentSecurityPolicy,
  );
  Response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  Response.setHeader("Cross-Origin-Resource-Policy", IsMarkdownPreview ? "cross-origin" : "same-origin");
  if (IsMarkdownPreview) Response.setHeader("Access-Control-Allow-Origin", "*");
  Response.setHeader("Strict-Transport-Security", "max-age=31536000");
  Response.setHeader("Permissions-Policy", "camera=(), display-capture=(), geolocation=(), microphone=(), payment=(), usb=()");
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
    async closeBundle() {
      await cp(
        fileURLToPath(new URL("../markdown/dist/preview", import.meta.url)),
        fileURLToPath(new URL("dist/markdown-preview", import.meta.url)),
        { recursive: true },
      );
    },
  };
}

export default defineConfig({
  build: {
    assetsDir: "assets",
    emptyOutDir: true,
    manifest: true,
    rollupOptions: {
      onwarn(Warning, Warn) {
        if (Warning.code === "MODULE_LEVEL_DIRECTIVE" && Warning.message.includes('"use client"')) return;
        Warn(Warning);
      },
      output: {
        manualChunks: {
          fluent: ["@fluentui/react-components"],
          icons: ["lucide-react"],
          react: ["react", "react-dom/client"],
        },
      },
    },
    sourcemap: false,
    target: "es2022",
  },
  resolve: {
    alias: {
      "@filebelt/admin": fileURLToPath(new URL("../admin/source/index.tsx", import.meta.url)),
      "@filebelt/design-system": fileURLToPath(new URL("../design-system/source/index.tsx", import.meta.url)),
      "@filebelt/markdown": fileURLToPath(new URL("../markdown/source/index.ts", import.meta.url)),
      "@filebelt/mcp-settings": fileURLToPath(new URL("../mcp-settings/source/index.tsx", import.meta.url)),
    },
  },
  plugins: [BrowserSecurityHeaders(), CopyMarkdownPreview()],
  test: {
    environment: "node",
    exclude: ["browser/**", "dist/**", "node_modules/**"],
  },
});
