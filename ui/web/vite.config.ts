// SPDX-License-Identifier: Apache-2.0

import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

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
      "@filebelt/mcp-settings": fileURLToPath(new URL("../mcp-settings/source/index.tsx", import.meta.url)),
    },
  },
  server: {
    headers: {
      "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    },
  },
  test: {
    environment: "node",
    exclude: ["browser/**", "dist/**", "node_modules/**"],
  },
});
