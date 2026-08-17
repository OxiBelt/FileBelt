// SPDX-License-Identifier: Apache-2.0

import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

const typescriptFiles = ["**/*.{ts,cts,mts,tsx}"];

export default tseslint.config(
  {
    ignores: ["**/dist/**", "**/node_modules/**", ".agents/temp/**", "coverage/**"],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: typescriptFiles,
    rules: {
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/naming-convention": [
        "error",
        {
          selector: ["function", "variable"],
          filter: {
            regex: "^use[A-Z][A-Za-z0-9]*$",
            match: true,
          },
          format: null,
        },
        {
          selector: ["variableLike", "parameterProperty", "classProperty", "typeProperty"],
          format: ["PascalCase"],
        },
        {
          selector: "typeLike",
          format: ["PascalCase"],
        },
      ],
      "@typescript-eslint/no-explicit-any": "error",
    },
  },
  {
    files: ["ui/web/source/generated/openapi.ts"],
    rules: {
      "@typescript-eslint/consistent-type-imports": "off",
      "@typescript-eslint/naming-convention": "off",
    },
  },
  {
    files: ["adapters/onlyoffice/ui/launcher.js"],
    languageOptions: {
      globals: {
        document: "readonly",
        HTMLButtonElement: "readonly",
        HTMLElement: "readonly",
        HTMLScriptElement: "readonly",
        window: "readonly",
      },
    },
  },
  {
    files: ["ui/web/browser/docker-integration.spec.mjs"],
    languageOptions: {
      globals: {
        clearTimeout: "readonly",
        crypto: "readonly",
        fetch: "readonly",
        location: "readonly",
        setTimeout: "readonly",
        TextEncoder: "readonly",
        WebSocket: "readonly",
      },
    },
  },
  {
    files: ["adapters/onlyoffice/ui/launcher.ts"],
    rules: {
      "@typescript-eslint/naming-convention": [
        "error",
        {
          selector: "typeProperty",
          filter: {
            regex: "^(apiJsUrl|editorConfig)$",
            match: true,
          },
          format: null,
        },
        {
          selector: ["function", "variable"],
          filter: {
            regex: "^use[A-Z][A-Za-z0-9]*$",
            match: true,
          },
          format: null,
        },
        {
          selector: ["variableLike", "parameterProperty", "classProperty", "typeProperty"],
          format: ["PascalCase"],
        },
        {
          selector: "typeLike",
          format: ["PascalCase"],
        },
      ],
    },
  },
);
