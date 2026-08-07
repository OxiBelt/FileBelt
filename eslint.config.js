// SPDX-License-Identifier: Apache-2.0

import eslint from "@eslint/js";
import stylistic from "@stylistic/eslint-plugin";
import tseslint from "typescript-eslint";

const javascriptFiles = ["**/*.{js,cjs,mjs,jsx,ts,cts,mts,tsx}"];
const typescriptFiles = ["**/*.{ts,cts,mts,tsx}"];

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      ".agents/temp/**",
      "coverage/**",
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: javascriptFiles,
    plugins: {
      "@stylistic": stylistic,
    },
    rules: {
      "@stylistic/indent": ["error", 2, { SwitchCase: 1 }],
      "@stylistic/jsx-quotes": ["error", "prefer-double"],
      "@stylistic/quotes": ["error", "double", { avoidEscape: true }],
      "@stylistic/semi": ["error", "always"],
    },
  },
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
      "@stylistic/indent": "off",
      "@stylistic/jsx-quotes": "off",
      "@stylistic/quotes": "off",
      "@stylistic/semi": "off",
      "@typescript-eslint/consistent-type-imports": "off",
      "@typescript-eslint/naming-convention": "off",
    },
  },
);
