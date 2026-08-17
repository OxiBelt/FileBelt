// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { URL, fileURLToPath } from "node:url";
import test from "node:test";

const Config = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../.oxlintrc.json", import.meta.url)), "utf8"),
);

const TypeAwareRuleNames = [
  "await-thenable",
  "consistent-return",
  "consistent-type-exports",
  "dot-notation",
  "no-array-delete",
  "no-base-to-string",
  "no-confusing-void-expression",
  "no-deprecated",
  "no-duplicate-type-constituents",
  "no-floating-promises",
  "no-for-in-array",
  "no-implied-eval",
  "no-meaningless-void-operator",
  "no-misused-promises",
  "no-misused-spread",
  "no-mixed-enums",
  "no-redundant-type-constituents",
  "no-unnecessary-boolean-literal-compare",
  "no-unnecessary-condition",
  "no-unnecessary-qualifier",
  "no-unnecessary-template-expression",
  "no-unnecessary-type-arguments",
  "no-unnecessary-type-assertion",
  "no-unnecessary-type-conversion",
  "no-unnecessary-type-parameters",
  "no-unsafe-argument",
  "no-unsafe-assignment",
  "no-unsafe-call",
  "no-unsafe-enum-comparison",
  "no-unsafe-member-access",
  "no-unsafe-return",
  "no-unsafe-type-assertion",
  "no-unsafe-unary-minus",
  "no-useless-default-assignment",
  "non-nullable-type-assertion-style",
  "only-throw-error",
  "prefer-find",
  "prefer-includes",
  "prefer-nullish-coalescing",
  "prefer-optional-chain",
  "prefer-promise-reject-errors",
  "prefer-readonly-parameter-types",
  "prefer-readonly",
  "prefer-reduce-type-parameter",
  "prefer-regexp-exec",
  "prefer-return-this-type",
  "prefer-string-starts-ends-with",
  "promise-function-async",
  "related-getter-setter-pairs",
  "require-array-sort-compare",
  "require-await",
  "restrict-plus-operands",
  "restrict-template-expressions",
  "return-await",
  "strict-boolean-expressions",
  "strict-void-return",
  "switch-exhaustiveness-check",
  "unbound-method",
  "use-unknown-in-catch-callback-variable",
];

function FindOverride(FilePattern) {
  const Override = Config.overrides.find(({ files: Files }) => Files.includes(FilePattern));
  assert.ok(Override, `missing override for ${FilePattern}`);
  return Override;
}

test("enables the complete tsgolint v7 type-aware rule catalog as errors", () => {
  assert.equal(Config.options.typeAware, true);
  assert.equal(TypeAwareRuleNames.length, 59);
  const TypeScriptOverride = FindOverride("**/*.{ts,cts,mts,tsx}");

  for (const RuleName of TypeAwareRuleNames) {
    const Setting = TypeScriptOverride.rules[`typescript/${RuleName}`];
    assert.ok(Setting === "error" || (Array.isArray(Setting) && Setting[0] === "error"), RuleName);
  }
  assert.equal(TypeScriptOverride.rules["typescript/naming-convention"], undefined);
  assert.equal(TypeScriptOverride.rules["typescript/prefer-destructuring"], undefined);
  assert.equal(TypeScriptOverride.rules["filebelt/pascal-case"], "error");
});

test("retains generated-source and runtime-global overrides", () => {
  assert.deepEqual(FindOverride("ui/web/source/generated/openapi.ts").rules, {
    "typescript/consistent-type-imports": "off",
    "filebelt/pascal-case": "off",
  });
  assert.deepEqual(FindOverride("adapters/onlyoffice/ui/launcher.js").globals, {
    document: "readonly",
    HTMLButtonElement: "readonly",
    HTMLElement: "readonly",
    HTMLScriptElement: "readonly",
    window: "readonly",
  });
  assert.deepEqual(FindOverride("ui/web/browser/docker-integration.spec.mjs").globals, {
    clearTimeout: "readonly",
    crypto: "readonly",
    fetch: "readonly",
    location: "readonly",
    setTimeout: "readonly",
    TextEncoder: "readonly",
    WebSocket: "readonly",
  });
});
