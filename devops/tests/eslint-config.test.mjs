// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { URL, fileURLToPath } from "node:url";
import test from "node:test";

import { ESLint } from "eslint";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const eslint = new ESLint({
  cwd: repositoryRoot,
  overrideConfigFile: fileURLToPath(new URL("../../eslint.config.js", import.meta.url)),
});

async function lintText(source, relativePath) {
  const [result] = await eslint.lintText(source, {
    filePath: fileURLToPath(new URL(`../../${relativePath}`, import.meta.url)),
  });
  assert.ok(result);
  return result;
}

function ruleIds(result) {
  return new Set(result.messages.map(({ ruleId }) => ruleId));
}

test("accepts FileBelt style and the contract-safe naming matrix", async () => {
  const result = await lintText(
    `import { external_name } from "./external.js";

export interface WireShape {
  external_name: string;
}

export const UPPER_CASE = 1;
export const camelCaseBinding = 2;
export const PascalCaseBinding = () => <div title="double quoted" />;

export function camelCaseFunction(_inputValue: string): string {
  return _inputValue;
}

export function PascalCaseComponent(): JSX.Element {
  return <span data-external_name="preserved">component</span>;
}

export class RequestHandler {
  methodName(inputValue: string): string {
    return inputValue;
  }
}

export class WirePayload {
  constructor(public readonly external_name: string) {}
}

export function readWireName(value: WireShape): string {
  const { external_name } = value;
  const wireObject = { external_name };
  return wireObject.external_name;
}

export { external_name };
`,
    "ui/web/source/eslint-policy-valid.tsx",
  );

  assert.equal(result.errorCount, 0, JSON.stringify(result.messages));
  assert.equal(result.warningCount, 0);
});

test("rejects style and identifier violations as errors", async () => {
  const result = await lintText(
    `export interface bad_shape {
  value: string;
}

export class bad_handler {
  bad_method(input_value: string): string {
    return input_value;
  }
}

export function bad_name(input_value: string): string {
    let mutable_value = input_value
    const local_value = 'bad'
    mutable_value += local_value
    return <span title='single quoted'>{mutable_value}</span>
}
`,
    "ui/web/source/eslint-policy-invalid.tsx",
  );
  const rules = ruleIds(result);

  for (const rule of [
    "@stylistic/indent",
    "@stylistic/jsx-quotes",
    "@stylistic/quotes",
    "@stylistic/semi",
    "@typescript-eslint/naming-convention",
  ]) {
    assert.ok(rules.has(rule), `expected ${rule}: ${JSON.stringify(result.messages)}`);
  }
  const namingMessages = result.messages
    .filter(({ ruleId }) => ruleId === "@typescript-eslint/naming-convention")
    .map(({ message }) => message);
  for (const name of [
    "bad_shape",
    "bad_handler",
    "bad_method",
    "input_value",
    "bad_name",
    "mutable_value",
    "local_value",
  ]) {
    assert.ok(
      namingMessages.some((message) => message.includes(`\`${name}\``)),
      `expected a naming error for ${name}: ${JSON.stringify(result.messages)}`,
    );
  }
  assert.equal(result.warningCount, 0);
});

test("keeps generated OpenAPI semantic checks without style or naming checks", async () => {
  const result = await lintText(
    `import { ExternalType } from './external.js'

const unused_generated = 1

export interface paths {
    external_name: ExternalType
}

export type unsafe_shape = any
`,
    "ui/web/source/generated/openapi.ts",
  );
  const rules = ruleIds(result);

  assert.ok(rules.has("@typescript-eslint/no-explicit-any"));
  assert.ok(rules.has("@typescript-eslint/no-unused-vars"));
  for (const rule of [
    "@stylistic/indent",
    "@stylistic/jsx-quotes",
    "@stylistic/quotes",
    "@stylistic/semi",
    "@typescript-eslint/consistent-type-imports",
    "@typescript-eslint/naming-convention",
  ]) {
    assert.ok(!rules.has(rule), `did not expect ${rule}: ${JSON.stringify(result.messages)}`);
  }
  assert.equal(result.warningCount, 0);
});
