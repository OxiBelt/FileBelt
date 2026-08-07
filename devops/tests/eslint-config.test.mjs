// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { URL, fileURLToPath } from "node:url";
import test from "node:test";

import { ESLint } from "eslint";
import repositoryConfig from "../../eslint.config.js";

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

test("exports the OxiBelt PascalCase selector matrix", () => {
  const policy = repositoryConfig.find(({ rules }) =>
    Array.isArray(rules?.["@typescript-eslint/naming-convention"]),
  );

  assert.ok(policy);
  assert.deepEqual(policy.rules["@typescript-eslint/naming-convention"], [
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
  ]);
});

test("accepts PascalCase declarations and contract-safe boundaries", async () => {
  const result = await lintText(
    `import createClient, { external_name } from "./external.js";

/* eslint-disable @typescript-eslint/naming-convention -- Wire fields retain their external spelling. */
export interface WireShape {
  external_name: string;
}
/* eslint-enable @typescript-eslint/naming-convention */

export interface InternalShape {
  InternalProperty: string;
}

export const PascalCaseBinding = () => <div title="double quoted" />;

export function PascalCaseFunction(InputValue: string): string {
  return InputValue;
}

export function PascalCaseComponent(): JSX.Element {
  return <span data-external_name="preserved">component</span>;
}

export function useExternalHook(): number {
  return 1;
}

export class RequestHandler {
  PascalProperty = 1;

  methodName(InputValue: string): string {
    return InputValue;
  }
}

export class WirePayload {
  constructor(public readonly InternalValue: string) {}
}

export function ReadWireName(Value: WireShape): string {
  const { external_name: ExternalName } = Value;
  const WireObject = { external_name: ExternalName };
  void createClient;
  return WireObject.external_name;
}

export { external_name };
`,
    "ui/web/source/eslint-policy-valid.tsx",
  );

  assert.equal(result.errorCount, 0, JSON.stringify(result.messages));
  assert.equal(result.warningCount, 0);
});

test("rejects non-PascalCase declarations as errors", async () => {
  const result = await lintText(
    `export interface bad_shape {
  bad_property: string;
}

export class bad_handler {
  bad_field = 1;

  bad_method(input_value: string): string {
    return input_value;
  }
}

export function bad_name(input_value: string): string {
    let mutable_value = input_value
    const UPPER_CASE = 'bad'
    mutable_value += UPPER_CASE
    return <span title='single quoted'>{mutable_value}</span>
}

export class PascalClass {
  constructor(public bad_parameter_property: string) {}
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
    "bad_property",
    "bad_handler",
    "bad_field",
    "input_value",
    "bad_name",
    "mutable_value",
    "UPPER_CASE",
    "bad_parameter_property",
  ]) {
    assert.ok(
      namingMessages.some((message) => message.includes(`\`${name}\``)),
      `expected a naming error for ${name}: ${JSON.stringify(result.messages)}`,
    );
  }
  assert.ok(
    !namingMessages.some((message) => message.includes("`bad_method`")),
    `did not expect methods to be checked: ${JSON.stringify(namingMessages)}`,
  );
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
