// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const RepositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const Oxlint = path.join(RepositoryRoot, "node_modules", ".bin", "oxlint");
const Plugin = path.join(RepositoryRoot, "devops", "oxlint-plugin.mjs");

function LintFixture(Source, Fix = false) {
  const Directory = mkdtempSync(path.join(tmpdir(), "filebelt-oxlint-plugin-"));
  const SourcePath = path.join(Directory, "fixture.ts");
  const ConfigPath = path.join(Directory, ".oxlintrc.json");
  writeFileSync(SourcePath, Source);
  writeFileSync(
    ConfigPath,
    JSON.stringify({
      plugins: [],
      jsPlugins: [Plugin],
      categories: { correctness: "off" },
      rules: { "filebelt/pascal-case": "error" },
    }),
  );

  const Arguments = ["-c", ConfigPath, SourcePath];
  if (Fix) Arguments.unshift("--fix");
  const Result = spawnSync(Oxlint, Arguments, { encoding: "utf8" });
  const Output = `${Result.stdout}${Result.stderr}`;
  const ResultSource = readFileSync(SourcePath, "utf8");
  rmSync(Directory, { recursive: true, force: true });
  return { Output, ResultSource, Status: Result.status };
}

test("enforces FileBelt's PascalCase selector contract", () => {
  const Valid = LintFixture(`
import { lower as ImportedValue } from "./external.js";
const $Value = 1;
const $lower = 2;
const useVariable = 3;
const { lower: RenamedValue, Nested: { lower: InnerValue }, ...RestValue } = ExternalValue;
function useExternalHook({ lower: BoundValue } = ExternalValue, ...MoreValues: unknown[]) {}
try {} catch (CaughtValue) {}
const ObjectValue = { lower: 1 };
ObjectValue.lower;
class ExampleValue<TypeValue> {
  #PrivateValue = 1;
  PropertyValue = 1;
  ["external"] = 2;
  constructor(public ParameterValue: number) {}
  get lower() { return 1; }
  lowerMethod(MethodValue: string) { return MethodValue; }
}
interface InterfaceValue { PropertyValue: string; lowerMethod(MethodValue: string): void; }
type AliasValue = InterfaceValue;
enum EnumValue { Member }
void ImportedValue;
void $Value;
void $lower;
void useVariable;
void RenamedValue;
void InnerValue;
void RestValue;
void useExternalHook;
void CaughtValue;
void ObjectValue;
void ExampleValue;
void AliasValue;
void EnumValue;
`);
  assert.equal(Valid.Status, 0, Valid.Output);

  const Invalid = LintFixture(`
const lower_value = 1;
function lowerFunction(lowerParameter: string) {}
function Handler(useParameter: string) {}
const ArrowValue = (lowerArrow: string) => lowerArrow;
const { external: useDestructured } = ExternalValue;
try {} catch (lowerCaught) {}
class lowerClass<lowerTypeParameter> {
  #lowerPrivate = 1;
  lowerProperty = 1;
  useProperty = 2;
  constructor(public lowerParameterProperty: number, public useParameterProperty: number) {}
  lowerMethod(lowerMethodParameter: string) { return lowerMethodParameter; }
}
interface lowerInterface { lowerTypeProperty: string; }
type lowerAlias = string;
type useType = string;
enum lowerEnum { Member }
`);
  assert.equal(Invalid.Status, 1, Invalid.Output);
  assert.match(Invalid.Output, /filebelt\(pascal-case\)/);
  for (const Name of [
    "lower_value",
    "lowerFunction",
    "lowerParameter",
    "useParameter",
    "lowerArrow",
    "useDestructured",
    "lowerCaught",
    "lowerClass",
    "lowerTypeParameter",
    "lowerPrivate",
    "lowerProperty",
    "useProperty",
    "lowerParameterProperty",
    "useParameterProperty",
    "lowerMethodParameter",
    "lowerInterface",
    "lowerTypeProperty",
    "lowerAlias",
    "useType",
    "lowerEnum",
  ]) {
    assert.match(Invalid.Output, new RegExp(Name));
  }
});

test("honors narrow Oxlint suppression directives", () => {
  const Result = LintFixture(`
/* oxlint-disable filebelt/pascal-case -- External wire name. */
const lowerWireName = 1;
/* oxlint-enable filebelt/pascal-case */
const LocalName = lowerWireName;
void LocalName;
`);
  assert.equal(Result.Status, 0, Result.Output);
});

test("remains diagnostic-only when Oxlint fixes", () => {
  const Source = "const lowerName = 1;\nvoid lowerName;\n";
  const Result = LintFixture(Source, true);
  assert.equal(Result.Status, 1, Result.Output);
  assert.equal(Result.ResultSource, Source);
});
