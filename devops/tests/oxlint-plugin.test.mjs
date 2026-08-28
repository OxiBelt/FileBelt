// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const RepositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const Oxlint = path.join(RepositoryRoot, 'node_modules', '.bin', 'oxlint')
const Plugin = path.join(RepositoryRoot, 'devops', 'oxlint-plugin.mjs')
const Fixture = (Parts, ...Values) =>
  Parts.reduce((Result, Part, Index) => Result + Part + (Values[Index] ?? ''), '')

function LintFixture(
  Source,
  Rules = { 'filebelt/pascal-case': 'error' },
  Fix = false,
  Extension = 'ts',
) {
  const Directory = mkdtempSync(path.join(tmpdir(), 'filebelt-oxlint-plugin-'))
  const SourcePath = path.join(Directory, `fixture.${Extension}`)
  const ConfigPath = path.join(Directory, '.oxlintrc.json')
  writeFileSync(SourcePath, Source)
  writeFileSync(
    ConfigPath,
    JSON.stringify({
      plugins: [],
      jsPlugins: [Plugin],
      categories: { correctness: 'off' },
      rules: Rules,
    }),
  )

  const Arguments = ['-c', ConfigPath, SourcePath]
  if (Fix) Arguments.unshift('--fix')
  const Result = spawnSync(Oxlint, Arguments, { encoding: 'utf8' })
  const Output = `${Result.stdout}${Result.stderr}`
  const ResultSource = readFileSync(SourcePath, 'utf8')
  rmSync(Directory, { recursive: true, force: true })
  return { Output, ResultSource, Status: Result.status }
}

test("enforces FileBelt's PascalCase selector contract", () => {
  const Valid = LintFixture(Fixture`
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
`)
  assert.equal(Valid.Status, 0, Valid.Output)

  const Invalid = LintFixture(Fixture`
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
`)
  assert.equal(Invalid.Status, 1, Invalid.Output)
  assert.match(Invalid.Output, /filebelt\(pascal-case\)/)
  for (const Name of [
    'lower_value',
    'lowerFunction',
    'lowerParameter',
    'useParameter',
    'lowerArrow',
    'useDestructured',
    'lowerCaught',
    'lowerClass',
    'lowerTypeParameter',
    'lowerPrivate',
    'lowerProperty',
    'useProperty',
    'lowerParameterProperty',
    'useParameterProperty',
    'lowerMethodParameter',
    'lowerInterface',
    'lowerTypeProperty',
    'lowerAlias',
    'useType',
    'lowerEnum',
  ]) {
    assert.match(Invalid.Output, new RegExp(Name))
  }
})

test('honors narrow Oxlint suppression directives', () => {
  const Result = LintFixture(Fixture`
/* oxlint-disable filebelt/pascal-case -- External wire name. */
const lowerWireName = 1;
/* oxlint-enable filebelt/pascal-case */
const LocalName = lowerWireName;
void LocalName;
`)
  assert.equal(Result.Status, 0, Result.Output)
})

test('preserves semicolons required for JavaScript grammar or automatic semicolon insertion', () => {
  const Result = LintFixture(
    Fixture`
for (let Index = 0; Index < 1; Index += 1) {}
const First = () => {}; const Second = First
const Callable = () => {}
;(Callable)()
class ExampleValue {
  get;
  value() {}
}
void Second
`,
    { 'filebelt/no-semicolons': 'error' },
  )
  assert.equal(Result.Status, 0, Result.Output)
})

test('rejects safely removable semicolons', () => {
  const Result = LintFixture('const Value = 1;\nvoid Value\n', {
    'filebelt/no-semicolons': 'error',
  })
  assert.equal(Result.Status, 1, Result.Output)
  assert.match(Result.Output, /filebelt\(no-semicolons\)/)
})

test('requires formatter-compatible single quotes for literals, templates, and JSX attributes', () => {
  const Rules = { 'filebelt/single-quotes': 'error' }
  const Valid = LintFixture(
    Fixture`
const Name = 'value'
const Interpolated = \`value: \${Name}\`
const Tagged = String.raw\`value\`
void Interpolated
void Tagged
`,
    Rules,
  )
  assert.equal(Valid.Status, 0, Valid.Output)

  const ApostropheHeavy = LintFixture('const Value = "can\\\'t"\nvoid Value\n', Rules)
  assert.equal(ApostropheHeavy.Status, 0, ApostropheHeavy.Output)

  for (const Source of [
    'const Plain = "value"\nvoid Plain\n',
    'const Tie = "can\\\'t\\\""\nvoid Tie\n',
    'const DoubleHeavy = "he said \\\"yes\\\""\nvoid DoubleHeavy\n',
  ]) {
    const Result = LintFixture(Source, Rules)
    assert.equal(Result.Status, 1, Result.Output)
    assert.match(Result.Output, /filebelt\(single-quotes\)/)
  }

  const SimpleTemplate = LintFixture('const Value = `value`\nvoid Value\n', Rules)
  assert.equal(SimpleTemplate.Status, 1, SimpleTemplate.Output)

  const JsxApostropheHeavy = LintFixture(
    'const View = <div title="can\\\'t" />\nvoid View\n',
    Rules,
    false,
    'tsx',
  )
  assert.equal(JsxApostropheHeavy.Status, 0, JsxApostropheHeavy.Output)

  for (const Source of [
    'const View = <div title="value" />\nvoid View\n',
    'const View = <div title={"can\\\'t\\\""} />\nvoid View\n',
    'const View = <div title={"he said \\\"yes\\\""} />\nvoid View\n',
  ]) {
    const Result = LintFixture(Source, Rules, false, 'tsx')
    assert.equal(Result.Status, 1, Result.Output)
    assert.match(Result.Output, /filebelt\(single-quotes\)/)
  }
})

test('remains diagnostic-only when Oxlint fixes', () => {
  const Source = 'const lowerName = "value";\nvoid lowerName;\n'
  const Result = LintFixture(
    Source,
    {
      'filebelt/no-semicolons': 'error',
      'filebelt/pascal-case': 'error',
      'filebelt/single-quotes': 'error',
    },
    true,
  )
  assert.equal(Result.Status, 1, Result.Output)
  assert.equal(Result.ResultSource, Source)
})
