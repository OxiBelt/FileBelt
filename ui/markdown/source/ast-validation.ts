// SPDX-License-Identifier: Apache-2.0

import type { FileBeltOfficeAstV1, OfficeBlock, OfficeInline, SourceRange } from './types.js'

const MaximumNodes = 100_000
const MaximumDepth = 64
const MaximumStringUnits = 8 * 1024 * 1024

interface Budget {
  Depth: number
  Nodes: number
  StringUnits: number
}

export function IsFileBeltOfficeAstV1(Value: unknown): Value is FileBeltOfficeAstV1 {
  if (
    !IsRecord(Value) ||
    !HasOnly(Value, ['Children', 'Profile', 'Range']) ||
    Value.Profile !== 'filebelt-gfm-v1' ||
    !Array.isArray(Value.Children) ||
    !IsRange(Value.Range)
  )
    return false
  const Budget: Budget = { Depth: 0, Nodes: 1, StringUnits: 0 }
  return Value.Children.every((Block) => IsBlock(Block, Budget))
}

function IsBlock(
  Value: unknown,
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- Validation updates this parser-local complexity budget.
  Budget: Budget,
): Value is OfficeBlock {
  if (!Enter(Value, Budget) || !IsRange(Value.Range) || typeof Value.Kind !== 'string') return false
  const Nested = { ...Budget, Depth: Budget.Depth + 1 }
  let Valid = false
  switch (Value.Kind) {
    case 'alert':
      Valid =
        HasOnly(Value, ['Children', 'Kind', 'Range', 'Severity']) &&
        IsOneOf(Value.Severity, ['caution', 'important', 'note', 'tip', 'warning']) &&
        IsArrayOf(Value.Children, (Child) => IsBlock(Child, Nested))
      break
    case 'code':
      Valid =
        HasOnly(Value, ['Code', 'Kind', 'Language', 'Range']) &&
        TakeString(Value.Code, Budget) &&
        (Value.Language === null || TakeString(Value.Language, Budget, 256))
      break
    case 'footnoteDefinition':
      Valid =
        HasOnly(Value, ['Children', 'Identifier', 'Kind', 'Range']) &&
        TakeString(Value.Identifier, Budget, 1_024) &&
        IsArrayOf(Value.Children, (Child) => IsBlock(Child, Nested))
      break
    case 'heading':
      Valid =
        HasOnly(Value, ['Children', 'Depth', 'Kind', 'Range']) &&
        Number.isInteger(Value.Depth) &&
        Number(Value.Depth) >= 1 &&
        Number(Value.Depth) <= 6 &&
        IsArrayOf(Value.Children, (Child) => IsInline(Child, Nested))
      break
    case 'list':
      Valid =
        HasOnly(Value, ['Items', 'Kind', 'Ordered', 'Range']) &&
        typeof Value.Ordered === 'boolean' &&
        IsArrayOf(Value.Items, (Item) => IsListItem(Item, Nested))
      break
    case 'math':
      Valid =
        HasOnly(Value, ['Expression', 'Kind', 'Range']) &&
        TakeString(Value.Expression, Budget, 64 * 1_024)
      break
    case 'mermaid':
      Valid =
        HasOnly(Value, ['Kind', 'Range', 'Source']) && TakeString(Value.Source, Budget, 64 * 1_024)
      break
    case 'paragraph':
      Valid =
        HasOnly(Value, ['Children', 'Kind', 'Range']) &&
        IsArrayOf(Value.Children, (Child) => IsInline(Child, Nested))
      break
    case 'quote':
      Valid =
        HasOnly(Value, ['Children', 'Kind', 'Range']) &&
        IsArrayOf(Value.Children, (Child) => IsBlock(Child, Nested))
      break
    case 'table':
      Valid =
        HasOnly(Value, ['Align', 'Kind', 'Range', 'Rows']) &&
        Array.isArray(Value.Align) &&
        Value.Align.length <= 1_024 &&
        Value.Align.every(
          (Align) => Align === null || IsOneOf(Align, ['center', 'left', 'right']),
        ) &&
        IsArrayOf(Value.Rows, (Row) => IsTableRow(Row, Nested))
      break
    case 'thematicBreak':
      Valid = HasOnly(Value, ['Kind', 'Range'])
      break
  }
  Leave(Budget, Nested)
  return Valid
}

function IsInline(
  Value: unknown,
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- Validation updates this parser-local complexity budget.
  Budget: Budget,
): Value is OfficeInline {
  if (!Enter(Value, Budget) || !IsRange(Value.Range) || typeof Value.Kind !== 'string') return false
  const Nested = { ...Budget, Depth: Budget.Depth + 1 }
  let Valid = false
  switch (Value.Kind) {
    case 'code':
    case 'text':
      Valid = HasOnly(Value, ['Kind', 'Range', 'Text']) && TakeString(Value.Text, Budget)
      break
    case 'emphasis':
    case 'strong':
      Valid =
        HasOnly(Value, ['Children', 'Kind', 'Range']) &&
        IsArrayOf(Value.Children, (Child) => IsInline(Child, Nested))
      break
    case 'filebeltLink':
      Valid =
        HasOnly(Value, ['Kind', 'Range', 'Target', 'Title']) &&
        IsFileBeltReference(Value.Target) &&
        (Value.Title === null || TakeString(Value.Title, Budget, 1_024))
      break
    case 'footnoteReference':
      Valid =
        HasOnly(Value, ['Identifier', 'Kind', 'Range']) &&
        TakeString(Value.Identifier, Budget, 1_024)
      break
    case 'link':
      Valid =
        HasOnly(Value, ['Children', 'Destination', 'Kind', 'Range', 'Title']) &&
        TakeString(Value.Destination, Budget, 8_192) &&
        (Value.Title === null || TakeString(Value.Title, Budget, 1_024)) &&
        IsArrayOf(Value.Children, (Child) => IsInline(Child, Nested))
      break
  }
  Leave(Budget, Nested)
  return Valid
}

function IsListItem(
  Value: unknown,
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- Validation updates this parser-local complexity budget.
  Budget: Budget,
): boolean {
  if (
    !Enter(Value, Budget) ||
    !HasOnly(Value, ['Checked', 'Children', 'Range']) ||
    !IsRange(Value.Range) ||
    !(Value.Checked === null || typeof Value.Checked === 'boolean')
  )
    return false
  const Nested = { ...Budget, Depth: Budget.Depth + 1 }
  const Valid = IsArrayOf(Value.Children, (Child) => IsBlock(Child, Nested))
  Leave(Budget, Nested)
  return Valid
}

function IsTableRow(
  Value: unknown,
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- Validation updates this parser-local complexity budget.
  Budget: Budget,
): boolean {
  if (
    !Enter(Value, Budget) ||
    !HasOnly(Value, ['Cells', 'Range']) ||
    !IsRange(Value.Range) ||
    !Array.isArray(Value.Cells) ||
    Value.Cells.length > 1_024
  )
    return false
  const Nested = { ...Budget, Depth: Budget.Depth + 1 }
  const Valid = Value.Cells.every((Cell) => IsArrayOf(Cell, (Inline) => IsInline(Inline, Nested)))
  Leave(Budget, Nested)
  return Valid
}

function IsFileBeltReference(Value: unknown): boolean {
  return (
    IsRecord(Value) &&
    HasOnly(
      Value,
      Value.VersionId === undefined ? ['DriveId', 'NodeId'] : ['DriveId', 'NodeId', 'VersionId'],
    ) &&
    IsUuid(Value.DriveId) &&
    IsUuid(Value.NodeId) &&
    (Value.VersionId === undefined || IsUuid(Value.VersionId))
  )
}

function IsRange(Value: unknown): Value is SourceRange {
  return (
    IsRecord(Value) &&
    HasOnly(Value, ['End', 'Start']) &&
    Number.isSafeInteger(Value.Start) &&
    Number.isSafeInteger(Value.End) &&
    Number(Value.Start) >= 0 &&
    Number(Value.End) >= Number(Value.Start) &&
    Number(Value.End) <= MaximumStringUnits
  )
}

function Enter(
  Value: unknown,
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- Validation updates this parser-local complexity budget.
  Budget: Budget,
): Value is Record<string, unknown> {
  if (!IsRecord(Value) || Budget.Depth >= MaximumDepth || Budget.Nodes >= MaximumNodes) return false
  Budget.Nodes += 1
  return true
}

function Leave(
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- This merges parser-local mutable budget state.
  Budget: Budget,
  Nested: Readonly<Budget>,
): void {
  Budget.Nodes = Nested.Nodes
  Budget.StringUnits = Nested.StringUnits
}

function TakeString(
  Value: unknown,
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- Validation updates this parser-local complexity budget.
  Budget: Budget,
  Maximum = MaximumStringUnits,
): Value is string {
  if (typeof Value !== 'string' || Value.length > Maximum || Value.includes('\0')) return false
  Budget.StringUnits += Value.length
  return Budget.StringUnits <= MaximumStringUnits
}

function IsArrayOf(Value: unknown, Predicate: (Item: unknown) => boolean): boolean {
  return Array.isArray(Value) && Value.length <= MaximumNodes && Value.every(Predicate)
}

function IsRecord(Value: unknown): Value is Record<string, unknown> {
  return typeof Value === 'object' && Value !== null && !Array.isArray(Value)
}

function HasOnly(Value: Readonly<Record<string, unknown>>, Keys: readonly string[]): boolean {
  const Actual = Object.keys(Value)
  return Actual.length === Keys.length && Actual.every((Key) => Keys.includes(Key))
}

function IsOneOf(Value: unknown, Allowed: readonly string[]): boolean {
  return typeof Value === 'string' && Allowed.includes(Value)
}

function IsUuid(Value: unknown): Value is string {
  return (
    typeof Value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(Value)
  )
}
