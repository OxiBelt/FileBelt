// SPDX-License-Identifier: Apache-2.0

export interface MermaidRenderOptions {
  DiagramId: string
  Source: string
}

export interface MermaidRenderBudget {
  Reserve(): void
}

// Mermaid's dynamic module, render result, and initialize options retain its public key spellings.
interface MermaidRenderer {
  initialize(Options: MermaidSecurityOptions): void
  render(Id: string, Source: string): Promise<Record<'svg', string>>
}

export type MermaidModule = Partial<Record<'default', MermaidRenderer>>
export type MermaidSecurityOptions = Record<'flowchart', Record<'htmlLabels', false>> &
  Record<'securityLevel', 'strict'> &
  Record<'startOnLoad', false>

interface KaTeXRenderer {
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- This preserves KaTeX's public dynamic-module contract.
  renderToString(Expression: string, Options: KaTeXRenderOptions): string
}

export type KaTeXModule = Partial<Record<'default', KaTeXRenderer>>
// KaTeX renders with these public option keys; local type names remain PascalCase.
type KaTeXRenderOptions = Record<'macros', Record<string, never>> &
  Record<'throwOnError', false> &
  Record<'trust', false>

export type OfficeImportSourceType =
  | 'csv'
  | 'docx'
  | 'odp'
  | 'ods'
  | 'odt'
  | 'pptx'
  | 'rtf'
  | 'xlsx'

export interface OfficeImportOptions {
  Contents: Uint8Array
  MaximumInputBytes?: number
  MaximumOutputBytes?: number
  Signal?: AbortSignal
  SourceType: OfficeImportSourceType
}

// officeparser/slim defines these conversion option and result keys.
type OfficeParserMessage = Record<'code', string> &
  Record<'message', string> &
  Record<'type', string>
type OfficeParserResult = Record<'messages', readonly OfficeParserMessage[]> &
  Record<'value', string>
type OfficeGeneratorConfig = Record<'ignoreInternalLinks', true> &
  Record<'includeCharts', false> &
  Record<'includeImages', false>
type OfficeDecompressionLimits = Record<'maxTableCells', 100_000> &
  Record<'maxUncompressedBytes', number> &
  Record<'maxZipEntries', 4_096>
type OfficeParseConfig = Partial<Record<'abortSignal', AbortSignal>> &
  Record<'decompressionLimits', OfficeDecompressionLimits> &
  Record<'extractAttachments', false> &
  Record<'fileType', OfficeImportSourceType> &
  Record<'ignoreInternalLinks', true> &
  Record<'includeRawContent', false> &
  Record<'ocr', false>
type OfficeParserOptions = Record<'generatorConfig', OfficeGeneratorConfig> &
  Record<'parseConfig', OfficeParseConfig>

export interface OfficeImportModule {
  convert(
    // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- This preserves officeparser's public dynamic-module contract.
    Contents: Uint8Array,
    Destination: 'md',
    // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- This preserves officeparser's public dynamic-module contract.
    Options: OfficeParserOptions,
  ): Promise<OfficeParserResult>
}

export function CreateMermaidRenderBudget(MaximumDiagrams = 50): MermaidRenderBudget {
  let Rendered = 0
  return {
    Reserve(): void {
      Rendered += 1
      if (Rendered > MaximumDiagrams)
        throw new RangeError('Markdown preview exceeds 50 Mermaid diagrams.')
    },
  }
}

export async function RenderMermaid(
  LoadMermaid: () => Promise<MermaidModule>,
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- The dynamic Mermaid API accepts its mutable public options shape.
  Options: MermaidRenderOptions,
  Budget = CreateMermaidRenderBudget(),
): Promise<string> {
  if (new TextEncoder().encode(Options.Source).byteLength > 64 * 1024)
    throw new RangeError('Mermaid source exceeds 64 KiB.')
  if (CountMermaidEdges(Options.Source) > 500)
    throw new RangeError('Mermaid diagram exceeds 500 edges.')
  if (/^\s*click\b/im.test(Options.Source))
    throw new RangeError('Mermaid click directives are not permitted.')
  Budget.Reserve()
  const Mermaid = (await LoadMermaid()).default
  if (Mermaid === undefined) throw new Error('Mermaid module has no default export.')
  Mermaid.initialize({
    flowchart: { htmlLabels: false },
    securityLevel: 'strict',
    startOnLoad: false,
  })
  return (await Mermaid.render(Options.DiagramId, Options.Source)).svg
}

export async function RenderKaTeX(
  LoadKaTeX: () => Promise<KaTeXModule>,
  Expression: string,
): Promise<string> {
  const KaTeX = (await LoadKaTeX()).default
  if (KaTeX === undefined) throw new Error('KaTeX module has no default export.')
  return KaTeX.renderToString(Expression, { macros: {}, throwOnError: false, trust: false })
}

export function OfficeImportType(Name: string): OfficeImportSourceType | null {
  const Extension = /\.([^.]+)$/.exec(Name)?.[1]?.toLocaleLowerCase()
  return Extension !== undefined && IsOfficeImportSourceType(Extension) ? Extension : null
}

export async function ImportOfficeMarkdown(
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- The exported import API preserves its public mutable byte-buffer shape.
  Options: OfficeImportOptions,
  LoadOfficeImporter: () => Promise<OfficeImportModule> = async () => import('officeparser/slim'),
): Promise<string> {
  const MaximumInputBytes = Options.MaximumInputBytes ?? 8 * 1024 * 1024
  const MaximumOutputBytes = Options.MaximumOutputBytes ?? 2 * 1024 * 1024
  if (Options.Contents.byteLength > MaximumInputBytes)
    throw new RangeError('Office import exceeds the 8 MiB browser input limit.')
  const Result = await (
    await LoadOfficeImporter()
  ).convert(Options.Contents, 'md', {
    generatorConfig: { ignoreInternalLinks: true, includeCharts: false, includeImages: false },
    parseConfig: {
      ...(Options.Signal === undefined ? {} : { abortSignal: Options.Signal }),
      decompressionLimits: {
        maxTableCells: 100_000,
        maxUncompressedBytes: 64 * 1024 * 1024,
        maxZipEntries: 4_096,
      },
      extractAttachments: false,
      fileType: Options.SourceType,
      ignoreInternalLinks: true,
      includeRawContent: false,
      ocr: false,
    },
  })
  if (typeof Result.value !== 'string' || Result.messages.length > 0) {
    throw new Error(
      Result.messages[0]?.message ?? 'The Office document could not be converted safely.',
    )
  }
  if (Result.value.includes('\0')) throw new Error('Converted Markdown contains a NUL byte.')
  if (new TextEncoder().encode(Result.value).byteLength > MaximumOutputBytes)
    throw new RangeError('Converted Markdown exceeds the 2 MiB editor limit.')
  return Result.value
}

function CountMermaidEdges(Source: string): number {
  return Source.split('\n').filter((Line) => /(?:-->|---|-.->|==>)/.test(Line)).length
}

function IsOfficeImportSourceType(Value: string): Value is OfficeImportSourceType {
  return (
    Value === 'csv' ||
    Value === 'docx' ||
    Value === 'odp' ||
    Value === 'ods' ||
    Value === 'odt' ||
    Value === 'pptx' ||
    Value === 'rtf' ||
    Value === 'xlsx'
  )
}
