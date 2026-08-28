// SPDX-License-Identifier: Apache-2.0

import { IsReleaseTag, SourceUrl, type ImagePlanSource, type ImagePlatform } from './image-plan.js'

/** Copyleft adapter artifacts have a separate, release-aware publication plan. */
export const AdapterImagePlanSchemaVersion = 3 as const
export const AdapterAmd64IsaBaseline = 'x86-64-v3' as const

export const AdapterImageRoles = [
  'filebelt-smb-gateway',
  'filebelt-ftp-ftps-gateway',
  'filebelt-onlyoffice-adapter',
  'filebelt-git-adapter',
  'filebelt-nfs-gateway',
  'filebelt-transcoder',
  'filebelt-wireguard-init',
] as const

export type AdapterImageRole = (typeof AdapterImageRoles)[number]
export type AdapterQualificationState = 'blocked' | 'pending' | 'qualified'
export type AdapterPublicationDecision = 'blocked' | 'eligible'
export type AdapterComponentRelationship =
  | 'build-only'
  | 'copied'
  | 'external'
  | 'linked'
  | 'separate-executable'

/* oxlint-disable filebelt/pascal-case -- Stable adapter plan schema v3 JSON keys. */
export interface AdapterComponent {
  readonly id: string
  readonly version: string
  readonly license: string
  readonly relationship: AdapterComponentRelationship
  readonly path: string
  readonly sourceRequired: boolean
}

export interface AdapterEvidenceNames {
  readonly imageValidation: string
  readonly runtimeSbom: string
  readonly buildSbom: string
  readonly vulnerabilityDecision: string
  readonly provenance: string
  readonly rebuild: string
  readonly notices: string
}

export interface AdapterQualification {
  readonly license: AdapterQualificationState
  readonly source: AdapterQualificationState
  readonly security: AdapterQualificationState
  readonly functional: AdapterQualificationState
  readonly platform: AdapterQualificationState
}

export interface AdapterPreImageQualification {
  readonly sourceBundle: 'blocked' | 'qualified'
  readonly dependencyCompatibility: 'blocked' | 'qualified'
  readonly componentPolicy: 'blocked' | 'qualified'
  readonly licenseNotices: 'blocked' | 'qualified'
  readonly buildInputs: 'blocked' | 'qualified'
  readonly immutableSource: 'blocked' | 'qualified'
  readonly buildContext: 'blocked' | 'qualified'
}

export interface AdapterImageBuildDecision {
  readonly state: AdapterPublicationDecision
  readonly blockingReasons: readonly string[]
}

export interface AdapterPublication {
  readonly state: AdapterPublicationDecision
  readonly blockingReasons: readonly string[]
}

export interface AdapterSourceBundle {
  readonly assetName: string
  readonly publicUrl: string
  readonly sha256: string | null
}

export interface AdapterImageEvidence {
  readonly role: AdapterImageRole
  readonly repository: `ghcr.io/oxibelt/${AdapterImageRole}`
  readonly version: string
  readonly source: {
    readonly url: typeof SourceUrl
    readonly ref: string
    readonly revision: string
  }
  readonly firstPartyLicense: string
  readonly imageLicense: string
  readonly platforms: readonly ImagePlatform[]
  readonly riscv64Policy: 'not-supported' | 'compile-and-probe-only' | 'publish-native'
  readonly build: {
    readonly dockerfile: string
    readonly context: '.'
    readonly stagedInputs: string
    readonly platformArguments: Readonly<
      Partial<Record<ImagePlatform, Readonly<Record<string, string>>>>
    >
  }
  readonly executablePaths: readonly string[]
  readonly entrypoint: string
  readonly components: readonly AdapterComponent[]
  readonly sourceBundle: AdapterSourceBundle
  readonly licenseTexts: readonly string[]
  readonly notices: readonly string[]
  readonly evidence: AdapterEvidenceNames
  readonly preImage: AdapterPreImageQualification
  readonly qualification: AdapterQualification
  readonly imageBuild: AdapterImageBuildDecision
  readonly publication: AdapterPublication
}

export interface AdapterImagePlanV3 {
  readonly schemaVersion: typeof AdapterImagePlanSchemaVersion
  readonly amd64IsaBaseline: typeof AdapterAmd64IsaBaseline
  readonly version: string
  readonly source: ImagePlanSource
  readonly roles: readonly AdapterImageEvidence[]
}

export interface AdapterRoleQualificationInput {
  readonly sourceBundleSha256?: string
  readonly preImage?: Partial<AdapterPreImageQualification>
  readonly qualification?: Partial<
    Pick<AdapterQualification, 'security' | 'functional' | 'platform'>
  >
  readonly blockingReasons?: readonly string[]
  readonly platformBuildArguments?: Readonly<
    Partial<Record<ImagePlatform, Readonly<Record<string, string>>>>
  >
}

export interface CreateAdapterImagePlanInput {
  readonly Version: string
  readonly Source: ImagePlanSource
  readonly Evidence?: Partial<Record<AdapterImageRole, AdapterRoleQualificationInput>>
}
/* oxlint-enable filebelt/pascal-case */

interface AdapterCatalogRow {
  readonly Role: AdapterImageRole
  readonly Path: 'smb' | 'ftp-ftps' | 'onlyoffice' | 'git' | 'nfs' | 'transcode' | 'wireguard'
  readonly FirstPartyLicense: string
  readonly ImageLicense: string
  readonly Platforms: readonly ImagePlatform[]
  readonly Riscv64Policy: AdapterImageEvidence['riscv64Policy']
  readonly ExecutablePaths: readonly string[]
  readonly Entrypoint: string
  readonly Components: readonly AdapterComponent[]
  readonly DefaultQualification: AdapterQualification
  readonly DefaultReasons: readonly string[]
  readonly RequiredBuildArguments: readonly string[] | null
}

type MutableAdapterRoleQualificationInput = {
  -readonly [
    Property in keyof AdapterRoleQualificationInput
  ]: AdapterRoleQualificationInput[Property]
}

const Pending: AdapterQualificationState = 'pending'
const Blocked: AdapterQualificationState = 'blocked'
const BlockedPreImage: AdapterPreImageQualification = {
  sourceBundle: 'blocked',
  dependencyCompatibility: 'blocked',
  componentPolicy: 'blocked',
  licenseNotices: 'blocked',
  buildInputs: 'blocked',
  immutableSource: 'blocked',
  buildContext: 'blocked',
}

const AdapterCatalog: readonly AdapterCatalogRow[] = [
  {
    Role: 'filebelt-smb-gateway',
    Path: 'smb',
    FirstPartyLicense: 'GPL-3.0-or-later',
    ImageLicense: 'GPL-3.0-or-later',
    Platforms: ['linux/amd64', 'linux/arm64'],
    Riscv64Policy: 'not-supported',
    ExecutablePaths: [
      '/usr/sbin/smbd',
      '/usr/lib/FILEBELT_VFS.so',
      '/usr/local/bin/filebelt-smb-bridge',
    ],
    Entrypoint: '/usr/sbin/smbd',
    Components: [
      {
        id: 'filebelt-smb-bridge',
        version: '0.1.0',
        license: 'GPL-3.0-or-later',
        relationship: 'linked',
        path: '/usr/local/bin/filebelt-smb-bridge',
        sourceRequired: true,
      },
      {
        id: 'filebelt-vfs-protocol',
        version: '0.1.0',
        license: 'Apache-2.0',
        relationship: 'linked',
        path: '/usr/local/bin/filebelt-smb-bridge',
        sourceRequired: true,
      },
      {
        id: 'samba-4.24.6',
        version: '4.24.6',
        license: 'GPL-3.0-or-later',
        relationship: 'linked',
        path: '/usr/lib/FILEBELT_VFS.so',
        sourceRequired: true,
      },
    ],
    DefaultQualification: {
      license: Pending,
      source: Pending,
      security: Pending,
      functional: Blocked,
      platform: Pending,
    },
    DefaultReasons: ['Samba source closure and bridge functional qualification are incomplete'],
    RequiredBuildArguments: null,
  },
  {
    Role: 'filebelt-ftp-ftps-gateway',
    Path: 'ftp-ftps',
    FirstPartyLicense: 'GPL-3.0-or-later',
    ImageLicense: 'GPL-3.0-or-later',
    Platforms: ['linux/amd64', 'linux/arm64'],
    Riscv64Policy: 'not-supported',
    ExecutablePaths: ['/filebelt-ftp-ftps-gateway'],
    Entrypoint: '/filebelt-ftp-ftps-gateway',
    Components: [
      {
        id: 'filebelt-ftp-ftps-gateway',
        version: '0.1.0',
        license: 'GPL-3.0-or-later',
        relationship: 'linked',
        path: '/filebelt-ftp-ftps-gateway',
        sourceRequired: true,
      },
      {
        id: 'filebelt-vfs-protocol',
        version: '0.1.0',
        license: 'Apache-2.0',
        relationship: 'linked',
        path: '/filebelt-ftp-ftps-gateway',
        sourceRequired: true,
      },
      {
        id: 'libunftp',
        version: '0.23.0',
        license: 'Apache-2.0 OR MIT',
        relationship: 'linked',
        path: '/filebelt-ftp-ftps-gateway',
        sourceRequired: true,
      },
    ],
    DefaultQualification: {
      license: Pending,
      source: Pending,
      security: Pending,
      functional: Blocked,
      platform: Pending,
    },
    DefaultReasons: ['FTPS certificate and end-to-end functional qualification are incomplete'],
    RequiredBuildArguments: null,
  },
  {
    Role: 'filebelt-onlyoffice-adapter',
    Path: 'onlyoffice',
    FirstPartyLicense: 'AGPL-3.0-only',
    ImageLicense: 'AGPL-3.0-only',
    Platforms: ['linux/amd64', 'linux/arm64'],
    Riscv64Policy: 'compile-and-probe-only',
    ExecutablePaths: ['/filebelt-onlyoffice-adapter'],
    Entrypoint: '/filebelt-onlyoffice-adapter',
    Components: [
      {
        id: 'filebelt-onlyoffice-adapter',
        version: '0.1.0',
        license: 'AGPL-3.0-only',
        relationship: 'linked',
        path: '/filebelt-onlyoffice-adapter',
        sourceRequired: true,
      },
      {
        id: 'filebelt-document-protocol',
        version: '0.1.0',
        license: 'Apache-2.0',
        relationship: 'linked',
        path: '/filebelt-onlyoffice-adapter',
        sourceRequired: true,
      },
      {
        id: 'filebelt-onlyoffice-launcher',
        version: '0.1.0',
        license: 'AGPL-3.0-only',
        relationship: 'copied',
        path: '/filebelt-onlyoffice-adapter',
        sourceRequired: true,
      },
      {
        id: 'onlyoffice-docs-community-9.4.0',
        version: '9.4.0',
        license: 'AGPL-3.0-only',
        relationship: 'external',
        path: 'external://operator-supplied/onlyoffice-docs',
        sourceRequired: false,
      },
    ],
    DefaultQualification: {
      license: Pending,
      source: Pending,
      security: Pending,
      functional: Pending,
      platform: Pending,
    },
    DefaultReasons: [
      'browser, source-offer, security, and native platform evidence are incomplete',
    ],
    RequiredBuildArguments: ['FILEBELT_ONLYOFFICE_BUILDER_IMAGE', 'RUST_TARGET'],
  },
  {
    Role: 'filebelt-git-adapter',
    Path: 'git',
    FirstPartyLicense: 'Apache-2.0',
    ImageLicense: 'Apache-2.0 AND GPL-2.0-only AND MIT AND Zlib',
    Platforms: ['linux/amd64', 'linux/arm64'],
    Riscv64Policy: 'not-supported',
    ExecutablePaths: ['/usr/local/bin/filebelt-git-adapter', '/opt/filebelt-git/bin/git'],
    Entrypoint: '/usr/local/bin/filebelt-git-adapter',
    Components: [
      {
        id: 'filebelt-git-adapter',
        version: '0.1.0',
        license: 'Apache-2.0',
        relationship: 'linked',
        path: '/usr/local/bin/filebelt-git-adapter',
        sourceRequired: true,
      },
      {
        id: 'filebelt-revision-protocol',
        version: '0.1.0',
        license: 'Apache-2.0',
        relationship: 'linked',
        path: '/usr/local/bin/filebelt-git-adapter',
        sourceRequired: true,
      },
      {
        id: 'git-2.55.0',
        version: '2.55.0',
        license: 'GPL-2.0-only',
        relationship: 'separate-executable',
        path: '/opt/filebelt-git/bin/git',
        sourceRequired: true,
      },
      {
        id: 'zlib-1.3.1',
        version: '1.3.1',
        license: 'Zlib',
        relationship: 'linked',
        path: '/opt/filebelt-git/bin/git',
        sourceRequired: true,
      },
    ],
    DefaultQualification: {
      license: Pending,
      source: Pending,
      security: Pending,
      functional: Blocked,
      platform: Pending,
    },
    DefaultReasons: [
      'Git restore, fsck, security, and native platform qualification are incomplete',
    ],
    RequiredBuildArguments: ['FILEBELT_GIT_BUILDER_IMAGE', 'RUST_TARGET', 'ZLIB_TARBALL_SHA256'],
  },
  {
    Role: 'filebelt-nfs-gateway',
    Path: 'nfs',
    FirstPartyLicense: 'LGPL-3.0-or-later',
    ImageLicense: 'LGPL-3.0-or-later',
    Platforms: ['linux/amd64', 'linux/arm64', 'linux/riscv64'],
    Riscv64Policy: 'publish-native',
    ExecutablePaths: [
      '/usr/bin/ganesha.nfsd',
      '/usr/lib/FILEBELT.so',
      '/usr/local/bin/filebelt-nfs-bridge',
    ],
    Entrypoint: '/usr/bin/ganesha.nfsd',
    Components: [
      {
        id: 'filebelt-nfs-bridge',
        version: '0.1.0',
        license: 'LGPL-3.0-or-later',
        relationship: 'linked',
        path: '/usr/local/bin/filebelt-nfs-bridge',
        sourceRequired: true,
      },
      {
        id: 'filebelt-vfs-protocol',
        version: '0.1.0',
        license: 'Apache-2.0',
        relationship: 'linked',
        path: '/usr/local/bin/filebelt-nfs-bridge',
        sourceRequired: true,
      },
      {
        id: 'filebelt-nfs-fsal',
        version: '0.1.0',
        license: 'LGPL-3.0-or-later',
        relationship: 'linked',
        path: '/usr/lib/FILEBELT.so',
        sourceRequired: true,
      },
      {
        id: 'nfs-ganesha-6.5-8',
        version: '6.5-8',
        license: 'LGPL-3.0-or-later',
        relationship: 'separate-executable',
        path: '/usr/bin/ganesha.nfsd',
        sourceRequired: true,
      },
      {
        id: 'ntirpc',
        version: '6.3-4',
        license: 'BSD-3-Clause',
        relationship: 'linked',
        path: '/usr/bin/ganesha.nfsd',
        sourceRequired: true,
      },
    ],
    DefaultQualification: {
      license: Pending,
      source: Pending,
      security: Pending,
      functional: Blocked,
      platform: Blocked,
    },
    DefaultReasons: [
      'NFS ABI, Kerberos, functional, and native platform qualification are incomplete',
    ],
    RequiredBuildArguments: null,
  },
  {
    Role: 'filebelt-transcoder',
    Path: 'transcode',
    FirstPartyLicense: 'GPL-3.0-or-later',
    ImageLicense: 'GPL-3.0-or-later',
    Platforms: ['linux/amd64', 'linux/arm64'],
    Riscv64Policy: 'compile-and-probe-only',
    ExecutablePaths: ['/usr/local/bin/filebelt-transcoder', '/usr/local/bin/ffmpeg'],
    Entrypoint: '/usr/local/bin/filebelt-transcoder',
    Components: [
      {
        id: 'filebelt-transcoder',
        version: '0.1.0',
        license: 'GPL-3.0-or-later',
        relationship: 'linked',
        path: '/usr/local/bin/filebelt-transcoder',
        sourceRequired: true,
      },
      {
        id: 'libaom',
        version: '3.14.1',
        license: 'BSD-2-Clause',
        relationship: 'linked',
        path: '/usr/local/bin/ffmpeg',
        sourceRequired: true,
      },
      {
        id: 'libvpx',
        version: '1.16.0',
        license: 'BSD-3-Clause',
        relationship: 'linked',
        path: '/usr/local/bin/ffmpeg',
        sourceRequired: true,
      },
      {
        id: 'opus',
        version: '1.5.2',
        license: 'BSD-3-Clause',
        relationship: 'linked',
        path: '/usr/local/bin/ffmpeg',
        sourceRequired: true,
      },
      {
        id: 'ffmpeg-8.1.2',
        version: '8.1.2',
        license: 'GPL-3.0-or-later',
        relationship: 'separate-executable',
        path: '/usr/local/bin/ffmpeg',
        sourceRequired: true,
      },
    ],
    DefaultQualification: {
      license: Pending,
      source: Pending,
      security: Pending,
      functional: Blocked,
      platform: Pending,
    },
    DefaultReasons: [
      'codec inventory, malicious-input, performance, and native platform qualification are incomplete',
    ],
    RequiredBuildArguments: null,
  },
  {
    Role: 'filebelt-wireguard-init',
    Path: 'wireguard',
    FirstPartyLicense: 'Apache-2.0',
    ImageLicense: 'Apache-2.0 AND GPL-2.0-only AND MIT',
    Platforms: ['linux/amd64', 'linux/arm64', 'linux/riscv64'],
    Riscv64Policy: 'publish-native',
    ExecutablePaths: [
      '/usr/local/bin/filebelt-wireguard-init',
      '/usr/local/bin/wg',
      '/usr/local/bin/ip',
    ],
    Entrypoint: '/usr/local/bin/filebelt-wireguard-init',
    Components: [
      {
        id: 'filebelt-wireguard-init',
        version: '0.1.0',
        license: 'Apache-2.0',
        relationship: 'linked',
        path: '/usr/local/bin/filebelt-wireguard-init',
        sourceRequired: true,
      },
      {
        id: 'wireguard-tools',
        version: '1.0.20260223',
        license: 'GPL-2.0-only',
        relationship: 'separate-executable',
        path: '/usr/local/bin/wg',
        sourceRequired: true,
      },
      {
        id: 'iproute2',
        version: '7.1.0',
        license: 'GPL-2.0-only',
        relationship: 'separate-executable',
        path: '/usr/local/bin/ip',
        sourceRequired: true,
      },
      {
        id: 'musl',
        version: '1.2.5',
        license: 'MIT',
        relationship: 'linked',
        path: '/usr/local/bin/filebelt-wireguard-init',
        sourceRequired: true,
      },
    ],
    DefaultQualification: {
      license: Blocked,
      source: Blocked,
      security: Blocked,
      functional: Blocked,
      platform: Blocked,
    },
    DefaultReasons: [
      'WireGuard source, security, functional, and native platform qualification are incomplete',
    ],
    RequiredBuildArguments: ['FILEBELT_WIREGUARD_BUILDER_IMAGE', 'RUST_TARGET'],
  },
] as const

const Sha256Pattern = /^[0-9a-f]{64}$/u
const RevisionPattern = /^[0-9a-f]{40}$/u

export function CreateAdapterImagePlan(Input: CreateAdapterImagePlanInput): AdapterImagePlanV3 {
  ValidateSource(Input.Version, Input.Source)
  ValidateEvidenceInput(Input.Evidence)
  const Roles = AdapterCatalog.map((Catalog): AdapterImageEvidence => {
    const Supplied = Input.Evidence?.[Catalog.Role]
    const PlatformArguments = NormalizePlatformBuildArguments(
      Catalog,
      Supplied?.platformBuildArguments,
    )
    const PreImage = { ...BlockedPreImage, ...Supplied?.preImage }
    const AssetName = `${Catalog.Role}-source-${Input.Version}.tar.gz`
    const SourceBundleSha256 = Supplied?.sourceBundleSha256 ?? null
    if (SourceBundleSha256 !== null && !Sha256Pattern.test(SourceBundleSha256)) {
      throw new Error(
        `${Catalog.Role} source-bundle SHA-256 must be 64 lowercase hexadecimal characters`,
      )
    }
    if (PreImage.sourceBundle === 'qualified' && SourceBundleSha256 === null) {
      throw new Error(`${Catalog.Role} cannot qualify a source bundle without its SHA-256`)
    }
    const LicenseQualified = [
      PreImage.dependencyCompatibility,
      PreImage.componentPolicy,
      PreImage.licenseNotices,
    ].every((State) => State === 'qualified')
    const SourceQualified =
      [
        PreImage.sourceBundle,
        PreImage.buildInputs,
        PreImage.immutableSource,
        PreImage.buildContext,
      ].every((State) => State === 'qualified') && SourceBundleSha256 !== null
    const Qualification: AdapterQualification = {
      ...Catalog.DefaultQualification,
      ...Supplied?.qualification,
      license: LicenseQualified ? 'qualified' : 'blocked',
      source: SourceQualified ? 'qualified' : 'blocked',
    }
    const ImageBuildReasons = ImageBuildBlockingReasons(
      PreImage,
      SourceBundleSha256,
      Catalog.RequiredBuildArguments !== null,
      PlatformArguments,
      Catalog.Platforms,
    )
    const PublicationReasons = PublicationBlockingReasons(Qualification, SourceBundleSha256)
    const EvidencePrefix = `${Catalog.Role}-${Input.Version}`
    return {
      role: Catalog.Role,
      repository: `ghcr.io/oxibelt/${Catalog.Role}`,
      version: Input.Version,
      source: { url: SourceUrl, ref: Input.Source.ref, revision: Input.Source.revision },
      firstPartyLicense: Catalog.FirstPartyLicense,
      imageLicense: Catalog.ImageLicense,
      platforms: Catalog.Platforms,
      riscv64Policy: Catalog.Riscv64Policy,
      build: {
        dockerfile: `adapters/${Catalog.Path}/Dockerfile`,
        context: '.',
        stagedInputs: `adapter-inputs/${Catalog.Path}`,
        platformArguments: PlatformArguments,
      },
      executablePaths: Catalog.ExecutablePaths,
      entrypoint: Catalog.Entrypoint,
      components: Catalog.Components,
      sourceBundle: {
        assetName: AssetName,
        publicUrl: `https://github.com/OxiBelt/FileBelt/releases/download/${Input.Version}/${AssetName}`,
        sha256: SourceBundleSha256,
      },
      licenseTexts: [`adapters/${Catalog.Path}/LICENSE`],
      notices: [`adapters/${Catalog.Path}/THIRD_PARTY_NOTICES.md`],
      evidence: {
        imageValidation: `${EvidencePrefix}-image-validation.json`,
        runtimeSbom: `${EvidencePrefix}-runtime.cdx.json`,
        buildSbom: `${EvidencePrefix}-build.cdx.json`,
        vulnerabilityDecision: `${EvidencePrefix}-vulnerability-decision.json`,
        provenance: `${EvidencePrefix}-provenance.intoto.jsonl`,
        rebuild: `${EvidencePrefix}-rebuild.json`,
        notices: `${EvidencePrefix}-notices.tar.gz`,
      },
      preImage: PreImage,
      qualification: Qualification,
      imageBuild: {
        state: ImageBuildReasons.length === 0 ? 'eligible' : 'blocked',
        blockingReasons: ImageBuildReasons,
      },
      publication: {
        state: PublicationReasons.length === 0 ? 'eligible' : 'blocked',
        blockingReasons:
          PublicationReasons.length === 0
            ? []
            : [
                ...Catalog.DefaultReasons,
                ...(Supplied?.blockingReasons ?? []),
                ...PublicationReasons,
              ],
      },
    }
  })
  const Plan = {
    schemaVersion: AdapterImagePlanSchemaVersion,
    amd64IsaBaseline: AdapterAmd64IsaBaseline,
    version: Input.Version,
    source: Input.Source,
    roles: Roles,
  } as const
  return Plan
}

function ValidateEvidenceInput(
  Evidence: Partial<Record<AdapterImageRole, AdapterRoleQualificationInput>> | undefined,
): void {
  /* oxlint-disable typescript/no-unsafe-type-assertion -- Runtime validation rejects unknown adapter roles before catalog lookup. */
  if (Evidence === undefined) return
  if (!IsRecord(Evidence)) throw new Error('adapter qualification evidence must be an object')
  for (const [Role, Value] of Object.entries(Evidence)) {
    if (!AdapterImageRoles.includes(Role as AdapterImageRole)) {
      throw new Error(`adapter qualification evidence contains unknown role ${Role}`)
    }
    if (!IsRecord(Value)) throw new Error(`${Role} qualification evidence must be an object`)
    for (const Name of Object.keys(Value)) {
      if (
        !new Set([
          'sourceBundleSha256',
          'preImage',
          'qualification',
          'blockingReasons',
          'platformBuildArguments',
        ]).has(Name)
      ) {
        throw new Error(`${Role} qualification evidence contains unknown property ${Name}`)
      }
    }
    if (
      Value.sourceBundleSha256 !== undefined &&
      (typeof Value.sourceBundleSha256 !== 'string' ||
        !Sha256Pattern.test(Value.sourceBundleSha256))
    ) {
      throw new Error(`${Role} sourceBundleSha256 must be lowercase SHA-256`)
    }
    if (
      Value.blockingReasons !== undefined &&
      (!Array.isArray(Value.blockingReasons) || !CustomStrings(Value.blockingReasons))
    ) {
      throw new Error(`${Role} blockingReasons must be non-empty strings`)
    }
    if (Value.platformBuildArguments !== undefined && !IsRecord(Value.platformBuildArguments)) {
      throw new Error(`${Role} platformBuildArguments must be an object`)
    }
    if (Value.qualification !== undefined) {
      if (!IsRecord(Value.qualification)) throw new Error(`${Role} qualification must be an object`)
      for (const [Category, State] of Object.entries(Value.qualification)) {
        if (!new Set(['security', 'functional', 'platform']).has(Category)) {
          throw new Error(`${Role} qualification contains unknown category ${Category}`)
        }
        ReadQualification(State, Role, Category)
      }
    }
    if (Value.preImage !== undefined) {
      if (!IsRecord(Value.preImage)) throw new Error(`${Role} preImage must be an object`)
      const Names = new Set(Object.keys(BlockedPreImage))
      for (const [Name, State] of Object.entries(Value.preImage)) {
        if (!Names.has(Name) || (State !== 'blocked' && State !== 'qualified')) {
          throw new Error(`${Role} preImage contains an invalid ${Name} state`)
        }
      }
    }
  }
  /* oxlint-enable typescript/no-unsafe-type-assertion */
}

export function ValidateAdapterImagePlan(Value: unknown): asserts Value is AdapterImagePlanV3 {
  /* oxlint-disable typescript/no-unsafe-type-assertion -- Exact-key and runtime checks establish the closed adapter image-plan representation. */
  if (!IsRecord(Value) || Value.schemaVersion !== AdapterImagePlanSchemaVersion) {
    throw new Error('adapter image plan schemaVersion must be 3')
  }
  if (!ExactKeys(Value, ['schemaVersion', 'amd64IsaBaseline', 'version', 'source', 'roles'])) {
    throw new Error('adapter image plan top-level properties differ from schema v3')
  }
  if (Value.amd64IsaBaseline !== AdapterAmd64IsaBaseline) {
    throw new Error(`adapter image plan amd64IsaBaseline must be ${AdapterAmd64IsaBaseline}`)
  }
  if (typeof Value.version !== 'string' || !IsReleaseTag(Value.version)) {
    throw new Error('adapter image plan version must be exact SemVer')
  }
  if (!IsRecord(Value.source)) {
    throw new Error('adapter image plan source must be an object')
  }
  if (!ExactKeys(Value.source, ['url', 'ref', 'revision', 'created', 'dirty', 'kind'])) {
    throw new Error('adapter image plan source properties differ from schema v3')
  }
  ValidateSource(Value.version, Value.source as unknown as ImagePlanSource)
  if (!Array.isArray(Value.roles) || Value.roles.length !== AdapterImageRoles.length) {
    throw new Error('adapter image plan must contain exactly six roles')
  }
  const Seen = new Set<string>()
  for (const RoleValue of Value.roles) {
    if (!IsRecord(RoleValue) || !AdapterImageRoles.includes(RoleValue.role as AdapterImageRole)) {
      throw new Error('adapter image plan contains an unknown role')
    }
    const Role = RoleValue.role as AdapterImageRole
    if (Seen.has(Role)) throw new Error(`adapter image plan duplicates ${Role}`)
    Seen.add(Role)
    const Expected = CreateAdapterImagePlan({
      Version: Value.version,
      Source: Value.source as unknown as ImagePlanSource,
      Evidence: {
        [Role]: ExtractEvidence(RoleValue, Role),
      },
    }).roles.find(({ role: CandidateRole }) => CandidateRole === Role)
    if (JSON.stringify(RoleValue) !== JSON.stringify(Expected)) {
      throw new Error(`${Role} does not match the canonical adapter catalog and derived decisions`)
    }
  }
  /* oxlint-enable typescript/no-unsafe-type-assertion */
}

export function SerializeAdapterImagePlan(Plan: AdapterImagePlanV3): string {
  ValidateAdapterImagePlan(Plan)
  return `${JSON.stringify(Plan, null, 2)}\n`
}

function ValidateSource(Version: string, Source: ImagePlanSource): void {
  // oxlint-disable-next-line typescript/no-unnecessary-condition -- This runtime source URL check protects untyped serialized input despite the narrowed internal type.
  if (Source.url !== SourceUrl)
    throw new Error('adapter source URL must be the canonical repository')
  if (!RevisionPattern.test(Source.revision))
    throw new Error('adapter source revision must be a 40-character lowercase Git object ID')
  if (
    typeof Source.created !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(Source.created)
  ) {
    throw new Error('adapter source creation time must be UTC second precision')
  }
  if (
    typeof Source.dirty !== 'boolean' ||
    !['local', 'ci', 'release', 'rebuild'].includes(Source.kind)
  ) {
    throw new Error('adapter source kind or dirty state is invalid')
  }
  if (!IsReleaseTag(Version)) throw new Error('adapter release version must be exact SemVer')
  const ExactTag = `refs/tags/${Version}`
  const ExactCommit = `refs/commits/${Source.revision}`
  if (Source.ref !== ExactTag && Source.ref !== ExactCommit) {
    throw new Error(
      'adapter source ref must be the exact release tag or commit ref; branches are forbidden',
    )
  }
  if (Source.ref === ExactTag && (Source.kind !== 'release' || Source.dirty)) {
    throw new Error('adapter release source must be clean and marked release')
  }
}

function ExtractEvidence(
  Value: Readonly<Record<string, unknown>>,
  Role: AdapterImageRole,
): AdapterRoleQualificationInput {
  /* oxlint-disable typescript/no-unsafe-type-assertion -- Runtime evidence validation establishes the reviewed adapter qualification representation. */
  const Bundle = Value.sourceBundle
  const PreImage = Value.preImage
  const Qualification = Value.qualification
  if (!IsRecord(Bundle) || !IsRecord(PreImage) || !IsRecord(Qualification))
    throw new Error(`${Role} evidence objects are required`)
  const Result: MutableAdapterRoleQualificationInput = {
    preImage: PreImage,
    platformBuildArguments:
      IsRecord(Value.build) && IsRecord(Value.build.platformArguments)
        ? Value.build.platformArguments
        : {},
    qualification: {
      security: ReadQualification(Qualification.security, Role, 'security'),
      functional: ReadQualification(Qualification.functional, Role, 'functional'),
      platform: ReadQualification(Qualification.platform, Role, 'platform'),
    },
  }
  if (Bundle.sha256 !== null) {
    if (typeof Bundle.sha256 !== 'string')
      throw new Error(`${Role} source-bundle SHA-256 is invalid`)
    Result.sourceBundleSha256 = Bundle.sha256
  }
  const Publication = Value.publication
  if (!IsRecord(Publication) || !Array.isArray(Publication.blockingReasons))
    throw new Error(`${Role} publication decision is invalid`)
  const Derived = PublicationBlockingReasons(
    Result.qualification as AdapterQualification,
    Result.sourceBundleSha256 ?? null,
  )
  const Default =
    Derived.length === 0
      ? []
      : (AdapterCatalog.find(({ Role: CandidateRole }) => CandidateRole === Role)?.DefaultReasons ??
        [])
  const Reported = Publication.blockingReasons
  const PrefixLength = Default.length
  const SuffixLength = Derived.length
  const CustomEnd = Reported.length - SuffixLength
  if (CustomEnd < PrefixLength) throw new Error(`${Role} publication reasons are incomplete`)
  const Custom = Reported.slice(PrefixLength, CustomEnd)
  if (!CustomStrings(Custom)) throw new Error(`${Role} publication reasons must be strings`)
  Result.blockingReasons = Custom as string[]
  return Result
  /* oxlint-enable typescript/no-unsafe-type-assertion */
}

function ImageBuildBlockingReasons(
  PreImage: AdapterPreImageQualification,
  BundleSha256: string | null,
  BuildContractImplemented: boolean,
  PlatformArguments: Readonly<Partial<Record<ImagePlatform, Readonly<Record<string, string>>>>>,
  Platforms: readonly ImagePlatform[],
): string[] {
  /* oxlint-disable typescript/no-unsafe-type-assertion -- The qualification object is constructed from the closed adapter catalog. */
  const Reasons: string[] = []
  const Labels: Readonly<Record<keyof AdapterPreImageQualification, string>> = {
    sourceBundle: 'source bundle',
    dependencyCompatibility: 'dependency compatibility',
    componentPolicy: 'component policy',
    licenseNotices: 'license and notice inventory',
    buildInputs: 'build inputs',
    immutableSource: 'immutable source',
    buildContext: 'build context',
  }
  for (const [Name, State] of Object.entries(PreImage) as [
    keyof AdapterPreImageQualification,
    string,
  ][]) {
    if (State !== 'qualified') Reasons.push(`${Labels[Name]} is not qualified`)
  }
  if (BundleSha256 === null) Reasons.push('source bundle checksum is missing')
  if (!BuildContractImplemented) Reasons.push('bundle-image build contract is not implemented')
  if (
    BuildContractImplemented &&
    Platforms.some((Platform) => PlatformArguments[Platform] === undefined)
  ) {
    Reasons.push('digest-bound platform build arguments are incomplete')
  }
  return Reasons
  /* oxlint-enable typescript/no-unsafe-type-assertion */
}

function NormalizePlatformBuildArguments(
  Catalog: AdapterCatalogRow,
  Value: AdapterRoleQualificationInput['platformBuildArguments'],
): Readonly<Partial<Record<ImagePlatform, Readonly<Record<string, string>>>>> {
  /* oxlint-disable typescript/no-unsafe-type-assertion, typescript/no-unnecessary-condition -- Runtime checks preserve validation of untyped platform-build evidence. */
  if (Value === undefined) return {}
  if (!IsRecord(Value)) throw new Error(`${Catalog.Role} platformBuildArguments must be an object`)
  if (Object.keys(Value).length === 0) return {}
  if (Catalog.RequiredBuildArguments === null) {
    throw new Error(`${Catalog.Role} has no qualified bundle-image build contract`)
  }
  const Result: Partial<Record<ImagePlatform, Readonly<Record<string, string>>>> = {}
  for (const Platform of Object.keys(Value).sort()) {
    if (!Catalog.Platforms.includes(Platform as ImagePlatform)) {
      throw new Error(`${Catalog.Role} has build arguments for undeclared platform ${Platform}`)
    }
    const Arguments = Value[Platform as ImagePlatform]
    if (!IsRecord(Arguments) || !ExactKeys(Arguments, Catalog.RequiredBuildArguments)) {
      throw new Error(
        `${Catalog.Role} ${Platform} build arguments differ from the reviewed contract`,
      )
    }
    const Normalized = Object.fromEntries(
      Object.entries(Arguments).sort(([Left], [Right]) => Left.localeCompare(Right)),
    )
    for (const [Name, Argument] of Object.entries(Normalized)) {
      if (typeof Argument !== 'string' || Argument.length === 0) {
        throw new Error(`${Catalog.Role} ${Platform} ${Name} must be a non-empty string`)
      }
    }
    const Builder = Object.entries(Normalized).find(([Name]) =>
      Name.endsWith('_BUILDER_IMAGE'),
    )?.[1]
    if (typeof Builder !== 'string' || !/^\S+@sha256:[0-9a-f]{64}$/u.test(Builder)) {
      throw new Error(`${Catalog.Role} ${Platform} builder image must be digest-pinned`)
    }
    const ExpectedTarget =
      Platform === 'linux/amd64'
        ? 'x86_64-unknown-linux-musl'
        : Platform === 'linux/arm64'
          ? 'aarch64-unknown-linux-musl'
          : Platform === 'linux/riscv64'
            ? 'riscv64gc-unknown-linux-musl'
            : undefined
    if (ExpectedTarget === undefined || Normalized.RUST_TARGET !== ExpectedTarget) {
      throw new Error(`${Catalog.Role} ${Platform} RUST_TARGET is not the reviewed native target`)
    }
    if (
      'ZLIB_TARBALL_SHA256' in Normalized &&
      !Sha256Pattern.test(Normalized.ZLIB_TARBALL_SHA256 ?? '')
    ) {
      throw new Error(`${Catalog.Role} ${Platform} zlib checksum must be lowercase SHA-256`)
    }
    Result[Platform as ImagePlatform] = Normalized
  }
  return Result
  /* oxlint-enable typescript/no-unsafe-type-assertion, typescript/no-unnecessary-condition */
}

function PublicationBlockingReasons(
  Qualification: AdapterQualification,
  BundleSha256: string | null,
): string[] {
  const Reasons: string[] = []
  if (Qualification.license !== 'qualified') Reasons.push('license qualification is not complete')
  if (Qualification.source !== 'qualified' || BundleSha256 === null)
    Reasons.push('source qualification is not complete')
  for (const Category of ['security', 'functional', 'platform'] as const) {
    if (Qualification[Category] !== 'qualified')
      Reasons.push(`${Category} qualification is not complete`)
  }
  Reasons.push('signed-tag adapter subject mapping and promotion are not implemented')
  return Reasons
}

function ReadQualification(
  Value: unknown,
  Role: string,
  Category: string,
): AdapterQualificationState {
  if (Value !== 'blocked' && Value !== 'pending' && Value !== 'qualified') {
    throw new Error(`${Role} ${Category} qualification is invalid`)
  }
  return Value
}

function IsRecord(Value: unknown): Value is Record<string, unknown> {
  return typeof Value === 'object' && Value !== null && !Array.isArray(Value)
}

function ExactKeys(Value: Readonly<Record<string, unknown>>, Names: readonly string[]): boolean {
  return Object.keys(Value).sort().join('\0') === [...Names].sort().join('\0')
}

function CustomStrings(Value: readonly unknown[]): Value is readonly string[] {
  return Value.every((Item) => typeof Item === 'string' && Item.length > 0)
}
