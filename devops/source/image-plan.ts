// SPDX-License-Identifier: Apache-2.0

export const ImagePlanSchemaVersion = 1 as const;
export const ImageRegistry = "ghcr.io/oxibelt" as const;
export const SourceUrl = "https://github.com/OxiBelt/FileBelt" as const;
export const RuntimeIdentity = Object.freeze({ uid: 10001, gid: 10001 });
export const RustImageLicense = "Apache-2.0 AND MIT" as const;
export const RustCdlaImageLicense =
  "Apache-2.0 AND MIT AND CDLA-Permissive-2.0" as const;
export const RustIggyImageLicense =
  "Apache-2.0 AND MIT AND MPL-2.0 AND CDLA-Permissive-2.0" as const;
export const WebImageLicense = "Apache-2.0 AND MIT AND ISC AND 0BSD" as const;
export const OxibeltImage =
  "ghcr.io/oxibelt/oxibelt@sha256:e8556a0103feff47bf6135062e70e980e000176598fd438959ea55d99c844030" as const;
export const OxibeltVersion = "0.7.1-beta.2" as const;
export const OxibeltRevision = "bf40172e40298325775ca9d708162a9d8d14e6d4" as const;

export const ImageRoles = [
  "filebelt-api",
  "filebelt-worker-io",
  "filebelt-worker-maintenance",
  "filebelt-media-controller",
  "filebelt-document",
  "filebelt-collaboration",
  "filebelt-mcp-broker",
  "filebelt-controller",
  "filebelt-mcp-runner",
  "filebelt-tools",
  "filebelt-vfs",
  "filebelt-headscale-sync",
  "filebelt-nfs-relay",
  "filebelt-web",
] as const;

export type ImageRole = (typeof ImageRoles)[number];

export const ImagePlatforms = [
  "linux/amd64",
  "linux/arm64",
  "linux/riscv64",
] as const;

export type ImagePlatform = (typeof ImagePlatforms)[number];
export type ImagePlanChannel = "build" | "release";
export type SourceKind = "local" | "ci" | "release" | "rebuild";
export type ImageLicense =
  | typeof RustImageLicense
  | typeof RustCdlaImageLicense
  | typeof RustIggyImageLicense
  | typeof WebImageLicense;
export type ComponentRelationship = "runtime" | "build-tool";

/* eslint-disable @typescript-eslint/naming-convention -- These properties are stable image-plan schema v1 JSON keys. */
export interface ImageComponent {
  readonly type: "application" | "library";
  readonly name: string;
  readonly version: string;
  readonly purl: string;
  readonly license: string;
  readonly relationship: ComponentRelationship;
  readonly evidence: string;
}

export type PlatformComponentInventory = Readonly<
  Record<ImagePlatform, readonly ImageComponent[]>
>;

export interface ImagePlanSource {
  readonly url: typeof SourceUrl;
  readonly ref: string;
  readonly revision: string;
  readonly created: string;
  readonly dirty: boolean;
  readonly kind: SourceKind;
}

export type ImageArtifact =
  | {
    readonly kind: "rust-binary";
    readonly binary: string;
    readonly components: PlatformComponentInventory;
  }
  | {
    readonly kind: "oxibelt-edge";
    readonly packages: readonly ["ui/web", "ui/markdown"];
    readonly base: {
      readonly image: typeof OxibeltImage;
      readonly version: typeof OxibeltVersion;
      readonly revision: typeof OxibeltRevision;
    };
  };

export interface ImageRow {
  readonly role: ImageRole;
  readonly repository: `ghcr.io/oxibelt/${ImageRole}`;
  readonly title: ImageRole;
  readonly description: string;
  readonly platforms: readonly ImagePlatform[];
  readonly license: ImageLicense;
  readonly build: {
    readonly dockerfile: "source/ops/Dockerfile.roles" | "ui/web/Dockerfile";
    readonly target: ImageRole;
  };
  readonly artifact: ImageArtifact;
}

export interface ImagePlanV1 {
  readonly schemaVersion: typeof ImagePlanSchemaVersion;
  readonly channel: ImagePlanChannel;
  readonly version: string;
  readonly tag: string;
  readonly source: ImagePlanSource;
  readonly runtime: typeof RuntimeIdentity;
  readonly images: readonly ImageRow[];
}
/* eslint-enable @typescript-eslint/naming-convention */

export interface CreateImagePlanInput {
  readonly Channel: ImagePlanChannel;
  readonly Version: string;
  readonly Source: ImagePlanSource;
}

interface RoleDefinition {
  readonly Role: ImageRole;
  readonly Dockerfile: ImageRow["build"]["dockerfile"];
  readonly License: ImageLicense;
  readonly Artifact: ImageArtifact;
}

const RustBuilderEvidence =
  "docker.io/library/rust@sha256:1bcff4befb740599103a2c7cb51058e14479b2e35e3a34a3f0dc4ede09927488";
const NativeSnapshotEvidence =
  "https://snapshot.debian.org/archive/debian/20260713T000000Z";
const Riscv64BuilderSnapshotEvidence =
  "https://snapshot.debian.org/archive/debian/20260713T000000Z";
const Riscv64ToolchainEvidence =
  "ghcr.io/cross-rs/riscv64gc-unknown-linux-musl@sha256:60372bf6ad955bc04ac9b0689476b05955b4e90fc2030d311be687025672cc6d";

const FileBeltPackageVersion = "0.1.0" as const;

const WebpkiRuntimeComponents = [
  Component(
    "library",
    "webpki-roots",
    "0.26.11",
    "pkg:cargo/webpki-roots@0.26.11",
    "CDLA-Permissive-2.0",
    "runtime",
    "Cargo.lock#webpki-roots@0.26.11",
  ),
  Component(
    "library",
    "webpki-roots",
    "1.0.9",
    "pkg:cargo/webpki-roots@1.0.9",
    "CDLA-Permissive-2.0",
    "runtime",
    "Cargo.lock#webpki-roots@1.0.9",
  ),
] as const;

const IggyRuntimeComponents = [
  ...WebpkiRuntimeComponents,
  Component(
    "library",
    "option-ext",
    "0.2.0",
    "pkg:cargo/option-ext@0.2.0",
    "MPL-2.0",
    "runtime",
    "Cargo.lock#option-ext@0.2.0",
  ),
] as const;

const RustPlatformComponents: PlatformComponentInventory = {
  "linux/amd64": NativeComponents("amd64", "x86_64-unknown-linux-musl"),
  "linux/arm64": NativeComponents("arm64", "aarch64-unknown-linux-musl"),
  "linux/riscv64": [
    Component(
      "library",
      "rust-std",
      "1.97.1",
      "pkg:generic/rust-std@1.97.1?target=riscv64gc-unknown-linux-musl",
      "Apache-2.0 OR MIT",
      "runtime",
      RustBuilderEvidence,
    ),
    Component(
      "library",
      "musl",
      "1.2.5",
      "pkg:generic/musl@1.2.5?target=riscv64-unknown-linux-musl",
      "MIT",
      "runtime",
      Riscv64ToolchainEvidence,
    ),
    Component(
      "application",
      "rustc",
      "1.97.1",
      "pkg:generic/rustc@1.97.1?host=x86_64-unknown-linux-gnu",
      "Apache-2.0 OR MIT",
      "build-tool",
      RustBuilderEvidence,
    ),
    Component(
      "application",
      "cmake",
      "3.31.6-2",
      "pkg:deb/debian/cmake@3.31.6-2?arch=amd64",
      "BSD-3-Clause",
      "build-tool",
      `${Riscv64BuilderSnapshotEvidence}#cmake=3.31.6-2`,
    ),
    Component(
      "application",
      "clang",
      "1:19.0-63",
      "pkg:deb/debian/clang@1%3A19.0-63?arch=amd64",
      "Apache-2.0 WITH LLVM-exception",
      "build-tool",
      `${Riscv64BuilderSnapshotEvidence}#clang=1:19.0-63`,
    ),
    Component(
      "library",
      "libclang-dev",
      "1:19.0-63",
      "pkg:deb/debian/libclang-dev@1%3A19.0-63?arch=amd64",
      "Apache-2.0 WITH LLVM-exception",
      "build-tool",
      `${Riscv64BuilderSnapshotEvidence}#libclang-dev=1:19.0-63`,
    ),
    Component(
      "application",
      "ninja-build",
      "1.12.1-1",
      "pkg:deb/debian/ninja-build@1.12.1-1?arch=amd64",
      "Apache-2.0",
      "build-tool",
      `${Riscv64BuilderSnapshotEvidence}#ninja-build=1.12.1-1`,
    ),
    Component(
      "application",
      "gcc",
      "14.3.0",
      "pkg:generic/gcc@14.3.0?target=riscv64-unknown-linux-musl",
      "GPL-3.0-or-later",
      "build-tool",
      Riscv64ToolchainEvidence,
    ),
    Component(
      "application",
      "binutils",
      "2.45",
      "pkg:generic/binutils@2.45?target=riscv64-unknown-linux-musl",
      "GPL-3.0-or-later",
      "build-tool",
      Riscv64ToolchainEvidence,
    ),
  ],
};

const RoleDefinitions: readonly RoleDefinition[] = [
  RustRole("filebelt-api", "filebelt-api", RustCdlaImageLicense, WebpkiRuntimeComponents),
  RustRole(
    "filebelt-worker-io",
    "filebelt-worker-io",
    RustCdlaImageLicense,
    WebpkiRuntimeComponents,
  ),
  RustRole(
    "filebelt-worker-maintenance",
    "filebelt-worker-maintenance",
    RustIggyImageLicense,
    IggyRuntimeComponents,
  ),
  RustRole("filebelt-media-controller", "filebelt-media-controller"),
  RustRole(
    "filebelt-document",
    "filebelt-document",
    RustCdlaImageLicense,
    WebpkiRuntimeComponents,
  ),
  RustRole(
    "filebelt-collaboration",
    "filebelt-collaboration",
    RustCdlaImageLicense,
    WebpkiRuntimeComponents,
  ),
  RustRole(
    "filebelt-mcp-broker",
    "filebelt-mcp-broker",
    RustCdlaImageLicense,
    WebpkiRuntimeComponents,
  ),
  RustRole(
    "filebelt-controller",
    "filebelt-controller",
    RustCdlaImageLicense,
    WebpkiRuntimeComponents,
  ),
  RustRole("filebelt-mcp-runner", "filebelt-mcp-runner"),
  RustRole("filebelt-tools", "filebeltctl", RustIggyImageLicense, IggyRuntimeComponents),
  RustRole(
    "filebelt-vfs",
    "filebelt-vfs",
    RustCdlaImageLicense,
    WebpkiRuntimeComponents,
  ),
  RustRole(
    "filebelt-headscale-sync",
    "filebelt-headscale-sync",
    RustCdlaImageLicense,
    WebpkiRuntimeComponents,
  ),
  RustRole(
    "filebelt-nfs-relay",
    "filebelt-nfs-relay",
    RustCdlaImageLicense,
    WebpkiRuntimeComponents,
  ),
  {
    Role: "filebelt-web",
    Dockerfile: "ui/web/Dockerfile",
    License: WebImageLicense,
    Artifact: {
      kind: "oxibelt-edge",
      packages: ["ui/web", "ui/markdown"],
      base: {
        image: OxibeltImage,
        version: OxibeltVersion,
        revision: OxibeltRevision,
      },
    },
  },
];

const RevisionPattern = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const CreatedPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const RoleDescriptions: Readonly<Record<ImageRole, string>> = {
  "filebelt-api": "FileBelt API service",
  "filebelt-worker-io": "FileBelt I/O worker",
  "filebelt-worker-maintenance": "FileBelt maintenance worker",
  "filebelt-media-controller": "FileBelt media controller",
  "filebelt-document": "FileBelt provider-neutral document coordinator",
  "filebelt-collaboration": "FileBelt Markdown collaboration service",
  "filebelt-mcp-broker": "FileBelt MCP broker",
  "filebelt-controller": "FileBelt MCP runner controller",
  "filebelt-mcp-runner": "FileBelt trusted MCP stdio runner relay",
  "filebelt-tools": "FileBelt command-line tools",
  "filebelt-vfs": "FileBelt VFS service",
  "filebelt-headscale-sync": "FileBelt Headscale synchronization service",
  "filebelt-nfs-relay": "FileBelt opaque NFS TCP relay",
  "filebelt-web": "FileBelt OxiBelt TLS edge and web application",
};

function RustRole(
  Role: ImageRole,
  Binary: string,
  License: ImageLicense = RustImageLicense,
  ExtraRuntimeComponents: readonly ImageComponent[] = [],
): RoleDefinition {
  return {
    Role,
    Dockerfile: "source/ops/Dockerfile.roles",
    License,
    Artifact: {
      kind: "rust-binary",
      binary: Binary,
      components: RustComponents(Binary, ExtraRuntimeComponents),
    },
  };
}

function RustComponents(
  PackageName: string,
  ExtraRuntimeComponents: readonly ImageComponent[],
): PlatformComponentInventory {
  return Object.fromEntries(
    ImagePlatforms.map((Platform) => [
      Platform,
      [
        Component(
          "application",
          PackageName,
          FileBeltPackageVersion,
          `pkg:cargo/${PackageName}@${FileBeltPackageVersion}`,
          "Apache-2.0",
          "runtime",
          `Cargo.lock#${PackageName}@${FileBeltPackageVersion}`,
        ),
        ...ExtraRuntimeComponents,
        ...RustPlatformComponents[Platform],
      ],
    ]),
  ) as unknown as PlatformComponentInventory;
}

function NativeComponents(
  Architecture: "amd64" | "arm64",
  Target: "x86_64-unknown-linux-musl" | "aarch64-unknown-linux-musl",
): readonly ImageComponent[] {
  const Host = Architecture === "amd64" ? "x86_64-unknown-linux-gnu" : "aarch64-unknown-linux-gnu";
  return [
    Component(
      "library",
      "rust-std",
      "1.97.1",
      `pkg:generic/rust-std@1.97.1?target=${Target}`,
      "Apache-2.0 OR MIT",
      "runtime",
      RustBuilderEvidence,
    ),
    Component(
      "library",
      "musl",
      "1.2.5-3.1~deb13u1",
      `pkg:deb/debian/musl-dev@1.2.5-3.1~deb13u1?arch=${Architecture}`,
      "MIT",
      "runtime",
      `${NativeSnapshotEvidence}#musl-dev=1.2.5-3.1~deb13u1`,
    ),
    Component(
      "application",
      "rustc",
      "1.97.1",
      `pkg:generic/rustc@1.97.1?host=${Host}`,
      "Apache-2.0 OR MIT",
      "build-tool",
      RustBuilderEvidence,
    ),
    Component(
      "application",
      "gcc",
      "14.2.0-19",
      `pkg:deb/debian/gcc-14@14.2.0-19?arch=${Architecture}`,
      "GPL-3.0-or-later",
      "build-tool",
      `${NativeSnapshotEvidence}#gcc-14=14.2.0-19`,
    ),
    Component(
      "application",
      "binutils",
      "2.44-3",
      `pkg:deb/debian/binutils@2.44-3?arch=${Architecture}`,
      "GPL-3.0-or-later",
      "build-tool",
      `${NativeSnapshotEvidence}#binutils=2.44-3`,
    ),
  ];
}

function Component(
  Type: ImageComponent["type"],
  Name: string,
  Version: string,
  Purl: string,
  License: string,
  Relationship: ComponentRelationship,
  Evidence: string,
): ImageComponent {
  return {
    type: Type,
    name: Name,
    version: Version,
    purl: Purl,
    license: License,
    relationship: Relationship,
    evidence: Evidence,
  };
}

export function IsReleaseTag(Value: string): boolean {
  let Offset = ConsumeNumericIdentifier(Value, 0);
  if (Offset === null || Value[Offset] !== ".") return false;
  Offset = ConsumeNumericIdentifier(Value, Offset + 1);
  if (Offset === null || Value[Offset] !== ".") return false;
  Offset = ConsumeNumericIdentifier(Value, Offset + 1);
  if (Offset === null) return false;
  if (Offset === Value.length) return true;
  if (Value[Offset] !== "-") return false;

  Offset += 1;
  while (Offset < Value.length) {
    const Start: number = Offset;
    let Numeric = true;
    while (Offset < Value.length) {
      const Character = Value.charCodeAt(Offset);
      if (IsAsciiDigit(Character)) {
        Offset += 1;
      } else if (IsAsciiLetter(Character) || Character === 0x2d) {
        Numeric = false;
        Offset += 1;
      } else {
        break;
      }
    }
    if (Offset === Start || (Numeric && Offset - Start > 1 && Value[Start] === "0")) {
      return false;
    }
    if (Offset === Value.length) return true;
    if (Value[Offset] !== ".") return false;
    Offset += 1;
  }
  return false;
}

function ConsumeNumericIdentifier(Value: string, Offset: number): number | null {
  if (Offset >= Value.length || !IsAsciiDigit(Value.charCodeAt(Offset))) return null;
  if (Value[Offset] === "0") return Offset + 1;
  do {
    Offset += 1;
  } while (Offset < Value.length && IsAsciiDigit(Value.charCodeAt(Offset)));
  return Offset;
}

function IsAsciiDigit(Character: number): boolean {
  return Character >= 0x30 && Character <= 0x39;
}

function IsAsciiLetter(Character: number): boolean {
  return (Character >= 0x41 && Character <= 0x5a)
    || (Character >= 0x61 && Character <= 0x7a);
}

export function CreateLocalBuildTag(Version: string, Revision: string): string {
  AssertReleaseTag(Version, "version");
  AssertRevision(Revision);
  return `${Version}-build.${Revision.slice(0, 12)}`;
}

export function CreateImagePlan(Input: CreateImagePlanInput): ImagePlanV1 {
  AssertChannel(Input.Channel);
  AssertReleaseTag(Input.Version, "version");
  ValidateSource(Input.Source, Input.Channel, Input.Version);

  const Tag =
    Input.Channel === "release"
      ? Input.Version
      : CreateLocalBuildTag(Input.Version, Input.Source.revision);

  return {
    schemaVersion: ImagePlanSchemaVersion,
    channel: Input.Channel,
    version: Input.Version,
    tag: Tag,
    source: {
      url: Input.Source.url,
      ref: Input.Source.ref,
      revision: Input.Source.revision,
      created: Input.Source.created,
      dirty: Input.Source.dirty,
      kind: Input.Source.kind,
    },
    runtime: { uid: RuntimeIdentity.uid, gid: RuntimeIdentity.gid },
    images: RoleDefinitions.map(CreateImageRow),
  };
}

export function ValidateImagePlan(Value: unknown): ImagePlanV1 {
  const Plan = AssertRecord(Value, "image plan");
  AssertExactKeys(
    Plan,
    ["schemaVersion", "channel", "version", "tag", "source", "runtime", "images"],
    "image plan",
  );
  if (Plan.schemaVersion !== ImagePlanSchemaVersion) {
    throw new Error(`image plan schemaVersion must be ${ImagePlanSchemaVersion}`);
  }
  AssertChannel(Plan.channel);
  if (typeof Plan.version !== "string") {
    throw new Error("image plan version must be a string");
  }
  AssertReleaseTag(Plan.version, "version");

  const Source = ValidateSource(Plan.source, Plan.channel, Plan.version);
  const ExpectedTag =
    Plan.channel === "release"
      ? Plan.version
      : CreateLocalBuildTag(Plan.version, Source.revision);
  if (Plan.tag !== ExpectedTag) {
    throw new Error(`image plan tag must be ${ExpectedTag}`);
  }
  ValidateRuntime(Plan.runtime);
  ValidateImageRows(Plan.images);

  return CreateImagePlan({ Channel: Plan.channel, Version: Plan.version, Source });
}

export function SerializeImagePlan(Value: ImagePlanV1 | unknown): string {
  return `${JSON.stringify(ValidateImagePlan(Value), null, 2)}\n`;
}

function CreateImageRow(Definition: RoleDefinition): ImageRow {
  return {
    role: Definition.Role,
    repository: `${ImageRegistry}/${Definition.Role}`,
    title: Definition.Role,
    description: RoleDescriptions[Definition.Role],
    platforms: [...ImagePlatforms],
    license: Definition.License,
    build: {
      dockerfile: Definition.Dockerfile,
      target: Definition.Role,
    },
    artifact:
      Definition.Artifact.kind === "rust-binary"
        ? {
          kind: "rust-binary",
          binary: Definition.Artifact.binary,
          components: CloneComponentInventory(Definition.Artifact.components),
        }
        : {
          kind: "oxibelt-edge",
          packages: [...Definition.Artifact.packages],
          base: { ...Definition.Artifact.base },
        },
  };
}

function CloneComponentInventory(
  Inventory: PlatformComponentInventory,
): PlatformComponentInventory {
  return Object.fromEntries(
    ImagePlatforms.map((Platform) => [
      Platform,
      Inventory[Platform].map((Entry) => ({ ...Entry })),
    ]),
  ) as unknown as PlatformComponentInventory;
}

function ValidateSource(
  Value: unknown,
  Channel: ImagePlanChannel,
  Version: string,
): ImagePlanSource {
  const Source = AssertRecord(Value, "image plan source");
  AssertExactKeys(
    Source,
    ["url", "ref", "revision", "created", "dirty", "kind"],
    "image plan source",
  );
  if (Source.url !== SourceUrl) {
    throw new Error(`image plan source url must be ${SourceUrl}`);
  }
  if (typeof Source.ref !== "string" || Source.ref.length === 0) {
    throw new Error("image plan source ref must be a non-empty string");
  }
  if (typeof Source.revision !== "string") {
    throw new Error("image plan source revision must be a string");
  }
  AssertRevision(Source.revision);
  if (typeof Source.created !== "string") {
    throw new Error("image plan source created must be a string");
  }
  AssertCreated(Source.created);
  if (typeof Source.dirty !== "boolean") {
    throw new Error("image plan source dirty must be a boolean");
  }
  if (!IsSourceKind(Source.kind)) {
    throw new Error("image plan source kind is invalid");
  }
  if (Channel === "release") {
    if (Source.kind !== "release") {
      throw new Error("release image plans require source kind release");
    }
    if (Source.dirty) {
      throw new Error("release image plans require a clean source tree");
    }
    if (Source.ref !== `refs/tags/${Version}`) {
      throw new Error(`release image plans require source ref refs/tags/${Version}`);
    }
  } else if (Source.kind === "release") {
    throw new Error("build image plans cannot use source kind release");
  }

  return {
    url: Source.url,
    ref: Source.ref,
    revision: Source.revision,
    created: Source.created,
    dirty: Source.dirty,
    kind: Source.kind,
  };
}

function ValidateRuntime(Value: unknown): void {
  const Runtime = AssertRecord(Value, "image plan runtime");
  AssertExactKeys(Runtime, ["uid", "gid"], "image plan runtime");
  if (Runtime.uid !== RuntimeIdentity.uid || Runtime.gid !== RuntimeIdentity.gid) {
    throw new Error("image plan runtime UID and GID must both be 10001");
  }
}

function ValidateImageRows(Value: unknown): void {
  if (!Array.isArray(Value)) {
    throw new Error("image plan images must be an array");
  }
  if (Value.length !== RoleDefinitions.length) {
    throw new Error(`image plan must contain exactly ${RoleDefinitions.length} images`);
  }

  const Seen = new Set<string>();
  for (const [Index, Definition] of RoleDefinitions.entries()) {
    const Row = AssertRecord(Value[Index], `image plan image ${Index}`);
    AssertExactKeys(
      Row,
      [
        "role",
        "repository",
        "title",
        "description",
        "platforms",
        "license",
        "build",
        "artifact",
      ],
      `image plan image ${Index}`,
    );
    if (typeof Row.role !== "string" || Seen.has(Row.role)) {
      throw new Error(`image plan image ${Index} has an invalid or duplicate role`);
    }
    Seen.add(Row.role);
    if (Row.role !== Definition.Role) {
      throw new Error(`image plan image ${Index} role must be ${Definition.Role}`);
    }
    const Expected = CreateImageRow(Definition);
    AssertJsonEqual(Row, Expected, `image plan image ${Definition.Role}`);
  }
}

function AssertJsonEqual(Actual: unknown, Expected: unknown, Description: string): void {
  if (JSON.stringify(SortObjectKeys(Actual)) !== JSON.stringify(SortObjectKeys(Expected))) {
    throw new Error(`${Description} does not match the fixed image contract`);
  }
}

function SortObjectKeys(Value: unknown): unknown {
  if (Array.isArray(Value)) {
    return Value.map(SortObjectKeys);
  }
  if (typeof Value === "object" && Value !== null) {
    return Object.fromEntries(
      Object.entries(Value)
        .sort(([Left], [Right]) => Left.localeCompare(Right))
        .map(([Key, NestedValue]) => [Key, SortObjectKeys(NestedValue)]),
    );
  }
  return Value;
}

function AssertReleaseTag(Value: string, Description: string): void {
  if (!IsReleaseTag(Value)) {
    throw new Error(
      `${Description} must be an exact SemVer stable or prerelease value without a v prefix or build metadata`,
    );
  }
}

function AssertRevision(Value: string): void {
  if (!RevisionPattern.test(Value)) {
    throw new Error("image plan source revision must be a full lowercase hexadecimal Git object ID");
  }
}

function AssertCreated(Value: string): void {
  if (!CreatedPattern.test(Value) || new Date(Value).toISOString() !== Value.replace("Z", ".000Z")) {
    throw new Error("image plan source created must be an exact RFC 3339 UTC second");
  }
}

function AssertChannel(Value: unknown): asserts Value is ImagePlanChannel {
  if (Value !== "build" && Value !== "release") {
    throw new Error("image plan channel must be build or release");
  }
}

function IsSourceKind(Value: unknown): Value is SourceKind {
  return Value === "local" || Value === "ci" || Value === "release" || Value === "rebuild";
}

function AssertRecord(Value: unknown, Description: string): Record<string, unknown> {
  if (typeof Value !== "object" || Value === null || Array.isArray(Value)) {
    throw new Error(`${Description} must be an object`);
  }
  return Value as Record<string, unknown>;
}

function AssertExactKeys(
  Value: Record<string, unknown>,
  ExpectedKeys: readonly string[],
  Description: string,
): void {
  const ActualKeys = Object.keys(Value).sort();
  const SortedExpected = [...ExpectedKeys].sort();
  if (JSON.stringify(ActualKeys) !== JSON.stringify(SortedExpected)) {
    throw new Error(`${Description} contains missing or unknown properties`);
  }
}
