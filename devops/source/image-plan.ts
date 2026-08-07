// SPDX-License-Identifier: Apache-2.0

export const IMAGE_PLAN_SCHEMA_VERSION = 1 as const;
export const IMAGE_REGISTRY = "ghcr.io/oxibelt" as const;
export const SOURCE_URL = "https://github.com/OxiBelt/FileBelt" as const;
export const RUNTIME_IDENTITY = Object.freeze({ uid: 10001, gid: 10001 });
export const RUST_IMAGE_LICENSE = "Apache-2.0 AND MIT" as const;
export const RUST_CDLA_IMAGE_LICENSE =
  "Apache-2.0 AND MIT AND CDLA-Permissive-2.0" as const;
export const RUST_IGGY_IMAGE_LICENSE =
  "Apache-2.0 AND MIT AND MPL-2.0 AND CDLA-Permissive-2.0" as const;
export const WEB_IMAGE_LICENSE = "Apache-2.0 AND MIT AND ISC AND 0BSD" as const;
export const OXIBELT_IMAGE =
  "ghcr.io/oxibelt/oxibelt@sha256:e8556a0103feff47bf6135062e70e980e000176598fd438959ea55d99c844030" as const;
export const OXIBELT_VERSION = "0.7.1-beta.2" as const;
export const OXIBELT_REVISION = "bf40172e40298325775ca9d708162a9d8d14e6d4" as const;

export const IMAGE_ROLES = [
  "filebelt-api",
  "filebelt-worker-io",
  "filebelt-worker-maintenance",
  "filebelt-media-controller",
  "filebelt-mcp-broker",
  "filebelt-tools",
  "filebelt-web",
] as const;

export type ImageRole = (typeof IMAGE_ROLES)[number];

export const IMAGE_PLATFORMS = [
  "linux/amd64",
  "linux/arm64",
  "linux/riscv64",
] as const;

export type ImagePlatform = (typeof IMAGE_PLATFORMS)[number];
export type ImagePlanChannel = "build" | "release";
export type SourceKind = "local" | "ci" | "release" | "rebuild";
export type ImageLicense =
  | typeof RUST_IMAGE_LICENSE
  | typeof RUST_CDLA_IMAGE_LICENSE
  | typeof RUST_IGGY_IMAGE_LICENSE
  | typeof WEB_IMAGE_LICENSE;
export type ComponentRelationship = "runtime" | "build-tool";

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
  readonly url: typeof SOURCE_URL;
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
        readonly image: typeof OXIBELT_IMAGE;
        readonly version: typeof OXIBELT_VERSION;
        readonly revision: typeof OXIBELT_REVISION;
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
  readonly schemaVersion: typeof IMAGE_PLAN_SCHEMA_VERSION;
  readonly channel: ImagePlanChannel;
  readonly version: string;
  readonly tag: string;
  readonly source: ImagePlanSource;
  readonly runtime: typeof RUNTIME_IDENTITY;
  readonly images: readonly ImageRow[];
}

export interface CreateImagePlanInput {
  readonly channel: ImagePlanChannel;
  readonly version: string;
  readonly source: ImagePlanSource;
}

interface RoleDefinition {
  readonly role: ImageRole;
  readonly dockerfile: ImageRow["build"]["dockerfile"];
  readonly license: ImageLicense;
  readonly artifact: ImageArtifact;
}

const RUST_BUILDER_EVIDENCE =
  "docker.io/library/rust@sha256:1bcff4befb740599103a2c7cb51058e14479b2e35e3a34a3f0dc4ede09927488";
const NATIVE_SNAPSHOT_EVIDENCE =
  "https://snapshot.debian.org/archive/debian/20260713T000000Z";
const RISCV64_BUILDER_SNAPSHOT_EVIDENCE =
  "https://snapshot.debian.org/archive/debian/20260713T000000Z";
const RISCV64_TOOLCHAIN_EVIDENCE =
  "ghcr.io/cross-rs/riscv64gc-unknown-linux-musl@sha256:60372bf6ad955bc04ac9b0689476b05955b4e90fc2030d311be687025672cc6d";

const FILEBELT_PACKAGE_VERSION = "0.1.0" as const;

const WEBPKI_RUNTIME_COMPONENTS = [
  component(
    "library",
    "webpki-roots",
    "0.26.11",
    "pkg:cargo/webpki-roots@0.26.11",
    "CDLA-Permissive-2.0",
    "runtime",
    "Cargo.lock#webpki-roots@0.26.11",
  ),
  component(
    "library",
    "webpki-roots",
    "1.0.9",
    "pkg:cargo/webpki-roots@1.0.9",
    "CDLA-Permissive-2.0",
    "runtime",
    "Cargo.lock#webpki-roots@1.0.9",
  ),
] as const;

const IGGY_RUNTIME_COMPONENTS = [
  ...WEBPKI_RUNTIME_COMPONENTS,
  component(
    "library",
    "option-ext",
    "0.2.0",
    "pkg:cargo/option-ext@0.2.0",
    "MPL-2.0",
    "runtime",
    "Cargo.lock#option-ext@0.2.0",
  ),
] as const;

const RUST_PLATFORM_COMPONENTS: PlatformComponentInventory = {
  "linux/amd64": nativeComponents("amd64", "x86_64-unknown-linux-musl"),
  "linux/arm64": nativeComponents("arm64", "aarch64-unknown-linux-musl"),
  "linux/riscv64": [
    component(
      "library",
      "rust-std",
      "1.97.1",
      "pkg:generic/rust-std@1.97.1?target=riscv64gc-unknown-linux-musl",
      "Apache-2.0 OR MIT",
      "runtime",
      RUST_BUILDER_EVIDENCE,
    ),
    component(
      "library",
      "musl",
      "1.2.5",
      "pkg:generic/musl@1.2.5?target=riscv64-unknown-linux-musl",
      "MIT",
      "runtime",
      RISCV64_TOOLCHAIN_EVIDENCE,
    ),
    component(
      "application",
      "rustc",
      "1.97.1",
      "pkg:generic/rustc@1.97.1?host=x86_64-unknown-linux-gnu",
      "Apache-2.0 OR MIT",
      "build-tool",
      RUST_BUILDER_EVIDENCE,
    ),
    component(
      "application",
      "cmake",
      "3.31.6-2",
      "pkg:deb/debian/cmake@3.31.6-2?arch=amd64",
      "BSD-3-Clause",
      "build-tool",
      `${RISCV64_BUILDER_SNAPSHOT_EVIDENCE}#cmake=3.31.6-2`,
    ),
    component(
      "application",
      "clang",
      "1:19.0-63",
      "pkg:deb/debian/clang@1%3A19.0-63?arch=amd64",
      "Apache-2.0 WITH LLVM-exception",
      "build-tool",
      `${RISCV64_BUILDER_SNAPSHOT_EVIDENCE}#clang=1:19.0-63`,
    ),
    component(
      "library",
      "libclang-dev",
      "1:19.0-63",
      "pkg:deb/debian/libclang-dev@1%3A19.0-63?arch=amd64",
      "Apache-2.0 WITH LLVM-exception",
      "build-tool",
      `${RISCV64_BUILDER_SNAPSHOT_EVIDENCE}#libclang-dev=1:19.0-63`,
    ),
    component(
      "application",
      "ninja-build",
      "1.12.1-1",
      "pkg:deb/debian/ninja-build@1.12.1-1?arch=amd64",
      "Apache-2.0",
      "build-tool",
      `${RISCV64_BUILDER_SNAPSHOT_EVIDENCE}#ninja-build=1.12.1-1`,
    ),
    component(
      "application",
      "gcc",
      "14.3.0",
      "pkg:generic/gcc@14.3.0?target=riscv64-unknown-linux-musl",
      "GPL-3.0-or-later",
      "build-tool",
      RISCV64_TOOLCHAIN_EVIDENCE,
    ),
    component(
      "application",
      "binutils",
      "2.45",
      "pkg:generic/binutils@2.45?target=riscv64-unknown-linux-musl",
      "GPL-3.0-or-later",
      "build-tool",
      RISCV64_TOOLCHAIN_EVIDENCE,
    ),
  ],
};

const ROLE_DEFINITIONS: readonly RoleDefinition[] = [
  rustRole("filebelt-api", "filebelt-api", RUST_CDLA_IMAGE_LICENSE, WEBPKI_RUNTIME_COMPONENTS),
  rustRole(
    "filebelt-worker-io",
    "filebelt-worker-io",
    RUST_CDLA_IMAGE_LICENSE,
    WEBPKI_RUNTIME_COMPONENTS,
  ),
  rustRole(
    "filebelt-worker-maintenance",
    "filebelt-worker-maintenance",
    RUST_IGGY_IMAGE_LICENSE,
    IGGY_RUNTIME_COMPONENTS,
  ),
  rustRole("filebelt-media-controller", "filebelt-media-controller"),
  rustRole("filebelt-mcp-broker", "filebelt-mcp-broker"),
  rustRole("filebelt-tools", "filebeltctl", RUST_IGGY_IMAGE_LICENSE, IGGY_RUNTIME_COMPONENTS),
  {
    role: "filebelt-web",
    dockerfile: "ui/web/Dockerfile",
    license: WEB_IMAGE_LICENSE,
    artifact: {
      kind: "oxibelt-edge",
      packages: ["ui/web", "ui/markdown"],
      base: {
        image: OXIBELT_IMAGE,
        version: OXIBELT_VERSION,
        revision: OXIBELT_REVISION,
      },
    },
  },
];

const RELEASE_TAG_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?$/;
const REVISION_PATTERN = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const CREATED_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const ROLE_DESCRIPTIONS: Readonly<Record<ImageRole, string>> = {
  "filebelt-api": "FileBelt API service",
  "filebelt-worker-io": "FileBelt I/O worker",
  "filebelt-worker-maintenance": "FileBelt maintenance worker",
  "filebelt-media-controller": "FileBelt media controller",
  "filebelt-mcp-broker": "FileBelt MCP broker",
  "filebelt-tools": "FileBelt command-line tools",
  "filebelt-web": "FileBelt OxiBelt TLS edge and web application",
};

function rustRole(
  role: ImageRole,
  binary: string,
  license: ImageLicense = RUST_IMAGE_LICENSE,
  extraRuntimeComponents: readonly ImageComponent[] = [],
): RoleDefinition {
  return {
    role,
    dockerfile: "source/ops/Dockerfile.roles",
    license,
    artifact: {
      kind: "rust-binary",
      binary,
      components: rustComponents(binary, extraRuntimeComponents),
    },
  };
}

function rustComponents(
  packageName: string,
  extraRuntimeComponents: readonly ImageComponent[],
): PlatformComponentInventory {
  return Object.fromEntries(
    IMAGE_PLATFORMS.map((platform) => [
      platform,
      [
        component(
          "application",
          packageName,
          FILEBELT_PACKAGE_VERSION,
          `pkg:cargo/${packageName}@${FILEBELT_PACKAGE_VERSION}`,
          "Apache-2.0",
          "runtime",
          `Cargo.lock#${packageName}@${FILEBELT_PACKAGE_VERSION}`,
        ),
        ...extraRuntimeComponents,
        ...RUST_PLATFORM_COMPONENTS[platform],
      ],
    ]),
  ) as unknown as PlatformComponentInventory;
}

function nativeComponents(
  architecture: "amd64" | "arm64",
  target: "x86_64-unknown-linux-musl" | "aarch64-unknown-linux-musl",
): readonly ImageComponent[] {
  const host = architecture === "amd64" ? "x86_64-unknown-linux-gnu" : "aarch64-unknown-linux-gnu";
  return [
    component(
      "library",
      "rust-std",
      "1.97.1",
      `pkg:generic/rust-std@1.97.1?target=${target}`,
      "Apache-2.0 OR MIT",
      "runtime",
      RUST_BUILDER_EVIDENCE,
    ),
    component(
      "library",
      "musl",
      "1.2.5-3.1~deb13u1",
      `pkg:deb/debian/musl-dev@1.2.5-3.1~deb13u1?arch=${architecture}`,
      "MIT",
      "runtime",
      `${NATIVE_SNAPSHOT_EVIDENCE}#musl-dev=1.2.5-3.1~deb13u1`,
    ),
    component(
      "application",
      "rustc",
      "1.97.1",
      `pkg:generic/rustc@1.97.1?host=${host}`,
      "Apache-2.0 OR MIT",
      "build-tool",
      RUST_BUILDER_EVIDENCE,
    ),
    component(
      "application",
      "gcc",
      "14.2.0-19",
      `pkg:deb/debian/gcc-14@14.2.0-19?arch=${architecture}`,
      "GPL-3.0-or-later",
      "build-tool",
      `${NATIVE_SNAPSHOT_EVIDENCE}#gcc-14=14.2.0-19`,
    ),
    component(
      "application",
      "binutils",
      "2.44-3",
      `pkg:deb/debian/binutils@2.44-3?arch=${architecture}`,
      "GPL-3.0-or-later",
      "build-tool",
      `${NATIVE_SNAPSHOT_EVIDENCE}#binutils=2.44-3`,
    ),
  ];
}

function component(
  type: ImageComponent["type"],
  name: string,
  version: string,
  purl: string,
  license: string,
  relationship: ComponentRelationship,
  evidence: string,
): ImageComponent {
  return { type, name, version, purl, license, relationship, evidence };
}

export function isReleaseTag(value: string): boolean {
  return RELEASE_TAG_PATTERN.test(value);
}

export function createLocalBuildTag(version: string, revision: string): string {
  assertReleaseTag(version, "version");
  assertRevision(revision);
  return `${version}-build.${revision.slice(0, 12)}`;
}

export function createImagePlan(input: CreateImagePlanInput): ImagePlanV1 {
  assertChannel(input.channel);
  assertReleaseTag(input.version, "version");
  validateSource(input.source, input.channel, input.version);

  const tag =
    input.channel === "release"
      ? input.version
      : createLocalBuildTag(input.version, input.source.revision);

  return {
    schemaVersion: IMAGE_PLAN_SCHEMA_VERSION,
    channel: input.channel,
    version: input.version,
    tag,
    source: {
      url: input.source.url,
      ref: input.source.ref,
      revision: input.source.revision,
      created: input.source.created,
      dirty: input.source.dirty,
      kind: input.source.kind,
    },
    runtime: { uid: RUNTIME_IDENTITY.uid, gid: RUNTIME_IDENTITY.gid },
    images: ROLE_DEFINITIONS.map(createImageRow),
  };
}

export function validateImagePlan(value: unknown): ImagePlanV1 {
  const plan = assertRecord(value, "image plan");
  assertExactKeys(
    plan,
    ["schemaVersion", "channel", "version", "tag", "source", "runtime", "images"],
    "image plan",
  );
  if (plan.schemaVersion !== IMAGE_PLAN_SCHEMA_VERSION) {
    throw new Error(`image plan schemaVersion must be ${IMAGE_PLAN_SCHEMA_VERSION}`);
  }
  assertChannel(plan.channel);
  if (typeof plan.version !== "string") {
    throw new Error("image plan version must be a string");
  }
  assertReleaseTag(plan.version, "version");

  const source = validateSource(plan.source, plan.channel, plan.version);
  const expectedTag =
    plan.channel === "release"
      ? plan.version
      : createLocalBuildTag(plan.version, source.revision);
  if (plan.tag !== expectedTag) {
    throw new Error(`image plan tag must be ${expectedTag}`);
  }
  validateRuntime(plan.runtime);
  validateImageRows(plan.images);

  return createImagePlan({ channel: plan.channel, version: plan.version, source });
}

export function serializeImagePlan(value: ImagePlanV1 | unknown): string {
  return `${JSON.stringify(validateImagePlan(value), null, 2)}\n`;
}

function createImageRow(definition: RoleDefinition): ImageRow {
  return {
    role: definition.role,
    repository: `${IMAGE_REGISTRY}/${definition.role}`,
    title: definition.role,
    description: ROLE_DESCRIPTIONS[definition.role],
    platforms: [...IMAGE_PLATFORMS],
    license: definition.license,
    build: {
      dockerfile: definition.dockerfile,
      target: definition.role,
    },
    artifact:
      definition.artifact.kind === "rust-binary"
        ? {
            kind: "rust-binary",
            binary: definition.artifact.binary,
            components: cloneComponentInventory(definition.artifact.components),
          }
        : {
            kind: "oxibelt-edge",
            packages: [...definition.artifact.packages],
            base: { ...definition.artifact.base },
          },
  };
}

function cloneComponentInventory(
  inventory: PlatformComponentInventory,
): PlatformComponentInventory {
  return Object.fromEntries(
    IMAGE_PLATFORMS.map((platform) => [
      platform,
      inventory[platform].map((entry) => ({ ...entry })),
    ]),
  ) as unknown as PlatformComponentInventory;
}

function validateSource(
  value: unknown,
  channel: ImagePlanChannel,
  version: string,
): ImagePlanSource {
  const source = assertRecord(value, "image plan source");
  assertExactKeys(
    source,
    ["url", "ref", "revision", "created", "dirty", "kind"],
    "image plan source",
  );
  if (source.url !== SOURCE_URL) {
    throw new Error(`image plan source url must be ${SOURCE_URL}`);
  }
  if (typeof source.ref !== "string" || source.ref.length === 0) {
    throw new Error("image plan source ref must be a non-empty string");
  }
  if (typeof source.revision !== "string") {
    throw new Error("image plan source revision must be a string");
  }
  assertRevision(source.revision);
  if (typeof source.created !== "string") {
    throw new Error("image plan source created must be a string");
  }
  assertCreated(source.created);
  if (typeof source.dirty !== "boolean") {
    throw new Error("image plan source dirty must be a boolean");
  }
  if (!isSourceKind(source.kind)) {
    throw new Error("image plan source kind is invalid");
  }
  if (channel === "release") {
    if (source.kind !== "release") {
      throw new Error("release image plans require source kind release");
    }
    if (source.dirty) {
      throw new Error("release image plans require a clean source tree");
    }
    if (source.ref !== `refs/tags/${version}`) {
      throw new Error(`release image plans require source ref refs/tags/${version}`);
    }
  } else if (source.kind === "release") {
    throw new Error("build image plans cannot use source kind release");
  }

  return {
    url: source.url,
    ref: source.ref,
    revision: source.revision,
    created: source.created,
    dirty: source.dirty,
    kind: source.kind,
  };
}

function validateRuntime(value: unknown): void {
  const runtime = assertRecord(value, "image plan runtime");
  assertExactKeys(runtime, ["uid", "gid"], "image plan runtime");
  if (runtime.uid !== RUNTIME_IDENTITY.uid || runtime.gid !== RUNTIME_IDENTITY.gid) {
    throw new Error("image plan runtime UID and GID must both be 10001");
  }
}

function validateImageRows(value: unknown): void {
  if (!Array.isArray(value)) {
    throw new Error("image plan images must be an array");
  }
  if (value.length !== ROLE_DEFINITIONS.length) {
    throw new Error(`image plan must contain exactly ${ROLE_DEFINITIONS.length} images`);
  }

  const seen = new Set<string>();
  for (const [index, definition] of ROLE_DEFINITIONS.entries()) {
    const row = assertRecord(value[index], `image plan image ${index}`);
    assertExactKeys(
      row,
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
      `image plan image ${index}`,
    );
    if (typeof row.role !== "string" || seen.has(row.role)) {
      throw new Error(`image plan image ${index} has an invalid or duplicate role`);
    }
    seen.add(row.role);
    if (row.role !== definition.role) {
      throw new Error(`image plan image ${index} role must be ${definition.role}`);
    }
    const expected = createImageRow(definition);
    assertJsonEqual(row, expected, `image plan image ${definition.role}`);
  }
}

function assertJsonEqual(actual: unknown, expected: unknown, description: string): void {
  if (JSON.stringify(sortObjectKeys(actual)) !== JSON.stringify(sortObjectKeys(expected))) {
    throw new Error(`${description} does not match the fixed image contract`);
  }
}

function sortObjectKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortObjectKeys);
  }
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nestedValue]) => [key, sortObjectKeys(nestedValue)]),
    );
  }
  return value;
}

function assertReleaseTag(value: string, description: string): void {
  if (!isReleaseTag(value)) {
    throw new Error(
      `${description} must be an exact SemVer stable or prerelease value without a v prefix or build metadata`,
    );
  }
}

function assertRevision(value: string): void {
  if (!REVISION_PATTERN.test(value)) {
    throw new Error("image plan source revision must be a full lowercase hexadecimal Git object ID");
  }
}

function assertCreated(value: string): void {
  if (!CREATED_PATTERN.test(value) || new Date(value).toISOString() !== value.replace("Z", ".000Z")) {
    throw new Error("image plan source created must be an exact RFC 3339 UTC second");
  }
}

function assertChannel(value: unknown): asserts value is ImagePlanChannel {
  if (value !== "build" && value !== "release") {
    throw new Error("image plan channel must be build or release");
  }
}

function isSourceKind(value: unknown): value is SourceKind {
  return value === "local" || value === "ci" || value === "release" || value === "rebuild";
}

function assertRecord(value: unknown, description: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${description} must be an object`);
  }
  return value as Record<string, unknown>;
}

function assertExactKeys(
  value: Record<string, unknown>,
  expectedKeys: readonly string[],
  description: string,
): void {
  const actualKeys = Object.keys(value).sort();
  const sortedExpected = [...expectedKeys].sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(sortedExpected)) {
    throw new Error(`${description} contains missing or unknown properties`);
  }
}
