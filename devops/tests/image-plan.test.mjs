// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { URL, fileURLToPath } from "node:url";

import {
  CreateImagePlan,
  CreateLocalBuildTag,
  Amd64IsaBaseline,
  ImagePlatforms,
  ImageRoles,
  PreviewImageRoles,
  IsReleaseTag,
  OxibeltImage,
  OxibeltRevision,
  OxibeltVersion,
  RustCdlaImageLicense,
  RustIggyImageLicense,
  RustImageLicense,
  SerializeImagePlan,
  SourceUrl,
  ValidateImagePlan,
  WebImageLicense,
  AdapterImagePlanSchemaVersion,
  AdapterImageRoles,
  CreateAdapterImagePlan,
  SerializeAdapterImagePlan,
  ValidateAdapterImagePlan,
} from "../dist/index.js";

const REVISION = "0123456789abcdef0123456789abcdef01234567";
const clone = (value) => JSON.parse(JSON.stringify(value));

function buildSource(overrides = {}) {
  return {
    url: SourceUrl,
    ref: "refs/heads/main",
    revision: REVISION,
    created: "2026-08-06T12:34:56Z",
    dirty: false,
    kind: "ci",
    ...overrides,
  };
}

test("build plan contains the seventeen fixed roles and immutable runtime contract", () => {
  const plan = CreateImagePlan({ Channel: "build", Version: "0.1.0", Source: buildSource() });

  assert.equal(plan.schemaVersion, 2);
  assert.equal(plan.amd64IsaBaseline, Amd64IsaBaseline);
  assert.equal(plan.tag, "0.1.0-build.0123456789ab");
  assert.deepEqual(plan.runtime, { uid: 10001, gid: 10001 });
  assert.deepEqual(
    plan.images.map(({ role }) => role),
    ImageRoles,
  );
  for (const image of plan.images) {
    assert.equal(image.repository, `ghcr.io/oxibelt/${image.role}`);
    assert.equal(image.title, image.role);
    assert.ok(image.description.startsWith("FileBelt "));
    assert.deepEqual(image.platforms, ImagePlatforms);
    const expectedLicense = {
      "filebelt-api": RustCdlaImageLicense,
      "filebelt-worker-io": RustCdlaImageLicense,
      "filebelt-worker-maintenance": RustIggyImageLicense,
      "filebelt-media-controller": RustImageLicense,
      "filebelt-document": RustCdlaImageLicense,
      "filebelt-revision": RustCdlaImageLicense,
      "filebelt-collaboration": RustCdlaImageLicense,
      "filebelt-mcp-broker": RustCdlaImageLicense,
      "filebelt-controller": RustCdlaImageLicense,
      "filebelt-mcp-runner": RustImageLicense,
      "filebelt-tools": RustIggyImageLicense,
      "filebelt-vfs": RustCdlaImageLicense,
      "filebelt-headscale-sync": RustCdlaImageLicense,
      "filebelt-nfs-relay": RustCdlaImageLicense,
      "filebelt-private-egress-gateway": RustCdlaImageLicense,
      "filebelt-tunnel-relay": RustCdlaImageLicense,
      "filebelt-web": WebImageLicense,
    }[image.role];
    assert.equal(image.license, expectedLicense);
    assert.equal(image.build.target, image.role);
    assert.deepEqual(image.artifact.targetCpu, {
      "linux/amd64": Amd64IsaBaseline,
      "linux/arm64": null,
      "linux/riscv64": null,
    });
    if (image.artifact.kind === "rust-binary") {
      assert.deepEqual(Object.keys(image.artifact.components), ImagePlatforms);
      for (const platform of ImagePlatforms) {
        const components = image.artifact.components[platform];
        assert.ok(components.length > 0);
        assert.deepEqual(
          new Set(components.map(({ relationship }) => relationship)),
          new Set(["runtime", "build-tool"]),
        );
        assert.equal(new Set(components.map(({ purl }) => purl)).size, components.length);
        assert.ok(
          components.some(
            ({ name, purl, relationship }) =>
              name === image.artifact.binary &&
              purl === `pkg:cargo/${image.artifact.binary}@0.1.0` &&
              relationship === "runtime",
          ),
          `${image.role} must identify its linked Cargo application for Trivy`,
        );
      }
      if (
        [
          "filebelt-api",
          "filebelt-worker-io",
          "filebelt-mcp-broker",
          "filebelt-controller",
        ].includes(image.role)
      ) {
        assert.ok(
          image.artifact.components["linux/amd64"].some(
            ({ name, license }) => name === "webpki-roots" && license === "CDLA-Permissive-2.0",
          ),
        );
      }
      if (["filebelt-worker-maintenance", "filebelt-tools"].includes(image.role)) {
        assert.ok(
          image.artifact.components["linux/amd64"].some(
            ({ name, license }) => name === "option-ext" && license === "MPL-2.0",
          ),
        );
      }
    }
  }
  const expectedRiscvBuildTools = [
    {
      type: "application",
      name: "cmake",
      version: "3.31.6-2",
      purl: "pkg:deb/debian/cmake@3.31.6-2?arch=amd64",
      license: "BSD-3-Clause",
      relationship: "build-tool",
      evidence: "https://snapshot.debian.org/archive/debian/20260713T000000Z#cmake=3.31.6-2",
    },
    {
      type: "application",
      name: "clang",
      version: "1:19.0-63",
      purl: "pkg:deb/debian/clang@1%3A19.0-63?arch=amd64",
      license: "Apache-2.0 WITH LLVM-exception",
      relationship: "build-tool",
      evidence: "https://snapshot.debian.org/archive/debian/20260713T000000Z#clang=1:19.0-63",
    },
    {
      type: "library",
      name: "libclang-dev",
      version: "1:19.0-63",
      purl: "pkg:deb/debian/libclang-dev@1%3A19.0-63?arch=amd64",
      license: "Apache-2.0 WITH LLVM-exception",
      relationship: "build-tool",
      evidence:
        "https://snapshot.debian.org/archive/debian/20260713T000000Z#libclang-dev=1:19.0-63",
    },
    {
      type: "application",
      name: "ninja-build",
      version: "1.12.1-1",
      purl: "pkg:deb/debian/ninja-build@1.12.1-1?arch=amd64",
      license: "Apache-2.0",
      relationship: "build-tool",
      evidence: "https://snapshot.debian.org/archive/debian/20260713T000000Z#ninja-build=1.12.1-1",
    },
  ];
  for (const image of plan.images.filter(({ artifact }) => artifact.kind === "rust-binary")) {
    const riscvComponents = image.artifact.components["linux/riscv64"];
    for (const expected of expectedRiscvBuildTools) {
      assert.deepEqual(
        riscvComponents.find(({ name }) => name === expected.name),
        expected,
      );
    }
    for (const platform of ["linux/amd64", "linux/arm64"]) {
      assert.ok(
        image.artifact.components[platform].every(
          ({ name }) => !expectedRiscvBuildTools.some(({ name: expected }) => name === expected),
        ),
      );
    }
  }
  assert.deepEqual(plan.images.at(-1).artifact, {
    kind: "oxibelt-edge",
    targetCpu: {
      "linux/amd64": Amd64IsaBaseline,
      "linux/arm64": null,
      "linux/riscv64": null,
    },
    packages: ["ui/web", "ui/markdown"],
    base: {
      image: OxibeltImage,
      version: OxibeltVersion,
      revision: OxibeltRevision,
    },
  });
  assert.equal(
    plan.images.find(({ role }) => role === "filebelt-tools").artifact.binary,
    "filebeltctl",
  );
  assert.deepEqual(PreviewImageRoles, ["filebelt-private-egress-gateway", "filebelt-tunnel-relay"]);
});

test("Rust Docker targets match their image-plan descriptions", () => {
  const Plan = CreateImagePlan({ Channel: "build", Version: "0.1.0", Source: buildSource() });
  const Dockerfile = readFileSync(
    new URL("../../source/ops/Dockerfile.roles", import.meta.url),
    "utf8",
  );
  assert.ok(Dockerfile.includes("ARG FILEBELT_TARGET_CPU="));
  assert.ok(Dockerfile.includes('test "${FILEBELT_TARGET_CPU}" = x86-64-v3'));
  assert.ok(Dockerfile.includes("-Ctarget-cpu=${FILEBELT_TARGET_CPU}"));
  assert.ok(Dockerfile.includes("-Clink-arg=-Wl,-z,${FILEBELT_TARGET_CPU}"));

  for (const Image of Plan.images.filter(({ artifact }) => artifact.kind === "rust-binary")) {
    assert.equal(Image.build.dockerfile, "source/ops/Dockerfile.roles");
    const StageHeader = `FROM runtime-files AS ${Image.build.target}\n`;
    const StageStart = Dockerfile.indexOf(StageHeader);
    assert.notEqual(StageStart, -1, `${Image.role} must have a Docker target`);
    const NextStage = Dockerfile.indexOf("\nFROM ", StageStart + StageHeader.length);
    const Stage = Dockerfile.slice(StageStart, NextStage === -1 ? undefined : NextStage);
    assert.ok(
      Stage.includes(`org.opencontainers.image.description="${Image.description}"`),
      `${Image.role} Docker description must match the immutable image plan`,
    );
  }
});

test("adapter publication plan covers six roles without mutable release sources", () => {
  const Source = buildSource({ ref: `refs/commits/${REVISION}`, kind: "ci" });
  const AdapterImagePlan = CreateAdapterImagePlan({ Version: "0.1.0", Source });
  assert.equal(AdapterImagePlanSchemaVersion, 3);
  assert.equal(AdapterImagePlan.amd64IsaBaseline, "x86-64-v3");
  assert.deepEqual(
    AdapterImagePlan.roles.map(({ role }) => role),
    AdapterImageRoles,
  );
  for (const image of AdapterImagePlan.roles) {
    assert.equal(image.repository, `ghcr.io/oxibelt/${image.role}`);
    assert.equal(image.source.ref, `refs/commits/${REVISION}`);
    assert.equal(image.source.revision, REVISION);
    assert.match(image.sourceBundle.publicUrl, /\/releases\/download\/0\.1\.0\//);
    assert.equal(image.sourceBundle.sha256, null);
    assert.equal(image.imageBuild.state, "blocked");
    assert.equal(image.publication.state, "blocked");
  }
  ValidateAdapterImagePlan(JSON.parse(SerializeAdapterImagePlan(AdapterImagePlan)));
  assert.deepEqual(
    AdapterImagePlan.roles.find(({ role }) => role === "filebelt-git-adapter")?.components,
    [
      {
        id: "filebelt-git-adapter",
        version: "0.1.0",
        license: "Apache-2.0",
        relationship: "linked",
        path: "/usr/local/bin/filebelt-git-adapter",
        sourceRequired: true,
      },
      {
        id: "filebelt-revision-protocol",
        version: "0.1.0",
        license: "Apache-2.0",
        relationship: "linked",
        path: "/usr/local/bin/filebelt-git-adapter",
        sourceRequired: true,
      },
      {
        id: "git-2.55.0",
        version: "2.55.0",
        license: "GPL-2.0-only",
        relationship: "separate-executable",
        path: "/opt/filebelt-git/bin/git",
        sourceRequired: true,
      },
      {
        id: "zlib-1.3.1",
        version: "1.3.1",
        license: "Zlib",
        relationship: "linked",
        path: "/opt/filebelt-git/bin/git",
        sourceRequired: true,
      },
    ],
  );
});

test("adapter plans reject a missing or altered AMD64 ISA baseline", () => {
  const Source = buildSource({ ref: `refs/commits/${REVISION}`, kind: "ci" });
  const Plan = CreateAdapterImagePlan({ Version: "0.1.0", Source });
  const Missing = clone(Plan);
  delete Missing.amd64IsaBaseline;
  assert.throws(() => ValidateAdapterImagePlan(Missing), /schema v3/);
  const Altered = clone(Plan);
  Altered.amd64IsaBaseline = "x86-64-v2";
  assert.throws(() => ValidateAdapterImagePlan(Altered), /amd64IsaBaseline/);
});

test("adapter native Dockerfiles reject AMD64 ISA drift", () => {
  const Contracts = {
    "../../adapters/git/Dockerfile": [
      'test "${FILEBELT_AMD64_ISA}" = x86-64-v3',
      "-march=${FILEBELT_AMD64_ISA}",
      "-C target-cpu=${FILEBELT_AMD64_ISA}",
      'io.filebelt.build.target-cpu="${FILEBELT_TARGET_CPU}"',
    ],
    "../../adapters/onlyoffice/Dockerfile": [
      'test "${FILEBELT_AMD64_ISA}" = x86-64-v3',
      "-C target-cpu=${FILEBELT_AMD64_ISA}",
      'io.filebelt.build.target-cpu="${FILEBELT_TARGET_CPU}"',
    ],
    "../../adapters/nfs/Dockerfile": [
      'test "${FILEBELT_AMD64_ISA}" = x86-64-v3',
      "-C target-cpu=${FILEBELT_AMD64_ISA}",
      "-march=${FILEBELT_AMD64_ISA}",
      'io.filebelt.build.target-cpu="${FILEBELT_TARGET_CPU}"',
    ],
  };
  for (const [Path, Fragments] of Object.entries(Contracts)) {
    const Dockerfile = readFileSync(new URL(Path, import.meta.url), "utf8");
    for (const Fragment of Fragments) {
      assert.ok(Dockerfile.includes(Fragment), `${Path} must retain ${Fragment}`);
    }
  }
});

test("source and license qualification unlock image construction but not publication", () => {
  const Source = buildSource({ ref: `refs/commits/${REVISION}`, kind: "ci" });
  const Plan = CreateAdapterImagePlan({
    Version: "0.1.0",
    Source,
    Evidence: {
      "filebelt-git-adapter": {
        sourceBundleSha256: "a".repeat(64),
        platformBuildArguments: {
          "linux/amd64": {
            FILEBELT_GIT_BUILDER_IMAGE: `example.test/filebelt-git-builder@sha256:${"b".repeat(64)}`,
            RUST_TARGET: "x86_64-unknown-linux-musl",
            ZLIB_TARBALL_SHA256: "c".repeat(64),
          },
          "linux/arm64": {
            FILEBELT_GIT_BUILDER_IMAGE: `example.test/filebelt-git-builder@sha256:${"b".repeat(64)}`,
            RUST_TARGET: "aarch64-unknown-linux-musl",
            ZLIB_TARBALL_SHA256: "c".repeat(64),
          },
        },
        preImage: {
          sourceBundle: "qualified",
          dependencyCompatibility: "qualified",
          componentPolicy: "qualified",
          licenseNotices: "qualified",
          buildInputs: "qualified",
          immutableSource: "qualified",
          buildContext: "qualified",
        },
      },
    },
  });
  const Git = Plan.roles.find(({ role }) => role === "filebelt-git-adapter");
  assert.equal(Git?.imageBuild.state, "eligible");
  assert.equal(Git?.publication.state, "blocked");
  assert.ok(Git?.publication.blockingReasons.includes("functional qualification is not complete"));
});

test("adapter plans reject mutable source refs and false source qualification", () => {
  assert.throws(
    () => CreateAdapterImagePlan({ Version: "0.1.0", Source: buildSource() }),
    /exact release tag or commit ref/,
  );
  const Source = buildSource({ ref: `refs/commits/${REVISION}`, kind: "ci" });
  assert.throws(
    () =>
      CreateAdapterImagePlan({
        Version: "0.1.0",
        Source,
        Evidence: { "filebelt-git-adapter": { preImage: { sourceBundle: "qualified" } } },
      }),
    /cannot qualify a source bundle without its SHA-256/,
  );
});

test("archive validator license contract matches the immutable Rust image plan", () => {
  const script = [
    "import importlib.util",
    "import json",
    "import pathlib",
    "import sys",
    "path = pathlib.Path(sys.argv[1])",
    'spec = importlib.util.spec_from_file_location("filebelt_validate_image", path)',
    'assert spec is not None and spec.loader is not None, "cannot load image validator"',
    "module = importlib.util.module_from_spec(spec)",
    "sys.modules[spec.name] = module",
    "spec.loader.exec_module(module)",
    "print(json.dumps(module.RUST_IMAGE_LICENSES, sort_keys=True))",
  ].join("\n");
  const validatorPath = fileURLToPath(
    new URL("../../tests/scripts/validate-image.py", import.meta.url),
  );
  const validatorLicenses = JSON.parse(
    execFileSync("python3", ["-c", script, validatorPath], { encoding: "utf8" }),
  );
  const plan = CreateImagePlan({ Channel: "build", Version: "0.1.0", Source: buildSource() });
  const plannedLicenses = Object.fromEntries(
    plan.images
      .filter(({ artifact }) => artifact.kind === "rust-binary")
      .map(({ role, license }) => [role, license]),
  );

  assert.deepEqual(validatorLicenses, plannedLicenses);
});

test("release plans accept exact stable and prerelease SemVer tags", () => {
  for (const version of [
    "0.1.0",
    "1.2.3-rc.1",
    "1.2.3-alpha-beta.7",
    `1.2.3-${"a".repeat(100_000)}`,
  ]) {
    const source = buildSource({ ref: `refs/tags/${version}`, kind: "release" });
    assert.equal(
      CreateImagePlan({ Channel: "release", Version: version, Source: source }).tag,
      version,
    );
  }

  for (const invalid of [
    "v1.2.3",
    "01.2.3",
    "1.02.3",
    "1.2.03",
    "1.2",
    "1.2.3.4",
    "1.2.3-",
    "1.2.3-alpha..1",
    "1.2.3-alpha_1",
    "1.2.3-α",
    "1.2.3+build.1",
    "1.2.3-01",
  ]) {
    assert.equal(IsReleaseTag(invalid), false, invalid);
  }
  assert.equal(IsReleaseTag("1.2.3"), true);
  assert.equal(IsReleaseTag("1.2.3-rc.1"), true);
  assert.throws(
    () =>
      CreateImagePlan({
        Channel: "release",
        Version: "1.2.3",
        Source: buildSource({ kind: "release" }),
      }),
    /source ref refs\/tags\/1.2.3/,
  );
});

test("release tag validation rejects adversarial prerelease input within a fixed deadline", () => {
  const DistIndex = new URL("../dist/index.js", import.meta.url).href;
  const AssertRejectedWithinDeadline = (Value, Description) => {
    const Program = [
      `import { IsReleaseTag } from ${JSON.stringify(DistIndex)};`,
      `if (IsReleaseTag(${JSON.stringify(Value)})) process.exit(1);`,
    ].join("\n");
    assert.doesNotThrow(
      () =>
        execFileSync(process.execPath, ["--input-type=module", "--eval", Program], {
          stdio: "pipe",
          timeout: 2_000,
        }),
      Description,
    );
  };

  AssertRejectedWithinDeadline(
    `0.0.0--${"-".repeat(100_000)}!`,
    "hyphen-heavy prerelease input must not cause polynomial backtracking",
  );
  AssertRejectedWithinDeadline(
    `0.0.0-0.${"--.".repeat(32)}!`,
    "dot-and-hyphen prerelease input must not cause exponential backtracking",
  );
});

test("local build tags use exactly twelve lowercase revision characters", () => {
  assert.equal(CreateLocalBuildTag("0.1.0", REVISION), "0.1.0-build.0123456789ab");
  assert.throws(() => CreateLocalBuildTag("0.1.0", REVISION.toUpperCase()), /lowercase/);
  assert.throws(() => CreateLocalBuildTag("0.1.0", "0123456789ab"), /full lowercase/);
});

test("validation rejects role, platform, runtime, source, and property drift", () => {
  const original = CreateImagePlan({ Channel: "build", Version: "0.1.0", Source: buildSource() });
  const wrongRole = clone(original);
  wrongRole.images[0].role = "filebelt-web";
  assert.throws(() => ValidateImagePlan(wrongRole), /role must be filebelt-api/);

  const wrongPlatforms = clone(original);
  wrongPlatforms.images[0].platforms = ["linux/amd64", "linux/arm64", "linux/arm64"];
  assert.throws(() => ValidateImagePlan(wrongPlatforms), /fixed image contract/);

  const wrongRuntime = clone(original);
  wrongRuntime.runtime.uid = 0;
  assert.throws(() => ValidateImagePlan(wrongRuntime), /10001/);

  const wrongAmd64IsaBaseline = clone(original);
  wrongAmd64IsaBaseline.amd64IsaBaseline = "x86-64-v2";
  assert.throws(() => ValidateImagePlan(wrongAmd64IsaBaseline), /amd64IsaBaseline/);

  const wrongTargetCpu = clone(original);
  wrongTargetCpu.images[0].artifact.targetCpu["linux/amd64"] = "x86-64-v2";
  assert.throws(() => ValidateImagePlan(wrongTargetCpu), /fixed image contract/);

  const missingComponents = clone(original);
  missingComponents.images[0].artifact.components["linux/amd64"] = [];
  assert.throws(() => ValidateImagePlan(missingComponents), /fixed image contract/);

  const wrongLicense = clone(original);
  wrongLicense.images[0].license = WebImageLicense;
  assert.throws(() => ValidateImagePlan(wrongLicense), /fixed image contract/);

  const unknownProperty = clone(original);
  unknownProperty.source.branch = "main";
  assert.throws(() => ValidateImagePlan(unknownProperty), /unknown properties/);

  const wrongCreated = clone(original);
  wrongCreated.source.created = "2026-08-06T12:34:56.000Z";
  assert.throws(() => ValidateImagePlan(wrongCreated), /RFC 3339/);
});

test("validation accepts property order changes and serialization is canonical", () => {
  const plan = CreateImagePlan({ Channel: "build", Version: "0.1.0", Source: buildSource() });
  const reordered = {
    images: plan.images,
    runtime: plan.runtime,
    source: plan.source,
    tag: plan.tag,
    version: plan.version,
    channel: plan.channel,
    amd64IsaBaseline: plan.amd64IsaBaseline,
    schemaVersion: plan.schemaVersion,
  };
  const serialized = SerializeImagePlan(reordered);

  assert.ok(serialized.endsWith("\n"));
  assert.equal(serialized, SerializeImagePlan(JSON.parse(serialized)));
  assert.match(serialized, /^\{\n {2}"schemaVersion": 2,/);
});

test("compiled CLI writes a validated canonical plan", () => {
  const output = join(tmpdir(), `filebelt-image-plan-${randomUUID()}.json`);
  try {
    execFileSync(process.execPath, [
      "dist/cli.js",
      "image-plan",
      "--channel",
      "build",
      "--version",
      "0.1.0",
      "--revision",
      REVISION,
      "--source-ref",
      "refs/heads/main",
      "--created",
      "2026-08-06T12:34:56Z",
      "--dirty",
      "false",
      "--kind",
      "ci",
      "--output",
      output,
    ]);
    const contents = readFileSync(output, "utf8");
    assert.equal(contents, SerializeImagePlan(JSON.parse(contents)));
    assert.doesNotThrow(() =>
      execFileSync(process.execPath, ["dist/cli.js", "validate-image-plan", "--input", output]),
    );

    const invalidOutput = `${output}.invalid`;
    writeFileSync(invalidOutput, JSON.stringify({ ...JSON.parse(contents), schemaVersion: 1 }));
    assert.throws(() =>
      execFileSync(process.execPath, [
        "dist/cli.js",
        "validate-image-plan",
        "--input",
        invalidOutput,
      ]),
    );
    rmSync(invalidOutput, { force: true });
  } finally {
    rmSync(output, { force: true });
  }
});
