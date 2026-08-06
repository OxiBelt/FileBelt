// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { randomUUID } from "node:crypto";
import test from "node:test";

import {
  IMAGE_PLATFORMS,
  IMAGE_ROLES,
  OXIBELT_IMAGE,
  OXIBELT_REVISION,
  OXIBELT_VERSION,
  RUST_CDLA_IMAGE_LICENSE,
  RUST_IGGY_IMAGE_LICENSE,
  RUST_IMAGE_LICENSE,
  SOURCE_URL,
  WEB_IMAGE_LICENSE,
  createImagePlan,
  createLocalBuildTag,
  isReleaseTag,
  serializeImagePlan,
  validateImagePlan,
} from "../dist/index.js";

const REVISION = "0123456789abcdef0123456789abcdef01234567";
const clone = (value) => JSON.parse(JSON.stringify(value));

function buildSource(overrides = {}) {
  return {
    url: SOURCE_URL,
    ref: "refs/heads/main",
    revision: REVISION,
    created: "2026-08-06T12:34:56Z",
    dirty: false,
    kind: "ci",
    ...overrides,
  };
}

test("build plan contains the seven fixed roles and immutable runtime contract", () => {
  const plan = createImagePlan({ channel: "build", version: "0.1.0", source: buildSource() });

  assert.equal(plan.schemaVersion, 1);
  assert.equal(plan.tag, "0.1.0-build.0123456789ab");
  assert.deepEqual(plan.runtime, { uid: 10001, gid: 10001 });
  assert.deepEqual(
    plan.images.map(({ role }) => role),
    IMAGE_ROLES,
  );
  for (const image of plan.images) {
    assert.equal(image.repository, `ghcr.io/oxibelt/${image.role}`);
    assert.equal(image.title, image.role);
    assert.ok(image.description.startsWith("FileBelt "));
    assert.deepEqual(image.platforms, IMAGE_PLATFORMS);
    const expectedLicense = {
      "filebelt-api": RUST_CDLA_IMAGE_LICENSE,
      "filebelt-worker-io": RUST_CDLA_IMAGE_LICENSE,
      "filebelt-worker-maintenance": RUST_IGGY_IMAGE_LICENSE,
      "filebelt-media-controller": RUST_IMAGE_LICENSE,
      "filebelt-mcp-broker": RUST_IMAGE_LICENSE,
      "filebelt-tools": RUST_IGGY_IMAGE_LICENSE,
      "filebelt-web": WEB_IMAGE_LICENSE,
    }[image.role];
    assert.equal(image.license, expectedLicense);
    assert.equal(image.build.target, image.role);
    if (image.artifact.kind === "rust-binary") {
      assert.deepEqual(Object.keys(image.artifact.components), IMAGE_PLATFORMS);
      for (const platform of IMAGE_PLATFORMS) {
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
      if (["filebelt-api", "filebelt-worker-io"].includes(image.role)) {
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
  assert.deepEqual(plan.images.at(-1).artifact, {
    kind: "oxibelt-edge",
    packages: ["ui/web", "ui/markdown"],
    base: {
      image: OXIBELT_IMAGE,
      version: OXIBELT_VERSION,
      revision: OXIBELT_REVISION,
    },
  });
  assert.equal(plan.images.find(({ role }) => role === "filebelt-tools").artifact.binary, "filebeltctl");
});

test("release plans accept exact stable and prerelease SemVer tags", () => {
  for (const version of ["0.1.0", "1.2.3-rc.1", "1.2.3-alpha-beta.7"]) {
    const source = buildSource({ ref: `refs/tags/${version}`, kind: "release" });
    assert.equal(createImagePlan({ channel: "release", version, source }).tag, version);
  }

  for (const invalid of ["v1.2.3", "01.2.3", "1.2", "1.2.3+build.1", "1.2.3-01"]) {
    assert.equal(isReleaseTag(invalid), false, invalid);
  }
  assert.equal(isReleaseTag("1.2.3"), true);
  assert.equal(isReleaseTag("1.2.3-rc.1"), true);
  assert.throws(
    () =>
      createImagePlan({
        channel: "release",
        version: "1.2.3",
        source: buildSource({ kind: "release" }),
      }),
    /source ref refs\/tags\/1.2.3/,
  );
});

test("local build tags use exactly twelve lowercase revision characters", () => {
  assert.equal(createLocalBuildTag("0.1.0", REVISION), "0.1.0-build.0123456789ab");
  assert.throws(() => createLocalBuildTag("0.1.0", REVISION.toUpperCase()), /lowercase/);
  assert.throws(() => createLocalBuildTag("0.1.0", "0123456789ab"), /full lowercase/);
});

test("validation rejects role, platform, runtime, source, and property drift", () => {
  const original = createImagePlan({ channel: "build", version: "0.1.0", source: buildSource() });
  const wrongRole = clone(original);
  wrongRole.images[0].role = "filebelt-web";
  assert.throws(() => validateImagePlan(wrongRole), /role must be filebelt-api/);

  const wrongPlatforms = clone(original);
  wrongPlatforms.images[0].platforms = ["linux/amd64", "linux/arm64", "linux/arm64"];
  assert.throws(() => validateImagePlan(wrongPlatforms), /fixed image contract/);

  const wrongRuntime = clone(original);
  wrongRuntime.runtime.uid = 0;
  assert.throws(() => validateImagePlan(wrongRuntime), /10001/);

  const missingComponents = clone(original);
  missingComponents.images[0].artifact.components["linux/amd64"] = [];
  assert.throws(() => validateImagePlan(missingComponents), /fixed image contract/);

  const wrongLicense = clone(original);
  wrongLicense.images[0].license = WEB_IMAGE_LICENSE;
  assert.throws(() => validateImagePlan(wrongLicense), /fixed image contract/);

  const unknownProperty = clone(original);
  unknownProperty.source.branch = "main";
  assert.throws(() => validateImagePlan(unknownProperty), /unknown properties/);

  const wrongCreated = clone(original);
  wrongCreated.source.created = "2026-08-06T12:34:56.000Z";
  assert.throws(() => validateImagePlan(wrongCreated), /RFC 3339/);
});

test("validation accepts property order changes and serialization is canonical", () => {
  const plan = createImagePlan({ channel: "build", version: "0.1.0", source: buildSource() });
  const reordered = {
    images: plan.images,
    runtime: plan.runtime,
    source: plan.source,
    tag: plan.tag,
    version: plan.version,
    channel: plan.channel,
    schemaVersion: plan.schemaVersion,
  };
  const serialized = serializeImagePlan(reordered);

  assert.ok(serialized.endsWith("\n"));
  assert.equal(serialized, serializeImagePlan(JSON.parse(serialized)));
  assert.match(serialized, /^\{\n {2}"schemaVersion": 1,/);
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
    assert.equal(contents, serializeImagePlan(JSON.parse(contents)));
    assert.doesNotThrow(() =>
      execFileSync(process.execPath, ["dist/cli.js", "validate-image-plan", "--input", output]),
    );

    const invalidOutput = `${output}.invalid`;
    writeFileSync(invalidOutput, JSON.stringify({ ...JSON.parse(contents), schemaVersion: 2 }));
    assert.throws(() =>
      execFileSync(process.execPath, ["dist/cli.js", "validate-image-plan", "--input", invalidOutput]),
    );
    rmSync(invalidOutput, { force: true });
  } finally {
    rmSync(output, { force: true });
  }
});
