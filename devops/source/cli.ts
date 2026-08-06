// SPDX-License-Identifier: Apache-2.0

import {
  IMAGE_PLATFORMS,
  IMAGE_ROLES,
  SOURCE_URL,
  createImagePlan,
  evaluateVulnerabilityPolicy,
  serializeImagePlan,
  validateImagePlan,
  type ImagePlanChannel,
  type ImagePlatform,
  type ImageRole,
  type SourceKind,
  type VulnerabilityFinding,
} from "./index.js";

interface RuntimeProcess {
  readonly argv: readonly string[];
  readonly stderr: { write(value: string): void };
  exitCode: number | undefined;
  getBuiltinModule(name: "node:fs"): unknown;
}

interface FileSystem {
  readFileSync(path: string, options: { encoding: "utf8" }): string;
  writeFileSync(path: string, data: string, options: { encoding: "utf8"; flag: "w" }): void;
}

const runtimeProcess = (globalThis as unknown as { process: RuntimeProcess }).process;

try {
  run(runtimeProcess.argv.slice(2));
} catch (error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  runtimeProcess.stderr.write(`filebelt devops: ${message}\n`);
  runtimeProcess.exitCode = 1;
}

function run(arguments_: readonly string[]): void {
  const [command, ...commandArguments] = arguments_;
  if (command === "image-plan") {
    createImagePlanFile(commandArguments);
    return;
  }
  if (command === "validate-image-plan") {
    validateImagePlanFile(commandArguments);
    return;
  }
  if (command === "evaluate-vulnerabilities") {
    evaluateVulnerabilities(commandArguments);
    return;
  }
  throw new Error(
    "expected the image-plan, validate-image-plan, or evaluate-vulnerabilities command",
  );
}

function createImagePlanFile(arguments_: readonly string[]): void {
  const options = parseOptions(arguments_, [
    "channel",
    "version",
    "revision",
    "source-ref",
    "created",
    "dirty",
    "kind",
    "output",
  ]);
  const channel = readChannel(options);
  const kind = readKind(options);
  const dirty = readBoolean(options, "dirty");
  const version = readOption(options, "version");
  const revision = readOption(options, "revision");
  const ref = readOption(options, "source-ref");
  const created = readOption(options, "created");
  const output = readOption(options, "output");

  const plan = createImagePlan({
    channel,
    version,
    source: {
      url: SOURCE_URL,
      ref,
      revision,
      created,
      dirty,
      kind,
    },
  });
  const fileSystem = runtimeProcess.getBuiltinModule("node:fs") as FileSystem;
  fileSystem.writeFileSync(output, serializeImagePlan(plan), { encoding: "utf8", flag: "w" });
}

function validateImagePlanFile(arguments_: readonly string[]): void {
  const options = parseOptions(arguments_, ["input"]);
  const input = readOption(options, "input");
  validateImagePlan(readJson(input));
}

function evaluateVulnerabilities(arguments_: readonly string[]): void {
  const options = parseOptions(arguments_, [
    "trivy",
    "policy",
    "role",
    "platform",
    "as-of",
    "output",
  ]);
  const role = readRole(options);
  const platform = readPlatform(options);
  const findings = normalizeTrivy(readJson(readOption(options, "trivy")), role, platform);
  const policy = readJson(readOption(options, "policy"));
  const decision = evaluateVulnerabilityPolicy(
    findings,
    policy,
    readOption(options, "as-of"),
  );
  const fileSystem = runtimeProcess.getBuiltinModule("node:fs") as FileSystem;
  fileSystem.writeFileSync(
    readOption(options, "output"),
    `${JSON.stringify(decision, null, 2)}\n`,
    { encoding: "utf8", flag: "w" },
  );
  if (!decision.allowed) {
    runtimeProcess.exitCode = 1;
  }
}

function parseOptions(
  arguments_: readonly string[],
  allowedNames: readonly string[],
): ReadonlyMap<string, string> {
  const options = new Map<string, string>();
  for (let index = 0; index < arguments_.length; index += 2) {
    const option = arguments_[index];
    const value = arguments_[index + 1];
    if (option === undefined || !option.startsWith("--") || option.length === 2) {
      throw new Error("image-plan options must use --name value pairs");
    }
    if (value === undefined) {
      throw new Error(`${option} requires a value`);
    }
    const name = option.slice(2);
    if (options.has(name)) {
      throw new Error(`${option} may only be provided once`);
    }
    options.set(name, value);
  }
  const allowed = new Set(allowedNames);
  for (const name of options.keys()) {
    if (!allowed.has(name)) {
      throw new Error(`unknown image-plan option --${name}`);
    }
  }
  return options;
}

function readJson(path: string): unknown {
  const fileSystem = runtimeProcess.getBuiltinModule("node:fs") as FileSystem;
  let contents: string;
  try {
    contents = fileSystem.readFileSync(path, { encoding: "utf8" });
  } catch (error: unknown) {
    throw new Error(`cannot read ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
  try {
    return JSON.parse(contents) as unknown;
  } catch (error: unknown) {
    throw new Error(`${path} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function readRole(options: ReadonlyMap<string, string>): ImageRole {
  const value = readOption(options, "role");
  if (!IMAGE_ROLES.includes(value as ImageRole)) {
    throw new Error("--role is not a Phase 1 image role");
  }
  return value as ImageRole;
}

function readPlatform(options: ReadonlyMap<string, string>): ImagePlatform {
  const value = readOption(options, "platform");
  if (!IMAGE_PLATFORMS.includes(value as ImagePlatform)) {
    throw new Error("--platform is not a Phase 1 image platform");
  }
  return value as ImagePlatform;
}

function normalizeTrivy(
  value: unknown,
  role: ImageRole,
  platform: ImagePlatform,
): readonly VulnerabilityFinding[] {
  const report = assertRecord(value, "Trivy report");
  if (report.SchemaVersion !== 2) {
    throw new Error("Trivy report SchemaVersion must be 2");
  }
  const trivy = assertRecord(report.Trivy, "Trivy report tool identity");
  if (trivy.Version !== "0.73.0") {
    throw new Error("Trivy report must be produced by version 0.73.0");
  }
  if (report.Results === undefined) {
    if (role !== "filebelt-web") {
      throw new Error("Rust Trivy report must contain a scanned runtime package inventory");
    }
    return [];
  }
  if (!Array.isArray(report.Results)) {
    throw new Error("Trivy report Results must be an array");
  }
  const findings: VulnerabilityFinding[] = [];
  let packageCount = 0;
  for (const [resultIndex, resultValue] of report.Results.entries()) {
    const result = assertRecord(resultValue, `Trivy result ${resultIndex}`);
    if (typeof result.Target !== "string" || result.Target.length === 0) {
      throw new Error(`Trivy result ${resultIndex} Target must be a non-empty string`);
    }
    if (result.Packages !== undefined) {
      if (!Array.isArray(result.Packages)) {
        throw new Error(`Trivy result ${resultIndex} Packages must be an array`);
      }
      packageCount += result.Packages.length;
    }
    if (result.Vulnerabilities === null || result.Vulnerabilities === undefined) {
      continue;
    }
    if (!Array.isArray(result.Vulnerabilities)) {
      throw new Error(`Trivy result ${resultIndex} Vulnerabilities must be an array or null`);
    }
    for (const [vulnerabilityIndex, vulnerabilityValue] of result.Vulnerabilities.entries()) {
      const description = `Trivy result ${resultIndex} vulnerability ${vulnerabilityIndex}`;
      const vulnerability = assertRecord(vulnerabilityValue, description);
      findings.push({
        role,
        platform,
        target: result.Target,
        vulnerabilityId: readTrivyString(vulnerability, "VulnerabilityID", description),
        packageName: readTrivyString(vulnerability, "PkgName", description),
        installedVersion: readTrivyString(vulnerability, "InstalledVersion", description),
        severity: readTrivyString(vulnerability, "Severity", description) as VulnerabilityFinding["severity"],
      });
    }
  }
  if (role !== "filebelt-web" && packageCount === 0) {
    throw new Error("Rust Trivy report must contain a scanned runtime package inventory");
  }
  return findings;
}

function readTrivyString(
  value: Record<string, unknown>,
  key: string,
  description: string,
): string {
  const field = value[key];
  if (typeof field !== "string" || field.length === 0) {
    throw new Error(`${description} ${key} must be a non-empty string`);
  }
  return field;
}

function assertRecord(value: unknown, description: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${description} must be an object`);
  }
  return value as Record<string, unknown>;
}

function readOption(options: ReadonlyMap<string, string>, name: string): string {
  const value = options.get(name);
  if (value === undefined || value.length === 0) {
    throw new Error(`--${name} is required`);
  }
  return value;
}

function readChannel(options: ReadonlyMap<string, string>): ImagePlanChannel {
  const value = readOption(options, "channel");
  if (value !== "build" && value !== "release") {
    throw new Error("--channel must be build or release");
  }
  return value;
}

function readKind(options: ReadonlyMap<string, string>): SourceKind {
  const value = readOption(options, "kind");
  if (value !== "local" && value !== "ci" && value !== "release" && value !== "rebuild") {
    throw new Error("--kind must be local, ci, release, or rebuild");
  }
  return value;
}

function readBoolean(options: ReadonlyMap<string, string>, name: string): boolean {
  const value = readOption(options, name);
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  throw new Error(`--${name} must be true or false`);
}
