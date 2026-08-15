// SPDX-License-Identifier: Apache-2.0

import {
  CreateAdapterImagePlan,
  CreateImagePlan,
  EvaluateVulnerabilityPolicy,
  ImagePlatforms,
  ImageRoles,
  SerializeAdapterImagePlan,
  SerializeImagePlan,
  SourceUrl,
  ValidateAdapterImagePlan,
  ValidateImagePlan,
  type AdapterImageRole,
  type AdapterRoleQualificationInput,
  type ImagePlanChannel,
  type ImagePlatform,
  type ImageRole,
  type SourceKind,
  type VulnerabilityFinding,
} from "./index.js";

interface RuntimeProcessContract {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- Node.js exposes this exact process property.
  readonly argv: readonly string[];
  // eslint-disable-next-line @typescript-eslint/naming-convention -- Node.js exposes this exact process property.
  readonly stderr: { write(Value: string): void };
  // eslint-disable-next-line @typescript-eslint/naming-convention -- Node.js exposes this exact process property.
  exitCode: number | undefined;
  getBuiltinModule(Name: "node:fs"): unknown;
}

interface ReadFileOptions {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- Node.js requires this exact file-system option.
  readonly encoding: "utf8";
}

interface WriteFileOptions extends ReadFileOptions {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- Node.js requires this exact file-system option.
  readonly flag: "w";
}

interface FileSystem {
  readFileSync(Path: string, Options: ReadFileOptions): string;
  writeFileSync(Path: string, Data: string, Options: WriteFileOptions): void;
}

interface RuntimeGlobals {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- The JavaScript global exposes this exact property.
  readonly process: RuntimeProcessContract;
}

const RuntimeProcess = (globalThis as unknown as RuntimeGlobals).process;

try {
  Run(RuntimeProcess.argv.slice(2));
} catch (ErrorValue: unknown) {
  const Message = ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue);
  RuntimeProcess.stderr.write(`filebelt devops: ${Message}\n`);
  RuntimeProcess.exitCode = 1;
}

function Run(InputArguments: readonly string[]): void {
  const [Command, ...CommandArguments] = InputArguments;
  if (Command === "image-plan") {
    CreateImagePlanFile(CommandArguments);
    return;
  }
  if (Command === "adapter-image-plan") {
    CreateAdapterImagePlanFile(CommandArguments);
    return;
  }
  if (Command === "validate-adapter-image-plan") {
    ValidateAdapterImagePlanFile(CommandArguments);
    return;
  }
  if (Command === "validate-image-plan") {
    ValidateImagePlanFile(CommandArguments);
    return;
  }
  if (Command === "evaluate-vulnerabilities") {
    EvaluateVulnerabilities(CommandArguments);
    return;
  }
  throw new Error(
    "expected the image-plan, adapter-image-plan, validate-image-plan, validate-adapter-image-plan, or evaluate-vulnerabilities command",
  );
}

function CreateAdapterImagePlanFile(InputArguments: readonly string[]): void {
  const Options = ParseOptions(InputArguments, [
    "version",
    "revision",
    "source-ref",
    "created",
    "dirty",
    "kind",
    "evidence",
    "output",
  ]);
  const Kind = ReadKind(Options);
  const Source = {
    url: SourceUrl,
    ref: ReadOption(Options, "source-ref"),
    revision: ReadOption(Options, "revision"),
    created: ReadOption(Options, "created"),
    dirty: ReadBoolean(Options, "dirty"),
    kind: Kind,
  } as const;
  let Evidence: Partial<Record<AdapterImageRole, AdapterRoleQualificationInput>> | undefined;
  const EvidencePath = Options.get("evidence");
  if (EvidencePath !== undefined) {
    Evidence = ReadJson(EvidencePath) as Partial<
      Record<AdapterImageRole, AdapterRoleQualificationInput>
    >;
  }
  const Plan = CreateAdapterImagePlan({
    Version: ReadOption(Options, "version"),
    Source,
    ...(Evidence === undefined ? {} : { Evidence }),
  });
  const FileSystemModule = RuntimeProcess.getBuiltinModule("node:fs") as FileSystem;
  FileSystemModule.writeFileSync(ReadOption(Options, "output"), SerializeAdapterImagePlan(Plan), {
    encoding: "utf8", flag: "w",
  });
}

function ValidateAdapterImagePlanFile(InputArguments: readonly string[]): void {
  const Options = ParseOptions(InputArguments, ["input"]);
  ValidateAdapterImagePlan(ReadJson(ReadOption(Options, "input")));
}

function CreateImagePlanFile(InputArguments: readonly string[]): void {
  const Options = ParseOptions(InputArguments, [
    "channel",
    "version",
    "revision",
    "source-ref",
    "created",
    "dirty",
    "kind",
    "output",
  ]);
  const Channel = ReadChannel(Options);
  const Kind = ReadKind(Options);
  const Dirty = ReadBoolean(Options, "dirty");
  const Version = ReadOption(Options, "version");
  const Revision = ReadOption(Options, "revision");
  const Ref = ReadOption(Options, "source-ref");
  const Created = ReadOption(Options, "created");
  const Output = ReadOption(Options, "output");

  const Plan = CreateImagePlan({
    Channel,
    Version,
    Source: {
      url: SourceUrl,
      ref: Ref,
      revision: Revision,
      created: Created,
      dirty: Dirty,
      kind: Kind,
    },
  });
  const FileSystemModule = RuntimeProcess.getBuiltinModule("node:fs") as FileSystem;
  FileSystemModule.writeFileSync(Output, SerializeImagePlan(Plan), { encoding: "utf8", flag: "w" });
}

function ValidateImagePlanFile(InputArguments: readonly string[]): void {
  const Options = ParseOptions(InputArguments, ["input"]);
  const Input = ReadOption(Options, "input");
  ValidateImagePlan(ReadJson(Input));
}

function EvaluateVulnerabilities(InputArguments: readonly string[]): void {
  const Options = ParseOptions(InputArguments, [
    "trivy",
    "policy",
    "role",
    "platform",
    "as-of",
    "output",
  ]);
  const Role = ReadRole(Options);
  const Platform = ReadPlatform(Options);
  const Findings = NormalizeTrivy(ReadJson(ReadOption(Options, "trivy")), Role, Platform);
  const Policy = ReadJson(ReadOption(Options, "policy"));
  const Decision = EvaluateVulnerabilityPolicy(
    Findings,
    Policy,
    ReadOption(Options, "as-of"),
  );
  const FileSystemModule = RuntimeProcess.getBuiltinModule("node:fs") as FileSystem;
  FileSystemModule.writeFileSync(
    ReadOption(Options, "output"),
    `${JSON.stringify(Decision, null, 2)}\n`,
    { encoding: "utf8", flag: "w" },
  );
  if (!Decision.allowed) {
    RuntimeProcess.exitCode = 1;
  }
}

function ParseOptions(
  InputArguments: readonly string[],
  AllowedNames: readonly string[],
): ReadonlyMap<string, string> {
  const Options = new Map<string, string>();
  for (let Index = 0; Index < InputArguments.length; Index += 2) {
    const Option = InputArguments[Index];
    const Value = InputArguments[Index + 1];
    if (Option === undefined || !Option.startsWith("--") || Option.length === 2) {
      throw new Error("image-plan options must use --name value pairs");
    }
    if (Value === undefined) {
      throw new Error(`${Option} requires a value`);
    }
    const Name = Option.slice(2);
    if (Options.has(Name)) {
      throw new Error(`${Option} may only be provided once`);
    }
    Options.set(Name, Value);
  }
  const Allowed = new Set(AllowedNames);
  for (const Name of Options.keys()) {
    if (!Allowed.has(Name)) {
      throw new Error(`unknown image-plan option --${Name}`);
    }
  }
  return Options;
}

function ReadJson(Path: string): unknown {
  const FileSystemModule = RuntimeProcess.getBuiltinModule("node:fs") as FileSystem;
  let Contents: string;
  try {
    Contents = FileSystemModule.readFileSync(Path, { encoding: "utf8" });
  } catch (ErrorValue: unknown) {
    throw new Error(`cannot read ${Path}: ${ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)}`, {
      cause: ErrorValue,
    });
  }
  try {
    return JSON.parse(Contents) as unknown;
  } catch (ErrorValue: unknown) {
    throw new Error(`${Path} is not valid JSON: ${ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)}`, {
      cause: ErrorValue,
    });
  }
}

function ReadRole(Options: ReadonlyMap<string, string>): ImageRole {
  const Value = ReadOption(Options, "role");
  if (!ImageRoles.includes(Value as ImageRole)) {
    throw new Error("--role is not a FileBelt image role");
  }
  return Value as ImageRole;
}

function ReadPlatform(Options: ReadonlyMap<string, string>): ImagePlatform {
  const Value = ReadOption(Options, "platform");
  if (!ImagePlatforms.includes(Value as ImagePlatform)) {
    throw new Error("--platform is not a FileBelt image platform");
  }
  return Value as ImagePlatform;
}

function NormalizeTrivy(
  Value: unknown,
  Role: ImageRole,
  Platform: ImagePlatform,
): readonly VulnerabilityFinding[] {
  const Report = AssertRecord(Value, "Trivy report");
  if (Report.SchemaVersion !== 2) {
    throw new Error("Trivy report SchemaVersion must be 2");
  }
  const Trivy = AssertRecord(Report.Trivy, "Trivy report tool identity");
  if (Trivy.Version !== "0.74.0") {
    throw new Error("Trivy report must be produced by version 0.74.0");
  }
  if (Report.Results === undefined) {
    throw new Error(`${Role} Trivy report must contain a scanned runtime package inventory`);
  }
  if (!Array.isArray(Report.Results)) {
    throw new Error("Trivy report Results must be an array");
  }
  const Findings: VulnerabilityFinding[] = [];
  let PackageCount = 0;
  for (const [ResultIndex, ResultValue] of Report.Results.entries()) {
    const Result = AssertRecord(ResultValue, `Trivy result ${ResultIndex}`);
    if (typeof Result.Target !== "string" || Result.Target.length === 0) {
      throw new Error(`Trivy result ${ResultIndex} Target must be a non-empty string`);
    }
    if (Result.Packages !== undefined) {
      if (!Array.isArray(Result.Packages)) {
        throw new Error(`Trivy result ${ResultIndex} Packages must be an array`);
      }
      PackageCount += Result.Packages.length;
    }
    if (Result.Vulnerabilities === null || Result.Vulnerabilities === undefined) {
      continue;
    }
    if (!Array.isArray(Result.Vulnerabilities)) {
      throw new Error(`Trivy result ${ResultIndex} Vulnerabilities must be an array or null`);
    }
    for (const [VulnerabilityIndex, VulnerabilityValue] of Result.Vulnerabilities.entries()) {
      const Description = `Trivy result ${ResultIndex} vulnerability ${VulnerabilityIndex}`;
      const Vulnerability = AssertRecord(VulnerabilityValue, Description);
      Findings.push({
        role: Role,
        platform: Platform,
        target: Result.Target,
        vulnerabilityId: ReadTrivyString(Vulnerability, "VulnerabilityID", Description),
        packageName: ReadTrivyString(Vulnerability, "PkgName", Description),
        installedVersion: ReadTrivyString(Vulnerability, "InstalledVersion", Description),
        severity: ReadTrivyString(Vulnerability, "Severity", Description) as VulnerabilityFinding["severity"],
      });
    }
  }
  if (PackageCount === 0) {
    throw new Error(`${Role} Trivy report must contain a scanned runtime package inventory`);
  }
  return Findings;
}

function ReadTrivyString(
  Value: Record<string, unknown>,
  Key: string,
  Description: string,
): string {
  const Field = Value[Key];
  if (typeof Field !== "string" || Field.length === 0) {
    throw new Error(`${Description} ${Key} must be a non-empty string`);
  }
  return Field;
}

function AssertRecord(Value: unknown, Description: string): Record<string, unknown> {
  if (typeof Value !== "object" || Value === null || Array.isArray(Value)) {
    throw new Error(`${Description} must be an object`);
  }
  return Value as Record<string, unknown>;
}

function ReadOption(Options: ReadonlyMap<string, string>, Name: string): string {
  const Value = Options.get(Name);
  if (Value === undefined || Value.length === 0) {
    throw new Error(`--${Name} is required`);
  }
  return Value;
}

function ReadChannel(Options: ReadonlyMap<string, string>): ImagePlanChannel {
  const Value = ReadOption(Options, "channel");
  if (Value !== "build" && Value !== "release") {
    throw new Error("--channel must be build or release");
  }
  return Value;
}

function ReadKind(Options: ReadonlyMap<string, string>): SourceKind {
  const Value = ReadOption(Options, "kind");
  if (Value !== "local" && Value !== "ci" && Value !== "release" && Value !== "rebuild") {
    throw new Error("--kind must be local, ci, release, or rebuild");
  }
  return Value;
}

function ReadBoolean(Options: ReadonlyMap<string, string>, Name: string): boolean {
  const Value = ReadOption(Options, Name);
  if (Value === "true") {
    return true;
  }
  if (Value === "false") {
    return false;
  }
  throw new Error(`--${Name} must be true or false`);
}
