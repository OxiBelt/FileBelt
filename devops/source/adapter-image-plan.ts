// SPDX-License-Identifier: Apache-2.0

/**
 * Copyleft adapter images intentionally do not participate in the Apache core
 * image plan. Their adapter-local build and source-offer evidence is reviewed
 * independently; this immutable index lets delivery tooling and Helm keep the
 * expected repository, SPDX expression, and corresponding-source location in
 * sync without importing adapter implementation code.
 */
export const AdapterImagePlanSchemaVersion = 1 as const;

export const AdapterImageRoles = [
  "filebelt-smb-gateway",
  "filebelt-ftp-ftps-gateway",
  "filebelt-onlyoffice-adapter",
  "filebelt-nfs-gateway",
  "filebelt-transcoder",
] as const;

export type AdapterImageRole = (typeof AdapterImageRoles)[number];

/* eslint-disable @typescript-eslint/naming-convention -- These properties are stable adapter evidence schema v1 JSON keys. */
export interface AdapterImageEvidence {
  readonly role: AdapterImageRole;
  readonly repository: `ghcr.io/oxibelt/${AdapterImageRole}`;
  readonly license: "AGPL-3.0-only" | "GPL-3.0-or-later" | "LGPL-3.0-or-later";
  readonly correspondingSource: `https://github.com/OxiBelt/FileBelt/tree/${string}`;
  /** Present only when an adapter has an approved release-platform contract. */
  readonly publishPlatforms?: readonly (
    | "linux/amd64"
    | "linux/arm64"
    | "linux/riscv64"
  )[];
  /** RISC-V never joins the published adapter manifest without separate review. */
  readonly riscv64Policy?: "compile-and-probe-only";
}
/* eslint-enable @typescript-eslint/naming-convention */

export const AdapterImagePlan: readonly AdapterImageEvidence[] = [
  {
    role: "filebelt-smb-gateway",
    repository: "ghcr.io/oxibelt/filebelt-smb-gateway",
    license: "GPL-3.0-or-later",
    correspondingSource: "https://github.com/OxiBelt/FileBelt/tree/main/adapters/smb",
  },
  {
    role: "filebelt-ftp-ftps-gateway",
    repository: "ghcr.io/oxibelt/filebelt-ftp-ftps-gateway",
    license: "GPL-3.0-or-later",
    correspondingSource: "https://github.com/OxiBelt/FileBelt/tree/main/adapters/ftp-ftps",
  },
  {
    role: "filebelt-onlyoffice-adapter",
    repository: "ghcr.io/oxibelt/filebelt-onlyoffice-adapter",
    license: "AGPL-3.0-only",
    correspondingSource: "https://github.com/OxiBelt/FileBelt/tree/0.1.0",
    publishPlatforms: ["linux/amd64", "linux/arm64"],
    riscv64Policy: "compile-and-probe-only",
  },
  {
    role: "filebelt-nfs-gateway",
    repository: "ghcr.io/oxibelt/filebelt-nfs-gateway",
    license: "LGPL-3.0-or-later",
    correspondingSource: "https://github.com/OxiBelt/FileBelt/tree/main/adapters/nfs",
    publishPlatforms: ["linux/amd64", "linux/arm64", "linux/riscv64"],
  },
  {
    role: "filebelt-transcoder",
    repository: "ghcr.io/oxibelt/filebelt-transcoder",
    license: "GPL-3.0-or-later",
    correspondingSource: "https://github.com/OxiBelt/FileBelt/tree/main/adapters/transcode",
    publishPlatforms: ["linux/amd64", "linux/arm64"],
    riscv64Policy: "compile-and-probe-only",
  },
] as const;
