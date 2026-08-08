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
] as const;

export type AdapterImageRole = (typeof AdapterImageRoles)[number];

/* eslint-disable @typescript-eslint/naming-convention -- These properties are stable adapter evidence schema v1 JSON keys. */
export interface AdapterImageEvidence {
  readonly role: AdapterImageRole;
  readonly repository: `ghcr.io/oxibelt/${AdapterImageRole}`;
  readonly license: "GPL-3.0-or-later";
  readonly correspondingSource: `https://github.com/OxiBelt/FileBelt/tree/main/adapters/${string}`;
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
] as const;
