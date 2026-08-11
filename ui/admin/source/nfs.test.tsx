// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  ExportTransitions,
  NfsAdminOverviewView,
} from "./nfs.js";
import type { NfsAdminSnapshot } from "./nfs.js";

const Snapshot: NfsAdminSnapshot = {
  Conflicts: [{
    BaseVersionId: null,
    ConflictCopyNodeId: null,
    ConflictCopyVersionId: null,
    CreatedAt: "2026-08-11T00:00:00Z",
    DriveId: "00000000-0000-4000-8000-000000000101",
    ExpectedHeadVersionId: null,
    ExpiresAt: "2026-08-18T00:00:00Z",
    Id: "00000000-0000-4000-8000-000000000107",
    LogicalSizeBytes: 17,
    ObservedHeadVersionId: null,
    SourceNodeId: "00000000-0000-4000-8000-000000000108",
    State: "retained",
    WriteSessionId: "00000000-0000-4000-8000-000000000109",
  }],
  Exports: [{
    AppliedGeneration: 2,
    AppliedState: "active",
    DesiredGeneration: 3,
    DesiredState: "draining",
    DriveId: "00000000-0000-4000-8000-000000000101",
    ExportId: 7,
    ExportPath: "/filebelt/00000000-0000-4000-8000-000000000101",
    InSync: false,
  }],
  Feature: {
    AppliedGatewayEpoch: 4,
    AppliedGatewayId: "nfs-gateway-1",
    AppliedManifestGeneration: 8,
    DesiredManifestGeneration: 9,
    Generation: 3,
    ManifestApplied: false,
    RestoreGeneration: 1,
    State: "draining",
  },
  Mappings: [{
    AllowedDriveIds: ["00000000-0000-4000-8000-000000000101"],
    CredentialId: "00000000-0000-4000-8000-000000000102",
    Generation: 2,
    KerberosPrincipal: "alice@EXAMPLE.TEST",
    PrincipalId: "00000000-0000-4000-8000-000000000103",
    ProjectedGid: 2001,
    ProjectedUid: 1001,
  }],
  PosixGroups: [{
    GroupId: "00000000-0000-4000-8000-000000000104",
    PosixName: "engineering.platform",
    ProjectedGid: 2001,
  }],
  Realm: "EXAMPLE.TEST",
  TenantSlug: "acme",
};

describe("NfsAdminOverviewView", () => {
  it("shows desired and applied generations, exact-realm mapping guidance, and confirmation gates", () => {
    const Markup = renderToStaticMarkup(
      <NfsAdminOverviewView
        Busy={false}
        OnCopyConflict={async () => undefined}
        OnDiscardConflict={async () => undefined}
        OnRegisterExport={async () => undefined}
        OnRegisterPosixGroup={async () => undefined}
        OnRevokeMapping={async () => undefined}
        OnTransitionExport={async () => undefined}
        OnTransitionFeature={async () => undefined}
        OnUpsertMapping={async () => undefined}
        Snapshot={Snapshot}
      />,
    );

    expect(Markup).toContain("Desired manifest generation");
    expect(Markup).toContain("Applied manifest generation");
    expect(Markup).toContain("Desired state");
    expect(Markup).toContain("Applied state");
    expect(Markup).toContain("user@EXAMPLE.TEST");
    expect(Markup).toContain("Configured Kerberos realm");
    expect(Markup).toContain("I reviewed the manifest generations");
    expect(Markup).toContain("I confirm this complete principal mapping");
    expect(Markup).toContain("I confirm this mapping should be revoked");
    expect(Markup).toMatch(/<button[^>]*disabled=""[^>]*>Transition to disabled<\/button>/);
    expect(Markup).toContain("Register POSIX group");
    expect(Markup).toContain("Type acme to enable one NFS mutation");
    expect(Markup).toContain("without trimming, normalization, or case folding");
    expect(Markup).toContain("Retained NFS write conflict");
    expect(Markup).toContain("Copy conflict");
    expect(Markup).toContain("Discard conflict");
  });

  it("does not allow disable before the draining generation is applied", () => {
    expect(ExportTransitions(Snapshot.Exports[0]!, "draining")).toEqual(["active"]);
    expect(ExportTransitions({
      ...Snapshot.Exports[0]!,
      AppliedGeneration: 3,
      AppliedState: "draining",
    }, "draining")).toEqual(["active", "disabled"]);
  });

  it("renders legacy mapping authority as unknown rather than an empty drive set", () => {
    const LegacySnapshot: NfsAdminSnapshot = {
      ...Snapshot,
      Mappings: [{
        CredentialId: "00000000-0000-4000-8000-000000000105",
        Generation: 1,
        KerberosPrincipal: "legacy@EXAMPLE.TEST",
        PrincipalId: "00000000-0000-4000-8000-000000000106",
        ProjectedGid: 2001,
        ProjectedUid: 1001,
      }],
    };
    const Markup = renderToStaticMarkup(
      <NfsAdminOverviewView
        Busy={false}
        OnCopyConflict={async () => undefined}
        OnDiscardConflict={async () => undefined}
        OnRegisterExport={async () => undefined}
        OnRegisterPosixGroup={async () => undefined}
        OnRevokeMapping={async () => undefined}
        OnTransitionExport={async () => undefined}
        OnTransitionFeature={async () => undefined}
        OnUpsertMapping={async () => undefined}
        Snapshot={LegacySnapshot}
      />,
    );

    expect(Markup).toContain("Unknown in this legacy replay response");
    expect(Markup).not.toContain("Allowed exports: </span>");
  });
});
