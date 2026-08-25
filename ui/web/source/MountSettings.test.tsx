// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  CreateCredentialWithRecovery,
  FormatMountSessionDetail,
  MountCredentialCreationBlocked,
  NfsActiveMappingCard,
  NfsProposalConsentCard,
} from "./MountSettings.js";
import { MountCredentialOutcomeUnknownError } from "./mount-http-client.js";
import type { MountCredentialOperation, MountSettingsClient } from "./mount-http-client.js";
import type { NfsMappingProposal, NfsPrincipalMapping } from "./nfs-target-http-client.js";

const DriveId = "00000000-0000-4000-8000-000000000141";
const CredentialOperation = {
  expires_at: "2026-08-11T00:02:00Z",
  operation_generation: 4,
  operation_id: "00000000-0000-4000-8000-000000000149",
} satisfies MountCredentialOperation;

const Proposal: NfsMappingProposal = {
  allowed_drive_ids: [DriveId],
  allowed_drives: [{ display_name: "Research", id: DriveId }],
  created_at: "2026-08-11T00:00:00Z",
  decided_at: null,
  expires_at: "2026-08-12T00:00:00Z",
  generation: 1,
  id: "00000000-0000-4000-8000-000000000142",
  kerberos_principal: "avery@EXAMPLE.TEST",
  principal_id: "00000000-0000-4000-8000-000000000143",
  posix_group_id: "00000000-0000-4000-8000-000000000146",
  posix_group_name: "researchers",
  posix_name: "avery",
  projected_gid: 2001,
  projected_uid: 1001,
  proposer_principal_id: "00000000-0000-4000-8000-000000000144",
  state: "pending",
};

const Mapping: NfsPrincipalMapping = {
  allowed_drive_ids: [DriveId],
  credential_id: "00000000-0000-4000-8000-000000000145",
  generation: 2,
  kerberos_principal: Proposal.kerberos_principal,
  principal_id: Proposal.principal_id,
  projected_gid: Proposal.projected_gid,
  projected_uid: Proposal.projected_uid,
};

const NfsSession = {
  absolute_expires_at: "2026-08-11T01:00:00Z",
  close_reason: null,
  created_at: "2026-08-11T00:00:00Z",
  gateway_id: "nfs-gateway-0",
  id: "00000000-0000-4000-8000-000000000147",
  idle_expires_at: "2026-08-11T00:15:00Z",
  last_activity_at: "2026-08-11T00:01:00Z",
  protocol: "nfs",
  source_address: "192.0.2.7",
  state: "active",
} as const;

// oxlint-disable typescript/require-await -- These receiver-free asynchronous fakes exercise the credential recovery state machine without performing I/O.
describe("mount credential recovery", () => {
  it("blocks a second credential while revocation of an unknown create remains unresolved", () => {
    expect(MountCredentialCreationBlocked(null)).toBe(false);
    expect(
      MountCredentialCreationBlocked({
        ...CredentialOperation,
      }),
    ).toBe(true);
  });

  it("prepares first and creates with the server-issued tuple", async () => {
    const Calls: string[] = [];
    await expect(
      CreateCredentialWithRecovery(
        {
          cancelCredentialOperation: async () => {
            throw new Error("cancellation must not run after success");
          },
          createCredential: async (Input) => {
            Calls.push(`create:${Input.operation_id}:${Input.operation_generation}`);
            return {
              credential_id: Input.operation_id,
              expires_at: Input.expires_at,
              password: "one-time-password",
              protocol: Input.protocol,
              username: "fb-example",
            };
          },
          prepareCredentialOperation: async () => {
            Calls.push("prepare");
            return { Created: true, Operation: CredentialOperation };
          },
        },
        {
          allowed_drive_ids: [DriveId],
          bound_device_id: null,
          expires_at: "2026-08-18T00:00:00Z",
          protocol: "smb",
          read_only: true,
        },
      ),
    ).resolves.toMatchObject({
      credential_id: CredentialOperation.operation_id,
      password: "one-time-password",
    });
    expect(Calls).toEqual([
      "prepare",
      `create:${CredentialOperation.operation_id}:${CredentialOperation.operation_generation}`,
    ]);
  });

  it("does not cancel a shared tuple after a definite create rejection", async () => {
    const Calls: string[] = [];
    const Rejection = new Error("credential request rejected");
    await expect(
      CreateCredentialWithRecovery(
        {
          cancelCredentialOperation: async (OperationId, Generation) => {
            Calls.push(`cancel:${OperationId}:${Generation}`);
          },
          createCredential: async () => {
            Calls.push("create");
            throw Rejection;
          },
          prepareCredentialOperation: async () => {
            Calls.push("prepare");
            return { Created: false, Operation: CredentialOperation };
          },
        },
        {
          allowed_drive_ids: [DriveId],
          bound_device_id: null,
          expires_at: "2026-08-18T00:00:00Z",
          protocol: "smb",
          read_only: true,
        },
      ),
    ).rejects.toBe(Rejection);
    expect(Calls).toEqual(["prepare", "create"]);
  });

  it("does not let a losing client revoke the credential created from a shared tuple", async () => {
    let CredentialActive = false;
    let CancellationCount = 0;
    const SharedClient = {
      cancelCredentialOperation: async () => {
        CancellationCount += 1;
        CredentialActive = false;
      },
      createCredential: async (Input: Parameters<MountSettingsClient["createCredential"]>[0]) => {
        if (CredentialActive) throw new Error("credential operation is stale");
        CredentialActive = true;
        return {
          credential_id: Input.operation_id,
          expires_at: Input.expires_at,
          password: "winner-password",
          protocol: Input.protocol,
          username: "fb-example",
        };
      },
      prepareCredentialOperation: async () => ({
        Created: false,
        Operation: CredentialOperation,
      }),
    };
    const Draft = {
      allowed_drive_ids: [DriveId],
      bound_device_id: null,
      expires_at: "2026-08-18T00:00:00Z",
      protocol: "smb",
      read_only: true,
    } as const;

    await expect(CreateCredentialWithRecovery(SharedClient, Draft)).resolves.toMatchObject({
      password: "winner-password",
    });
    await expect(CreateCredentialWithRecovery(SharedClient, Draft)).rejects.toThrow(
      "credential operation is stale",
    );
    expect(CredentialActive).toBe(true);
    expect(CancellationCount).toBe(0);
  });

  it("keeps the exact tuple blocked when recovery has a transport-unknown outcome", async () => {
    const UnknownCreate = new MountCredentialOutcomeUnknownError(
      CredentialOperation.operation_id,
      CredentialOperation.operation_generation,
    );
    await expect(
      CreateCredentialWithRecovery(
        {
          cancelCredentialOperation: async () => {
            throw new TypeError("connection interrupted");
          },
          createCredential: async () => {
            throw UnknownCreate;
          },
          prepareCredentialOperation: async () => ({
            Created: true,
            Operation: CredentialOperation,
          }),
        },
        {
          allowed_drive_ids: [DriveId],
          bound_device_id: null,
          expires_at: "2026-08-18T00:00:00Z",
          protocol: "ftps",
          read_only: true,
        },
      ),
    ).rejects.toMatchObject({
      Operation: CredentialOperation,
      name: "MountCredentialRecoveryRequiredError",
    });
  });
});
// oxlint-enable typescript/require-await

describe("NFS target approval controls", () => {
  it("labels NFS session addresses as a transport or relay peer", () => {
    expect(FormatMountSessionDetail(NfsSession)).toContain("NFS · transport/relay peer 192.0.2.7");
  });

  it("shows every server-held consent field and gates approval on explicit review", () => {
    const Markup = renderToStaticMarkup(
      <NfsProposalConsentCard
        Busy={false}
        // oxlint-disable-next-line typescript/require-await -- Static rendering requires the asynchronous prop shape but performs no mutation.
        OnApprove={async () => undefined}
        // oxlint-disable-next-line typescript/require-await -- Static rendering requires the asynchronous prop shape but performs no mutation.
        OnDecline={async () => undefined}
        Proposal={Proposal}
      />,
    );

    expect(Markup).toContain("avery@EXAMPLE.TEST");
    expect(Markup).toContain(Proposal.principal_id);
    expect(Markup).toContain(Proposal.proposer_principal_id);
    expect(Markup).toContain(Proposal.id);
    expect(Markup).toContain(DriveId);
    expect(Markup).toContain("Research");
    expect(Markup).toContain("researchers");
    expect(Markup).toContain("Projected UID");
    expect(Markup).toContain("Projected GID");
    expect(Markup).toContain("Proposal generation");
    expect(Markup).toContain("Virtual ACL");
    expect(Markup).toMatch(/<button[^>]*disabled=""[^>]*>Approve<\/button>/);
    expect(Markup).toContain(">Decline</button>");
  });

  it("shows the active alias ceiling and confirmation-gates direct revocation", () => {
    const Markup = renderToStaticMarkup(
      <NfsActiveMappingCard
        Busy={false}
        Mapping={Mapping}
        // oxlint-disable-next-line typescript/require-await -- Static rendering requires the asynchronous prop shape but performs no mutation.
        OnRevoke={async () => undefined}
      />,
    );

    expect(Markup).toContain(Mapping.kerberos_principal);
    expect(Markup).toContain(DriveId);
    expect(Markup).toContain("separately approved aliases");
    expect(Markup).toMatch(/<button[^>]*disabled=""[^>]*>Revoke<\/button>/);
  });
});
