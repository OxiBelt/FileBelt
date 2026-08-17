// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  FormatMountSessionDetail,
  NfsActiveMappingCard,
  NfsProposalConsentCard,
} from "./MountSettings.js";
import type { NfsMappingProposal, NfsPrincipalMapping } from "./nfs-target-http-client.js";

const DriveId = "00000000-0000-4000-8000-000000000141";

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

describe("NFS target approval controls", () => {
  it("labels NFS session addresses as a transport or relay peer", () => {
    expect(FormatMountSessionDetail(NfsSession)).toContain("NFS · transport/relay peer 192.0.2.7");
  });

  it("shows every server-held consent field and gates approval on explicit review", () => {
    const Markup = renderToStaticMarkup(
      <NfsProposalConsentCard
        Busy={false}
        OnApprove={async () => undefined}
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
      <NfsActiveMappingCard Busy={false} Mapping={Mapping} OnRevoke={async () => undefined} />,
    );

    expect(Markup).toContain(Mapping.kerberos_principal);
    expect(Markup).toContain(DriveId);
    expect(Markup).toContain("separately approved aliases");
    expect(Markup).toMatch(/<button[^>]*disabled=""[^>]*>Revoke<\/button>/);
  });
});
