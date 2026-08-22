// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  AclPresets,
  AclScopeOptions,
  GroupAclEntries,
  PreserveAclDraftAfterConflict,
} from "./AclEditor.js";
import type { AclEntry } from "./client.js";

const PrincipalId = "00000000-0000-4000-8000-000000000021";
const GroupId = "00000000-0000-4000-8000-000000000022";

function Rule(Source: AclEntry["Source"], ReadOnly: boolean): AclEntry {
  return {
    Action: Source === "core" ? "READ_CONTENT" : "TRAVERSE",
    DisplayName: "Research group",
    Effect: "allow",
    GroupId,
    Inheritance: Source === "core" ? "children" : "self_and_descendants",
    PrincipalId,
    PrincipalKind: "group",
    ReadOnly,
    Source,
    VerifiedEmail: null,
  };
}

describe("AclEditor", () => {
  it("groups a principal's mutable and source-owned rules without losing provenance", () => {
    const Groups = GroupAclEntries([Rule("core", false), Rule("share", true), Rule("nfs", true)]);

    expect(Groups).toHaveLength(1);
    expect(Groups[0]).toMatchObject({
      Kind: "group",
      Label: "Research group",
      SelectorValue: GroupId,
    });
    expect(Groups[0]?.Entries.map(({ ReadOnly, Source }) => ({ ReadOnly, Source }))).toEqual([
      { ReadOnly: false, Source: "core" },
      { ReadOnly: true, Source: "share" },
      { ReadOnly: true, Source: "nfs" },
    ]);
  });

  it("keeps reviewed presets identical to the living authorization contract", () => {
    expect(AclPresets.Viewer).toEqual([
      "READ_METADATA",
      "LIST_CHILDREN",
      "READ_CONTENT",
      "USE_EXTERNAL_EDITOR",
    ]);
    expect(AclPresets.Contributor).toEqual([
      ...AclPresets.Viewer,
      "CREATE_CHILD",
      "WRITE_CONTENT",
      "CREATE_VERSION",
      "RENAME",
      "MOVE",
      "DELETE",
      "RESTORE",
      "SET_ATTRIBUTES",
      "COMMENT",
      "REVIEW",
    ]);
    expect(AclPresets.Manager).toEqual([...AclPresets.Contributor, "SHARE", "MANAGE_ACL"]);
    expect(AclPresets.Manager).not.toContain("MANAGE_DRIVE");
  });

  it("supports every contract scope and preserves the exact draft across conflict refresh", () => {
    expect(AclScopeOptions).toEqual(["self", "children", "descendants", "self_and_descendants"]);
    const Draft = [{ Action: "TRAVERSE", Effect: "deny", Inheritance: "children" }] as const;
    const Current = {
      Entries: [Rule("share", true)],
      SupportedActions: ["TRAVERSE"],
    } as const;
    const Refreshed = PreserveAclDraftAfterConflict(Draft, Current);

    expect(Refreshed.Draft).toBe(Draft);
    expect(Refreshed.Collection).toBe(Current);
  });
});
