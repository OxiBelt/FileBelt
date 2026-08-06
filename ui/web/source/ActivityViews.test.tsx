// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { SharesView } from "./ActivityViews.js";
import type { FileEntry, ShareRecord } from "./model.js";
import { en } from "./strings.js";

describe("SharesView", () => {
  it("filters same-named shares by immutable resource identity", () => {
    const selected: FileEntry = {
      id: "00000000-0000-4000-8000-000000000101",
      kind: "file",
      modifiedAt: "2026-08-06T12:00:00Z",
      name: "same-name.txt",
      owner: "Owner",
      shared: true,
      size: 1,
      status: "ready",
      trashed: false,
      version: 1,
    };
    const shares: ShareRecord[] = [
      {
        id: "share-selected",
        kind: "direct",
        permission: "Viewer",
        resourceId: selected.id,
        resourceName: selected.name,
        target: "selected@example.test",
      },
      {
        id: "share-other",
        kind: "direct",
        permission: "Viewer",
        resourceId: "00000000-0000-4000-8000-000000000102",
        resourceName: selected.name,
        target: "other@example.test",
      },
    ];

    const markup = renderToStaticMarkup(
      <SharesView
        file={selected}
        onCreate={async () => undefined}
        onRevoke={async () => undefined}
        shares={shares}
        strings={en}
      />,
    );

    expect(markup).toContain("selected@example.test");
    expect(markup).not.toContain("other@example.test");
    expect(markup).not.toContain(en.anonymousLink);
    expect(markup).not.toContain(en.groupShare);
  });
});
