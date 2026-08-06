// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { FileTable } from "./FileTable.js";
import { en } from "./strings.js";

describe("FileTable", () => {
  it("renders a multiselect grid with selected state and bidi-isolated names", () => {
    const markup = renderToStaticMarkup(
      <FileTable
        dispatchSelection={() => undefined}
        entries={[{
          id: "file-1",
          kind: "file",
          modifiedAt: "2026-08-06T12:00:00Z",
          name: "‫خطة المشروع‬.pdf",
          owner: "Layla Hassan",
          shared: true,
          size: 512,
          status: "ready",
          trashed: false,
          version: 4,
        }]}
        onOpenActions={() => undefined}
        selection={{ anchorId: "file-1", focusedId: "file-1", selectedIds: new Set(["file-1"]) }}
        strings={en}
      />,
    );

    expect(markup).toContain('role="grid"');
    expect(markup).toContain('aria-multiselectable="true"');
    expect(markup).toContain('aria-selected="true"');
    expect(markup).toContain('<bdi dir="auto"');
  });
});
