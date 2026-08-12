// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { MockFileBeltClient } from "./client.js";
import type { FileEntry } from "./model.js";
import { TextHistory } from "./TextHistory.js";

const Entry: FileEntry = {
  HeadVersionId: "00000000-0000-4000-8000-000000000301",
  Id: "00000000-0000-4000-8000-000000000102",
  Kind: "file",
  MediaType: "text/plain",
  ModifiedAt: "2026-08-06T12:00:00Z",
  Name: "notes.txt",
  Owner: "Avery Morgan",
  Shared: false,
  Size: 42,
  Status: "ready",
  TextEligibility: "editable",
  Trashed: false,
  Version: 1,
};

describe("TextHistory", () => {
  it("renders a labeled lazy history shell", () => {
    const Markup = renderToStaticMarkup(<TextHistory Client={new MockFileBeltClient()} Entry={Entry} OnRestore={async () => undefined} />);
    expect(Markup).toContain("Text history");
    expect(Markup).toContain("Loading history");
  });
});
