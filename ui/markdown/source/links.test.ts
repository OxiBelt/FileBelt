// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { ParseFileBeltReference } from "./links.js";

describe("FileBelt Markdown links", () => {
  it("accepts only the canonical drive/node form", () => {
    expect(ParseFileBeltReference("filebelt://drive/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/node/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb?version=cccccccc-cccc-4ccc-8ccc-cccccccccccc")).toEqual({ DriveId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", NodeId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", VersionId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc" });
    expect(ParseFileBeltReference("filebelt://drive/a/node/b?version=c&other=d")).toBeUndefined();
  });
});
