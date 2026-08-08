// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { MergeMarkdownSources } from "./conflict.js";

describe("Markdown conflict merge", () => {
  it("combines disjoint changes and marks overlapping edits for explicit review", () => {
    expect(MergeMarkdownSources("one\ntwo", "local\ntwo", "one\nremote")).toEqual({ Conflict: false, Text: "local\nremote" });
    const Conflict = MergeMarkdownSources("same", "local", "remote");
    expect(Conflict.Conflict).toBe(true);
    expect(Conflict.Text).toContain("<<<<<<< local FileBelt edits");
    expect(Conflict.Text).toContain(">>>>>>> latest FileBelt version");
  });
});
