// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { emptySelection, selectionReducer } from "./selection.js";

const ids = ["one", "two", "three", "four"];

describe("selectionReducer", () => {
  it("supports additive keyboard selection", () => {
    const one = selectionReducer(emptySelection, { id: "one", type: "toggle" });
    const three = selectionReducer(one, { id: "three", type: "toggle" });
    expect([...three.selectedIds]).toEqual(["one", "three"]);
  });

  it("selects a contiguous range from its anchor", () => {
    const anchored = selectionReducer(emptySelection, { id: "two", type: "replace" });
    const ranged = selectionReducer(anchored, { id: "four", orderedIds: ids, type: "range" });
    expect([...ranged.selectedIds]).toEqual(["two", "three", "four"]);
  });

  it("selects all rows without losing focus", () => {
    const focused = selectionReducer(emptySelection, { id: "three", type: "focus" });
    const all = selectionReducer(focused, { orderedIds: ids, type: "all" });
    expect(all.focusedId).toBe("three");
    expect(all.selectedIds.size).toBe(4);
  });
});
