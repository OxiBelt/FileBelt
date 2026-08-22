// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { EmptySelection, SelectionReducer } from "./selection.js";

const Ids = ["one", "two", "three", "four"];

describe("selectionReducer", () => {
  it("supports additive keyboard selection", () => {
    const One = SelectionReducer(EmptySelection, { Id: "one", Type: "toggle" });
    const Three = SelectionReducer(One, { Id: "three", Type: "toggle" });
    expect([...Three.SelectedIds]).toEqual(["one", "three"]);
  });

  it("selects a contiguous range from its anchor", () => {
    const Anchored = SelectionReducer(EmptySelection, { Id: "two", Type: "replace" });
    const Ranged = SelectionReducer(Anchored, { Id: "four", OrderedIds: Ids, Type: "range" });
    expect([...Ranged.SelectedIds]).toEqual(["two", "three", "four"]);
  });

  it("selects all rows without losing focus", () => {
    const Focused = SelectionReducer(EmptySelection, { Id: "three", Type: "focus" });
    const All = SelectionReducer(Focused, { OrderedIds: Ids, Type: "all" });
    expect(All.FocusedId).toBe("three");
    expect(All.SelectedIds.size).toBe(4);
  });

  it("replaces a completed batch selection with only the failed item IDs", () => {
    const Selected = SelectionReducer(EmptySelection, { Ids: ["two", "four"], Type: "set" });

    expect(Selected).toMatchObject({ AnchorId: "two", FocusedId: "two" });
    expect([...Selected.SelectedIds]).toEqual(["two", "four"]);
  });
});
