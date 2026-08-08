// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { CreateLineStarts, RangeFromPosition } from "./ranges.js";

describe("Markdown source ranges", () => {
  it("maps one-based parser points to zero-based source offsets", () => {
    const Starts = CreateLineStarts("one\r\ntwo");
    expect(Starts).toEqual([0, 5]);
    expect(RangeFromPosition({ end: { column: 4, line: 2 }, start: { column: 1, line: 2 } }, Starts)).toEqual({ End: 8, Start: 5 });
  });
});
