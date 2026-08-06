// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { parsePublicShareFragment } from "./PublicShareApp.js";

describe("parsePublicShareFragment", () => {
  it("extracts encoded token parameters without including the leading hash", () => {
    expect(parsePublicShareFragment("#token=alpha%2Fbeta")).toBe("alpha/beta");
  });

  it("supports an opaque token as the entire fragment", () => {
    expect(parsePublicShareFragment("#opaque-token")).toBe("opaque-token");
  });
});
