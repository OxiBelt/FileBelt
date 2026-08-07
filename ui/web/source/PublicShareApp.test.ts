// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { ParsePublicShareFragment } from "./PublicShareApp.js";

describe("parsePublicShareFragment", () => {
  it("extracts encoded token parameters without including the leading hash", () => {
    expect(ParsePublicShareFragment("#token=alpha%2Fbeta")).toBe("alpha/beta");
  });

  it("supports an opaque token as the entire fragment", () => {
    expect(ParsePublicShareFragment("#opaque-token")).toBe("opaque-token");
  });
});
