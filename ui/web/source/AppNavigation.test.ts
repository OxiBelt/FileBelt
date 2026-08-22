// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { HasDevelopmentMockMarker, InternalNavigationHref } from "./navigation.js";

describe("InternalNavigationHref", () => {
  it("preserves only the exact development mock marker", () => {
    expect(HasDevelopmentMockMarker("?filebelt-development=mock&debug=true")).toBe(true);
    expect(HasDevelopmentMockMarker("?filebelt-development=Mock")).toBe(false);
    expect(HasDevelopmentMockMarker("?filebelt-development=mocked")).toBe(false);
    expect(InternalNavigationHref("/drive?token=secret#fragment", true)).toBe(
      "/drive?filebelt-development=mock",
    );
    expect(InternalNavigationHref("/markdown/node-id?debug=true", true)).toBe(
      "/markdown/node-id?filebelt-development=mock",
    );
  });

  it("does not add the marker outside mock development mode", () => {
    expect(InternalNavigationHref("/drive?filebelt-development=mock&debug=true", false)).toBe(
      "/drive",
    );
  });
});
