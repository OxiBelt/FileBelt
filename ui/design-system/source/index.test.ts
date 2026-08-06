// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { resolveTheme } from "./index.js";

describe("resolveTheme", () => {
  it("uses an explicit theme regardless of the system preference", () => {
    expect(resolveTheme("light", true)).toBe("light");
    expect(resolveTheme("dark", false)).toBe("dark");
  });

  it("follows the system when requested", () => {
    expect(resolveTheme("system", true)).toBe("dark");
    expect(resolveTheme("system", false)).toBe("light");
  });
});
