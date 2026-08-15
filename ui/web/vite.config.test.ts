// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { ParentContentSecurityPolicy } from "./vite.config.js";
import { ResolveFluentIconsContextId } from "../vitest-fluent-icons-resolver.js";

describe("ParentContentSecurityPolicy", () => {
  it("admits only the configured isolated editor origin for form posts", () => {
    const Csp = ParentContentSecurityPolicy("https://editor.example.test/onlyoffice/launch");
    expect(Csp).toContain("form-action 'self' https://editor.example.test");
    expect(Csp).toContain("connect-src 'self'");
    expect(Csp).toContain("script-src 'self'");
  });

  it("rejects a non-HTTPS or non-launch configuration", () => {
    expect(() => ParentContentSecurityPolicy("http://editor.example.test/onlyoffice/launch")).toThrow();
    expect(() => ParentContentSecurityPolicy("https://editor.example.test/integrations/launch")).toThrow();
    expect(() => ParentContentSecurityPolicy("https://editor.example.test:8443/onlyoffice/launch")).toThrow();
    expect(() => ParentContentSecurityPolicy("https://editor.example.test./onlyoffice/launch")).toThrow();
  });
});

describe("ResolveFluentIconsContextId", () => {
  it("resolves only Fluent Icons' extensionless context import", () => {
    expect(
      ResolveFluentIconsContextId(
        "./contexts/index",
        "/workspace/node_modules/@fluentui/react-icons/lib/providers.js",
      ),
    ).toBe("/workspace/node_modules/@fluentui/react-icons/lib/contexts/index.js");
    expect(ResolveFluentIconsContextId("./contexts/other", "/workspace/node_modules/@fluentui/react-icons/lib/providers.js")).toBeNull();
    expect(ResolveFluentIconsContextId("./contexts/index", "/workspace/node_modules/example/lib/providers.js")).toBeNull();
  });
});
