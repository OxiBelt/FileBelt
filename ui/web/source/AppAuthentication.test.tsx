// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { oidcLoginHref, SignInPrompt } from "./App.js";

describe("SignInPrompt", () => {
  it("offers the generated-contract OIDC login route without embedding a secret", () => {
    const markup = renderToStaticMarkup(<SignInPrompt />);

    expect(markup).toContain("Sign in to FileBelt");
    expect(markup).toContain(`href="${oidcLoginHref().replaceAll("&", "&amp;")}"`);
    expect(oidcLoginHref()).toBe("/api/v1/auth/login?return_path=%2F");
    expect(oidcLoginHref()).not.toMatch(/token|state|nonce|secret/i);
  });
});
