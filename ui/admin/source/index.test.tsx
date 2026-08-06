// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import AdminPanel from "./index.js";

describe("AdminPanel", () => {
  it("exposes tenant controls with labelled tabs and bidi-isolated user content", () => {
    const markup = renderToStaticMarkup(
      <AdminPanel
        drives={[]}
        groups={[]}
        onCreateGroup={async () => undefined}
        onCreateSharedDrive={async () => undefined}
        onToggleUserSuspension={async () => undefined}
        users={[{ email: "layla@example.test", id: "user-1", name: "ليلى", status: "active" }]}
      />,
    );

    expect(markup).toContain('aria-label="Tenant administration"');
    expect(markup).toContain('<bdi dir="auto">ليلى</bdi>');
    expect(markup).toContain("Sensitive changes require recent sign-in");
  });
});
