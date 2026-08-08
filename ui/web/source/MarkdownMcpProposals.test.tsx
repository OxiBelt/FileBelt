// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { MarkdownMcpProposals } from "./MarkdownMcpProposals.js";

describe("Markdown MCP proposals", () => {
  it("renders proposal-only controls without a save action", () => {
    const Client = {
      approveAndInvoke: async () => undefined,
      createInvocationIntent: async () => { throw new Error("not reached"); },
      getCapabilityReview: async () => null,
      getSnapshot: async () => ({ Activity: [], BlockRules: [], Registrations: [], ServiceIdentities: [], Templates: [] }),
    };
    const Markup = renderToStaticMarkup(<MarkdownMcpProposals BaseVersionId="00000000-0000-4000-8000-000000000002" Client={Client as never} NodeId="00000000-0000-4000-8000-000000000001" OnApply={() => true} Selection={{ End: 4, Start: 0 }} Source="# draft" />);
    expect(Markup).toContain("MCP proposal");
    expect(Markup).toContain("Request proposal");
    expect(Markup).not.toContain("Save");
  });
});
