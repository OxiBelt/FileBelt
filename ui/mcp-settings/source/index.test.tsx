// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import McpSettings, { SafeJsonResult, SafeTextResult } from "./index.js";
import type { McpSettingsClient, McpSettingsSnapshot } from "./index.js";
import { MaximumJsonRenderNodes } from "./result-renderers.js";
import { McpEn } from "./strings.js";

const EmptySnapshot: McpSettingsSnapshot = {
  Activity: [],
  BlockRules: [],
  Registrations: [],
  ServiceIdentities: [],
  Templates: [],
};

const Client: McpSettingsClient = {
  async approveAndInvoke() {},
  async cancelInvocation() {},
  async assignTemplate() {},
  async changeRegistrationState() {},
  async createBlockRule() {},
  async createInvocationIntent() {
    throw new Error("not used");
  },
  async createRegistration() {},
  async createServiceIdentity() {},
  async createServiceInvocationGrant() {},
  async createTemplate() {},
  async deleteRegistration() {},
  async discoverCapabilities() {
    throw new Error("not used");
  },
  async exportRegistration() {
    return "{}";
  },
  async getCapabilityReview() {
    return null;
  },
  async getSnapshot() {
    return EmptySnapshot;
  },
  async importRegistration() {},
  async putCapabilityReview() {},
  async putCredential() {},
  async startOauth() {
    return "https://issuer.example.test/authorize";
  },
  async testRegistration() {
    return true;
  },
};

describe("McpSettings", () => {
  it("keeps administrator controls out of the ordinary user surface", () => {
    const UserMarkup = renderToStaticMarkup(<McpSettings Client={Client} IsTenantAdmin={false} />);
    const AdminMarkup = renderToStaticMarkup(<McpSettings Client={Client} IsTenantAdmin />);

    expect(UserMarkup).not.toContain("Managed MCP");
    expect(AdminMarkup).toContain("Managed MCP");
  });

  it("renders server-controlled text and JSON without an HTML insertion boundary", () => {
    const Value = '<img src=x onerror="alert(1)">';
    const Markup = renderToStaticMarkup(
      <>
        <SafeTextResult Value={Value} />
        <SafeJsonResult Value={{ "‫name‬": Value }} />
      </>,
    );

    expect(Markup).not.toContain("<img");
    expect(Markup).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
    expect(Markup).toContain("<bdi");
  });

  it("shares one aggregate node budget across an adversarial nested JSON result", () => {
    const Value = Array.from({ length: 10 }, () =>
      Array.from({ length: 30 }, () => Array.from({ length: 30 }, () => "x")),
    );
    const Markup = renderToStaticMarkup(<SafeJsonResult Value={Value} />);
    const RenderedNodes = Markup.match(/<li/g)?.length ?? 0;

    expect(RenderedNodes).toBeLessThanOrEqual(MaximumJsonRenderNodes + 1);
    expect(Markup).toContain(McpEn.resultTruncated);
  });
});
