// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { URL } from "node:url";

import {
  ConfusedIntegrationSession,
  IntegrationResponse,
  IntegrationSession,
  IntegrationSessionDenial,
  IsIntegrationTarget,
  RedirectFollowPath,
  RedirectLocation,
} from "./integration.mjs";

const Host = "filebelt-mcp-integration.example.test";

test("integration synthesis is exact-host, port, profile, path, and query bound", () => {
  assert.equal(IsIntegrationTarget(new URL(`https://${Host}/mcp`), 443, "integration", Host), true);
  assert.equal(
    IsIntegrationTarget(new URL(`https://${Host}/mcp?escape=1`), 443, "integration", Host),
    false,
  );
  assert.equal(
    IsIntegrationTarget(new URL(`https://${Host}/unknown`), 443, "integration", Host),
    false,
  );
  assert.equal(
    IsIntegrationTarget(new URL("https://other.example.test/mcp"), 443, "integration", Host),
    false,
  );
  assert.equal(IsIntegrationTarget(new URL(`https://${Host}/mcp`), 443, "public", Host), false);
});

test("integration responses expose bounded normal and hostile behaviors", () => {
  const Initialize = IntegrationResponse({ id: 1, method: "initialize" }, "/mcp", 64);
  assert.equal(Initialize.Session, IntegrationSession);
  assert.equal(Initialize.Body.result.protocolVersion, "2026-07-28");
  assert.equal(
    IntegrationResponse({ id: 1, method: "initialize" }, "/malformed", 64).Raw.toString(),
    "{not-json",
  );
  assert.equal(
    IntegrationResponse({ id: 1, method: "initialize" }, "/oversized", 64).Raw.length,
    65,
  );
  assert.equal(IntegrationResponse({ id: 1, method: "initialize" }, "/slow", 64).DelayMs, 6_000);
  assert.equal(
    IntegrationResponse({ id: 1, method: "initialize" }, "/redirect", 64).Redirect,
    RedirectLocation,
  );
  assert.equal(
    IntegrationResponse({ id: 1, method: "initialize" }, "/redirect", 64, RedirectFollowPath)
      .Session,
    IntegrationSession,
  );
});

test("session confusion accepts the issued identity before injecting a distinct identity", () => {
  assert.equal(
    IntegrationResponse({ id: 1, method: "initialize" }, "/session-confusion", 64).Session,
    IntegrationSession,
  );
  assert.equal(
    IntegrationSessionDenial("/session-confusion", "notifications/initialized", IntegrationSession),
    undefined,
  );
  assert.equal(
    IntegrationResponse({ method: "notifications/initialized" }, "/session-confusion", 64).Session,
    ConfusedIntegrationSession,
  );
  assert.match(
    IntegrationSessionDenial("/session-confusion", "tools/list", ConfusedIntegrationSession),
    /injected session identity/,
  );
});
