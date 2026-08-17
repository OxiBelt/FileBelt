// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  BuildForwardHeaders,
  ParseAuthority,
  PrivateAddress,
  ValidateForwardTarget,
} from "./policy.mjs";

test("private, loopback, metadata, and documentation addresses fail closed", () => {
  for (const Address of [
    "10.0.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "192.0.2.1",
    "::1",
    "fc00::1",
  ]) {
    assert.equal(PrivateAddress(Address), true, Address);
  }
  assert.equal(PrivateAddress("1.1.1.1"), false);
});

test("forwarding requires an admitted profile and credential-free HTTPS DNS target", () => {
  assert.throws(() => ValidateForwardTarget("http://example.com/", "GET", "public"));
  assert.throws(() => ValidateForwardTarget("https://127.0.0.1/", "GET", "public"));
  assert.throws(() => ValidateForwardTarget("https://example.com/", "GET", "unknown"));
  const { Port, Target } = ValidateForwardTarget("https://example.com/mcp", "POST", "public");
  assert.equal(Port, 443);
  assert.equal(Target.pathname, "/mcp");
});

test("the integration profile retains the same HTTPS DNS boundary", () => {
  const Host = "filebelt-mcp-integration.example.test";
  const { Port, Target } = ValidateForwardTarget(
    `https://${Host}/mcp`,
    "POST",
    "integration",
    Host,
  );
  assert.equal(Port, 443);
  assert.equal(Target.hostname, "filebelt-mcp-integration.example.test");
  assert.throws(() => ValidateForwardTarget("https://127.0.0.1/mcp", "POST", "integration"));
  assert.throws(() =>
    ValidateForwardTarget("https://example.test:8444/mcp", "POST", "integration"),
  );
  assert.throws(() =>
    ValidateForwardTarget("https://other.example.test/mcp", "POST", "integration", Host),
  );
});

test("forwarding pins virtual-host routing and only approved credential headers", () => {
  const { Port, Target } = ValidateForwardTarget("https://example.com/mcp", "POST", "public");
  const Headers = BuildForwardHeaders(
    {
      authorization: "Bearer secret",
      cookie: "must-not-forward",
      "x-api-key": "api-secret",
    },
    Target,
    Port,
  );
  assert.equal(Headers.host, "example.com");
  assert.equal(Headers.authorization, "Bearer secret");
  assert.equal(Headers["x-api-key"], "api-secret");
  assert.equal(Headers.cookie, undefined);
});

test("CONNECT authorities require an approved port and DNS hostname", () => {
  assert.deepEqual(ParseAuthority("example.com:443"), { Host: "example.com", Port: 443 });
  assert.throws(() => ParseAuthority("127.0.0.1:443"));
  assert.throws(() => ParseAuthority("example.com:22"));
});
