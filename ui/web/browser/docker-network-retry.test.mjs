// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { GotoWithNetworkChangeRetry } from "./docker-network-retry.mjs";

test("retries one Chromium network-change navigation after 250 ms", async () => {
  const Calls = [];
  const Delays = [];
  const Response = { ok: true };
  const Page = {
    async goto(Url) {
      Calls.push(Url);
      if (Calls.length === 1) throw new Error("page.goto: net::ERR_NETWORK_CHANGED");
      return Response;
    },
    async waitForTimeout(Delay) {
      Delays.push(Delay);
    },
  };

  assert.equal(await GotoWithNetworkChangeRetry(Page, "/api/v1/auth/login?return_path=%2F"), Response);
  assert.deepEqual(Calls, ["/api/v1/auth/login?return_path=%2F", "/api/v1/auth/login?return_path=%2F"]);
  assert.deepEqual(Delays, [250]);
});

test("propagates a nonmatching navigation error without retrying", async () => {
  const Calls = [];
  const Delays = [];
  const Failure = new Error("page.goto: net::ERR_CONNECTION_RESET");
  const Page = {
    async goto(Url) {
      Calls.push(Url);
      throw Failure;
    },
    async waitForTimeout(Delay) {
      Delays.push(Delay);
    },
  };

  await assert.rejects(GotoWithNetworkChangeRetry(Page, "/api/v1/auth/login?return_path=%2F"), Failure);
  assert.deepEqual(Calls, ["/api/v1/auth/login?return_path=%2F"]);
  assert.deepEqual(Delays, []);
});

test("propagates the single retry failure", async () => {
  const Calls = [];
  const Delays = [];
  const Failure = new Error("page.goto: net::ERR_CONNECTION_RESET");
  const Page = {
    async goto(Url) {
      Calls.push(Url);
      if (Calls.length === 1) throw new Error("page.goto: net::ERR_NETWORK_CHANGED");
      throw Failure;
    },
    async waitForTimeout(Delay) {
      Delays.push(Delay);
    },
  };

  await assert.rejects(GotoWithNetworkChangeRetry(Page, "/api/v1/auth/login?return_path=%2F"), Failure);
  assert.deepEqual(Calls, ["/api/v1/auth/login?return_path=%2F", "/api/v1/auth/login?return_path=%2F"]);
  assert.deepEqual(Delays, [250]);
});
