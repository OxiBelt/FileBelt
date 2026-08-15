// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  CompleteLoginWithNetworkChangeRetry,
  GotoWithNetworkChangeRetry,
} from "./docker-network-retry.mjs";

function WorkspacePage({ Failure, InitialState, RefreshState = "ready" }) {
  const Listeners = new Set();
  const State = { Refreshes: 0, Value: "identity" };
  const Locator = (Kind) => ({
    filter() {
      return this;
    },
    getByRole(Role, Options) {
      assert.equal(Kind, "failure");
      assert.equal(Role, "button");
      assert.deepEqual(Options, { name: "Refresh" });
      return {
        async click() {
          State.Refreshes += 1;
          State.Value = RefreshState;
        },
      };
    },
    async isVisible() {
      return State.Value === Kind;
    },
    or(Other) {
      return {
        async waitFor(Options) {
          assert.deepEqual(Options, { state: "visible", timeout: 15_000 });
          assert.equal(await Locator(Kind).isVisible() || await Other.isVisible(), true);
        },
      };
    },
  });
  const Page = {
    getByRole(Role, Options) {
      if (Role === "heading") {
        assert.deepEqual(Options, { name: "My Drive" });
        return Locator("ready");
      }
      if (Role === "alert") {
        assert.equal(Options, undefined);
        return Locator("failure");
      }
      assert.equal(Role, "link");
      assert.deepEqual(Options, { name: "Administrator" });
      return {
        async click() {
          if (Failure !== undefined) {
            const Request = {
              failure: () => ({ errorText: Failure }),
              url: () => { throw new Error("request URLs must not be inspected"); },
            };
            for (const Listener of Listeners) Listener(Request);
          }
          State.Value = InitialState;
        },
      };
    },
    off(Event, Listener) {
      assert.equal(Event, "requestfailed");
      Listeners.delete(Listener);
    },
    on(Event, Listener) {
      assert.equal(Event, "requestfailed");
      Listeners.add(Listener);
    },
  };
  return { ListenerCount: () => Listeners.size, Page, State };
}

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

test("keeps a successful workspace bootstrap unchanged", async () => {
  const Fixture = WorkspacePage({ InitialState: "ready" });

  await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator");

  assert.equal(Fixture.State.Value, "ready");
  assert.equal(Fixture.State.Refreshes, 0);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("refreshes one workspace bootstrap after the exact network-change failure", async () => {
  const Fixture = WorkspacePage({
    Failure: "net::ERR_NETWORK_CHANGED",
    InitialState: "failure",
  });

  await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator");

  assert.equal(Fixture.State.Value, "ready");
  assert.equal(Fixture.State.Refreshes, 1);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("does not refresh a generic workspace failure", async () => {
  const Fixture = WorkspacePage({
    Failure: "net::ERR_CONNECTION_RESET",
    InitialState: "failure",
  });

  await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator");

  assert.equal(Fixture.State.Value, "failure");
  assert.equal(Fixture.State.Refreshes, 0);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("does not repeat a failed workspace refresh", async () => {
  const Fixture = WorkspacePage({
    Failure: "net::ERR_NETWORK_CHANGED",
    InitialState: "failure",
    RefreshState: "failure",
  });

  await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator");

  assert.equal(Fixture.State.Value, "failure");
  assert.equal(Fixture.State.Refreshes, 1);
  assert.equal(Fixture.ListenerCount(), 0);
});
