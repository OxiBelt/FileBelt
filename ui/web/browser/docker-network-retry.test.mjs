// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { setTimeout as DelayTask } from "node:timers/promises";

import {
  CompleteLoginWithNetworkChangeRetry,
  GotoWithNetworkChangeRetry,
} from "./docker-network-retry.mjs";

function WorkspacePage({
  Failure,
  FailureDuringDelay,
  InitialState,
  LinkFailure,
  RefreshFailure,
  RefreshState = "ready",
  WaitForFailure,
}) {
  const Listeners = new Set();
  const State = { Delays: [], Refreshes: 0, Value: "identity" };
  const EmitFailedRequest = (ErrorText) => {
    const Request = new Proxy({
      failure: () => ({ errorText: ErrorText }),
    }, {
      get(Target, Property, Receiver) {
        if (Property === "failure") return Reflect.get(Target, Property, Receiver);
        throw new Error(`request ${String(Property)} must not be inspected`);
      },
    });
    for (const Listener of Listeners) Listener(Request);
  };
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
          if (RefreshFailure !== undefined) throw RefreshFailure;
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
          if (WaitForFailure !== undefined) throw WaitForFailure;
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
          if (LinkFailure !== undefined) throw LinkFailure;
          if (Failure !== undefined) EmitFailedRequest(Failure);
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
    async waitForTimeout(Delay) {
      State.Delays.push(Delay);
      if (FailureDuringDelay !== undefined) {
        await DelayTask(0);
        EmitFailedRequest(FailureDuringDelay);
      }
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

  const Disposition = await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator");

  assert.deepEqual(Disposition, { ExactNetworkChangeObserved: false, RefreshClicked: false });
  assert.deepEqual(Fixture.State.Delays, []);
  assert.equal(Fixture.State.Value, "ready");
  assert.equal(Fixture.State.Refreshes, 0);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("refreshes once when a later task reports the exact failure during the settle window", async () => {
  const Fixture = WorkspacePage({
    FailureDuringDelay: "net::ERR_NETWORK_CHANGED",
    InitialState: "failure",
  });

  const Disposition = await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator");

  assert.deepEqual(Disposition, { ExactNetworkChangeObserved: true, RefreshClicked: true });
  assert.deepEqual(Fixture.State.Delays, [250]);
  assert.equal(Fixture.State.Value, "ready");
  assert.equal(Fixture.State.Refreshes, 1);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("uses only the immediate exact request failure metadata after the settle window", async () => {
  const Fixture = WorkspacePage({
    Failure: "net::ERR_NETWORK_CHANGED",
    InitialState: "failure",
  });

  const Disposition = await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator");

  assert.deepEqual(Disposition, { ExactNetworkChangeObserved: true, RefreshClicked: true });
  assert.deepEqual(Fixture.State.Delays, [250]);
  assert.equal(Fixture.State.Refreshes, 1);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("does not refresh a delayed generic workspace failure", async () => {
  const Fixture = WorkspacePage({
    FailureDuringDelay: "net::ERR_CONNECTION_RESET",
    InitialState: "failure",
  });

  const Disposition = await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator");

  assert.deepEqual(Disposition, { ExactNetworkChangeObserved: false, RefreshClicked: false });
  assert.deepEqual(Fixture.State.Delays, [250]);
  assert.equal(Fixture.State.Value, "failure");
  assert.equal(Fixture.State.Refreshes, 0);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("does not refresh a workspace failure without a request failure signal", async () => {
  const Fixture = WorkspacePage({ InitialState: "failure" });

  const Disposition = await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator");

  assert.deepEqual(Disposition, { ExactNetworkChangeObserved: false, RefreshClicked: false });
  assert.deepEqual(Fixture.State.Delays, [250]);
  assert.equal(Fixture.State.Refreshes, 0);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("does not repeat an exhausted workspace refresh", async () => {
  const Fixture = WorkspacePage({
    Failure: "net::ERR_NETWORK_CHANGED",
    InitialState: "failure",
    RefreshState: "failure",
  });

  const Disposition = await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator");

  assert.deepEqual(Disposition, { ExactNetworkChangeObserved: true, RefreshClicked: true });
  assert.deepEqual(Fixture.State.Delays, [250]);
  assert.equal(Fixture.State.Value, "failure");
  assert.equal(Fixture.State.Refreshes, 1);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("removes the failed-request listener when workspace bootstrap throws", async () => {
  const LinkFailure = new Error("identity click failed");
  const Fixture = WorkspacePage({ InitialState: "identity", LinkFailure });

  await assert.rejects(CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator"), LinkFailure);

  assert.equal(Fixture.ListenerCount(), 0);
});

test("removes the failed-request listener when the workspace outcome wait throws", async () => {
  const WaitForFailure = new Error("workspace outcome wait failed");
  const Fixture = WorkspacePage({
    InitialState: "failure",
    WaitForFailure,
  });

  await assert.rejects(CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator"), WaitForFailure);

  assert.equal(Fixture.ListenerCount(), 0);
});

test("removes the failed-request listener when the single refresh throws", async () => {
  const RefreshFailure = new Error("refresh failed");
  const Fixture = WorkspacePage({
    Failure: "net::ERR_NETWORK_CHANGED",
    InitialState: "failure",
    RefreshFailure,
  });

  await assert.rejects(CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator"), RefreshFailure);

  assert.equal(Fixture.State.Refreshes, 1);
  assert.equal(Fixture.ListenerCount(), 0);
});
