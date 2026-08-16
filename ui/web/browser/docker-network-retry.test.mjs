// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { setTimeout as DelayTask } from "node:timers/promises";

import {
  CompleteLoginWithNetworkChangeRetry,
  GotoWithNetworkChangeRetry,
} from "./docker-network-retry.mjs";

const LoginUrl = "/api/v1/auth/login?return_path=%2F";

function WorkspacePage({
  Failure,
  FailureDuringDelay,
  GotoFailure,
  InitialState,
  LinkFailure,
  ReplayFailure,
  ReplayState = InitialState,
  RefreshFailure,
  RefreshState = "ready",
  WaitForFailure,
  WaitFailures,
}) {
  const Listeners = new Set();
  const OutcomeFailures = [...(WaitFailures ?? (WaitForFailure === undefined ? [] : [WaitForFailure]))];
  const State = { Delays: [], Gotos: [], Links: 0, Refreshes: 0, Value: "identity" };
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
          if (OutcomeFailures.length > 0) throw OutcomeFailures.shift();
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
          State.Links += 1;
          const RequestFailure = State.Links === 1 ? Failure : ReplayFailure;
          if (RequestFailure !== undefined) EmitFailedRequest(RequestFailure);
          State.Value = State.Links === 1 ? InitialState : ReplayState;
        },
      };
    },
    async goto(Url) {
      State.Gotos.push(Url);
      if (GotoFailure !== undefined) throw GotoFailure;
      State.Value = "identity";
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

  assert.equal(await GotoWithNetworkChangeRetry(Page, LoginUrl), Response);
  assert.deepEqual(Calls, [LoginUrl, LoginUrl]);
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

  await assert.rejects(GotoWithNetworkChangeRetry(Page, LoginUrl), Failure);
  assert.deepEqual(Calls, [LoginUrl]);
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

  await assert.rejects(GotoWithNetworkChangeRetry(Page, LoginUrl), Failure);
  assert.deepEqual(Calls, [LoginUrl, LoginUrl]);
  assert.deepEqual(Delays, [250]);
});

test("keeps a successful workspace bootstrap unchanged", async () => {
  const Fixture = WorkspacePage({ InitialState: "ready" });

  const Disposition = await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator", LoginUrl);

  assert.deepEqual(Disposition, { ExactNetworkChangeObserved: false, LoginReplayed: false, RefreshClicked: false });
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

  const Disposition = await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator", LoginUrl);

  assert.deepEqual(Disposition, { ExactNetworkChangeObserved: true, LoginReplayed: false, RefreshClicked: true });
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

  const Disposition = await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator", LoginUrl);

  assert.deepEqual(Disposition, { ExactNetworkChangeObserved: true, LoginReplayed: false, RefreshClicked: true });
  assert.deepEqual(Fixture.State.Delays, [250]);
  assert.equal(Fixture.State.Refreshes, 1);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("does not refresh a delayed generic workspace failure", async () => {
  const Fixture = WorkspacePage({
    FailureDuringDelay: "net::ERR_CONNECTION_RESET",
    InitialState: "failure",
  });

  const Disposition = await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator", LoginUrl);

  assert.deepEqual(Disposition, { ExactNetworkChangeObserved: false, LoginReplayed: false, RefreshClicked: false });
  assert.deepEqual(Fixture.State.Delays, [250]);
  assert.equal(Fixture.State.Value, "failure");
  assert.equal(Fixture.State.Refreshes, 0);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("does not refresh a workspace failure without a request failure signal", async () => {
  const Fixture = WorkspacePage({ InitialState: "failure" });

  const Disposition = await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator", LoginUrl);

  assert.deepEqual(Disposition, { ExactNetworkChangeObserved: false, LoginReplayed: false, RefreshClicked: false });
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

  const Disposition = await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator", LoginUrl);

  assert.deepEqual(Disposition, { ExactNetworkChangeObserved: true, LoginReplayed: false, RefreshClicked: true });
  assert.deepEqual(Fixture.State.Delays, [250]);
  assert.equal(Fixture.State.Value, "failure");
  assert.equal(Fixture.State.Refreshes, 1);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("replays the synthetic login once after an exact-signal blank timeout", async () => {
  const Timeout = new Error("workspace outcome timed out");
  Timeout.name = "TimeoutError";
  const Fixture = WorkspacePage({
    Failure: "net::ERR_NETWORK_CHANGED",
    InitialState: "blank",
    ReplayState: "ready",
    WaitFailures: [Timeout],
  });

  const Disposition = await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator", LoginUrl);

  assert.deepEqual(Disposition, {
    ExactNetworkChangeObserved: true,
    LoginReplayed: true,
    RefreshClicked: false,
  });
  assert.deepEqual(Fixture.State.Gotos, [LoginUrl]);
  assert.equal(Fixture.State.Links, 2);
  assert.equal(Fixture.State.Refreshes, 0);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("does not refresh after spending the recovery budget on login replay", async () => {
  const Timeout = new Error("workspace outcome timed out");
  Timeout.name = "TimeoutError";
  const Fixture = WorkspacePage({
    Failure: "net::ERR_NETWORK_CHANGED",
    InitialState: "blank",
    ReplayFailure: "net::ERR_NETWORK_CHANGED",
    ReplayState: "failure",
    WaitFailures: [Timeout],
  });

  const Disposition = await CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator", LoginUrl);

  assert.deepEqual(Disposition, {
    ExactNetworkChangeObserved: true,
    LoginReplayed: true,
    RefreshClicked: false,
  });
  assert.deepEqual(Fixture.State.Delays, []);
  assert.deepEqual(Fixture.State.Gotos, [LoginUrl]);
  assert.equal(Fixture.State.Refreshes, 0);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("propagates a failed login replay and removes the request listener", async () => {
  const Timeout = new Error("workspace outcome timed out");
  Timeout.name = "TimeoutError";
  const GotoFailure = new Error("login replay navigation failed");
  const Fixture = WorkspacePage({
    Failure: "net::ERR_NETWORK_CHANGED",
    GotoFailure,
    InitialState: "blank",
    WaitFailures: [Timeout],
  });

  await assert.rejects(
    CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator", LoginUrl),
    GotoFailure,
  );

  assert.deepEqual(Fixture.State.Gotos, [LoginUrl]);
  assert.equal(Fixture.State.Links, 1);
  assert.equal(Fixture.State.Refreshes, 0);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("does not replay a blank workspace after a generic outcome failure", async () => {
  const OutcomeFailure = new Error("workspace outcome failed");
  const Fixture = WorkspacePage({
    Failure: "net::ERR_NETWORK_CHANGED",
    InitialState: "blank",
    WaitForFailure: OutcomeFailure,
  });

  await assert.rejects(
    CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator", LoginUrl),
    OutcomeFailure,
  );

  assert.deepEqual(Fixture.State.Gotos, []);
  assert.equal(Fixture.State.Links, 1);
  assert.equal(Fixture.ListenerCount(), 0);
});

test("removes the failed-request listener when workspace bootstrap throws", async () => {
  const LinkFailure = new Error("identity click failed");
  const Fixture = WorkspacePage({ InitialState: "identity", LinkFailure });

  await assert.rejects(CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator", LoginUrl), LinkFailure);

  assert.equal(Fixture.ListenerCount(), 0);
});

test("removes the failed-request listener when the workspace outcome wait throws", async () => {
  const WaitForFailure = new Error("workspace outcome wait failed");
  const Fixture = WorkspacePage({
    InitialState: "failure",
    WaitForFailure,
  });

  await assert.rejects(CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator", LoginUrl), WaitForFailure);

  assert.equal(Fixture.ListenerCount(), 0);
});

test("removes the failed-request listener when the single refresh throws", async () => {
  const RefreshFailure = new Error("refresh failed");
  const Fixture = WorkspacePage({
    Failure: "net::ERR_NETWORK_CHANGED",
    InitialState: "failure",
    RefreshFailure,
  });

  await assert.rejects(CompleteLoginWithNetworkChangeRetry(Fixture.Page, "Administrator", LoginUrl), RefreshFailure);

  assert.equal(Fixture.State.Refreshes, 1);
  assert.equal(Fixture.ListenerCount(), 0);
});
