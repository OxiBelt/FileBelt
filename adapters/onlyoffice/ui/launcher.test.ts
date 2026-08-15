// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

test("launcher source keeps state local to the tab and exposes no browser storage", async () => {
  const Source = await import("node:fs/promises").then((Fs) => Fs.readFile(new URL("./launcher.ts", import.meta.url), "utf8"));
  assert.doesNotMatch(Source, /localStorage|sessionStorage|indexedDB|cookie/);
  assert.match(Source, /"idle" \| "loading-api" \| "launching" \| "ready" \| "error"/);
});

test("launcher view contract provides accessible state and disabled-launch hooks", async () => {
  const Source = await import("node:fs/promises").then((Fs) => Fs.readFile(new URL("./launcher.ts", import.meta.url), "utf8"));
  assert.match(Source, /setState\(State: LauncherState, Message: string\)/);
  assert.match(Source, /setLaunchEnabled\(Enabled: boolean\)/);
  assert.match(Source, /DocEditor\("onlyoffice-editor", Response.editorConfig\)/);
});

test("browser launcher uses an inert descriptor and an external provider script", async () => {
  const Source = await import("node:fs/promises").then((Fs) => Fs.readFile(new URL("./launcher.js", import.meta.url), "utf8"));
  assert.match(Source, /onlyoffice-launch-descriptor/);
  assert.match(Source, /script\.src = apiJsUrl/);
  assert.match(Source, /DocEditor\("onlyoffice-editor", descriptor.editorConfig\)/);
  assert.doesNotMatch(Source, /localStorage|sessionStorage|indexedDB|document\.cookie/);
});

test("launch shell keeps the static source link outside provider-controlled state", async () => {
  const Source = await import("node:fs/promises").then((Fs) => Fs.readFile(new URL("../src/main.rs", import.meta.url), "utf8"));
  assert.match(Source, /config\.public_origin\.as_str\(\)/);
  assert.match(Source, /\/onlyoffice\/source/);
  assert.match(Source, /target=\\\"_blank\\\" rel=\\\"noopener noreferrer\\\">Source &amp; License/);
  assert.doesNotMatch(Source, /descriptor[^\n]*source_and_license_url/);
});
