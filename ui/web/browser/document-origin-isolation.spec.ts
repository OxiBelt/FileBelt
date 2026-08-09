// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

const Sandbox = "allow-scripts allow-same-origin allow-forms allow-downloads allow-popups";
let PublicOrigin = "";
let EditorOrigin = "";
let ProviderOrigin = "";
let SessionReads = 0;
let Preflights = 0;
let Mutations = 0;

const PublicServer = createServer((Request, Response) => {
  if (Request.url === "/api/v1/session" && Request.method === "GET") {
    SessionReads += 1;
    Response.writeHead(200, { "Content-Type": "application/json" });
    Response.end(JSON.stringify({ csrf_token: "public-host-csrf" }));
    return;
  }
  if (Request.method === "OPTIONS") {
    Preflights += 1;
    Response.writeHead(403, { "Content-Type": "text/plain" });
    Response.end("CORS denied");
    return;
  }
  if (Request.method === "PATCH") {
    Mutations += 1;
    Response.writeHead(204);
    Response.end();
    return;
  }
  Response.writeHead(404);
  Response.end();
});

const ProviderServer = createServer((Request, Response) => {
  if (Request.url !== "/web-apps/apps/api/documents/api.js") {
    Response.writeHead(404);
    Response.end();
    return;
  }
  Response.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8" });
  Response.end(`
    globalThis.ProviderEvidence = {
      EditorOrigin: location.origin,
      VisibleCookie: document.cookie,
      SessionReadable: false,
      MutationSent: false,
      Complete: false,
    };
    void (async () => {
      try {
        const response = await fetch("${PublicOrigin}/api/v1/session", { credentials: "include" });
        await response.json();
        globalThis.ProviderEvidence.SessionReadable = true;
      } catch {}
      try {
        await fetch("${PublicOrigin}/api/v1/nodes/example", {
          method: "PATCH",
          credentials: "include",
          headers: { "content-type": "application/json", "x-filebelt-csrf": "public-host-csrf" },
          body: "{}",
        });
        globalThis.ProviderEvidence.MutationSent = true;
      } catch {}
      globalThis.ProviderEvidence.Complete = true;
    })();
  `);
});

const EditorServer = createServer((Request, Response) => {
  if (Request.url !== "/onlyoffice/launch") {
    Response.writeHead(404);
    Response.end();
    return;
  }
  Response.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": `default-src 'none'; base-uri 'none'; connect-src 'self' ${ProviderOrigin}; form-action 'self' ${ProviderOrigin}; frame-src ${ProviderOrigin}; frame-ancestors 'none'; img-src 'self' data: blob: ${ProviderOrigin}; media-src 'none'; object-src 'none'; script-src 'self' ${ProviderOrigin}; style-src 'self' 'unsafe-inline'; sandbox ${Sandbox}`,
    "Referrer-Policy": "no-referrer",
  });
  Response.end(`<script src="${ProviderOrigin}/web-apps/apps/api/documents/api.js"></script>`);
});

test.beforeAll(async () => {
  SessionReads = 0;
  Preflights = 0;
  Mutations = 0;
  PublicOrigin = await Listen(PublicServer, "127.0.0.1");
  ProviderOrigin = await Listen(ProviderServer, "127.0.0.3");
  EditorOrigin = await Listen(EditorServer, "127.0.0.2");
});

test.afterAll(async () => {
  await Promise.all([Close(PublicServer), Close(ProviderServer), Close(EditorServer)]);
});

test("provider JavaScript cannot read a FileBelt session or send a credentialed mutation", async ({ context: Context, page: Page }) => {
  await Context.addCookies([
    {
      name: "filebelt_session",
      value: "public-host-session",
      url: `${PublicOrigin}/api/v1`,
      httpOnly: true,
      sameSite: "Lax",
    },
    {
      name: "filebelt_csrf",
      value: "public-host-csrf",
      url: `${PublicOrigin}/api/v1`,
      httpOnly: false,
      sameSite: "Strict",
    },
  ]);

  await Page.goto(`${EditorOrigin}/onlyoffice/launch`);
  await expect
    .poll(() => Page.evaluate(() => globalThis.ProviderEvidence?.Complete ?? false))
    .toBe(true);
  const Evidence = await Page.evaluate(() => globalThis.ProviderEvidence);
  expect(Evidence).toEqual({
    EditorOrigin,
    VisibleCookie: "",
    SessionReadable: false,
    MutationSent: false,
    Complete: true,
  });
  expect(SessionReads).toBe(0);
  expect(Preflights).toBe(0);
  expect(Mutations).toBe(0);
});

async function Listen(Server: typeof PublicServer, Host: string): Promise<string> {
  await new Promise<void>((Resolve, Reject) => {
    Server.once("error", Reject);
    Server.listen(0, Host, () => Resolve());
  });
  const Address = Server.address() as AddressInfo;
  return `http://${Host}:${Address.port}`;
}

async function Close(Server: typeof PublicServer): Promise<void> {
  if (!Server.listening) return;
  await new Promise<void>((Resolve, Reject) => {
    Server.close((Error) => Error === undefined ? Resolve() : Reject(Error));
  });
}

declare global {
  // Browser-only test evidence populated by the hostile provider fixture.
  var ProviderEvidence: {
    EditorOrigin: string;
    VisibleCookie: string;
    SessionReadable: boolean;
    MutationSent: boolean;
    Complete: boolean;
  } | undefined;
}
