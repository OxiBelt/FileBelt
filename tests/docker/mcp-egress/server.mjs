// SPDX-License-Identifier: Apache-2.0

import { Buffer } from "node:buffer";
import { promises as dns } from "node:dns";
import { readFileSync } from "node:fs";
import { connect } from "node:net";
import { createServer, request as httpsRequest } from "node:https";

import {
  BuildForwardHeaders,
  ParseAuthority,
  PrivateAddress,
  ValidateForwardTarget,
} from "./policy.mjs";

const ListenPort = 8443;
const MaximumHeaderBytes = 16 * 1024;
const MaximumRequestBytes = 16 * 1024 * 1024;
const MaximumResponseBytes = 25_165_824;

async function ResolvePublic(Host) {
  const Answers = await dns.lookup(Host, { all: true, verbatim: true });
  if (Answers.length === 0 || Answers.length > 16 || Answers.some(({ address: Address }) => PrivateAddress(Address))) {
    throw new Error("DNS answer is not uniformly public");
  }
  return Answers[0].address;
}

const Server = createServer({
  ca: readFileSync("/run/secrets/client-ca.crt"),
  cert: readFileSync("/run/secrets/tls.crt"),
  key: readFileSync("/run/secrets/tls.key"),
  minVersion: "TLSv1.3",
  requestCert: true,
  rejectUnauthorized: true,
}, async (Request, Response) => {
  try {
    if (!Request.socket.authorized || Request.rawHeaders.join("\r\n").length > MaximumHeaderBytes) {
      throw new Error("client is not authorized");
    }
    const TargetValue = Request.headers["x-filebelt-mcp-target"];
    const MethodValue = Request.headers["x-filebelt-mcp-upstream-method"];
    const TrustProfile = Request.headers["x-filebelt-mcp-trust-profile"];
    const { Port, Target } = ValidateForwardTarget(TargetValue, MethodValue, TrustProfile);
    const Address = await ResolvePublic(Target.hostname);
    const Chunks = [];
    let Size = 0;
    for await (const Chunk of Request) {
      Size += Chunk.length;
      if (Size > MaximumRequestBytes) {
        throw new Error("request exceeds the forwarding limit");
      }
      Chunks.push(Chunk);
    }
    const Headers = BuildForwardHeaders(Request.headers, Target, Port);
    const Upstream = httpsRequest({
      host: Address,
      port: Port,
      servername: Target.hostname,
      method: MethodValue,
      path: `${Target.pathname}${Target.search}`,
      headers: Headers,
      rejectUnauthorized: true,
    }, (UpstreamResponse) => {
      let ResponseSize = 0;
      const ResponseHeaders = {"cache-control": "no-store"};
      for (const Name of ["content-type", "mcp-session-id", "www-authenticate"]) {
        const Value = UpstreamResponse.headers[Name];
        if (typeof Value === "string") {
          ResponseHeaders[Name] = Value;
        }
      }
      Response.writeHead(UpstreamResponse.statusCode ?? 502, ResponseHeaders);
      UpstreamResponse.on("data", (Chunk) => {
        ResponseSize += Chunk.length;
        if (ResponseSize > MaximumResponseBytes) {
          UpstreamResponse.destroy();
          Response.destroy();
          return;
        }
        Response.write(Chunk);
      });
      UpstreamResponse.on("end", () => Response.end());
      UpstreamResponse.on("error", () => Response.destroy());
    });
    Upstream.setTimeout(60_000, () => Upstream.destroy());
    Upstream.on("error", () => {
      if (!Response.headersSent) {
        Response.writeHead(502, {"Cache-Control": "no-store", "Content-Type": "text/plain"});
      }
      Response.end("upstream unavailable\n");
    });
    Upstream.end(Buffer.concat(Chunks));
  } catch {
    Response.writeHead(403, {"Cache-Control": "no-store", "Content-Type": "text/plain"});
    Response.end("egress denied\n");
  }
});

Server.maxHeadersCount = 64;
Server.on("connect", async (Request, ClientSocket, Head) => {
  try {
    if (!Request.socket.authorized || Request.rawHeaders.join("\r\n").length > MaximumHeaderBytes) {
      throw new Error("client is not authorized");
    }
    const { Host, Port } = ParseAuthority(Request.url ?? "");
    const Address = await ResolvePublic(Host);
    const Upstream = connect({host: Address, port: Port});
    Upstream.setTimeout(60_000, () => Upstream.destroy());
    Upstream.once("connect", () => {
      ClientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (Head.length > 0) {
        Upstream.write(Head);
      }
      ClientSocket.pipe(Upstream).pipe(ClientSocket);
    });
    Upstream.once("error", () => ClientSocket.destroy());
  } catch {
    ClientSocket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
  }
});

Server.headersTimeout = 5_000;
Server.requestTimeout = 60_000;
Server.listen(ListenPort, "0.0.0.0");
