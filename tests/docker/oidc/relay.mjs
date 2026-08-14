// SPDX-License-Identifier: Apache-2.0

import { createConnection, createServer } from "node:net";
import process from "node:process";
import { pathToFileURL } from "node:url";

const LISTEN_HOST = "0.0.0.0";
const LISTEN_PORT = 8443;
const TARGET_HOST = "filebelt-web";
const TARGET_PORT = 8443;
const MAXIMUM_CONNECTIONS = 64;
const CONNECT_TIMEOUT_MS = 5_000;

export function createRelay({
  targetHost,
  targetPort,
  maximumConnections = MAXIMUM_CONNECTIONS,
}) {
  const connections = new Set();
  let activeConnections = 0;
  const server = createServer((client) => {
    if (activeConnections >= maximumConnections) {
      client.destroy();
      return;
    }
    activeConnections += 1;
    client.setNoDelay(true);
    const upstream = createConnection({ host: targetHost, port: targetPort });
    const connection = { client, upstream };
    connections.add(connection);
    let closed = false;
    const close = () => {
      if (!closed) {
        closed = true;
        activeConnections -= 1;
        connections.delete(connection);
      }
      client.destroy();
      upstream.destroy();
    };
    upstream.setTimeout(CONNECT_TIMEOUT_MS, close);
    upstream.once("connect", () => upstream.setTimeout(0));
    client.once("error", close);
    client.once("close", close);
    upstream.once("error", close);
    upstream.once("close", close);
    client.pipe(upstream);
    upstream.pipe(client);
  });
  server.shutdown = (callback) => {
    server.close(callback);
    for (const { client, upstream } of connections) {
      client.destroy();
      upstream.destroy();
    }
  };
  return server;
}

function main() {
  const relay = createRelay({
    targetHost: TARGET_HOST,
    targetPort: TARGET_PORT,
  });
  relay.listen(LISTEN_PORT, LISTEN_HOST, () => {
    process.stdout.write("FileBelt Docker acceptance relay ready\n");
  });
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => relay.shutdown(() => process.exit(0)));
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
