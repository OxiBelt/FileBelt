#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Small development-only TCP forwarder for Docker-outside-of-Docker browsers."""

from __future__ import annotations

import argparse
import selectors
import socket
import threading


MAXIMUM_CONNECTIONS = 64


def forward(client: socket.socket, target: tuple[str, int], admission: threading.BoundedSemaphore) -> None:
    try:
        try:
            upstream = socket.create_connection(target, timeout=10)
        except OSError:
            return
        try:
            client.setblocking(False)
            upstream.setblocking(False)
            selector = selectors.DefaultSelector()
            selector.register(client, selectors.EVENT_READ, upstream)
            selector.register(upstream, selectors.EVENT_READ, client)
            active = True
            while active:
                for key, _ in selector.select(timeout=30):
                    source = key.fileobj
                    destination = key.data
                    try:
                        chunk = source.recv(64 * 1024)
                        if not chunk:
                            active = False
                            break
                        destination.sendall(chunk)
                    except OSError:
                        active = False
                        break
            selector.close()
        finally:
            upstream.close()
    finally:
        client.close()
        admission.release()


def serve(listener: socket.socket, target: tuple[str, int], admission: threading.BoundedSemaphore) -> None:
    while True:
        client, _ = listener.accept()
        if not admission.acquire(blocking=False):
            client.close()
            continue
        threading.Thread(target=forward, args=(client, target, admission), daemon=True).start()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    arguments = parser.parse_args()
    host, separator, port_text = arguments.target.rpartition(":")
    if not separator or not host or not port_text.isdigit():
        raise SystemExit("target must be HOST:PORT")
    target = (host, int(port_text))
    ipv4 = socket.create_server(("127.0.0.1", 8443), reuse_port=False)
    ipv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    ipv6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ipv6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    ipv6.bind(("::1", 8443))
    ipv6.listen()
    admission = threading.BoundedSemaphore(MAXIMUM_CONNECTIONS)
    threading.Thread(target=serve, args=(ipv6, target, admission), daemon=True).start()
    serve(ipv4, target, admission)


if __name__ == "__main__":
    raise SystemExit(main())
