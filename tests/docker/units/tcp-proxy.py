#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Small development-only TCP forwarder for Docker-outside-of-Docker browsers."""

from __future__ import annotations

import argparse
import errno
import selectors
import socket
import threading


MAXIMUM_CONNECTIONS = 64
LOOPBACK_PORT = 8443
IPV6_OPTIONAL_ERRORS = frozenset(
    error
    for error in (
        getattr(errno, "EAFNOSUPPORT", None),
        getattr(errno, "EPROTONOSUPPORT", None),
        getattr(errno, "EADDRNOTAVAIL", None),
        getattr(errno, "ENOPROTOOPT", None),
    )
    if error is not None
)


def create_listener(family: socket.AddressFamily, address: tuple[str, int]) -> socket.socket:
    """Create one loopback listener without relying on dual-stack defaults."""
    listener = socket.socket(family, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind(address)
        listener.listen()
        return listener
    except Exception:
        listener.close()
        raise


def create_listeners() -> tuple[socket.socket, ...]:
    """Bind the mandatory IPv4 edge and an IPv6 edge when the host supports it."""
    listeners: list[socket.socket] = []
    try:
        listeners.append(create_listener(socket.AF_INET, ("127.0.0.1", LOOPBACK_PORT)))
        try:
            listeners.append(create_listener(socket.AF_INET6, ("::1", LOOPBACK_PORT)))
        except OSError as error:
            if error.errno not in IPV6_OPTIONAL_ERRORS:
                raise RuntimeError("IPv6 loopback bridge listener could not be created") from error
        return tuple(listeners)
    except Exception:
        for listener in listeners:
            listener.close()
        raise


def forward(client: socket.socket, target: tuple[str, int], admission: threading.BoundedSemaphore) -> None:
    try:
        try:
            upstream = socket.create_connection(target, timeout=10)
        except OSError:
            return
        try:
            # `selectors` gates reads; keep writes blocking so `sendall` cannot
            # turn ordinary backpressure on a large TLS body into a reset.
            client.setblocking(True)
            upstream.setblocking(True)
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
    listeners = create_listeners()
    admission = threading.BoundedSemaphore(MAXIMUM_CONNECTIONS)
    for listener in listeners[1:]:
        threading.Thread(target=serve, args=(listener, target, admission), daemon=True).start()
    print("FileBelt browser TCP bridge is listening", flush=True)
    serve(listeners[0], target, admission)


if __name__ == "__main__":
    raise SystemExit(main())
