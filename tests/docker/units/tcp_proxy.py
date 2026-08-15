#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Managed loopback TCP bridge for Docker acceptance clients."""

from __future__ import annotations

import errno
import selectors
import socket
import threading
import time


MAXIMUM_CONNECTIONS = 64
LOOPBACK_PORT = 8443
UPSTREAM_CONNECT_TIMEOUT_SECONDS = 1.0
UPSTREAM_RETRY_DELAY_SECONDS = 0.1
UPSTREAM_RETRY_WINDOW_SECONDS = 5.0
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


def create_listener(
    family: socket.AddressFamily,
    address: tuple[str, int],
) -> socket.socket:
    """Create one loopback listener without relying on dual-stack defaults."""
    listener = socket.socket(family, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind(address)
        listener.listen()
        listener.settimeout(0.2)
        return listener
    except Exception:
        listener.close()
        raise


def create_listeners(port: int = LOOPBACK_PORT) -> tuple[socket.socket, ...]:
    """Bind the mandatory IPv4 edge and an IPv6 edge when supported."""
    listeners: list[socket.socket] = []
    try:
        listeners.append(create_listener(socket.AF_INET, ("127.0.0.1", port)))
        try:
            listeners.append(create_listener(socket.AF_INET6, ("::1", port)))
        except OSError as error:
            if error.errno not in IPV6_OPTIONAL_ERRORS:
                raise RuntimeError(
                    "IPv6 loopback bridge listener could not be created"
                ) from error
        return tuple(listeners)
    except Exception:
        for listener in listeners:
            listener.close()
        raise


class ManagedTcpBridge:
    """Own listeners, connections, forwarding workers, and deterministic cleanup."""

    def __init__(
        self,
        target: tuple[str, int],
        port: int = LOOPBACK_PORT,
        maximum_connections: int = MAXIMUM_CONNECTIONS,
    ) -> None:
        if maximum_connections < 1:
            raise ValueError("maximum connections must be positive")
        self.target = target
        self.port = port
        self._listeners: tuple[socket.socket, ...] = ()
        self._accept_threads: set[threading.Thread] = set()
        self._worker_threads: set[threading.Thread] = set()
        self._active_sockets: set[socket.socket] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._fatal_error: str | None = None
        self._admission = threading.BoundedSemaphore(maximum_connections)
        self._statistics = {
            "admission_rejections": 0,
            "retry_exhaustions": 0,
            "upstream_attempts": 0,
            "upstream_failures": 0,
        }

    @property
    def listener_count(self) -> int:
        return len(self._listeners)

    @property
    def bound_port(self) -> int:
        if not self._listeners:
            raise RuntimeError("TCP bridge has not been started")
        return int(self._listeners[0].getsockname()[1])

    @property
    def fatal_error(self) -> str | None:
        with self._lock:
            return self._fatal_error

    @property
    def statistics(self) -> dict[str, int]:
        """Return non-secret aggregate connection lifecycle counters."""
        with self._lock:
            return dict(self._statistics)

    def start(self) -> None:
        if self._listeners:
            raise RuntimeError("TCP bridge has already been started")
        self._listeners = create_listeners(self.port)
        try:
            for listener in self._listeners:
                thread = threading.Thread(
                    target=self._serve,
                    args=(listener,),
                    name="filebelt-tcp-bridge-accept",
                    daemon=True,
                )
                thread.start()
                self._accept_threads.add(thread)
        except Exception:
            self.stop()
            raise

    def check(self) -> None:
        error = self.fatal_error
        if error is not None:
            raise RuntimeError(f"browser TCP bridge failed: {error}")
        if not self._listeners or self._stop.is_set():
            raise RuntimeError("browser TCP bridge is not running")
        if any(not thread.is_alive() for thread in self._accept_threads):
            error = RuntimeError("browser TCP bridge listener stopped unexpectedly")
            self._record_fatal(error)
            raise error

    def stop(self, timeout: float = 5) -> str:
        self._stop.set()
        for listener in self._listeners:
            listener.close()
        with self._lock:
            sockets = tuple(self._active_sockets)
        for connection in sockets:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        deadline = time.monotonic() + timeout
        accept_threads = tuple(self._accept_threads)
        for thread in accept_threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        with self._lock:
            workers = tuple(self._worker_threads)
        threads = accept_threads + workers
        for thread in workers:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        remaining = [
            thread.name
            for thread in threads
            if thread.is_alive()
        ]
        self._listeners = ()
        if remaining:
            raise RuntimeError(
                f"browser TCP bridge cleanup left {len(remaining)} worker(s)"
            )
        return "stopped"

    def _record_fatal(self, error: BaseException) -> None:
        detail = "".join(
            character if character.isprintable() and character not in "\r\n\t" else "?"
            for character in str(error)
        )[:240]
        with self._lock:
            if self._fatal_error is None:
                self._fatal_error = detail or error.__class__.__name__
        self._stop.set()

    def _increment_statistic(self, name: str) -> None:
        with self._lock:
            self._statistics[name] += 1

    def _serve(self, listener: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError as error:
                if not self._stop.is_set():
                    self._record_fatal(error)
                return
            if self._stop.is_set():
                client.close()
                return
            if not self._admission.acquire(blocking=False):
                self._increment_statistic("admission_rejections")
                client.close()
                continue
            thread = threading.Thread(
                target=self._forward,
                args=(client,),
                name="filebelt-tcp-bridge-forward",
                daemon=True,
            )
            with self._lock:
                if self._stop.is_set():
                    self._admission.release()
                    client.close()
                    return
                self._worker_threads.add(thread)
                self._active_sockets.add(client)
                try:
                    thread.start()
                except Exception:
                    self._worker_threads.discard(thread)
                    self._active_sockets.discard(client)
                    self._admission.release()
                    client.close()
                    raise

    def _forward(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            upstream = self._connect_upstream()
            if upstream is None:
                return
            with self._lock:
                self._active_sockets.add(upstream)
            client.setblocking(True)
            upstream.setblocking(True)
            selector = selectors.DefaultSelector()
            try:
                selector.register(client, selectors.EVENT_READ, upstream)
                selector.register(upstream, selectors.EVENT_READ, client)
                active = True
                while active and not self._stop.is_set():
                    for key, _ in selector.select(timeout=0.2):
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
            finally:
                selector.close()
        finally:
            client.close()
            if upstream is not None:
                upstream.close()
            with self._lock:
                self._active_sockets.discard(client)
                if upstream is not None:
                    self._active_sockets.discard(upstream)
                self._worker_threads.discard(threading.current_thread())
            self._admission.release()

    def _connect_upstream(self) -> socket.socket | None:
        deadline = time.monotonic() + UPSTREAM_RETRY_WINDOW_SECONDS
        while not self._stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._increment_statistic("retry_exhaustions")
                return None
            self._increment_statistic("upstream_attempts")
            try:
                return socket.create_connection(
                    self.target,
                    timeout=min(UPSTREAM_CONNECT_TIMEOUT_SECONDS, remaining),
                )
            except OSError:
                self._increment_statistic("upstream_failures")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._increment_statistic("retry_exhaustions")
                return None
            if self._stop.wait(min(UPSTREAM_RETRY_DELAY_SECONDS, remaining)):
                return None
        return None
