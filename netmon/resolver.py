"""Background reverse-DNS lookups (never blocks the UI)."""

from __future__ import annotations

import ipaddress
import queue
import socket
import threading


class Resolver:
    def __init__(self, enabled: bool = True, workers: int = 4) -> None:
        self.enabled = enabled
        self._cache: dict[str, str | None] = {}
        self._pending: set[str] = set()
        self._queue: queue.Queue[str] = queue.Queue()
        self._lock = threading.Lock()
        if enabled:
            for _ in range(workers):
                threading.Thread(target=self._worker, daemon=True, name="resolver").start()

    def name(self, ip: str) -> str | None:
        if not self.enabled:
            return None
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
            if ip in self._pending:
                return None
            self._pending.add(ip)
        self._queue.put(ip)
        return None

    def _worker(self) -> None:
        while True:
            ip = self._queue.get()
            name = None
            if not _is_group_address(ip):
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except (OSError, UnicodeError):
                    name = None
            with self._lock:
                self._cache[ip] = name
                self._pending.discard(ip)


def _is_group_address(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_multicast or addr.is_unspecified or ip == "255.255.255.255"
