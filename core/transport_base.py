"""
Abstract base and metadata contract for all SentryPack transport plugins.

Every transport plugin module must:
  1. Define a class that inherits ITransport
  2. Set a class-level `meta` attribute of type TransportMeta
  3. Implement all four abstract methods: connect, send, receive, disconnect
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class TransportMeta:
    id: str              # machine-readable, e.g. "tcp", "https", "dns"
    name: str            # human-readable, e.g. "TCP Raw Socket"
    version: str         # semver string, e.g. "0.1.0"
    description: str
    author: str = "unknown"
    options: list = field(default_factory=list)  # same ModuleOption list pattern as BaseModule


class ITransport(abc.ABC):
    meta: TransportMeta  # must be set at class level by every subclass

    @abc.abstractmethod
    def connect(self, host: str, port: int, options: dict) -> bool:
        """Establish the transport connection. Return True on success."""

    @abc.abstractmethod
    def send(self, data: bytes) -> int:
        """Send bytes. Return number of bytes sent."""

    @abc.abstractmethod
    def receive(self, size: int = 4096) -> bytes:
        """Receive up to `size` bytes. Return raw bytes."""

    @abc.abstractmethod
    def disconnect(self) -> None:
        """Tear down the connection cleanly."""
