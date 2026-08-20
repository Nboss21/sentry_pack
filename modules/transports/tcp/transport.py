"""
Raw TCP Socket Transport Plugin for SentryPack.
"""

from __future__ import annotations

import logging
import socket
from typing import Optional

from core.transport_base import ITransport, TransportMeta

logger = logging.getLogger("sentrypack.transports.tcp")


class TcpTransport(ITransport):
    """Concrete TCP raw socket transport."""

    meta = TransportMeta(
        id="tcp",
        name="TCP Raw Socket",
        version="0.1.0",
        description="Raw TCP socket transport for C2 sessions.",
        author="SentryPack",
    )

    def __init__(self) -> None:
        self._sock: Optional[socket.socket] = None

    def connect(self, host: str, port: int, options: dict) -> bool:
        """Establish the TCP connection."""
        try:
            self.disconnect()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            timeout = options.get("timeout", 10) if isinstance(options, dict) else 10
            sock.settimeout(timeout)
            sock.connect((host, port))
            self._sock = sock
            return True
        except Exception as exc:
            logger.warning("TCP connect failed to %s:%s: %s", host, port, exc)
            self._sock = None
            return False

    def send(self, data: bytes) -> int:
        """Send bytes over the TCP socket."""
        if not self._sock:
            return 0
        try:
            self._sock.sendall(data)
            return len(data)
        except Exception as exc:
            logger.warning("TCP send error: %s", exc)
            return 0

    def receive(self, size: int = 4096) -> bytes:
        """Receive bytes from the TCP socket."""
        if not self._sock:
            return b""
        try:
            return self._sock.recv(size)
        except Exception as exc:
            logger.warning("TCP receive error: %s", exc)
            return b""

    def disconnect(self) -> None:
        """Close TCP socket connection cleanly."""
        if self._sock:
            try:
                self._sock.close()
            except Exception as exc:
                logger.warning("TCP disconnect error: %s", exc)
            finally:
                self._sock = None
