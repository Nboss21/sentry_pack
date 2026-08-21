"""
Raw TCP Socket Transport Plugin for SentryPack.

Implements ITransport for a plain TCP socket channel.
"""

from __future__ import annotations

import logging
import socket
from typing import Any, Optional, Union

from core.transport_base import ITransport, Task, TaskResult, TransportMeta

logger = logging.getLogger("sentrypack.transports.tcp")


class TcpTransport(ITransport):
    """
    Concrete TCP raw socket transport implementing ITransport.

    Configuration keys expected in the config dict passed to connect():
        host (str, required)  — Remote IP or hostname
        port (int, required)  — Remote TCP port number
        timeout (int)         — Socket timeout in seconds (default 10)
    """

    meta = TransportMeta(
        id="tcp",
        name="TCP Raw Socket",
        version="0.1.0",
        description="Raw TCP socket transport for C2 sessions.",
        author="SentryPack",
    )

    def __init__(self) -> None:
        self._sock: Optional[socket.socket] = None

    def connect(self, host_or_config: Any, port: Optional[int] = None, options: Optional[dict] = None, **kwargs) -> bool:
        """
        Establish a TCP connection.

        Accepts either:
          connect(host, port, options) — positional legacy form
          connect({"host": ..., "port": ..., "timeout": ...}) — config dict form
        """
        self.disconnect()

        # Resolve arguments
        if isinstance(host_or_config, dict):
            cfg = host_or_config
            host = cfg.get("host", "127.0.0.1")
            _port = cfg.get("port", port or 4444)
            timeout = cfg.get("timeout", 10)
        else:
            host = str(host_or_config)
            _port = port or 4444
            opts = options or kwargs
            timeout = opts.get("timeout", 10) if isinstance(opts, dict) else 10

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, int(_port)))
            self._sock = sock
            return True
        except Exception as exc:
            logger.warning("TCP connect failed to %s:%s: %s", host, _port, exc)
            self._sock = None
            return False

    def send(self, data: Union[bytes, str, Task, Any]) -> int:
        """Send bytes, string, or Task payload over the TCP socket."""
        if not self._sock:
            return 0
        try:
            if isinstance(data, Task):
                raw = str(data.payload).encode() if not isinstance(data.payload, bytes) else data.payload
            elif isinstance(data, str):
                raw = data.encode()
            elif isinstance(data, bytes):
                raw = data
            else:
                raw = str(data).encode()
            self._sock.sendall(raw)
            return len(raw)
        except Exception as exc:
            logger.warning("TCP send error: %s", exc)
            return 0

    def receive(self, size: int = 4096) -> bytes:
        """Receive up to `size` bytes. Returns b"" if no data or on error."""
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

    def is_alive(self) -> bool:
        """Return True if the socket is connected and alive."""
        return self._sock is not None
