"""
TLS Encrypted Transport Plugin for SentryPack C2.

Implements ITransport using Python's built-in ssl module.
Wraps a raw TCP socket with a TLS/SSL context for encrypted
command-and-control sessions.

Module location: modules/c2/transports/tls_transport/
"""

from __future__ import annotations

import logging
import socket
import ssl
from typing import Any, Optional, Union

from core.transport_base import ITransport, Task, TaskResult, TransportMeta

logger = logging.getLogger("sentrypack.transports.tls")


class TLSTransport(ITransport):
    """
    Concrete TLS-encrypted socket transport implementing ITransport.

    ALL TLS logic — SSL context, certificate handling, hostname verification,
    and cipher configuration — lives exclusively in this class. The SessionManager
    and core application are never exposed to any TLS-specific details.

    Configuration keys expected in the config dict passed to connect():
        host (str, required)           — Remote IP or hostname
        port (int, required)           — Remote port (default 4443)
        certfile (str, optional)       — Path to client cert file (PEM)
        keyfile (str, optional)        — Path to private key file (PEM)
        ca_certs (str, optional)       — Path to CA certificate bundle (PEM)
        verify_cert (bool, optional)   — Verify server certificate (default True)
        server_hostname (str, optional)— Explicit SNI hostname (default: same as host)
        timeout (int, optional)        — Socket timeout in seconds (default 10)
    """

    meta = TransportMeta(
        id="tls",
        name="TLS Encrypted Transport",
        version="0.1.0",
        description=(
            "TLS/SSL encrypted socket transport for secure C2 sessions. "
            "Supports client-side certificates, CA verification, and SNI."
        ),
        author="SentryPack",
    )

    def __init__(self) -> None:
        self._sock: Optional[ssl.SSLSocket] = None
        self._raw_sock: Optional[socket.socket] = None
    @classmethod
    def from_socket(
        cls,
        sock: ssl.SSLSocket,
    ) -> "TLSTransport":
        """Create a TLS transport from an already-established socket."""

        transport = cls()
        transport._sock = sock
        return transport

    def connect(self, host_or_config: Any, port: Optional[int] = None, options: Optional[dict] = None, **kwargs) -> bool:
        """
        Establish a TLS-encrypted connection.

        Accepts either:
          connect("1.2.3.4", 4443, {"certfile": ..., "keyfile": ..., ...}) — positional form
          connect({"host": ..., "port": ..., "certfile": ..., ...})           — config dict form
          connect(agent_config.transport_config)                               — AgentConfig blob form

        Returns True on successful handshake, False otherwise.
        """
        self.disconnect()

        # Resolve configuration
        if isinstance(host_or_config, dict):
            cfg = host_or_config
            host = cfg.get("host", "127.0.0.1")
            _port = int(cfg.get("port", port or 4443))
            certfile = cfg.get("certfile")
            keyfile = cfg.get("keyfile")
            ca_certs = cfg.get("ca_certs")
            verify_cert = bool(cfg.get("verify_cert", True))
            server_hostname = cfg.get("server_hostname", host)
            timeout = int(cfg.get("timeout", 10))
        else:
            host = str(host_or_config)
            _port = int(port or 4443)
            opts = options or {}
            certfile = opts.get("certfile")
            keyfile = opts.get("keyfile")
            ca_certs = opts.get("ca_certs")
            verify_cert = bool(opts.get("verify_cert", True))
            server_hostname = opts.get("server_hostname", host)
            timeout = int(opts.get("timeout", 10))

        try:
            # Build SSL context
            if verify_cert:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.check_hostname = True
                if ca_certs:
                    ctx.load_verify_locations(ca_certs)
                else:
                    ctx.load_default_certs()
            else:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.verify_mode = ssl.CERT_NONE
                ctx.check_hostname = False

            if certfile:
                ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

            # Connect raw socket then wrap with SSL
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(timeout)
            raw_sock.connect((host, _port))
            self._raw_sock = raw_sock

            # TLS handshake
            self._sock = ctx.wrap_socket(
                raw_sock,
                server_hostname=server_hostname,
            )
            logger.info(
                "TLS connection established to %s:%d (cipher=%s)",
                host,
                _port,
                self._sock.cipher(),
            )
            return True

        except ssl.SSLError as exc:
            logger.warning("TLS handshake error to %s:%s: %s", host, _port, exc)
            self._cleanup_sockets()
            return False
        except OSError as exc:
            logger.warning("TLS connect failed to %s:%s: %s", host, _port, exc)
            self._cleanup_sockets()
            return False
        except Exception as exc:
            logger.warning("TLS unexpected error to %s:%s: %s", host, _port, exc)
            self._cleanup_sockets()
            return False

    def send(self, data: Union[bytes, str, Task, Any]) -> int:
        """
        Send a task or raw data over the encrypted TLS channel.

        Non-blocking contract: raises no unhandled exceptions; returns 0 on failure.
        """
        if not self._sock:
            return 0
        try:
            if isinstance(data, Task):
                raw = (
                    data.payload
                    if isinstance(data.payload, bytes)
                    else str(data.payload).encode()
                )
            elif isinstance(data, str):
                raw = data.encode()
            elif isinstance(data, bytes):
                raw = data
            else:
                raw = str(data).encode()
            self._sock.sendall(raw)
            return len(raw)
        except ssl.SSLError as exc:
            logger.warning("TLS send SSL error: %s", exc)
            return 0
        except OSError as exc:
            logger.warning("TLS send OS error: %s", exc)
            return 0
        except Exception as exc:
            logger.warning("TLS send error: %s", exc)
            return 0

    def receive(self, size: int = 4096) -> bytes:
        """
        Receive up to `size` encrypted bytes from the TLS channel.

        Returns b"" if no data is available or on any error. Never raises.
        """
        if not self._sock:
            return b""
        try:
            data = self._sock.recv(size)
            return data or b""
        except ssl.SSLError as exc:
            logger.warning("TLS receive SSL error: %s", exc)
            return b""
        except OSError as exc:
            logger.warning("TLS receive OS error: %s", exc)
            return b""
        except Exception as exc:
            logger.warning("TLS receive error: %s", exc)
            return b""

    def disconnect(self) -> None:
        """Cleanly shut down the TLS session and release socket resources."""
        if self._sock:
            try:
                self._sock.unwrap()
            except Exception:
                pass
            try:
                self._sock.close()
            except Exception:
                pass
            finally:
                self._sock = None
        self._cleanup_sockets()

    def is_alive(self) -> bool:
        """Return True if the TLS socket is open and connected."""
        return self._sock is not None

    def get_cipher_info(self) -> Optional[tuple]:
        """
        Return cipher negotiation details as a tuple or None if not connected.
        Useful for logging and diagnostics only.
        """
        if self._sock:
            return self._sock.cipher()
        return None

    def _cleanup_sockets(self) -> None:
        """Release raw socket resources unconditionally."""
        if self._raw_sock:
            try:
                self._raw_sock.close()
            except Exception:
                pass
            finally:
                self._raw_sock = None
