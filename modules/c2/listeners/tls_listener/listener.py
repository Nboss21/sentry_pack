"""
TLS listener implementation for SentryPack C2.
"""

from __future__ import annotations

import socket
import ssl
import threading
from typing import Any, Callable, Optional

from core.listener_base import IListener


class TLSListener(IListener):
    """Inbound TLS listener."""

    def __init__(self) -> None:
        self._running = False
        self._server_socket: Optional[socket.socket] = None
        self._ssl_context: Optional[ssl.SSLContext] = None
        self._on_connection: Optional[Callable[[Any], None]] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def listener_id(self) -> str:
        return "tls"

    def start(
        self,
        config: dict[str, Any],
        on_connection: Callable[[Any], None],
    ) -> bool:
        """Start the TLS listener."""

        if self._running:
            return True

        host = str(config.get("host", "127.0.0.1"))
        port = int(config.get("port", 4443))
        certfile = config.get("certfile")
        keyfile = config.get("keyfile")

        if not certfile or not keyfile:
            raise ValueError(
                "TLS listener requires certfile and keyfile"
            )

        context = ssl.SSLContext(
            ssl.PROTOCOL_TLS_SERVER
        )

        context.load_cert_chain(
            certfile=certfile,
            keyfile=keyfile,
        )

        server_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        server_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )

        server_socket.bind((host, port))
        server_socket.listen()

        self._ssl_context = context
        self._server_socket = server_socket
        self._on_connection = on_connection
        self._running = True

        self._thread = threading.Thread(
            target=self._accept_loop,
            daemon=True,
        )
        self._thread.start()

        return True

    def stop(self) -> None:
        """Stop the listener."""

        self._running = False

        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass

        self._server_socket = None
        self._ssl_context = None
        self._on_connection = None

    def is_running(self) -> bool:
        """Return whether the listener is running."""

        return self._running

    def _accept_loop(self) -> None:
        """Accept and TLS-wrap inbound connections."""

        while self._running and self._server_socket:
            try:
                raw_connection, _ = (
                    self._server_socket.accept()
                )

                if not self._ssl_context:
                    raw_connection.close()
                    continue

                connection = (
                    self._ssl_context.wrap_socket(
                        raw_connection,
                        server_side=True,
                    )
                )

                if self._on_connection:
                    self._on_connection(connection)
                else:
                    connection.close()

            except OSError:
                if self._running:
                    continue
                break

            except ssl.SSLError:
                try:
                    raw_connection.close()
                except Exception:
                    pass# """
# TLS listener implementation for SentryPack C2.






# """

# from typing import Any, Callable, Optional

# from core.listener_base import IListener


# class TLSListener(IListener):
#     """Listener implementation for inbound TLS connections."""

#     def __init__(self) -> None:
#         self._running = False
#         self._on_connection: Optional[Callable[[Any], None]] = None

#     @property
#     def listener_id(self) -> str:
#         return "tls"

#     def start(
#         self,
#         config: dict[str, Any],
#         on_connection: Callable[[Any], None],
#     ) -> bool:
#         """Start the TLS listener."""

#         del config

#         self._on_connection = on_connection
#         self._running = True

#         return True

#     def stop(self) -> None:
#         """Stop the TLS listener."""

#         self._running = False
#         self._on_connection = None

#     def is_running(self) -> bool:
#         """Return whether the TLS listener is running."""
#         return self._running