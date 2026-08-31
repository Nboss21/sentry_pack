
from __future__ import annotations

from typing import Any

from core.session_manager import SessionManager
from core.transport_base import AgentIdentity
from modules.c2.transports.tls_transport.transport import TLSTransport


def handle_tls_connection(
    connection: Any,
    session_manager: SessionManager,
) -> None:
    """Convert an accepted TLS socket into a registered inbound session."""

    transport = TLSTransport.from_socket(connection)

    identity = AgentIdentity(
        agent_id="tls-inbound",
        name="TLS Inbound Agent",
    )

    session_manager.register_connected_session(
        identity=identity,
        transport=transport,
        metadata={
            "direction": "inbound",
            "listener": "tls",
        },
    )