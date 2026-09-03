
from __future__ import annotations

from typing import Any
import uuid

from core.session_manager import SessionManager
from core.transport_base import AgentIdentity
from modules.c2.transports.tls_transport.transport import TLSTransport

from api.db.models import C2Session
from api.db.session import SessionLocal

def handle_tls_connection(
    connection: Any,
    session_manager: SessionManager,
) -> None:
    """Convert an accepted TLS socket into a registered inbound session."""

    transport = TLSTransport.from_socket(connection)

    identity = AgentIdentity(
        agent_id=f"tls-inbound-{uuid.uuid4().hex[:12]}",
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

    db = SessionLocal()

    try:
        session = C2Session(
            session_key=identity.agent_id,
            transport="tls",
            status="active",
        )

        db.add(session)
        db.commit()

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()