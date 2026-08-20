"""
C2 WebSocket channel — /ws/projects/{project_id}/sessions/{session_key}

Authorization: client must pass ?token=<project_auth_token> as a query param.
Scoping: only streams events for sessions belonging to project_id.
Unauthorized clients are rejected before any session data is sent.
"""

from __future__ import annotations

import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from sqlalchemy.orm import Session as DBSession
from api.db.session import SessionLocal
from core.c2_channel import c2_channel

logger = logging.getLogger("sentrypack.c2_session_stream")

router = APIRouter()

_CLOSE_POLICY_VIOLATION = 1008  # WebSocket close code for auth failure


@router.websocket("/ws/projects/{project_id}/sessions/{session_key}")
async def c2_session_stream(
    websocket: WebSocket,
    project_id: int,
    session_key: str,
    token: str = Query(default=""),
) -> None:
    # Accept the TCP connection but DO NOT send any data yet
    await websocket.accept()

    db: DBSession = SessionLocal()
    queue = None
    try:
        # === AUTHORIZATION CHECK — before any data flows ===
        ok, reason = await c2_channel.authorize_subscription(
            project_id, session_key, token, db
        )
        if not ok:
            await websocket.send_json({
                "type": "error",
                "code": "unauthorized",
                "message": reason,
            })
            await websocket.close(code=_CLOSE_POLICY_VIOLATION)
            return

        # === AUTHORIZED — send confirmation, then stream ===
        await websocket.send_json({
            "type": "subscribed",
            "project_id": project_id,
            "session_key": session_key,
        })

        queue, snapshot = c2_channel.subscribe(project_id, session_key)

        # Replay buffered events for late joiners
        for event in snapshot:
            await websocket.send_json(event)

        # Stream live events
        while True:
            event = await queue.get()
            await websocket.send_json(event)

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        c2_channel.unsubscribe(project_id, session_key, queue)
        db.close()
        try:
            await websocket.close()
        except Exception:
            pass
