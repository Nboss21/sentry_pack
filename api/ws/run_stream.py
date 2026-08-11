"""
WebSocket live run-stream endpoint — /ws/runs/{run_id}

Drains the asyncio.Queue registered in core.run_store.run_store and forwards
every event as a JSON message to connected clients.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.run_store import run_store
from core.execution import QUEUE_SENTINEL

logger = logging.getLogger("sentrypack.api.ws.run_stream")
router = APIRouter()

_QUEUE_WAIT_TIMEOUT = 10.0
_QUEUE_POLL_INTERVAL = 0.05


@router.websocket("/ws/runs/{run_id}")
async def run_stream(websocket: WebSocket, run_id: str) -> None:
    """Stream live run events to the connected client."""
    await websocket.accept()

    queue: asyncio.Queue | None = None
    deadline = asyncio.get_event_loop().time() + _QUEUE_WAIT_TIMEOUT

    while queue is None:
        queue = run_store.get(run_id)
        if queue is None:
            if asyncio.get_event_loop().time() >= deadline:
                logger.warning("run_id '%s' never appeared in run_store.", run_id)
                await websocket.close(code=4404, reason=f"run '{run_id}' not found")
                return
            await asyncio.sleep(_QUEUE_POLL_INTERVAL)

    try:
        await websocket.send_json({"event_type": "connected", "run_id": run_id})

        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=120.0)
            except asyncio.TimeoutError:
                logger.warning("Queue for run '%s' timed out waiting for events.", run_id)
                await websocket.send_json(
                    {"event_type": "error", "run_id": run_id, "message": "stream timeout"}
                )
                break

            if event is QUEUE_SENTINEL:
                await websocket.send_json({"event_type": "completed", "run_id": run_id})
                break

            await websocket.send_json(event)

    except WebSocketDisconnect:
        logger.info("Client disconnected from run stream '%s'.", run_id)
    except Exception as exc:
        logger.exception("Error in run stream '%s': %s", run_id, exc)
    finally:
        run_store.release(run_id)
