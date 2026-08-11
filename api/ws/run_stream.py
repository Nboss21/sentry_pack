"""
WebSocket live run-stream endpoint — /ws/runs/{run_id}

Drains the asyncio.Queue registered in core.run_store.run_store and forwards
every event as a JSON message to connected clients.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from core.run_manager import run_manager

router = APIRouter()

_QUEUE_WAIT_TIMEOUT = 10.0
_QUEUE_POLL_INTERVAL = 0.05


@router.websocket("/ws/runs/{run_id}")
async def run_stream(websocket: WebSocket, run_id: str) -> None:
    """Stream live run events to the connected client."""
    await websocket.accept()
    queue, snapshot = run_manager.subscribe(run_id)

    if queue is None or snapshot is None:
        try:
            await websocket.send_json({
                "type": "error",
                "run_id": run_id,
                "message": f"Run {run_id} not found",
            })
            await websocket.close()
        except Exception:
            pass
        return

    try:
        done = False
        for event in snapshot:
            await websocket.send_json(event)
            if event.get("type") in ("complete", "error"):
                done = True
                break

        if not done:
            while True:
                event = await queue.get()
                await websocket.send_json(event)
                if event.get("type") in ("complete", "error"):
                    break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        run_manager.unsubscribe(run_id, queue)
        try:
            await websocket.close()
        except Exception:
            pass

