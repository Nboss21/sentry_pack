"""
C2 listener management API routes.

Endpoints:
  GET  /api/listeners
  GET  /api/listeners/{listener_id}
  POST /api/listeners/{listener_id}/start
  POST /api/listeners/{listener_id}/stop
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.listener_manager import listener_manager

from core.session_manager import session_manager
from modules.c2.listeners.tls_listener.handler import handle_tls_connection

router = APIRouter()


class ListenerStartRequest(BaseModel):
    config: dict[str, Any] = {}


@router.get("/")
def list_listeners() -> dict[str, Any]:
    """Return all registered listeners and their current state."""

    listeners = []

    for listener_id in listener_manager.list():
        listeners.append(
            {
                "id": listener_id,
                "running": listener_manager.is_running(listener_id),
            }
        )

    return {
        "listeners": listeners,
        "count": len(listeners),
    }


@router.get("/{listener_id}")
def get_listener(listener_id: str) -> dict[str, Any]:
    """Return one registered listener and its current state."""

    try:
        running = listener_manager.is_running(listener_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"Listener '{listener_id}' not found",
        ) from None

    return {
        "id": listener_id,
        "running": running,
    }


@router.post("/{listener_id}/start")
def start_listener(
    listener_id: str,
    payload: ListenerStartRequest,
) -> dict[str, Any]:
    """Start a registered listener."""

    try:
        if listener_manager.is_running(listener_id):
            raise HTTPException(
                status_code=409,
                detail=f"Listener '{listener_id}' is already running",
            )

        started = listener_manager.start(
            listener_id,
            payload.config,
            lambda connection: handle_tls_connection(
                connection,
                session_manager,
            ),
        )

    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"Listener '{listener_id}' not found",
        ) from None

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start listener '{listener_id}': {exc}",
        ) from exc

    if not started:
        raise HTTPException(
            status_code=500,
            detail=f"Listener '{listener_id}' failed to start",
        )

    return {
        "id": listener_id,
        "running": listener_manager.is_running(listener_id),
    }


@router.post("/{listener_id}/stop")
def stop_listener(listener_id: str) -> dict[str, Any]:
    """Stop a registered listener."""

    try:
        if not listener_manager.is_running(listener_id):
            raise HTTPException(
                status_code=409,
                detail=f"Listener '{listener_id}' is not running",
            )

        listener_manager.stop(listener_id)

    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"Listener '{listener_id}' not found",
        ) from None

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to stop listener '{listener_id}': {exc}",
        ) from exc

    return {
        "id": listener_id,
        "running": listener_manager.is_running(listener_id),
    }