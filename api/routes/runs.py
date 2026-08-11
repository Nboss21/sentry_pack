"""
Module execution routes.

POST /api/targets/{target_id}/run
    Instantiate and launch the requested module against a target in a
    background asyncio task.  Returns immediately with the new ``run_id``
    so the caller can subscribe to the WebSocket stream.

GET  /api/runs/{run_id}/status
    Poll the run status (pending / running / completed / timeout / error).
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.session import get_db
from core.registry import ModuleRegistry
from core.run_store import run_store
from core.runner import new_run_id, run_module

logger = logging.getLogger("sentrypack.api.runs")
router = APIRouter()

MODULES_DIR = Path(__file__).resolve().parent.parent.parent / "modules"

# Module-level registry; populated once per process lifetime.
_registry: Optional[ModuleRegistry] = None


def _get_registry() -> ModuleRegistry:
    global _registry
    if _registry is None:
        _registry = ModuleRegistry(MODULES_DIR)
        _registry.scan()
    return _registry


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class RunRequest(BaseModel):
    """Body for POST /api/targets/{target_id}/run."""

    module_id: str
    options: dict = {}
    timeout_seconds: Optional[int] = None


class RunResponse(BaseModel):
    run_id: str
    target_id: int
    module_id: str
    status: str
    ws_url: str


# ---------------------------------------------------------------------------
# Background task wrapper
# ---------------------------------------------------------------------------


async def _execute_run(
    run_id: str,
    module_id: str,
    target: str,
    options: dict,
    timeout_seconds: Optional[int],
) -> None:
    """Coroutine run as a background asyncio task."""
    registry = _get_registry()
    meta = registry.get_module(module_id)
    if meta is None:
        logger.error("Module '%s' not found in registry for run '%s'.", module_id, run_id)
        return

    # Dynamically import module.py
    folder_name = module_id.split(".")[-1]
    module_py = MODULES_DIR / folder_name / "module.py"
    if not module_py.exists():
        # Search recursively
        for p in MODULES_DIR.glob(f"**/{folder_name}/module.py"):
            module_py = p
            break

    import importlib.util
    spec = importlib.util.spec_from_file_location(f"mod_{run_id}", module_py)
    if spec is None or spec.loader is None:
        return
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    module_cls = mod.Module

    try:
        _findings, queue = await run_module(
            module_cls=module_cls,
            options=options,
            run_id=run_id,
            target=target,
            timeout_seconds=timeout_seconds,
        )
        run_store.register(run_id, queue)
    except Exception as exc:
        logger.exception("Unhandled error launching run '%s': %s", run_id, exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/targets/{target_id}/run", response_model=RunResponse)
async def start_run(
    target_id: int,
    body: RunRequest,
    db: Session = Depends(get_db),
) -> RunResponse:
    """Launch a module run against a target."""
    registry = _get_registry()
    meta = registry.get_module(body.module_id)
    if meta is None:
        raise HTTPException(
            status_code=404,
            detail=f"Module '{body.module_id}' not found in registry.",
        )

    run_id = new_run_id()
    target = f"target-{target_id}"

    asyncio.create_task(
        _execute_run(
            run_id=run_id,
            module_id=body.module_id,
            target=target,
            options=body.options,
            timeout_seconds=body.timeout_seconds,
        ),
        name=f"run-{run_id}",
    )

    return RunResponse(
        run_id=run_id,
        target_id=target_id,
        module_id=body.module_id,
        status="started",
        ws_url=f"/ws/runs/{run_id}",
    )


@router.get("/runs/{run_id}/status")
async def get_run_status(run_id: str) -> dict:
    """Return whether a run's queue is still active in the run store."""
    queue = run_store.get(run_id)
    if queue is None:
        return {"run_id": run_id, "status": "unknown"}
    return {
        "run_id": run_id,
        "status": "active",
        "queue_size": queue.qsize(),
    }
