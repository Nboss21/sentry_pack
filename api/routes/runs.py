"""
Module execution routes.

POST /api/targets/{target_id}/run
    Instantiate and launch the requested module against a target in a
    background asyncio task.  Returns immediately with the new ``run_id``
    so the caller can subscribe to the WebSocket stream.

GET  /api/runs/{run_id}/status
    Poll the run status (pending / running / completed / timeout / error).
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.models import ModuleRun, Target
from api.db.session import get_db
from core.registry import ModuleRegistry, load_module_class, validate_options
from core.run_manager import run_manager

logger = logging.getLogger("sentrypack.api.runs")
router = APIRouter()

MODULES_DIR = Path(__file__).resolve().parent.parent.parent / "modules"


class RunRequest(BaseModel):
    module_id: str
    options: Optional[Dict[str, Any]] = None


@router.post("/targets/{target_id}/run")
async def run_module(
    target_id: int,
    req: RunRequest,
    db: Session = Depends(get_db),
):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail=f"Target {target_id} not found")

    registry = ModuleRegistry(MODULES_DIR)
    registry.scan()
    meta = registry.get_module(req.module_id)
    if not meta:
        raise HTTPException(status_code=404, detail=f"Module '{req.module_id}' not found")

    module_dir = registry.get_module_dir(req.module_id)
    if not module_dir or not module_dir.exists():
        raise HTTPException(status_code=404, detail=f"Module directory for '{req.module_id}' not found")

    try:
        module_cls = load_module_class(module_dir)
        if hasattr(module_cls, "meta") and module_cls.meta.options:
            meta = module_cls.meta
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load module class: {e}")

    is_valid, errors = validate_options(meta, req.options)
    if not is_valid:
        raise HTTPException(status_code=422, detail=errors)

    run_id = str(uuid.uuid4())

    try:
        run_record = ModuleRun(
            target_id=target_id,
            module_id=req.module_id,
            status="pending",
            started_at=datetime.utcnow(),
        )
        db.add(run_record)
        db.commit()
    except Exception:
        db.rollback()

    run_manager.start_run(
        run_id=run_id,
        module_class=module_cls,
        options=req.options or {},
        target=target.ip_address,
    )

    return {
        "run_id": run_id,
        "target_id": target_id,
        "module_id": req.module_id,
        "status": "started",
    }


