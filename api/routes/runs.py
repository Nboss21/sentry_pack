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
import logging
from pathlib import Path
from typing import Any, Dict, Optional
import uuid


from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.models import FindingModel, ModuleRun, Target
from api.db.session import get_db, SessionLocal
from core.registry import ModuleRegistry, load_module_class, validate_options
from core.run_manager import run_manager

logger = logging.getLogger("sentrypack.api.runs")
router = APIRouter()

MODULES_DIR = Path(__file__).resolve().parent.parent.parent / "modules"


class RunRequest(BaseModel):
    module_id: str
    options: Optional[Dict[str, Any]] = None


def _persist_run_results(run_id: str, target_id: Any, status: str, findings: list) -> None:
    """Callback invoked by RunManager after a run finishes.

    Persists all findings to the DB and updates the target's status column.
    This function must never raise — all exceptions are caught and logged.
    """
    db = SessionLocal()
    try:
        try:
            for finding in findings:
                db.add(
                    FindingModel(
                        target_id=target_id,
                        title=finding.title,
                        severity=finding.severity,
                        description=finding.description,
                        cve=finding.cve,
                        cpe=finding.cpe,
                        remediation=finding.remediation,
                        evidence=finding.evidence,
                    )
                )

            target = db.query(Target).filter(Target.id == target_id).first()
            if target is not None:
                if status == "completed":
                    target.status = "scanned"
                elif status in ("failed", "timeout"):
                    target.status = "error"
                # Otherwise leave status unchanged

            db.commit()
        except Exception:
            db.rollback()
            logger.exception(
                "_persist_run_results: DB error for run_id=%s target_id=%s",
                run_id,
                target_id,
            )
    finally:
        db.close()


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
        target_id=target_id,
        on_finish=_persist_run_results,
    )

    return {
        "run_id": run_id,
        "target_id": target_id,
        "module_id": req.module_id,
        "status": "started",
    }


