"""
Module execution routes (POST /api/targets/{id}/run).
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.models import ModuleRun, Target
from api.db.session import SessionLocal, get_db
from core.execution import ExecutionContext
from core.registry import ModuleRegistry, load_module_class, validate_options

router = APIRouter()

MODULES_DIR = Path(__file__).resolve().parent.parent.parent / "modules"


class RunRequest(BaseModel):
    module_id: str
    options: Optional[Dict[str, Any]] = None


def _execute_module_background(
    run_db_id: int,
    module_id: str,
    target_ip: str,
    options: Dict[str, Any],
    modules_dir: Path,
):
    """Background task to execute a module instance and persist completion results."""
    db = SessionLocal()
    logs: List[str] = []

    def emit_callback(payload: dict):
        msg = payload.get("message", "")
        event_type = payload.get("event_type", "log")
        logs.append(f"[{event_type.upper()}] {msg}")

    try:
        registry = ModuleRegistry(modules_dir)
        registry.scan()
        module_dir = registry.get_module_dir(module_id)
        if not module_dir:
            module_dir = modules_dir / module_id.split(".")[-1]

        module_cls = load_module_class(module_dir)
        mod_instance = module_cls(options=options)

        ctx = ExecutionContext(
            run_id=str(run_db_id),
            target=target_ip,
            emit_callback=emit_callback,
        )

        can_run = mod_instance.check(ctx)
        if not can_run:
            run_record = db.query(ModuleRun).filter(ModuleRun.id == run_db_id).first()
            if run_record:
                run_record.status = "skipped"
                run_record.completed_at = datetime.utcnow()
                run_record.logs = "\n".join(logs)
                db.commit()
            return

        mod_instance.run(ctx)

        run_record = db.query(ModuleRun).filter(ModuleRun.id == run_db_id).first()
        if run_record:
            run_record.status = "completed"
            run_record.completed_at = datetime.utcnow()
            run_record.logs = "\n".join(logs)
            db.commit()
    except Exception as e:
        logs.append(f"[ERROR] Execution error: {e}")
        run_record = db.query(ModuleRun).filter(ModuleRun.id == run_db_id).first()
        if run_record:
            run_record.status = "failed"
            run_record.completed_at = datetime.utcnow()
            run_record.logs = "\n".join(logs)
            db.commit()
    finally:
        db.close()


@router.post("/targets/{target_id}/run")
def run_module(
    target_id: int,
    req: RunRequest,
    background_tasks: BackgroundTasks,
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

    # Prefer python module class metadata if available for full ModuleOption definitions
    module_dir = registry.get_module_dir(req.module_id)
    if module_dir and module_dir.exists():
        try:
            module_cls = load_module_class(module_dir)
            if hasattr(module_cls, "meta") and module_cls.meta.options:
                meta = module_cls.meta
        except Exception:
            pass

    is_valid, errors = validate_options(meta, req.options)
    if not is_valid:
        raise HTTPException(status_code=422, detail=errors)

    run_record = ModuleRun(
        target_id=target_id,
        module_id=req.module_id,
        status="pending",
        started_at=datetime.utcnow(),
    )
    db.add(run_record)
    db.commit()
    db.refresh(run_record)

    run_id_str = str(run_record.id)

    background_tasks.add_task(
        _execute_module_background,
        run_db_id=run_record.id,
        module_id=req.module_id,
        target_ip=target.ip_address,
        options=req.options or {},
        modules_dir=MODULES_DIR,
    )

    return {
        "run_id": run_id_str,
        "target_id": target_id,
        "module_id": req.module_id,
        "status": "started",
    }

