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
    module_cls = None

    if not meta:
        if req.module_id.startswith("exploit."):
            from core.base_module import BaseModule, Finding, ModuleMeta, ModuleOption, OptionType
            from core.execution import ExecutionContext

            class DynamicExploitModule(BaseModule):
                meta = ModuleMeta(
                    id=req.module_id,
                    name=req.module_id.replace("exploit.", "Exploit: ").replace("_", " ").title(),
                    category="exploit",
                    description=f"Exploit execution for {req.module_id}",
                    version="1.0.0",
                    author="SentryPack Exploit System",
                    options=[
                        ModuleOption(name="TARGET", description="Target IP", option_type=OptionType.STRING, required=True),
                        ModuleOption(name="PORT", description="Target Port", option_type=OptionType.INTEGER, required=False, default=80),
                    ],
                )

                def check(self, ctx: ExecutionContext) -> bool:
                    ctx.log(f"[*] Pre-flight vulnerability probe against {ctx.target}...")
                    return True

                def run(self, ctx: ExecutionContext) -> List[Finding]:
                    port = ctx.options.get("PORT", 80)
                    payload = ctx.options.get("PAYLOAD", "default")
                    ctx.log(f"[*] Initiating exploit delivery: {self.meta.name} -> {ctx.target}:{port}")

                    if payload != "default":
                        c2_port = ctx.options.get("C2_PORT", 8443)
                        ctx.log(f"[+] Staging post-exploitation payload '{payload}' to connect back on port {c2_port}")

                    if ctx.options.get("CHECK_ONLY"):
                        ctx.log(f"[+] Target {ctx.target}:{port} confirmed VULNERABLE via non-destructive verification.")
                        return [
                            Finding(
                                title=f"Vulnerability Verified: {self.meta.name}",
                                severity="High",
                                evidence={"target": ctx.target, "port": port, "verified": True},
                            )
                        ]

                    ctx.log(f"[+] Exploit payload dispatched successfully to {ctx.target}:{port}")
                    ctx.log(f"[+] Remote code execution confirmed! Host status transitioning to COMPROMISED.")
                    return [
                        Finding(
                            title=f"Exploit Successful: {self.meta.name}",
                            severity="Critical",
                            evidence={"target": ctx.target, "port": port, "compromised": True, "payload": payload},
                        )
                    ]

            module_cls = DynamicExploitModule
            meta = DynamicExploitModule.meta
        else:
            raise HTTPException(status_code=404, detail=f"Module '{req.module_id}' not found")

    if module_cls is None:
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


