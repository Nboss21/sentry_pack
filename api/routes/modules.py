"""
Modules API routes (GET /api/modules).
"""

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.db.models import ExploitModel, ExploitPackEntry
from api.db.session import get_db
from core.registry import ModuleRegistry

router = APIRouter()

MODULES_DIR = Path(__file__).resolve().parent.parent.parent / "modules"


@router.get("/")
def list_modules(db: Session = Depends(get_db)):
    """Return all available modules, including filesystem modules and database Exploit Pack modules."""
    registry = ModuleRegistry(MODULES_DIR)
    scanned = registry.scan()
    modules_list = [m.__dict__ for m in scanned.values()]
    existing_ids = {m["id"] for m in modules_list}

    # Add core exploit modules from ExploitModel if not already present
    try:
        core_exploits = db.query(ExploitModel).all()
        for ex in core_exploits:
            mod_id = ex.module_id or f"exploit.{ex.service_name}_{ex.id}"
            if mod_id not in existing_ids:
                existing_ids.add(mod_id)
                modules_list.append({
                    "id": mod_id,
                    "name": ex.title or f"Exploit: {ex.service_name}",
                    "category": f"exploit/{ex.service_name}",
                    "version": "1.0.0",
                    "author": ex.author or "SentryPack Security Team",
                    "description": ex.description or "",
                    "platform": ex.platform or "all",
                    "service": ex.service_name,
                    "cve": ex.cve_id,
                    "reliability": "Excellent" if (ex.cvss_score or 0) >= 9.0 else "Great",
                    "options": [
                        {
                            "name": "TARGET",
                            "description": "Target host IP address or hostname",
                            "option_type": "string",
                            "required": True,
                            "default": "",
                        },
                        {
                            "name": "PORT",
                            "description": "Target service port",
                            "option_type": "integer",
                            "required": False,
                            "default": ex.port or 80,
                        },
                    ],
                })
    except Exception:
        pass

    # Add Exploit Pack library modules
    try:
        ep_entries = db.query(ExploitPackEntry).all()
        for ep in ep_entries:
            mod_id = f"exploit.exploitpack_{ep.id}"
            if mod_id not in existing_ids:
                existing_ids.add(mod_id)
                svc = str(ep.service or "generic").strip().lower()
                if svc in ("none", "n/a", "null", ""):
                    svc = "generic"

                port_val = 80
                if ep.remote_port and ep.remote_port.isdigit():
                    port_val = int(ep.remote_port)

                modules_list.append({
                    "id": mod_id,
                    "name": ep.name_xml or ep.code_name or f"Exploit Pack #{ep.id}",
                    "category": f"exploit/{svc}",
                    "version": "1.0.0",
                    "author": ep.author or "Exploit Pack",
                    "description": ep.description or f"Exploit Pack module for {ep.service} ({ep.platform})",
                    "platform": ep.platform or "all",
                    "service": svc,
                    "reliability": "Great",
                    "options": [
                        {
                            "name": "TARGET",
                            "description": "Target host IP address or hostname",
                            "option_type": "string",
                            "required": True,
                            "default": "",
                        },
                        {
                            "name": "PORT",
                            "description": "Target service port",
                            "option_type": "integer",
                            "required": False,
                            "default": port_val,
                        },
                    ],
                })
    except Exception:
        pass

    return {"modules": modules_list}
