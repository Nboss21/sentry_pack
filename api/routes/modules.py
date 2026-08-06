"""
Modules API routes (GET /api/modules).
"""

from fastapi import APIRouter
from pathlib import Path
from core.registry import ModuleRegistry

router = APIRouter()

MODULES_DIR = Path(__file__).resolve().parent.parent.parent / "modules"


@router.get("/")
def list_modules():
    registry = ModuleRegistry(MODULES_DIR)
    modules = registry.scan()
    return {"modules": [m.__dict__ for m in modules.values()]}
