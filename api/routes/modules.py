"""
Modules API routes (GET /api/modules).
"""

from typing import Any, List, Optional
from pathlib import Path
from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict
from core.registry import ModuleRegistry

router = APIRouter()

MODULES_DIR = Path(__file__).resolve().parent.parent.parent / "modules"


class ModuleOptionOut(BaseModel):
    name: str
    description: str
    option_type: str
    required: bool = True
    default: Optional[Any] = None
    choices: Optional[List[str]] = None

    model_config = ConfigDict(from_attributes=True)


class ModuleMetaOut(BaseModel):
    id: str
    name: str
    description: str
    author: str
    version: str
    category: str
    options: List[ModuleOptionOut] = []

    model_config = ConfigDict(from_attributes=True)


class ModulesResponse(BaseModel):
    modules: List[ModuleMetaOut]


@router.get("/", response_model=ModulesResponse)
def list_modules():
    registry = ModuleRegistry(MODULES_DIR)
    registry.scan()
    modules = registry.list_all()
    return {"modules": modules}


