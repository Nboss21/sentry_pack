"""
FastAPI Route Handlers for Infrastructure Modules Management.

Exposes REST endpoints for querying, configuring, enabling, disabling, and
associating infrastructure modules with projects and transports.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.infra_registry import infra_registry

logger = logging.getLogger("sentrypack.api.infra_modules")
router = APIRouter()


class ConfigureRequest(BaseModel):
    """Request payload for configuring an infrastructure module."""
    config: Dict[str, Any] = Field(default_factory=dict, description="Configuration options dictionary")


class AssociateRequest(BaseModel):
    """Request payload for associating an infrastructure module with a project or transport."""
    project_id: Optional[int] = Field(None, description="Project ID to associate with")
    transport_id: Optional[str] = Field(None, description="Transport ID slug to associate with")


@router.get("/")
def list_infrastructure_modules() -> Dict[str, Any]:
    """
    List all registered infrastructure modules and their current statuses.
    """
    modules = infra_registry.list_modules()
    return {
        "infra_modules": modules,
        "count": len(modules),
    }


@router.get("/{module_id}")
def get_infrastructure_module(module_id: str) -> Dict[str, Any]:
    """
    Retrieve full descriptor, current status, and associations for a specific infrastructure module.
    """
    cls = infra_registry.get_module(module_id)
    if not cls:
        raise HTTPException(
            status_code=404,
            detail=f"Infrastructure module '{module_id}' not found",
        )

    meta = cls.meta
    status = infra_registry.get_status(module_id)
    associations = infra_registry.get_associations(module_id)

    return {
        "id": meta.id,
        "name": meta.name,
        "version": meta.version,
        "description": meta.description,
        "author": meta.author,
        "category": meta.category,
        "capabilities": list(meta.capabilities),
        "status": status.value if status else "disabled",
        "associations": associations,
    }


@router.post("/{module_id}/enable")
def enable_infrastructure_module(module_id: str) -> Dict[str, Any]:
    """
    Activate an infrastructure module.
    """
    cls = infra_registry.get_module(module_id)
    if not cls:
        raise HTTPException(
            status_code=404,
            detail=f"Infrastructure module '{module_id}' not found",
        )

    infra_registry.enable_module(module_id)
    status = infra_registry.get_status(module_id)

    return {
        "module_id": module_id,
        "status": status.value if status else "error",
    }


@router.post("/{module_id}/disable")
def disable_infrastructure_module(module_id: str) -> Dict[str, Any]:
    """
    Deactivate an infrastructure module cleanly.
    """
    cls = infra_registry.get_module(module_id)
    if not cls:
        raise HTTPException(
            status_code=404,
            detail=f"Infrastructure module '{module_id}' not found",
        )

    infra_registry.disable_module(module_id)
    status = infra_registry.get_status(module_id)

    return {
        "module_id": module_id,
        "status": status.value if status else "disabled",
    }


@router.post("/{module_id}/configure")
def configure_infrastructure_module(
    module_id: str,
    payload: ConfigureRequest,
) -> Dict[str, Any]:
    """
    Update runtime configuration for an infrastructure module.
    """
    cls = infra_registry.get_module(module_id)
    if not cls:
        raise HTTPException(
            status_code=404,
            detail=f"Infrastructure module '{module_id}' not found",
        )

    configured = infra_registry.configure_module(module_id, payload.config)
    return {
        "module_id": module_id,
        "configured": configured,
    }


@router.post("/{module_id}/associate")
def associate_infrastructure_module(
    module_id: str,
    payload: AssociateRequest,
) -> Dict[str, Any]:
    """
    Associate an infrastructure module with a project and/or transport channel.
    """
    cls = infra_registry.get_module(module_id)
    if not cls:
        raise HTTPException(
            status_code=404,
            detail=f"Infrastructure module '{module_id}' not found",
        )

    if payload.project_id is None and (payload.transport_id is None or not payload.transport_id.strip()):
        raise HTTPException(
            status_code=400,
            detail="At least one of project_id or transport_id must be provided",
        )

    infra_registry.associate(
        module_id=module_id,
        project_id=payload.project_id,
        transport_id=payload.transport_id,
    )
    associations = infra_registry.get_associations(module_id)

    return {
        "module_id": module_id,
        "associations": associations,
    }


@router.get("/{module_id}/associations")
def get_infrastructure_module_associations(module_id: str) -> Dict[str, Any]:
    """
    List all project and transport associations for an infrastructure module.
    """
    cls = infra_registry.get_module(module_id)
    if not cls:
        raise HTTPException(
            status_code=404,
            detail=f"Infrastructure module '{module_id}' not found",
        )

    associations = infra_registry.get_associations(module_id)
    return {
        "module_id": module_id,
        "associations": associations,
    }
