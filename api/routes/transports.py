"""
GET /api/transports — list available transport plugins loaded at startup.
This is what the operator sees when choosing a transport for POST /api/sessions/.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from core.transport_registry import transport_registry

router = APIRouter()


@router.get("/")
def list_available_transports():
    transports = transport_registry.list_transports()
    return {
        "transports": [
            {
                "id": t.id,
                "name": t.name,
                "version": t.version,
                "description": t.description,
                "author": t.author,
            }
            for t in transports
        ],
        "count": len(transports),
    }


@router.get("/{transport_id}")
def get_transport_detail(transport_id: str):
    cls = transport_registry.get_transport(transport_id)
    if not cls:
        raise HTTPException(status_code=404, detail=f"Transport '{transport_id}' not found")
    t = cls.meta
    return {
        "id": t.id,
        "name": t.name,
        "version": t.version,
        "description": t.description,
        "author": t.author,
    }
