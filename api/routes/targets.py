"""
Target CRUD, status, and recommendations API routes.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.models import Project, Target
from api.db.session import get_db
from core.recommendation import recommendation_engine

router = APIRouter()


class TargetCreate(BaseModel):
    """Data required to create a target."""

    project_id: int
    name: str
    ip_address: str


class TargetUpdate(BaseModel):
    """Data that can be changed on a target."""

    project_id: int | None = None
    name: str | None = None
    ip_address: str | None = None
    status: str | None = None


def target_to_dict(target: Target) -> dict:
    """Convert a Target database object to an API response."""
    return {
        "id": target.id,
        "project_id": target.project_id,
        "name": target.name,
        "ip_address": target.ip_address,
        "status": target.status,
        "created_at": (
            target.created_at.isoformat()
            if target.created_at
            else None
        ),
    }


@router.get("/")
def list_targets(db: Session = Depends(get_db)):
    """Return all targets."""
    targets = db.query(Target).order_by(Target.id).all()

    return {
        "targets": [
            target_to_dict(target)
            for target in targets
        ]
    }


@router.post("/", status_code=201)
def create_target(
    target_data: TargetCreate,
    db: Session = Depends(get_db),
):
    """Create a new target belonging to an existing project."""

    project = (
        db.query(Project)
        .filter(Project.id == target_data.project_id)
        .first()
    )

    if project is None:
        raise HTTPException(
            status_code=404,
            detail=f"Project {target_data.project_id} not found",
        )

    target = Target(
        project_id=target_data.project_id,
        name=target_data.name,
        ip_address=target_data.ip_address,
        status="idle",
    )

    db.add(target)
    db.commit()
    db.refresh(target)

    return target_to_dict(target)


@router.get("/{target_id}")
def get_target(
    target_id: int,
    db: Session = Depends(get_db),
):
    """Return one target."""

    target = (
        db.query(Target)
        .filter(Target.id == target_id)
        .first()
    )

    if target is None:
        raise HTTPException(
            status_code=404,
            detail=f"Target {target_id} not found",
        )

    return target_to_dict(target)


@router.put("/{target_id}")
def update_target(
    target_id: int,
    target_data: TargetUpdate,
    db: Session = Depends(get_db),
):
    """Update an existing target."""

    target = (
        db.query(Target)
        .filter(Target.id == target_id)
        .first()
    )

    if target is None:
        raise HTTPException(
            status_code=404,
            detail=f"Target {target_id} not found",
        )

    if target_data.project_id is not None:
        project = (
            db.query(Project)
            .filter(Project.id == target_data.project_id)
            .first()
        )

        if project is None:
            raise HTTPException(
                status_code=404,
                detail=f"Project {target_data.project_id} not found",
            )

        target.project_id = target_data.project_id

    if target_data.name is not None:
        target.name = target_data.name

    if target_data.ip_address is not None:
        target.ip_address = target_data.ip_address

    if target_data.status is not None:
        target.status = target_data.status

    db.commit()
    db.refresh(target)

    return target_to_dict(target)


@router.delete("/{target_id}")
def delete_target(
    target_id: int,
    db: Session = Depends(get_db),
):
    """Delete an existing target."""

    target = (
        db.query(Target)
        .filter(Target.id == target_id)
        .first()
    )

    if target is None:
        raise HTTPException(
            status_code=404,
            detail=f"Target {target_id} not found",
        )

    db.delete(target)
    db.commit()

    return {
        "id": target_id,
        "message": f"Target {target_id} deleted",
    }


@router.get("/{target_id}/recommendations")
def get_target_recommendations(
    target_id: int,
    db: Session = Depends(get_db),
):
    """Return recommendations for a target."""

    target = (
        db.query(Target)
        .filter(Target.id == target_id)
        .first()
    )

    if target is None:
        raise HTTPException(
            status_code=404,
            detail=f"Target {target_id} not found",
        )

    recommendations = recommendation_engine.recommend_for_target(
        target_id,
        db,
    )

    return {
        "target_id": target_id,
        "recommendations": recommendations,
    }