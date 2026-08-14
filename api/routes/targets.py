"""
Target CRUD, status, and recommendations API routes.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.db.models import Target
from api.db.session import get_db
from core.recommendation import recommendation_engine

router = APIRouter()


@router.get("/")
def list_targets(db: Session = Depends(get_db)):
    targets = db.query(Target).all()
    return {
        "targets": [
            {
                "id": t.id,
                "project_id": t.project_id,
                "name": t.name,
                "ip_address": t.ip_address,
                "status": t.status,
            }
            for t in targets
        ]
    }


@router.post("/")
def create_target(project_id: int, name: str, ip_address: str, db: Session = Depends(get_db)):
    target = Target(project_id=project_id, name=name, ip_address=ip_address, status="idle")
    db.add(target)
    db.commit()
    db.refresh(target)
    return {
        "id": target.id,
        "project_id": target.project_id,
        "name": target.name,
        "ip_address": target.ip_address,
        "status": target.status,
    }


@router.get("/{target_id}/recommendations")
def get_target_recommendations(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail=f"Target {target_id} not found")

    recommendations = recommendation_engine.recommend_for_target(target_id, db)
    return {
        "target_id": target_id,
        "recommendations": recommendations,
    }
