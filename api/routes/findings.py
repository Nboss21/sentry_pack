"""
Findings API routes (GET /api/targets/{id}/findings).
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from api.db.session import get_db

router = APIRouter()


@router.get("/targets/{target_id}/findings")
def get_findings(target_id: int, db: Session = Depends(get_db)):
    return {"target_id": target_id, "findings": []}
