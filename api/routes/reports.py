"""
Reports API routes (GET /api/projects/{id}/report).
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from api.db.session import get_db

router = APIRouter()


@router.get("/{project_id}/report")
def generate_report(project_id: int, format: str = "html", db: Session = Depends(get_db)):
    return {"project_id": project_id, "format": format, "status": "generated"}
