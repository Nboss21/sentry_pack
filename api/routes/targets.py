"""
Target CRUD and status API routes.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from api.db.session import get_db

router = APIRouter()


@router.get("/")
def list_targets(db: Session = Depends(get_db)):
    return {"targets": []}


@router.post("/")
def create_target(project_id: int, name: str, ip_address: str, db: Session = Depends(get_db)):
    return {"id": 1, "project_id": project_id, "name": name, "ip_address": ip_address, "status": "idle"}
