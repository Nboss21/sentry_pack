"""
Project CRUD API routes.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from api.db.session import get_db

router = APIRouter()


@router.get("/")
def list_projects(db: Session = Depends(get_db)):
    return {"projects": []}


@router.post("/")
def create_project(name: str, description: str = "", db: Session = Depends(get_db)):
    return {"id": 1, "name": name, "description": description}
