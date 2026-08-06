"""
Module execution routes (POST /api/targets/{id}/run).
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from api.db.session import get_db

router = APIRouter()


@router.post("/targets/{target_id}/run")
def run_module(target_id: int, module_id: str, options: dict = None, db: Session = Depends(get_db)):
    return {
        "run_id": "run-12345",
        "target_id": target_id,
        "module_id": module_id,
        "status": "started",
    }
