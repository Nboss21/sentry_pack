"""
C2 Session CRUD and task queue API routes.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from api.db.session import get_db

router = APIRouter()


@router.get("/")
def list_sessions(db: Session = Depends(get_db)):
    return {"sessions": []}


@router.post("/{session_id}/tasks")
def queue_task(session_id: str, command: str, db: Session = Depends(get_db)):
    return {"session_id": session_id, "task_id": "task-001", "command": command, "status": "queued"}
