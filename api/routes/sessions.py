"""
C2 Session CRUD and task queue API routes.

Full REST endpoints for session lifecycle and task submission:
  POST   /api/sessions/                       — create session
  GET    /api/sessions/                       — list sessions (filterable)
  GET    /api/sessions/{id}                   — get one session
  PATCH  /api/sessions/{id}                   — update status
  DELETE /api/sessions/{id}                   — delete session

  POST   /api/sessions/{id}/tasks             — enqueue task
  GET    /api/sessions/{id}/tasks             — list tasks
  GET    /api/sessions/{id}/tasks/{task_id}   — get one task
  PATCH  /api/sessions/{id}/tasks/{task_id}   — update task result
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from api.db.models import C2Session, SessionTask, Target
from api.db.session import get_db
from api.schemas.sessions import (
    SessionCreateRequest,
    SessionListResponse,
    SessionResponse,
    SessionUpdateRequest,
    TaskCreateRequest,
    TaskListResponse,
    TaskResponse,
    TaskResultUpdateRequest,
)
from core.session_manager import session_manager

logger = logging.getLogger("sentrypack.api.sessions")
router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _session_to_response(sess: C2Session) -> SessionResponse:
    return SessionResponse(
        id=sess.id,
        session_key=sess.session_key,
        transport=sess.transport,
        status=sess.status,
        target_id=sess.target_id,
        last_seen=sess.last_seen,
    )


def _task_to_response(task: SessionTask) -> TaskResponse:
    return TaskResponse(
        task_id=task.id,
        session_id=task.session_id,
        command=task.command,
        status=task.status,
        output=task.output,
        created_at=task.created_at,
        completed_at=task.completed_at,
    )


def _not_found(resource: str, id_val) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={"error": "not_found", "message": f"{resource} {id_val} not found", "detail": None},
    )


def _conflict(message: str) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={"error": "conflict", "message": message, "detail": None},
    )


def _internal_error(message: str = "An unexpected error occurred") -> HTTPException:
    return HTTPException(
        status_code=500,
        detail={"error": "internal_error", "message": message, "detail": None},
    )


# ---------------------------------------------------------------------------
# Session CRUD
# ---------------------------------------------------------------------------

@router.post("/", status_code=201, response_model=SessionResponse)
def create_session(
    payload: SessionCreateRequest,
    db: Session = Depends(get_db),
) -> SessionResponse:
    """Create a new C2 session."""
    if payload.target_id is not None:
        target = db.query(Target).filter(Target.id == payload.target_id).first()
        if not target:
            raise _not_found("Target", payload.target_id)

    session_key = payload.session_key or f"sess-{uuid.uuid4().hex[:12]}"
    existing = db.query(C2Session).filter(C2Session.session_key == session_key).first()
    if existing is not None:
        raise _conflict(f"Session key '{session_key}' already exists")

    try:
        sess = C2Session(
            target_id=payload.target_id,
            session_key=session_key,
            transport=payload.transport,
            status="active",
        )
        db.add(sess)
        db.commit()
        db.refresh(sess)
    except Exception:
        db.rollback()
        logger.exception("DB error creating session")
        raise _internal_error()

    # Register in the in-memory event bus after successful DB commit
    session_manager.register_session(session_key=sess.session_key, transport=sess.transport)

    return _session_to_response(sess)


@router.get("/", response_model=SessionListResponse)
def list_sessions(
    status: Optional[str] = Query(None),
    transport: Optional[str] = Query(None),
    target_id: Optional[int] = Query(None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> SessionListResponse:
    """List all C2 sessions with optional filters."""
    q = db.query(C2Session)
    if status is not None:
        q = q.filter(C2Session.status == status)
    if transport is not None:
        q = q.filter(C2Session.transport == transport)
    if target_id is not None:
        q = q.filter(C2Session.target_id == target_id)

    total = q.count()
    sessions = q.order_by(C2Session.id).offset(offset).limit(limit).all()

    return SessionListResponse(
        sessions=[_session_to_response(s) for s in sessions],
        total=total,
    )


@router.get("/{session_id}", response_model=SessionResponse)
def get_session(
    session_id: int,
    db: Session = Depends(get_db),
) -> SessionResponse:
    """Get a single session by ID."""
    sess = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not sess:
        raise _not_found("Session", session_id)
    return _session_to_response(sess)


@router.patch("/{session_id}", response_model=SessionResponse)
def update_session(
    session_id: int,
    payload: SessionUpdateRequest,
    db: Session = Depends(get_db),
) -> SessionResponse:
    """Update session status."""
    sess = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not sess:
        raise _not_found("Session", session_id)

    try:
        sess.status = payload.status
        sess.last_seen = datetime.utcnow()
        db.commit()
        db.refresh(sess)
    except Exception:
        db.rollback()
        logger.exception("DB error updating session %s", session_id)
        raise _internal_error()

    # Emit status event if session is registered in the in-memory bus
    state = session_manager.get_session(sess.session_key)
    if state is not None:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            asyncio.run_coroutine_threadsafe(
                session_manager.emit_event(
                    sess.session_key,
                    {"type": "session_status", "status": payload.status},
                ),
                loop,
            )
        except Exception:
            logger.debug("No running event loop for session_manager emit on PATCH session")

    return _session_to_response(sess)


@router.delete("/{session_id}", status_code=204)
def delete_session(
    session_id: int,
    db: Session = Depends(get_db),
) -> Response:
    """Delete a session and all its tasks."""
    sess = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not sess:
        raise _not_found("Session", session_id)

    try:
        db.delete(sess)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("DB error deleting session %s", session_id)
        raise _internal_error()

    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Task endpoints
# ---------------------------------------------------------------------------

@router.post("/{session_id}/tasks", status_code=202, response_model=TaskResponse)
def queue_task(
    session_id: int,
    payload: TaskCreateRequest,
    db: Session = Depends(get_db),
) -> TaskResponse:
    """Enqueue a task for a session."""
    sess = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not sess:
        raise _not_found("Session", session_id)

    if sess.status == "terminated":
        raise _conflict("cannot enqueue task for terminated session")

    try:
        task = SessionTask(
            session_id=sess.id,
            command=payload.command,
            status="queued",
        )
        db.add(task)
        db.commit()
        db.refresh(task)
    except Exception:
        db.rollback()
        logger.exception("DB error creating task for session %s", session_id)
        raise _internal_error()

    # Emit task_queued event after successful DB commit
    state = session_manager.get_session(sess.session_key)
    if state is not None:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            asyncio.run_coroutine_threadsafe(
                session_manager.emit_event(
                    sess.session_key,
                    {"type": "task_queued", "task_id": task.id, "command": payload.command},
                ),
                loop,
            )
        except Exception:
            logger.debug("No running event loop for session_manager emit on task queue")

    return _task_to_response(task)


@router.get("/{session_id}/tasks", response_model=TaskListResponse)
def list_tasks(
    session_id: int,
    status: Optional[str] = Query(None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> TaskListResponse:
    """List tasks for a session."""
    sess = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not sess:
        raise _not_found("Session", session_id)

    q = db.query(SessionTask).filter(SessionTask.session_id == session_id)
    if status is not None:
        q = q.filter(SessionTask.status == status)

    total = q.count()
    tasks = q.order_by(SessionTask.id).offset(offset).limit(limit).all()

    return TaskListResponse(
        session_id=session_id,
        tasks=[_task_to_response(t) for t in tasks],
        total=total,
    )


@router.get("/{session_id}/tasks/{task_id}", response_model=TaskResponse)
def get_task(
    session_id: int,
    task_id: int,
    db: Session = Depends(get_db),
) -> TaskResponse:
    """Get a specific task."""
    sess = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not sess:
        raise _not_found("Session", session_id)

    task = db.query(SessionTask).filter(
        SessionTask.id == task_id,
        SessionTask.session_id == session_id,
    ).first()
    if not task:
        raise _not_found("Task", task_id)

    return _task_to_response(task)


@router.patch("/{session_id}/tasks/{task_id}", response_model=TaskResponse)
def update_task_result(
    session_id: int,
    task_id: int,
    payload: TaskResultUpdateRequest,
    db: Session = Depends(get_db),
) -> TaskResponse:
    """Update task result (called by transport plugin when agent responds)."""
    sess = db.query(C2Session).filter(C2Session.id == session_id).first()
    if not sess:
        raise _not_found("Session", session_id)

    task = db.query(SessionTask).filter(
        SessionTask.id == task_id,
        SessionTask.session_id == session_id,
    ).first()
    if not task:
        raise _not_found("Task", task_id)

    try:
        task.status = payload.status
        task.output = payload.output
        task.completed_at = datetime.utcnow()
        db.commit()
        db.refresh(task)
    except Exception:
        db.rollback()
        logger.exception("DB error updating task %s for session %s", task_id, session_id)
        raise _internal_error()

    # Emit task_result event after successful DB commit
    state = session_manager.get_session(sess.session_key)
    if state is not None:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            asyncio.run_coroutine_threadsafe(
                session_manager.emit_event(
                    sess.session_key,
                    {
                        "type": "task_result",
                        "task_id": task_id,
                        "status": payload.status,
                        "output": payload.output,
                    },
                ),
                loop,
            )
        except Exception:
            logger.debug("No running event loop for session_manager emit on task result")

    return _task_to_response(task)
