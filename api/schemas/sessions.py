"""
Pydantic schemas for C2 session and task endpoints.
Request schemas: validate incoming data, reject bad input before it hits the DB.
Response schemas: ensure consistent shape on every response.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Session schemas
# ---------------------------------------------------------------------------

class SessionCreateRequest(BaseModel):
    target_id: Optional[int] = Field(None, description="Target this session is associated with")
    transport: str = Field(..., min_length=1, max_length=64, description="Transport plugin id, e.g. 'tcp', 'https'")
    session_key: Optional[str] = Field(None, min_length=1, max_length=255, description="Custom session key; auto-generated if omitted")

    @field_validator("transport")
    @classmethod
    def transport_no_spaces(cls, v: str) -> str:
        if " " in v:
            raise ValueError("transport id must not contain spaces")
        return v.lower().strip()


class SessionUpdateRequest(BaseModel):
    status: str = Field(..., description="New session status")

    @field_validator("status")
    @classmethod
    def valid_status(cls, v: str) -> str:
        allowed = {"active", "inactive", "terminated", "lost"}
        if v not in allowed:
            raise ValueError(f"status must be one of: {', '.join(sorted(allowed))}")
        return v


class SessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    session_key: str
    transport: str
    status: str
    target_id: Optional[int]
    last_seen: Optional[datetime]


class SessionListResponse(BaseModel):
    sessions: List[SessionResponse]
    total: int


# ---------------------------------------------------------------------------
# Task schemas
# ---------------------------------------------------------------------------

class TaskCreateRequest(BaseModel):
    command: str = Field(..., min_length=1, max_length=4096, description="Command to send to the agent")
    timeout_seconds: Optional[int] = Field(None, ge=1, le=3600, description="Optional per-task timeout override")

    @field_validator("command")
    @classmethod
    def command_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("command must not be blank or whitespace only")
        return v


class TaskResultUpdateRequest(BaseModel):
    status: str = Field(..., description="Task result status: completed or error")
    output: Optional[str] = Field(None, description="Output from the agent")

    @field_validator("status")
    @classmethod
    def valid_status(cls, v: str) -> str:
        allowed = {"completed", "error"}
        if v not in allowed:
            raise ValueError(f"status must be one of: {', '.join(sorted(allowed))}")
        return v


class TaskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    task_id: int
    session_id: int
    command: str
    status: str
    output: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]


class TaskListResponse(BaseModel):
    session_id: int
    tasks: List[TaskResponse]
    total: int


# ---------------------------------------------------------------------------
# Shared error response schema — used by ALL endpoints in this file
# ---------------------------------------------------------------------------

class ErrorResponse(BaseModel):
    error: str           # machine-readable error code, e.g. "not_found", "validation_error"
    message: str         # human-readable explanation
    detail: Optional[Any] = None  # validation detail list from Pydantic, if applicable
