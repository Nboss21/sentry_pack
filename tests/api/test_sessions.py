"""
Tests for transport-aware C2 Session endpoints, task queue, session stream, and transport-agnostic enforcement.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from api.db.models import C2Session, Project, SessionTask, Target
from api.db.session import SessionLocal, init_db
from api.main import app
from core.session_manager import session_manager

client = TestClient(app)


def _setup_db():
    init_db()
    db = SessionLocal()
    return db


@pytest.mark.parametrize(
    "transport_str",
    ["tcp", "https", "dns", "icmp", "custom_proto", "ws", "kcp", "random_transport_123"],
)
def test_create_session_supports_arbitrary_transports(transport_str: str):
    init_db()
    payload = {"transport": transport_str}
    response = client.post("/api/sessions/", json=payload)
    assert response.status_code == 201
    data = response.json()

    assert "id" in data
    assert "session_key" in data
    assert data["transport"] == transport_str
    assert data["status"] == "active"

    # Verify session is registered in session_manager
    state = session_manager.get_session(data["session_key"])
    assert state is not None
    assert state.transport == transport_str


def test_create_session_with_custom_key_and_target():
    db = _setup_db()
    project = Project(name="C2 Test Project", description="C2 testing")
    db.add(project)
    db.commit()
    db.refresh(project)

    target = Target(project_id=project.id, name="C2 Target", ip_address="10.0.0.99")
    db.add(target)
    db.commit()
    db.refresh(target)
    target_id = target.id
    db.close()

    import uuid
    custom_key = f"agent-custom-key-{uuid.uuid4().hex[:8]}"
    payload = {
        "transport": "dns",
        "target_id": target_id,
        "session_key": custom_key,
    }
    response = client.post("/api/sessions/", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["session_key"] == custom_key
    assert data["target_id"] == target_id
    assert data["transport"] == "dns"


def test_list_sessions():
    init_db()
    # Create a couple sessions
    client.post("/api/sessions/", json={"transport": "proto_a"})
    client.post("/api/sessions/", json={"transport": "proto_b"})

    response = client.get("/api/sessions/")
    assert response.status_code == 200
    data = response.json()
    assert "sessions" in data
    assert len(data["sessions"]) >= 2
    transports = [s["transport"] for s in data["sessions"]]
    assert "proto_a" in transports
    assert "proto_b" in transports


def test_queue_and_list_tasks_success():
    init_db()
    create_res = client.post("/api/sessions/", json={"transport": "tcp"})
    assert create_res.status_code == 201
    session_id = create_res.json()["id"]

    # Queue task
    task_res = client.post(
        f"/api/sessions/{session_id}/tasks",
        json={"command": "whoami /all"},
    )
    assert task_res.status_code == 202
    task_data = task_res.json()
    assert task_data["status"] == "queued"
    assert task_data["command"] == "whoami /all"
    assert task_data["session_id"] == session_id
    assert "task_id" in task_data

    # List tasks
    list_res = client.get(f"/api/sessions/{session_id}/tasks")
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert "tasks" in list_data
    assert len(list_data["tasks"]) == 1
    assert list_data["tasks"][0]["command"] == "whoami /all"
    assert list_data["tasks"][0]["status"] == "queued"


def test_queue_task_nonexistent_session_returns_404():
    response = client.post(
        "/api/sessions/99999/tasks",
        json={"command": "id"},
    )
    assert response.status_code == 404
    assert "not found" in response.json()["message"].lower()


def test_list_tasks_nonexistent_session_returns_404():
    response = client.get("/api/sessions/99999/tasks")
    assert response.status_code == 404
    assert "not found" in response.json()["message"].lower()


def test_no_hardcoded_tls_or_transport_in_api_codebase():
    """Verify that no file under api/ contains hardcoded TLS strings or references."""
    api_dir = Path(__file__).resolve().parent.parent.parent / "api"
    assert api_dir.exists() and api_dir.is_dir()

    forbidden_patterns = ['"tls"', "'tls'", "tls_port", "tls_cert"]

    violations = []
    for py_file in api_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for line_no, line in enumerate(content.splitlines(), start=1):
            lower_line = line.lower()
            for pattern in forbidden_patterns:
                if pattern in lower_line:
                    violations.append(f"{py_file.name}:{line_no} -> {line.strip()}")

    assert not violations, f"Forbidden TLS references found under api/: {violations}"


@pytest.mark.asyncio
async def test_session_manager_and_events_multi_transport():
    """
    Assert that events emitted from multiple distinct transports are received by subscribers,
    and verify no event contains transport-specific fields or 'tls' string.
    """
    init_db()

    # Session 1: custom_proto_1
    res1 = client.post("/api/sessions/", json={"transport": "custom_proto_1"})
    assert res1.status_code == 201
    s1_key = res1.json()["session_key"]

    # Session 2: custom_proto_2
    res2 = client.post("/api/sessions/", json={"transport": "custom_proto_2"})
    assert res2.status_code == 201
    s2_key = res2.json()["session_key"]

    # Emit buffered event to s1 before subscribing
    await session_manager.emit_event(s1_key, {"type": "output", "data": "initial output from proto 1"})

    # Subscribe to session 1
    q1, snapshot1 = session_manager.subscribe(s1_key)
    assert q1 is not None
    assert len(snapshot1) == 1
    assert snapshot1[0]["data"] == "initial output from proto 1"
    assert "tls" not in str(snapshot1[0]).lower()

    # Emit live event to session 1
    await session_manager.emit_event(s1_key, {"type": "log", "data": "live log proto 1"})
    live_event1 = await q1.get()
    assert live_event1["type"] == "log"
    assert live_event1["data"] == "live log proto 1"
    assert "tls" not in str(live_event1).lower()

    # Subscribe to session 2
    q2, snapshot2 = session_manager.subscribe(s2_key)
    assert q2 is not None
    assert snapshot2 == []

    await session_manager.emit_event(s2_key, {"type": "exec", "data": "executing on proto 2"})
    live_event2 = await q2.get()
    assert live_event2["type"] == "exec"
    assert live_event2["data"] == "executing on proto 2"
    assert "tls" not in str(live_event2).lower()

    session_manager.unsubscribe(s1_key, q1)
    session_manager.unsubscribe(s2_key, q2)
