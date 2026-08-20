"""
Verification tests for C2 WebSocket channel.

Criteria:
  ✓ C2 WebSocket streams session status/results
  ✓ Scoped to project
  ✓ Unauthorized clients cannot subscribe
"""

import asyncio
import secrets
import pytest
from fastapi.testclient import TestClient

from api.db.models import C2Session, Project, Target
from api.db.session import SessionLocal, init_db
from api.main import app
from core.c2_channel import C2Channel, c2_channel

client = TestClient(app)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db():
    init_db()
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def project_with_token(db):
    token = secrets.token_urlsafe(16)
    project = Project(name=f"TestProject-{secrets.token_hex(4)}", auth_token=token)
    db.add(project)
    db.commit()
    db.refresh(project)
    yield project, token
    try:
        db.delete(project)
        db.commit()
    except Exception:
        pass


@pytest.fixture
def session_in_project(db, project_with_token):
    project, token = project_with_token
    target = Target(project_id=project.id, name="t1", ip_address="10.0.0.1")
    db.add(target)
    db.commit()
    db.refresh(target)
    sess_key = f"test-key-{secrets.token_hex(4)}"
    c2 = C2Session(
        target_id=target.id,
        session_key=sess_key,
        transport="tcp",
        status="active",
    )
    db.add(c2)
    db.commit()
    db.refresh(c2)
    yield c2, project, token
    try:
        db.delete(c2)
        db.delete(target)
        db.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 1. Unauthorized clients cannot subscribe
# ---------------------------------------------------------------------------

def test_ws_rejects_missing_token(session_in_project):
    c2, project, _ = session_in_project
    with client.websocket_connect(
        f"/ws/projects/{project.id}/sessions/{c2.session_key}"
        # no ?token=
    ) as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert msg["code"] == "unauthorized"


def test_ws_rejects_wrong_token(session_in_project):
    c2, project, _ = session_in_project
    with client.websocket_connect(
        f"/ws/projects/{project.id}/sessions/{c2.session_key}?token=wrongtoken"
    ) as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert msg["code"] == "unauthorized"


def test_ws_rejects_session_not_in_project(session_in_project, db):
    c2, project, token = session_in_project
    # Create a second project
    other_project = Project(name="OtherProject", auth_token=token)
    db.add(other_project)
    db.commit()
    # Try to subscribe to c2 session using other_project's id
    with client.websocket_connect(
        f"/ws/projects/{other_project.id}/sessions/{c2.session_key}?token={token}"
    ) as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert msg["code"] == "unauthorized"
    db.delete(other_project)
    db.commit()


# ---------------------------------------------------------------------------
# 2. Authorized client receives subscribed confirmation
# ---------------------------------------------------------------------------

def test_ws_authorized_client_receives_subscribed(session_in_project):
    c2, project, token = session_in_project
    with client.websocket_connect(
        f"/ws/projects/{project.id}/sessions/{c2.session_key}?token={token}"
    ) as ws:
        msg = ws.receive_json()
        assert msg["type"] == "subscribed"
        assert msg["project_id"] == project.id
        assert msg["session_key"] == c2.session_key


# ---------------------------------------------------------------------------
# 3. Streams session status and results (unit level via c2_channel directly)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_c2_channel_streams_events_to_subscriber():
    channel = C2Channel()
    project_id = 99
    session_key = "stream-test"

    # Subscribe
    queue, snapshot = channel.subscribe(project_id, session_key)
    assert snapshot == []

    # Emit a task result event
    await channel.emit(project_id, session_key, {
        "type": "task_result",
        "task_id": 1,
        "output": "root",
        "status": "completed",
    })

    event = await asyncio.wait_for(queue.get(), timeout=1.0)
    assert event["type"] == "task_result"
    assert event["output"] == "root"

    channel.unsubscribe(project_id, session_key, queue)


@pytest.mark.asyncio
async def test_c2_channel_scoped_to_project():
    """Events emitted for project A must NOT reach subscribers of project B."""
    channel = C2Channel()
    session_key = "shared-key"

    queue_a, _ = channel.subscribe(project_id=1, session_key=session_key)
    queue_b, _ = channel.subscribe(project_id=2, session_key=session_key)

    await channel.emit(project_id=1, session_key=session_key, event={
        "type": "session_output", "data": "project-A-only"
    })

    # Project A subscriber receives it
    event = await asyncio.wait_for(queue_a.get(), timeout=1.0)
    assert event["data"] == "project-A-only"

    # Project B subscriber must NOT receive it
    assert queue_b.empty(), "Project B received an event scoped to Project A — scope leak!"

    channel.unsubscribe(1, session_key, queue_a)
    channel.unsubscribe(2, session_key, queue_b)


@pytest.mark.asyncio
async def test_late_joiner_receives_buffered_events():
    channel = C2Channel()
    project_id = 42
    session_key = "late-joiner"

    # Emit before anyone subscribes
    await channel.emit(project_id, session_key, {"type": "session_output", "data": "early-event"})

    # Late subscriber should get the buffered event as snapshot
    queue, snapshot = channel.subscribe(project_id, session_key)
    assert any(e["data"] == "early-event" for e in snapshot)
    channel.unsubscribe(project_id, session_key, queue)


@pytest.mark.asyncio
async def test_buffer_caps_at_500_events():
    channel = C2Channel()
    project_id = 7
    session_key = "cap-test"

    for i in range(600):
        await channel.emit(project_id, session_key, {"type": "log", "seq": i})

    _, snapshot = channel.subscribe(project_id, session_key)
    assert len(snapshot) <= 500


# ---------------------------------------------------------------------------
# 4. Auth token generation endpoint
# ---------------------------------------------------------------------------

def test_generate_auth_token_for_project(db):
    project = Project(name="TokenProject")
    db.add(project)
    db.commit()
    db.refresh(project)

    resp = client.post(f"/api/projects/{project.id}/auth-token")
    assert resp.status_code == 201
    body = resp.json()
    assert "auth_token" in body
    assert "ws_url" in body
    assert len(body["auth_token"]) > 20

    db.delete(project)
    db.commit()
