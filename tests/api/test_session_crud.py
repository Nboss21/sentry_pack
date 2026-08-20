"""
Verification tests for session CRUD and task submission endpoints.

Criteria:
  ✓ Session CRUD endpoints work
  ✓ Task submission endpoint enqueues tasks
  ✓ Proper validation and error responses
"""
import uuid
import pytest
from fastapi.testclient import TestClient
from api.main import app
from api.db.session import SessionLocal, init_db
from api.db.models import Project, Target

client = TestClient(app)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def db():
    init_db()
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture(scope="module")
def target(db):
    project = Project(name="CRUDTestProject")
    db.add(project)
    db.commit()
    db.refresh(project)
    t = Target(project_id=project.id, name="target1", ip_address="10.0.0.99")
    db.add(t)
    db.commit()
    db.refresh(t)
    yield t
    db.delete(t)
    db.delete(project)
    db.commit()


# ---------------------------------------------------------------------------
# 1. Session CREATE
# ---------------------------------------------------------------------------

def test_create_session_returns_201(target):
    resp = client.post("/api/sessions/", json={"transport": "tcp", "target_id": target.id})
    assert resp.status_code == 201
    body = resp.json()
    assert body["transport"] == "tcp"
    assert body["status"] == "active"
    assert "session_key" in body
    assert "id" in body


def test_create_session_auto_generates_session_key():
    resp = client.post("/api/sessions/", json={"transport": "dns"})
    assert resp.status_code == 201
    assert len(resp.json()["session_key"]) > 0


def test_create_session_custom_key():
    custom_key = f"my-custom-key-{uuid.uuid4().hex[:8]}"
    resp = client.post("/api/sessions/", json={"transport": "https", "session_key": custom_key})
    assert resp.status_code == 201
    assert resp.json()["session_key"] == custom_key


def test_create_session_duplicate_key_returns_409():
    dup_key = f"dup-key-{uuid.uuid4().hex[:8]}"
    client.post("/api/sessions/", json={"transport": "tcp", "session_key": dup_key})
    resp = client.post("/api/sessions/", json={"transport": "tcp", "session_key": dup_key})
    assert resp.status_code == 409
    assert resp.json()["error"] == "conflict"


def test_create_session_invalid_target_returns_404():
    resp = client.post("/api/sessions/", json={"transport": "tcp", "target_id": 999999})
    assert resp.status_code == 404


def test_create_session_empty_transport_returns_422():
    resp = client.post("/api/sessions/", json={"transport": ""})
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"] == "validation_error"


def test_create_session_transport_with_spaces_returns_422():
    resp = client.post("/api/sessions/", json={"transport": "tc p"})
    assert resp.status_code == 422


def test_create_session_missing_transport_returns_422():
    resp = client.post("/api/sessions/", json={})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 2. Session READ
# ---------------------------------------------------------------------------

def test_list_sessions_returns_200():
    resp = client.get("/api/sessions/")
    assert resp.status_code == 200
    body = resp.json()
    assert "sessions" in body
    assert "total" in body
    assert isinstance(body["sessions"], list)


def test_list_sessions_filter_by_transport():
    client.post("/api/sessions/", json={"transport": "filter-test-transport"})
    resp = client.get("/api/sessions/?transport=filter-test-transport")
    assert resp.status_code == 200
    for s in resp.json()["sessions"]:
        assert s["transport"] == "filter-test-transport"


def test_get_session_by_id():
    create = client.post("/api/sessions/", json={"transport": "tcp"})
    sid = create.json()["id"]
    resp = client.get(f"/api/sessions/{sid}")
    assert resp.status_code == 200
    assert resp.json()["id"] == sid


def test_get_nonexistent_session_returns_404():
    resp = client.get("/api/sessions/999999")
    assert resp.status_code == 404
    assert resp.json()["error"] == "not_found"


# ---------------------------------------------------------------------------
# 3. Session UPDATE
# ---------------------------------------------------------------------------

def test_patch_session_status():
    sid = client.post("/api/sessions/", json={"transport": "tcp"}).json()["id"]
    resp = client.patch(f"/api/sessions/{sid}", json={"status": "inactive"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "inactive"


def test_patch_session_invalid_status_returns_422():
    sid = client.post("/api/sessions/", json={"transport": "tcp"}).json()["id"]
    resp = client.patch(f"/api/sessions/{sid}", json={"status": "flying"})
    assert resp.status_code == 422
    assert resp.json()["error"] == "validation_error"


def test_patch_nonexistent_session_returns_404():
    resp = client.patch("/api/sessions/999999", json={"status": "inactive"})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 4. Session DELETE
# ---------------------------------------------------------------------------

def test_delete_session_returns_204():
    sid = client.post("/api/sessions/", json={"transport": "tcp"}).json()["id"]
    resp = client.delete(f"/api/sessions/{sid}")
    assert resp.status_code == 204


def test_delete_session_then_get_returns_404():
    sid = client.post("/api/sessions/", json={"transport": "tcp"}).json()["id"]
    client.delete(f"/api/sessions/{sid}")
    resp = client.get(f"/api/sessions/{sid}")
    assert resp.status_code == 404


def test_delete_nonexistent_session_returns_404():
    resp = client.delete("/api/sessions/999999")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 5. Task submission — the core enqueue verification
# ---------------------------------------------------------------------------

def test_task_submission_enqueues_task():
    sid = client.post("/api/sessions/", json={"transport": "tcp"}).json()["id"]
    resp = client.post(f"/api/sessions/{sid}/tasks", json={"command": "whoami"})
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "queued"
    assert body["command"] == "whoami"
    assert "task_id" in body
    assert body["task_id"] > 0     # real DB id, not stub


def test_task_submission_persisted_to_db():
    """Verify task appears in GET /tasks after submission."""
    sid = client.post("/api/sessions/", json={"transport": "tcp"}).json()["id"]
    task = client.post(f"/api/sessions/{sid}/tasks", json={"command": "id"}).json()
    resp = client.get(f"/api/sessions/{sid}/tasks/{task['task_id']}")
    assert resp.status_code == 200
    assert resp.json()["command"] == "id"


def test_task_submission_blank_command_returns_422():
    sid = client.post("/api/sessions/", json={"transport": "tcp"}).json()["id"]
    resp = client.post(f"/api/sessions/{sid}/tasks", json={"command": "   "})
    assert resp.status_code == 422
    assert resp.json()["error"] == "validation_error"


def test_task_submission_empty_command_returns_422():
    sid = client.post("/api/sessions/", json={"transport": "tcp"}).json()["id"]
    resp = client.post(f"/api/sessions/{sid}/tasks", json={"command": ""})
    assert resp.status_code == 422


def test_task_submission_to_terminated_session_returns_409():
    sid = client.post("/api/sessions/", json={"transport": "tcp"}).json()["id"]
    client.patch(f"/api/sessions/{sid}", json={"status": "terminated"})
    resp = client.post(f"/api/sessions/{sid}/tasks", json={"command": "whoami"})
    assert resp.status_code == 409
    assert "terminated" in resp.json()["message"]


def test_task_submission_to_nonexistent_session_returns_404():
    resp = client.post("/api/sessions/999999/tasks", json={"command": "id"})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 6. Task result update
# ---------------------------------------------------------------------------

def test_patch_task_result():
    sid = client.post("/api/sessions/", json={"transport": "tcp"}).json()["id"]
    task = client.post(f"/api/sessions/{sid}/tasks", json={"command": "hostname"}).json()
    resp = client.patch(
        f"/api/sessions/{sid}/tasks/{task['task_id']}",
        json={"status": "completed", "output": "sentry-host"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert body["output"] == "sentry-host"
    assert body["completed_at"] is not None


def test_patch_task_invalid_status_returns_422():
    sid = client.post("/api/sessions/", json={"transport": "tcp"}).json()["id"]
    task = client.post(f"/api/sessions/{sid}/tasks", json={"command": "id"}).json()
    resp = client.patch(
        f"/api/sessions/{sid}/tasks/{task['task_id']}",
        json={"status": "pending", "output": ""},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 7. Consistent error response shape
# ---------------------------------------------------------------------------

def test_all_404s_have_error_field():
    endpoints = [
        "/api/sessions/999999",
        "/api/sessions/999999/tasks",
        "/api/sessions/999999/tasks/1",
    ]
    for url in endpoints:
        resp = client.get(url)
        assert resp.status_code == 404
        body = resp.json()
        assert "error" in body, f"Missing 'error' field in 404 from {url}"
        assert "message" in body, f"Missing 'message' field in 404 from {url}"


def test_all_422s_have_validation_error_code():
    bad_requests = [
        ("/api/sessions/", "post", {"transport": ""}),
        ("/api/sessions/", "post", {}),
    ]
    for url, method, body in bad_requests:
        resp = getattr(client, method)(url, json=body)
        assert resp.status_code == 422
        assert resp.json()["error"] == "validation_error"
