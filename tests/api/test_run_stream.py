"""
WebSocket stream integration tests for /ws/runs/{run_id}.
"""

from fastapi.testclient import TestClient
from api.main import app
from api.db.session import init_db, SessionLocal
from api.db.models import Project, Target

client = TestClient(app)


def _setup_test_target() -> int:
    init_db()
    db = SessionLocal()
    project = db.query(Project).filter(Project.name == "Test Project WS").first()
    if not project:
        project = Project(name="Test Project WS", description="Test project for WS API")
        db.add(project)
        db.commit()
        db.refresh(project)

    target = Target(project_id=project.id, name="WS Target", ip_address="127.0.0.1")
    db.add(target)
    db.commit()
    db.refresh(target)
    target_id = target.id
    db.close()
    return target_id


def test_ws_run_stream_hello_world():
    target_id = _setup_test_target()
    res = client.post(
        f"/api/targets/{target_id}/run",
        json={"module_id": "dev.hello_world", "options": {}},
    )
    assert res.status_code in (200, 201)
    run_id = res.json()["run_id"]

    events = []
    with client.websocket_connect(f"/ws/runs/{run_id}") as ws:
        while True:
            try:
                data = ws.receive_json()
                events.append(data)
                if data.get("type") in ("complete", "error"):
                    break
            except Exception:
                break

    event_types = [e["type"] for e in events]
    assert "log" in event_types
    assert "complete" in event_types

    log_messages = [e.get("message", "") for e in events if e.get("type") == "log"]
    assert any("still working" in m for m in log_messages)

    complete_event = next(e for e in events if e.get("type") == "complete")
    assert len(complete_event["findings"]) == 1
    assert complete_event["findings"][0]["title"] == "Hello World"


def test_ws_run_stream_multiple_concurrent_clients():
    target_id = _setup_test_target()
    res = client.post(
        f"/api/targets/{target_id}/run",
        json={"module_id": "dev.hello_world", "options": {}},
    )
    assert res.status_code in (200, 201)
    run_id = res.json()["run_id"]

    events1 = []
    events2 = []

    with client.websocket_connect(f"/ws/runs/{run_id}") as ws1:
        with client.websocket_connect(f"/ws/runs/{run_id}") as ws2:
            while True:
                try:
                    data1 = ws1.receive_json()
                    events1.append(data1)
                    if data1.get("type") in ("complete", "error"):
                        break
                except Exception:
                    break

            while True:
                try:
                    data2 = ws2.receive_json()
                    events2.append(data2)
                    if data2.get("type") in ("complete", "error"):
                        break
                except Exception:
                    break

    types1 = [e["type"] for e in events1]
    types2 = [e["type"] for e in events2]
    assert types1 == types2
    assert "complete" in types1


def test_ws_run_stream_unknown_run_id():
    with client.websocket_connect("/ws/runs/nonexistent-run-id-999") as ws:
        data = ws.receive_json()
        assert data.get("type") == "error"
        assert "not found" in data.get("message", "").lower()
