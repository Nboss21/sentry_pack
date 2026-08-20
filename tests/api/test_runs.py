"""
Tests for POST /api/targets/{id}/run route.
"""

from fastapi.testclient import TestClient
from api.main import app
from api.db.session import init_db, SessionLocal
from api.db.models import Project, Target

client = TestClient(app)


def _setup_test_target() -> int:
    init_db()
    db = SessionLocal()
    project = db.query(Project).filter(Project.name == "Test Project").first()
    if not project:
        project = Project(name="Test Project", description="Test project for runs API")
        db.add(project)
        db.commit()
        db.refresh(project)

    target = Target(project_id=project.id, name="Test Target", ip_address="127.0.0.1")
    db.add(target)
    db.commit()
    db.refresh(target)
    target_id = target.id
    db.close()
    return target_id


def test_run_module_success():
    target_id = _setup_test_target()
    payload = {
        "module_id": "dev.hello_world",
        "options": {"GREETING": "Test Hello"},
    }
    response = client.post(f"/api/targets/{target_id}/run", json=payload)
    assert response.status_code in (200, 201)
    data = response.json()
    assert "run_id" in data
    assert data["run_id"] is not None
    assert data["status"] == "started"
    assert data["target_id"] == target_id
    assert data["module_id"] == "dev.hello_world"


def test_run_module_missing_required_option():
    target_id = _setup_test_target()
    # recon.nmap_scan requires TARGET option
    payload = {
        "module_id": "recon.nmap_scan",
        "options": {},
    }
    response = client.post(f"/api/targets/{target_id}/run", json=payload)
    assert response.status_code == 422
    data = response.json()
    # Ensure error detail identifies missing option name TARGET
    detail_str = str(data.get("detail", ""))
    assert "TARGET" in detail_str


def test_run_module_invalid_option_type():
    target_id = _setup_test_target()
    # dev.hello_world option GREETING must be a string, pass an int/invalid type
    payload = {
        "module_id": "dev.hello_world",
        "options": {"GREETING": 12345},
    }
    response = client.post(f"/api/targets/{target_id}/run", json=payload)
    assert response.status_code == 422
    data = response.json()
    detail_str = str(data.get("detail", ""))
    assert "GREETING" in detail_str


def test_run_module_unknown_module():
    target_id = _setup_test_target()
    payload = {
        "module_id": "nonexistent.module_id",
        "options": {},
    }
    response = client.post(f"/api/targets/{target_id}/run", json=payload)
    assert response.status_code == 404
